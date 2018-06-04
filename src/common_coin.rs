//! A small-scale unbiasable asynchronous distributed Common Coin protocol.
//!
//! Reference: Ewa Syta, Philipp Jovanovic, Eleftherios Kokoris Kogias, Nicolas Gailly, Linus
//! Gasser, Ismail Khoffi, Michael J. Fischer, Bryan Ford. Scalable Bias-Resistant Distributed
//! Randomness. https://eprint.iacr.org/2016/1067.pdf

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Debug;
use std::rc::Rc;

use rand::thread_rng;

use pairing::Engine;

use crypto::{self, CommitmentSet, SecretKey, SecretKeySet};
use messaging::{DistAlgorithm, NetworkInfo, Target, TargetedMessage};

error_chain!{
    types {
        Error, ErrorKind, ResultExt, CommonCoinResult;
    }

    links {
        Crypto(crypto::error::Error, crypto::error::ErrorKind);
    }

    errors {
        UnknownSender {
            description("Unknown sender")
        }

        VssThresholdNotReached {
            description("VSS threshold was not reached")
        }
    }
}

/// Messages exchanged by instances of Common Coin.
#[derive(Debug)]
pub enum CommonCoinMessage<E: Debug + Engine, N> {
    /// Secret share from a proposer node.
    SecretShare(SecretKey<E>),
    /// Polynomial commitments (public keys) for all coefficients of the secret sharing polynomial.
    Commitments(CommitmentSet<E>),
    /// Positive vote on a secret share from a given remote node.
    PositiveVote(N),
    /// Negative vote on a secret share from a given remote node.
    NegativeVote(N),
    /// Positive commitment for a given node's secret.
    PositiveCommit(N),
    /// Negative commitment for a given node's secret.
    NegativeCommit(N),
    /// Secret share broadcast during a share disclosure round.
    DisclosedShare(N, SecretKey<E>),
}

/// A relatively simple distributed BFT common coin protocol, RandShare, whose communication
/// complexity is O(n^3). It tolerates a Byzantine adversary controlling `num_faulty` nodes in a
/// network of `num_nodes = 3 * num_faulty + 1` nodes where messages are eventually delivered. The
/// protocol uses a `(num_faulty + 1, num_nodes)`-secret sharing scheme:
///
/// - All `num_nodes` peers distribute secret shares of their inputs using a `num_faulty + 1`
/// recovery threshold.
///
/// - Only after each peer receives `num_faulty + 1` shares will they reconstruct their inputs and
/// generate the random output.
pub struct CommonCoin<E, N>
where
    E: Debug + Engine,
{
    netinfo: Rc<NetworkInfo<N>>,
    /// The collective random string.
    output: Option<Vec<u8>>,
    messages: VecDeque<TargetedMessage<CommonCoinMessage<E, N>, N>>,
    terminated: bool,
    valid_secrets: BTreeMap<usize, bool>,
    secret_shares: BTreeMap<usize, SecretKey<E>>,
    commitment_sets: BTreeMap<usize, CommitmentSet<E>>,
    /// A mapping of a node ID to the set of indices of nodes that voted for that node's secret.
    positive_votes: BTreeMap<N, BTreeSet<usize>>,
    /// A mapping of a node ID to the set of indices of nodes that voted against that node's secret.
    negative_votes: BTreeMap<N, BTreeSet<usize>>,
    /// A mapping of node indices to the number of positive commit messages received for that node's
    /// secret.
    positive_commits: BTreeMap<N, BTreeSet<usize>>,
    /// A mapping of node indices to the number of negative commit messages received for that node's
    /// secret.
    negative_commits: BTreeMap<N, BTreeSet<usize>>,
}

impl<E, N> DistAlgorithm for CommonCoin<E, N>
where
    E: Debug + Engine,
    N: Clone + Debug + Ord,
{
    type NodeUid = N;
    type Input = ();
    type Output = Vec<u8>;
    type Message = CommonCoinMessage<E, N>;
    type Error = Error;

    fn input(&mut self, _input: Self::Input) -> CommonCoinResult<()> {
        self.share_distribution();
        Ok(())
    }

    fn handle_message(&mut self, sender_id: &N, message: Self::Message) -> CommonCoinResult<()> {
        if let Some(j) = self.get_node_index(sender_id) {
            match message {
                CommonCoinMessage::SecretShare(share) => {
                    self.handle_secret_share(sender_id.clone(), j, share)
                }
                CommonCoinMessage::Commitments(cs) => self.handle_commitments(j, cs),
                CommonCoinMessage::PositiveVote(id) => self.handle_pos_vote(id, j),
                CommonCoinMessage::NegativeVote(id) => self.handle_neg_vote(id, j),
                CommonCoinMessage::PositiveCommit(id) => self.handle_pos_commit(&id, j),
                CommonCoinMessage::NegativeCommit(id) => self.handle_neg_commit(&id, j),
                CommonCoinMessage::DisclosedShare(id, share) => self.handle_disclosed(&id, &share),
            }
        } else {
            Err(ErrorKind::UnknownSender.into())
        }
    }

    fn next_message(&mut self) -> Option<TargetedMessage<Self::Message, N>> {
        self.messages.pop_front()
    }

    fn next_output(&mut self) -> Option<Self::Output> {
        self.output.take()
    }

    fn terminated(&self) -> bool {
        self.terminated
    }

    fn our_id(&self) -> &N {
        self.netinfo.our_uid()
    }
}

impl<E, N> CommonCoin<E, N>
where
    E: Debug + Engine,
    N: Clone + Ord,
{
    pub fn new(netinfo: Rc<NetworkInfo<N>>) -> Self {
        CommonCoin {
            netinfo,
            output: None,
            messages: VecDeque::new(),
            terminated: false,
            valid_secrets: BTreeMap::new(),
            secret_shares: BTreeMap::new(),
            commitment_sets: BTreeMap::new(),
            positive_votes: BTreeMap::new(),
            negative_votes: BTreeMap::new(),
            positive_commits: BTreeMap::new(),
            negative_commits: BTreeMap::new(),
        }
    }

    fn get_node_index(&self, uid: &N) -> Option<usize> {
        self.netinfo.all_uids().iter().position(|uid0| uid0 == uid)
    }

    /// Selects coefficients of a degree `num_faulty` secret sharing polynomial. The secret to be
    /// shared is the value of the polynomial at `0`. Computes polynomial commitments for all
    /// coefficients and calculates secret shares for all peers. Securely sends shares to their
    /// corresponding remote peers and starts a Byzantine agreement run on the secret share by
    /// broadcasting the vector of all commitments.
    fn share_distribution(&mut self) {
        let mut rng = thread_rng();

        let sk_set = SecretKeySet::<E>::new(self.netinfo.num_faulty(), &mut rng);
        let commit_set = sk_set.commitments();
        self.messages
            .push_back(Target::All.message(CommonCoinMessage::Commitments(commit_set)));
        for (i, id) in self.netinfo.all_uids().into_iter().enumerate() {
            // FIXME: Send securely.
            self.messages.push_back(Target::Node(id.clone()).message(
                CommonCoinMessage::SecretShare(sk_set.secret_key_share(i as u64 + 1)),
            ));
        }
    }

    /// After a decision has been made for all entries of `secrets`, checks the number of valid
    /// secrets. If that number is greater than `num_faulty`, broadcasts the secret shares of those
    /// secrets. Otherwise aborts.
    fn try_share_disclosure(&mut self) -> CommonCoinResult<()> {
        let num_valid_secrets = self.valid_secrets.len();
        if num_valid_secrets != self.netinfo.num_nodes() {
            Ok(())
        } else if num_valid_secrets <= self.netinfo.num_faulty() {
            Err(ErrorKind::VssThresholdNotReached.into())
        } else {
            self.broadcast_shares()
        }
    }

    fn broadcast_shares(&self) -> CommonCoinResult<()> {
        // FIXME
        Ok(())
    }

    /// After at least `num_faulty + 1` shares have been received for each remote node, recovers the
    /// secret sharing polynomial of that node through Lagrange interpolation and computes its
    /// secret, the value of the polynomial at `0`. Computes and publishes the collective random
    /// string as a sum of secrets.
    fn handle_disclosed(
        &mut self,
        _proposer_id: &N,
        _share: &SecretKey<E>,
    ) -> CommonCoinResult<()> {
        // FIXME
        Ok(())
    }

    /// Verifies a share against the received commitments. If verification of a share succeeds,
    /// broadcasts the "prepare" message as a positive vote on the share's remote node shared
    /// secret. Otherwise, broadcasts a negative vote. The latter also includes the case when the
    /// commitments were not received from the remote node.
    fn handle_secret_share(
        &mut self,
        sender_id: N,
        j: usize,
        share: SecretKey<E>,
    ) -> CommonCoinResult<()> {
        let our_uid = self.netinfo.our_uid().clone();
        let node_index = &self.get_node_index(&our_uid);
        let commitment_set = &mut self.commitment_sets.get(&j);
        let secret_shares = &mut self.secret_shares;
        let messages = &mut self.messages;
        let pos_votes = &mut self.positive_votes;
        let neg_votes = &mut self.negative_votes;
        let pos = if let Some(cs) = commitment_set {
            cs.verify(&share, j)
        } else {
            false
        };

        if pos {
            secret_shares.insert(j, share);
            messages.push_back(Target::All.message(CommonCoinMessage::PositiveVote(our_uid)));
            node_index.map(|i| insert_at_key(pos_votes, sender_id, i));
        } else {
            messages.push_back(Target::All.message(CommonCoinMessage::NegativeVote(our_uid)));
            node_index.map(|i| insert_at_key(neg_votes, sender_id, i));
        }

        Ok(())
    }

    fn handle_commitments(
        &mut self,
        i: usize,
        commitment_set: CommitmentSet<E>,
    ) -> CommonCoinResult<()> {
        self.commitment_sets.insert(i, commitment_set);
        Ok(())
    }

    /// If there are at least `2 * num_faulty + 1` positive votes for the shared
    /// secret, broadcasts a positive commitment.
    fn handle_pos_vote(&mut self, proposer_id: N, j: usize) -> CommonCoinResult<()> {
        insert_at_key(&mut self.positive_votes, proposer_id.clone(), j);
        if let Some(set) = self.positive_votes.get(&proposer_id) {
            if set.len() > 2 * self.netinfo.num_faulty() {
                self.messages
                    .push_back(Target::All.message(CommonCoinMessage::PositiveCommit(proposer_id)));
            }
        }
        Ok(())
    }

    /// If there are at least `num_faulty + 1` negative votes for the secret, broadcasts a negative
    /// commitment.
    fn handle_neg_vote(&mut self, proposer_id: N, j: usize) -> CommonCoinResult<()> {
        insert_at_key(&mut self.negative_votes, proposer_id.clone(), j);
        if let Some(set) = self.negative_votes.get(&proposer_id) {
            if set.len() > self.netinfo.num_faulty() {
                self.messages
                    .push_back(Target::All.message(CommonCoinMessage::NegativeCommit(proposer_id)));
            }
        }
        Ok(())
    }

    /// If there are at least `2 * num_faulty + 1` either all positive or all negative commitments
    /// for a secret, considers that secret valid (recoverable) or invalid, respectively.
    fn handle_pos_commit(&mut self, proposer_id: &N, j: usize) -> CommonCoinResult<()> {
        insert_at_key(&mut self.positive_commits, proposer_id.clone(), j);
        if let Some(set) = self.positive_commits.get(&proposer_id) {
            if set.len() > 2 * self.netinfo.num_faulty() {
                self.valid_secrets.insert(j, true);
            }
        }
        self.try_share_disclosure()
    }

    fn handle_neg_commit(&mut self, proposer_id: &N, j: usize) -> CommonCoinResult<()> {
        insert_at_key(&mut self.negative_commits, proposer_id.clone(), j);
        if let Some(set) = self.negative_commits.get(&proposer_id) {
            if set.len() > 2 * self.netinfo.num_faulty() {
                self.valid_secrets.insert(j, false);
            }
        }
        self.try_share_disclosure()
    }
}

fn insert_at_key<N: Ord, V: Ord>(map: &mut BTreeMap<N, BTreeSet<V>>, key: N, value: V) {
    map.entry(key)
        .and_modify(|e| {
            e.insert(value);
        })
        .or_insert_with(BTreeSet::new);
}

#[test]
fn insert_at_key_1_2_2() {
    let mut map = BTreeMap::new();
    insert_at_key(&mut map, 42, 1);
    assert_eq!(map.get(&42).unwrap().len(), 1);
    for _ in 0..2 {
        insert_at_key(&mut map, 42, 2);
        assert_eq!(map.get(&42).unwrap().len(), 2);
    }
}
