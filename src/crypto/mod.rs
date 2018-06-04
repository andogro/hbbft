pub mod error;

use byteorder::{BigEndian, ByteOrder};
use init_with::InitWith;
use pairing::{CurveAffine, CurveProjective, Engine, Field, PrimeField};
use rand::{ChaChaRng, OsRng, Rng, SeedableRng};
use ring::digest;

use self::error::{ErrorKind, Result};

/// The number of words (`u32`) in a ChaCha RNG seed.
const CHACHA_RNG_SEED_SIZE: usize = 8;

const ERR_OS_RNG: &str = "could not initialize the OS random number generator";

/// A public key, or a public key share.
#[derive(Debug)]
pub struct PublicKey<E: Engine>(E::G1);

impl<E: Engine> PartialEq for PublicKey<E> {
    fn eq(&self, other: &PublicKey<E>) -> bool {
        self.0 == other.0
    }
}

impl<E: Engine> PublicKey<E> {
    /// Returns `true` if the signature matches the element of `E::G2`.
    pub fn verify_g2<H: Into<E::G2Affine>>(&self, sig: &Signature<E>, hash: H) -> bool {
        E::pairing(self.0, hash) == E::pairing(E::G1Affine::one(), sig.0)
    }

    /// Returns `true` if the signature matches the message.
    pub fn verify<M: AsRef<[u8]>>(&self, sig: &Signature<E>, msg: M) -> bool {
        self.verify_g2(sig, hash_g2::<E, M>(msg))
    }

    /// Returns `true` if the decryption share matches the ciphertext.
    pub fn verify_decryption_share(&self, share: &DecryptionShare<E>, ct: &Ciphertext<E>) -> bool {
        let Ciphertext(ref u, ref v, ref w) = *ct;
        let hash = hash_g1_g2::<E, _>(*u, v);
        E::pairing(share.0, hash) == E::pairing(self.0, *w)
    }

    /// Encrypts the message.
    pub fn encrypt<M: AsRef<[u8]>>(&self, msg: M) -> Ciphertext<E> {
        let r: E::Fr = OsRng::new().expect(ERR_OS_RNG).gen();
        let u = E::G1Affine::one().mul(r);
        let v: Vec<u8> = {
            let g = self.0.into_affine().mul(r);
            xor_vec(&hash_bytes::<E>(g, msg.as_ref().len()), msg.as_ref())
        };
        let w = hash_g1_g2::<E, _>(u, &v).into_affine().mul(r);
        Ciphertext(u, v, w)
    }
}

#[derive(Debug)]
pub struct Commitment<E: Engine>(E::Fq);

impl<E: Engine> PartialEq for Commitment<E> {
    fn eq(&self, other: &Commitment<E>) -> bool {
        self.0 == other.0
    }
}

// TODO
impl<E: Engine> Commitment<E> {}

/// A signature, or a signature share.
#[derive(Debug)]
pub struct Signature<E: Engine>(E::G2);

impl<E: Engine> PartialEq for Signature<E> {
    fn eq(&self, other: &Signature<E>) -> bool {
        self.0 == other.0
    }
}

/// A secret key, or a secret key share.
#[derive(Debug)]
pub struct SecretKey<E: Engine>(E::Fr);

impl<E: Engine> PartialEq for SecretKey<E> {
    fn eq(&self, other: &SecretKey<E>) -> bool {
        self.0 == other.0
    }
}

impl<E: Engine> SecretKey<E> {
    /// Creates a new secret key.
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        SecretKey(rng.gen())
    }

    /// Returns the matching public key.
    pub fn public_key(&self) -> PublicKey<E> {
        PublicKey(E::G1Affine::one().mul(self.0))
    }

    /// Signs the given element of `E::G2`.
    pub fn sign_g2<H: Into<E::G2Affine>>(&self, hash: H) -> Signature<E> {
        Signature(hash.into().mul(self.0))
    }

    /// Signs the given message.
    pub fn sign<M: AsRef<[u8]>>(&self, msg: M) -> Signature<E> {
        self.sign_g2(hash_g2::<E, M>(msg))
    }

    /// Returns the decrypted text, or `None`, if the ciphertext isn't valid.
    pub fn decrypt(&self, ct: &Ciphertext<E>) -> Option<Vec<u8>> {
        if !ct.verify() {
            return None;
        }
        let Ciphertext(ref u, ref v, _) = *ct;
        let g = u.into_affine().mul(self.0);
        Some(xor_vec(&hash_bytes::<E>(g, v.len()), v))
    }

    /// Returns a decryption share, or `None`, if the ciphertext isn't valid.
    pub fn decrypt_share(&self, ct: &Ciphertext<E>) -> Option<DecryptionShare<E>> {
        if !ct.verify() {
            return None;
        }
        Some(DecryptionShare(ct.0.into_affine().mul(self.0)))
    }
}

/// An encrypted message.
#[derive(Debug)]
pub struct Ciphertext<E: Engine>(E::G1, Vec<u8>, E::G2);

impl<E: Engine> PartialEq for Ciphertext<E> {
    fn eq(&self, other: &Ciphertext<E>) -> bool {
        self.0 == other.0 && self.1 == other.1 && self.2 == other.2
    }
}

impl<E: Engine> Ciphertext<E> {
    /// Returns `true` if this is a valid ciphertext. This check is necessary to prevent
    /// chosen-ciphertext attacks.
    pub fn verify(&self) -> bool {
        let Ciphertext(ref u, ref v, ref w) = *self;
        let hash = hash_g1_g2::<E, _>(*u, v);
        E::pairing(E::G1Affine::one(), *w) == E::pairing(*u, hash)
    }
}

/// A decryption share. A threshold of decryption shares can be used to decrypt a message.
#[derive(Debug)]
pub struct DecryptionShare<E: Engine>(E::G1);

impl<E: Engine> PartialEq for DecryptionShare<E> {
    fn eq(&self, other: &DecryptionShare<E>) -> bool {
        self.0 == other.0
    }
}

/// A public key and an associated set of public key shares.
#[cfg_attr(feature = "serialization-serde", derive(Serialize, Deserialize))]
pub struct PublicKeySet<E: Engine> {
    /// The coefficients of a polynomial whose value at `0` is the "master key", and value at
    /// `i + 1` is key share number `i`.
    coeff: Vec<PublicKey<E>>,
}

impl<E: Engine> PublicKeySet<E> {
    /// Returns the threshold `t`: any set of `t + 1` signature shares can be combined into a full
    /// signature.
    pub fn threshold(&self) -> usize {
        self.coeff.len() - 1
    }

    /// Returns the public key.
    pub fn public_key(&self) -> &PublicKey<E> {
        &self.coeff[0]
    }

    /// Returns the `i`-th public key share.
    pub fn public_key_share<T>(&self, i: T) -> PublicKey<E>
    where
        T: Into<<E::Fr as PrimeField>::Repr>,
    {
        let mut x = E::Fr::one();
        x.add_assign(&E::Fr::from_repr(i.into()).expect("invalid index"));
        let mut pk = self.coeff.last().expect("at least one coefficient").0;
        for c in self.coeff.iter().rev().skip(1) {
            pk.mul_assign(x);
            pk.add_assign(&c.0);
        }
        PublicKey(pk)
    }

    /// Combines the shares into a signature that can be verified with the main public key.
    pub fn combine_signatures<'a, ITR, IND>(&self, shares: ITR) -> Result<Signature<E>>
    where
        ITR: IntoIterator<Item = (&'a IND, &'a Signature<E>)>,
        IND: Into<<E::Fr as PrimeField>::Repr> + Clone + 'a,
    {
        let samples = shares.into_iter().map(|(i, share)| (i, &share.0));
        Ok(Signature(interpolate(self.coeff.len(), samples)?))
    }

    /// Combines the shares to decrypt the ciphertext.
    pub fn decrypt<'a, ITR, IND>(&self, shares: ITR, ct: &Ciphertext<E>) -> Result<Vec<u8>>
    where
        ITR: IntoIterator<Item = (&'a IND, &'a DecryptionShare<E>)>,
        IND: Into<<E::Fr as PrimeField>::Repr> + Clone + 'a,
    {
        let samples = shares.into_iter().map(|(i, share)| (i, &share.0));
        let g = interpolate(self.coeff.len(), samples)?;
        Ok(xor_vec(&hash_bytes::<E>(g, ct.1.len()), &ct.1))
    }
}

/// A set of polynomial commitments corresponding to a shared secret in Common Coin.
#[cfg_attr(feature = "serialization-serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct CommitmentSet<E: Engine> {
    commitments: Vec<Commitment<E>>,
}

impl<E: Engine> CommitmentSet<E> {
    /// Verifies a secret share of a node with a 0-based index `i` against the commitments received
    /// from another node that sent the secret share.
    pub fn verify(&self, share: &SecretKey<E>, i: usize) -> bool {
        let i = i + 1;
        let prod_exp = self.commitments.iter().enumerate().fold(
            E::Fq::one(),
            |mut result, (k, a)| {
                result.mul_assign(&a.0.pow([(i ^ k) as u64]));
                result
            },
        );
        prod_exp == E::Fq::one().pow(share.0.into_repr())
    }
}

/// A secret key and an associated set of secret key shares.
pub struct SecretKeySet<E: Engine> {
    /// The coefficients of a polynomial whose value at `0` is the "master key", and value at
    /// `i + 1` is key share number `i`.
    coeff: Vec<E::Fr>,
}

impl<E: Engine> SecretKeySet<E> {
    /// Creates a set of secret key shares, where any `threshold + 1` of them can collaboratively
    /// sign and decrypt.
    pub fn new<R: Rng>(threshold: usize, rng: &mut R) -> Self {
        SecretKeySet {
            coeff: (0..(threshold + 1)).map(|_| rng.gen()).collect(),
        }
    }

    /// Returns the threshold `t`: any set of `t + 1` signature shares can be combined into a full
    /// signature.
    pub fn threshold(&self) -> usize {
        self.coeff.len() - 1
    }

    /// Returns the `i`-th secret key share.
    pub fn secret_key_share<T>(&self, i: T) -> SecretKey<E>
    where
        T: Into<<E::Fr as PrimeField>::Repr>,
    {
        let x = from_repr_plus_1(i.into());
        let mut pk = *self.coeff.last().expect("at least one coefficient");
        for c in self.coeff.iter().rev().skip(1) {
            pk.mul_assign(&x);
            pk.add_assign(c);
        }
        SecretKey(pk)
    }

    /// Returns the corresponding public key set. That information can be shared publicly.
    pub fn public_keys(&self) -> PublicKeySet<E> {
        let to_pub = |c: &E::Fr| PublicKey(E::G1Affine::one().mul(*c));
        PublicKeySet {
            coeff: self.coeff.iter().map(to_pub).collect(),
        }
    }

    /// Computes the polynomial commitments for Common Coin.
    pub fn commitments(&self) -> CommitmentSet<E> {
        let to_commit = |a: &E::Fr| Commitment(E::Fq::one().pow(a.into_repr()));
        CommitmentSet {
            commitments: self.coeff.iter().map(to_commit).collect(),
        }
    }
}

/// Returns a hash of the given message in `G2`.
fn hash_g2<E: Engine, M: AsRef<[u8]>>(msg: M) -> E::G2 {
    let digest = digest::digest(&digest::SHA256, msg.as_ref());
    let seed = <[u32; CHACHA_RNG_SEED_SIZE]>::init_with_indices(|i| {
        BigEndian::read_u32(&digest.as_ref()[(4 * i)..(4 * i + 4)])
    });
    let mut rng = ChaChaRng::from_seed(&seed);
    rng.gen()
}

/// Returns a hash of the group element and message, in the second group.
fn hash_g1_g2<E: Engine, M: AsRef<[u8]>>(g1: E::G1, msg: M) -> E::G2 {
    // If the message is large, hash it, otherwise copy it.
    // TODO: Benchmark and optimize the threshold.
    let mut msg = if msg.as_ref().len() > 64 {
        let digest = digest::digest(&digest::SHA256, msg.as_ref());
        digest.as_ref().to_vec()
    } else {
        msg.as_ref().to_vec()
    };
    msg.extend(g1.into_affine().into_compressed().as_ref());
    hash_g2::<E, _>(&msg)
}

/// Returns a hash of the group element with the specified length in bytes.
fn hash_bytes<E: Engine>(g1: E::G1, len: usize) -> Vec<u8> {
    let digest = digest::digest(&digest::SHA256, g1.into_affine().into_compressed().as_ref());
    let seed = <[u32; CHACHA_RNG_SEED_SIZE]>::init_with_indices(|i| {
        BigEndian::read_u32(&digest.as_ref()[(4 * i)..(4 * i + 4)])
    });
    let mut rng = ChaChaRng::from_seed(&seed);
    rng.gen_iter().take(len).collect()
}

/// Returns the bitwise xor.
fn xor_vec(x: &[u8], y: &[u8]) -> Vec<u8> {
    x.iter().zip(y).map(|(a, b)| a ^ b).collect()
}

/// Given a list of `t` samples `(i - 1, f(i) * g)` for a polynomial `f` of degree `t - 1`, and a
/// group generator `g`, returns `f(0) * g`.
pub fn interpolate<'a, C, ITR, IND>(t: usize, items: ITR) -> Result<C>
where
    C: CurveProjective,
    ITR: IntoIterator<Item = (&'a IND, &'a C)>,
    IND: Into<<C::Scalar as PrimeField>::Repr> + Clone + 'a,
{
    let samples: Vec<_> = items
        .into_iter()
        .map(|(i, sample)| (from_repr_plus_1::<C::Scalar>(i.clone().into()), sample))
        .collect();
    if samples.len() < t {
        return Err(ErrorKind::NotEnoughShares.into());
    }
    let mut result = C::zero();
    let mut indexes = Vec::new();
    for (x, sample) in samples.iter().take(t) {
        if indexes.contains(x) {
            return Err(ErrorKind::DuplicateEntry.into());
        }
        indexes.push(x.clone());
        // Compute the value at 0 of the Lagrange polynomial that is `0` at the other data
        // points but `1` at `x`.
        let mut l0 = C::Scalar::one();
        for (x0, _) in samples.iter().take(t).filter(|(x0, _)| x0 != x) {
            let mut denom = *x0;
            denom.sub_assign(x);
            l0.mul_assign(x0);
            l0.mul_assign(&denom.inverse().expect("indices are different"));
        }
        result.add_assign(&sample.into_affine().mul(l0));
    }
    Ok(result)
}

fn from_repr_plus_1<F: PrimeField>(repr: F::Repr) -> F {
    let mut x = F::one();
    x.add_assign(&F::from_repr(repr).expect("invalid index"));
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use pairing::bls12_381::Bls12;
    use rand;

    #[test]
    fn test_simple_sig() {
        let mut rng = rand::thread_rng();
        let sk0 = SecretKey::<Bls12>::new(&mut rng);
        let sk1 = SecretKey::<Bls12>::new(&mut rng);
        let pk0 = sk0.public_key();
        let msg0 = b"Real news";
        let msg1 = b"Fake news";
        assert!(pk0.verify(&sk0.sign(msg0), msg0));
        assert!(!pk0.verify(&sk1.sign(msg0), msg0)); // Wrong key.
        assert!(!pk0.verify(&sk0.sign(msg1), msg0)); // Wrong message.
    }

    #[test]
    fn test_threshold_sig() {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::<Bls12>::new(3, &mut rng);
        let pk_set = sk_set.public_keys();

        // Make sure the keys are different, and the first coefficient is the main key.
        assert_eq!(*pk_set.public_key(), pk_set.coeff[0]);
        assert_ne!(*pk_set.public_key(), pk_set.public_key_share(0));
        assert_ne!(*pk_set.public_key(), pk_set.public_key_share(1));
        assert_ne!(*pk_set.public_key(), pk_set.public_key_share(2));

        // Make sure we don't hand out the main secret key to anyone.
        assert_ne!(SecretKey(sk_set.coeff[0]), sk_set.secret_key_share(0));
        assert_ne!(SecretKey(sk_set.coeff[0]), sk_set.secret_key_share(1));
        assert_ne!(SecretKey(sk_set.coeff[0]), sk_set.secret_key_share(2));

        let msg = "Totally real news";

        // The threshold is 3, so 4 signature shares will suffice to recreate the share.
        let sigs: BTreeMap<_, _> = [5, 8, 7, 10]
            .into_iter()
            .map(|i| (*i, sk_set.secret_key_share(*i).sign(msg)))
            .collect();

        // Each of the shares is a valid signature matching its public key share.
        for (i, sig) in &sigs {
            pk_set.public_key_share(*i).verify(sig, msg);
        }

        // Combined, they produce a signature matching the main public key.
        let sig = pk_set.combine_signatures(&sigs).expect("signatures match");
        assert!(pk_set.public_key().verify(&sig, msg));

        // A different set of signatories produces the same signature.
        let sigs2: BTreeMap<_, _> = [42, 43, 44, 45]
            .into_iter()
            .map(|i| (*i, sk_set.secret_key_share(*i).sign(msg)))
            .collect();
        let sig2 = pk_set.combine_signatures(&sigs2).expect("signatures match");
        assert_eq!(sig, sig2);
    }

    #[test]
    fn test_simple_enc() {
        let mut rng = rand::thread_rng();
        let sk_bob = SecretKey::<Bls12>::new(&mut rng);
        let sk_eve = SecretKey::<Bls12>::new(&mut rng);
        let pk_bob = sk_bob.public_key();
        let msg = b"Muffins in the canteen today! Don't tell Eve!";
        let ciphertext = pk_bob.encrypt(&msg[..]);
        assert!(ciphertext.verify());

        // Bob can decrypt the message.
        let decrypted = sk_bob.decrypt(&ciphertext).expect("valid ciphertext");
        assert_eq!(msg[..], decrypted[..]);

        // Eve can't.
        let decrypted_eve = sk_eve.decrypt(&ciphertext).expect("valid ciphertext");
        assert_ne!(msg[..], decrypted_eve[..]);

        // Eve tries to trick Bob into decrypting `msg` xor `v`, but it doesn't validate.
        let Ciphertext(u, v, w) = ciphertext;
        let fake_ciphertext = Ciphertext::<Bls12>(u, vec![0; v.len()], w);
        assert!(!fake_ciphertext.verify());
        assert_eq!(None, sk_bob.decrypt(&fake_ciphertext));
    }

    #[test]
    fn test_threshold_enc() {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::<Bls12>::new(3, &mut rng);
        let pk_set = sk_set.public_keys();
        let msg = b"Totally real news";
        let ciphertext = pk_set.public_key().encrypt(&msg[..]);

        // The threshold is 3, so 4 signature shares will suffice to decrypt.
        let shares: BTreeMap<_, _> = [5, 8, 7, 10]
            .into_iter()
            .map(|i| {
                let ski = sk_set.secret_key_share(*i);
                let share = ski.decrypt_share(&ciphertext).expect("ciphertext is valid");
                (*i, share)
            })
            .collect();

        // Each of the shares is valid matching its public key share.
        for (i, share) in &shares {
            pk_set
                .public_key_share(*i)
                .verify_decryption_share(share, &ciphertext);
        }

        // Combined, they can decrypt the message.
        let decrypted = pk_set
            .decrypt(&shares, &ciphertext)
            .expect("decryption shares match");
        assert_eq!(msg[..], decrypted[..]);
    }

    /// Some basic sanity checks for the `hash_g2` function.
    #[test]
    fn test_hash_g2() {
        let mut rng = rand::thread_rng();
        let msg: Vec<u8> = (0..1000).map(|_| rng.gen()).collect();
        let msg_end0: Vec<u8> = msg.iter().chain(b"end0").cloned().collect();
        let msg_end1: Vec<u8> = msg.iter().chain(b"end1").cloned().collect();

        let hash = hash_g2::<Bls12, _>;
        assert_eq!(hash(&msg), hash(&msg));
        assert_ne!(hash(&msg), hash(&msg_end0));
        assert_ne!(hash(&msg_end0), hash(&msg_end1));
    }

    /// Some basic sanity checks for the `hash_g1_g2` function.
    #[test]
    fn test_hash_g1_g2() {
        let mut rng = rand::thread_rng();
        let msg: Vec<u8> = (0..1000).map(|_| rng.gen()).collect();
        let msg_end0: Vec<u8> = msg.iter().chain(b"end0").cloned().collect();
        let msg_end1: Vec<u8> = msg.iter().chain(b"end1").cloned().collect();
        let g0 = rng.gen();
        let g1 = rng.gen();

        let hash = hash_g1_g2::<Bls12, _>;
        assert_eq!(hash(g0, &msg), hash(g0, &msg));
        assert_ne!(hash(g0, &msg), hash(g0, &msg_end0));
        assert_ne!(hash(g0, &msg_end0), hash(g0, &msg_end1));
        assert_ne!(hash(g0, &msg), hash(g1, &msg));
    }

    /// Some basic sanity checks for the `hash_bytes` function.
    #[test]
    fn test_hash_bytes() {
        let mut rng = rand::thread_rng();
        let g0 = rng.gen();
        let g1 = rng.gen();
        let hash = hash_bytes::<Bls12>;
        assert_eq!(hash(g0, 5), hash(g0, 5));
        assert_ne!(hash(g0, 5), hash(g1, 5));
        assert_eq!(5, hash(g0, 5).len());
        assert_eq!(6, hash(g0, 6).len());
        assert_eq!(20, hash(g0, 20).len());
    }

    #[cfg(feature = "serialization-serde")]
    #[test]
    fn test_serde() {
        use bincode;

        let mut rng = rand::thread_rng();
        let sk = SecretKey::<Bls12>::new(&mut rng);
        let sig = sk.sign("Please sign here: ______");
        let pk = sk.public_key();
        let ser_pk = bincode::serialize(&pk).expect("serialize public key");
        let deser_pk = bincode::deserialize(&ser_pk).expect("deserialize public key");
        assert_eq!(pk, deser_pk);
        let ser_sig = bincode::serialize(&sig).expect("serialize signature");
        let deser_sig = bincode::deserialize(&ser_sig).expect("deserialize signature");
        assert_eq!(sig, deser_sig);
    }
}

#[cfg(feature = "serialization-serde")]
mod serde {
    use pairing::{CurveAffine, CurveProjective, EncodedPoint, Engine};

    use super::{DecryptionShare, PublicKey, Signature};
    use serde::de::Error as DeserializeError;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    const ERR_LEN: &str = "wrong length of deserialized group element";
    const ERR_CODE: &str = "deserialized bytes don't encode a group element";

    impl<E: Engine> Serialize for PublicKey<E> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            serialize_projective(&self.0, s)
        }
    }

    impl<'de, E: Engine> Deserialize<'de> for PublicKey<E> {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            Ok(PublicKey(deserialize_projective(d)?))
        }
    }

    impl<E: Engine> Serialize for Signature<E> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            serialize_projective(&self.0, s)
        }
    }

    impl<'de, E: Engine> Deserialize<'de> for Signature<E> {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            Ok(Signature(deserialize_projective(d)?))
        }
    }

    impl<E: Engine> Serialize for DecryptionShare<E> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            serialize_projective(&self.0, s)
        }
    }

    impl<'de, E: Engine> Deserialize<'de> for DecryptionShare<E> {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            Ok(DecryptionShare(deserialize_projective(d)?))
        }
    }

    /// Serializes the compressed representation of a group element.
    fn serialize_projective<S, C>(c: &C, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        C: CurveProjective,
    {
        c.into_affine().into_compressed().as_ref().serialize(s)
    }

    /// Deserializes the compressed representation of a group element.
    fn deserialize_projective<'de, D, C>(d: D) -> Result<C, D::Error>
    where
        D: Deserializer<'de>,
        C: CurveProjective,
    {
        let bytes = <Vec<u8>>::deserialize(d)?;
        if bytes.len() != <C::Affine as CurveAffine>::Compressed::size() {
            return Err(D::Error::custom(ERR_LEN));
        }
        let mut compressed = <C::Affine as CurveAffine>::Compressed::empty();
        compressed.as_mut().copy_from_slice(&bytes);
        let to_err = |_| D::Error::custom(ERR_CODE);
        Ok(compressed.into_affine().map_err(to_err)?.into_projective())
    }
}
