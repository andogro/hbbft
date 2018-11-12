# Fail Messages and Monitoring in HBBFT

# Summary

Bridge `fault_log` and `slog` capabilities in order to create a consistent performance monitoring
stream within hbbft. This capability will improve testing capability, create a basis for development
of performance benchmarks, and improve ability of nodes to detect byzantine failures within their
peers.


Specific tasks are enumerated below:

1. Replace `fault_log::Fault` with `EdgeData`. `.node_id` becomes `.source_id`. `.failure` becomes
   `.content`. `content` holds types that implement `Fail`.
2. Instead of including every module's `FaultKind` enumerations within `fault_log`, create a generic
   `ByzantineFaultKind` enumeration used to wrap module specific faults. `ByzantineFaultKind` enums
   wrap structs which implement `Fail`.
3.  Implement `failure::Fault.cause()` and `failure::Fault.context()` for `fault_log::EdgeData` and
   `ByzantineFaultKind`.
4. Rename `fault_log` to `monitor`.
5. Incrementally replace `fault_log::FaultKind` with `ByzantineFaultKind`. Add module tests during
    each replacement such that each module-specific fault trigger is tested.
6. Change `FaultLog` into `StepLog`, which holds a vector of all `EdgeData` created during step
   execution.
7. Add a StepTimer enum that implements `Fail`. `StepTimer` contains a start and stop (or tick and
   tock?) element to record systime and a static string (used to record things like algorithm name)
   when called.
8. Add a structure into `EpochStep` for tallying metrics. This aggregates useful metrics across all
   algorithm executions involved withinin one Epoch for one node.
9. Add a `compute` function to `StepLog` which transforms a `StopLog`'s `EdgeData` into metrics
   stored within an `EpochStep`. Specific metrics that are computed include:

   * Number of byzantine fault types per source node
   * Total time from algorithm start until 1) first reply received, 2) algorithm output

10. Add a `flush` function to `metrics` that writes to IO using `slog`. Through `slog`, `flush`
    operates differently based on compilation arguments.

    * In the most verbose mode it flushes the log without transformation (with backtraces?).
    * In development mode it flushes high level timing statistics and failure statistics.
    * In benchmark mode it flushes all available timing statistics.
    * In release mode nothing is flushed.

11. Ensure that Steps either extend another step or are `compute`d prior to their destruction.


# Motivation

The use case for faults is more a sub-class of system logging, and as such should be further
integrated into the logging interface used by hbbft. Interestingly, the interface requirements for
fault logging work just as well for generating high fidelity benchmark metrics as well as monitoring
validation peers in order to detect failures in those peers. Capitalizing on this commonality allows
the hbbft protocol to be heavily instrumented without impacting operational
performance. Additionally, the monitoring stream can also feed back into hbbft applications, most
notably by providing a means to track peer performance and use that information to generate votes
for promoting and demoting observers and validators.

## Background

I wrote much of the following while trying to understand how faults were different than the errors
passed around within `Result` returning functions.

### Faults vs Errors -- How Are They Different?

As defined in hbbft, faults and errors both denote non-standard inputs and are used to identify
issues encountered during execution. The differences start once the issue is encountered. Errors
occur when a function must terminate in a non-standard fashion due to the issue. Errors need to be
explicitly handled by their calling functions or else the program will terminate. With faults, early
function termination is not necessarily required. A fault denotes that the function received an
unexpected input (or lack of input), but was able to continue operation anyways.

Faults are captured in order to assess program and/or network health. The way Faults are implemented
within hbbft, their principle interface is within the `hbbft::traits::Step` struct, where they are
the elements which make up the `Step.fault_log`. The `fault_log` records Faults encountered within
any of the module's implementing `hbbft::traits::DistAlgorithm`.

Although errors in the application layer should not occur, errors within sub modules may still
occur. For example, from a caller's perspective an error may just be a symptom of a
failure. Therefore, error handlers have the option of transforming an error into a fault when, to
the handlers perspective the error is a fault. Because faults and errors need to communicate in this
manner, error types should provide sufficient information such that they can be transformed into
informative failures as needed.

Faults are aggregated within steps and serve to provide a chronological view of issues encountered
while handling input from a hbbft network. Errors may be transformed into faults, but faults should
not be transformed into errors. Note that although faults are to be expected in an adversarial
network they may also be symptoms of underlying protocol or implementation errors. Therefore, both
faults and errors should be tested heavily within the libraries test infrastructure.

So, in summary, errors identify non-standard termination paths within hbbft algorithms. Errors must
always be handled but not necessarily logged, while failures identify bad inputs from the
network. Failures should always be logged, but not necessarily handled. Remember hbbft is designed
to operate within an adversarial network and so network traffic is not expected to be pristine.


### Logging

Logging (or monitoring) interfaces provide feedback on whether the software is performing as
expected. Feedback needs vary depending on context: an operator only wants a high level perspective
on their application's health, and only cares about recording logs if something anomalous occurs and
they need to share a crash report; tests may need to know whether intermediate and final outputs
meet predetermined expectations; and a developer may need to inspect many intermediate values in
order to evaluate whether their algorithm is operating as they expect. In addition, logs can be
processed to provide system performance metrics. Performance metrics may be used by a developer or
test to monitor the software, or they may even be used within the algorithm itself to assess node,
peer node, or network health. Ideally, the same logging interface serves all these purposes.

There's a difference between log messages and log records. Messages are issued at the point of
execution, while records are static representations of those messages as stored on disk or in
memory. In many cases, what is recorded is a small subset of the issued messages.

There are multiple methods to transform logging data streams, and often multiple methods are
necessary in order to record a logging record that's suitable for both the end user as well as the
application hardware. Some examples of log transformation methods include: compiling out messages
based on the compilation target, filtering log messages based on type or contents, compressing
contents, or only recording metrics aggregated from log messages. Since hbbft is intended to provide
a highly resilient network protocol and applications are likely to have a long uptime, logging
messages originating from the hbbft library should easily operate with all of these types of
transformations.

### Transforming Messages into Metrics

An individual log message is seldom useful on its own. Instead, logs are often mined to uncover
trends or other significant behavior through aggregating multiple messages. Creating higher level
metrics compresses the data stream and offers actionable inputs for debugging, benchmarking, or
real-time performance control.

## Relevant issues:

Issues fully or partially resolved by this change

* [#120 Test fault logs.](https://github.com/poanetwork/hbbft/issues/120)
* [#198 Optimization: Evaluate different strategies for picking agreement's `vals`.](https://github.com/poanetwork/hbbft/issues/198)
* [#247 Improve Logging](https://github.com/poanetwork/hbbft/issues/247)
* [#285 Split up `FaultKind`.](https://github.com/poanetwork/hbbft/issues/285)
* [#318 Include evidence in fault logs](https://github.com/poanetwork/hbbft/issues/318)
* [#324 Refactor `Step`.](https://github.com/poanetwork/hbbft/issues/324)


Relevant background information

* [rust-lang #53487 Fix the Error trait](https://github.com/rust-lang/rust/issues/53487)
* [rust-lang RFC #2504 Change the std::error::Error trait to improve its usability.](https://github.com/rust-lang/rfcs/blob/master/text/2504-fix-error.md)
* [How RFC #2504 impacts the Failure crate](https://github.com/rust-lang/rfcs/blob/master/text/2504-fix-error.md#how-this-impacts-failure)
* [Docs for `failure` Crate](https://github.com/rust-lang-nursery/failure)


# Concerns

Handling dynamic memory utilization

Evaluating Performance impacts (mainly from compute and flush)

Minimizing boilerplate
