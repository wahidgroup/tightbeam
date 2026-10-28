# The Testing Framework

This page specifies the Rust surface of the tightbeam testing framework:

- the grammar of each spec macro and the types it generates
- the fields, defaults, and modes of the FDR configuration
- the verdict, the decisions, and the witnesses of Layer 3
- the fault model, the hooks, the scenario environments, and the fuzz harness
- the types of the FMEA report

It drills down from [README §12](../README.md#12-testing-framework) for engineers who write scenarios and specs. The README states what each layer checks, the CSP and FDR theory behind it, and the standards it serves. This page holds the items that carry it.

## Contents

- [Assertion specifications](#assertion-specifications)
- [Process specifications](#process-specifications)
- [Refinement checking](#refinement-checking)
- [CSP export and trace analysis](#csp-export-and-trace-analysis)
- [Fault injection](#fault-injection)
- [Scenarios](#scenarios)
- [Fuzz harness](#fuzz-harness)
- [FMEA reports](#fmea-reports)
- [Sources](#sources)

## Assertion specifications

`tb_assert_spec!` builds the specs of Layer 1 ([README §12.2](../README.md#122-layer-1-assertion-specifications)). The items live in `tightbeam::testing::macros`, and the recording API lives on `tightbeam::trace::TraceCollector`.

### The version block

A spec names its type and then one block per version, `V(major, minor, patch): { .. }`. The keys of a block keep this order:

| Key              | Form                                                                          | Required | Builder call                        | Feature          |
| ---------------- | ----------------------------------------------------------------------------- | -------- | ----------------------------------- | ---------------- |
| `mode:`          | `Accept`, `Reject`, or `Error`, a variant of `ExecutionMode`                  | Yes      | `AssertSpecBuilder::new`            | `testing`        |
| `gate:`          | A variant of `TransitStatus`                                                  | No       | `expected_gate`                     | `testing`        |
| `response:`      | `Present` or `Absent`, a variant of `Presence`                                | No       | `expected_response`                 | `testing`        |
| `tag_filter:`    | `["tag", ..]`                                                                 | No       | `tag_filter`                        | `testing`        |
| `assertions:`    | A list of assertion tuples                                                    | Yes      | `assertion`, `assertion_with_value` | `testing`        |
| `events:`        | `[KIND, ..]`, in the order the trace records them                             | No       | `required_events`                   | `instrument`     |
| `event_counts:`  | `[(KIND, cardinality), ..]`                                                   | No       | `event_count`                       | `instrument`     |
| `schedulability:` | `{ task_set: EXPR, scheduler: NAME, must_be_schedulable: BOOL, }`           | No       | `schedulability`                    | `testing-timing` |

A key whose feature is off fails to compile, and the error names the key and the feature. An optional `annotations { description: "..." }` block after the last version block gives every version the same description.

The execution mode classifies how the run ended:

| Mode     | The run                                       |
| -------- | --------------------------------------------- |
| `Accept` | The body returned, and no gate refused the run |
| `Reject` | A gate decision other than `Ok` refused it    |
| `Error`  | The body returned an error                    |

An assertion tuple takes one of four forms. The label is a `Urn<'static>` expression:

- `(LABEL, cardinality)`
- `(LABEL, cardinality, equals!(value))`
- `(LABEL, cardinality, tags: ["tag", ..])`
- `(LABEL, cardinality, equals!(value), tags: ["tag", ..])`

A counted assertion carries every tag of the spec-wide `tag_filter:` and every tag of its own `tags:` list.

The `schedulability:` block takes a `TaskSet` expression. The scheduler it names, `RateMonotonic` or `EarliestDeadlineFirst`, replaces the scheduler of a clone of that task set. The block ends with a comma after `must_be_schedulable`.

### The generated type

The macro emits a unit struct with three associated functions:

| Function                    | Returns                              | Behavior                                                                 |
| --------------------------- | ------------------------------------ | ------------------------------------------------------------------------ |
| `all()`                     | `&'static [BuiltAssertSpec]`         | Builds every version once, in a `OnceLock`, and returns them in source order |
| `get(major, minor, patch)`  | `Option<&'static BuiltAssertSpec>`   | The version with that triple                                             |
| `latest()`                  | `&'static BuiltAssertSpec`           | The highest version                                                      |

The macro checks its blocks at two times:

- Version blocks that do not strictly ascend in semantic version order fail to compile.
- The first call of `all()`, `get()`, or `latest()` panics on a block that names one label twice, or on a `between!` bound whose maximum is below its minimum.

### AssertSpecBuilder

The macro drives `AssertSpecBuilder`, and code can call it directly. `AssertSpecBuilder::new(id, mode)` starts a spec at version 1.0.0:

| Method                                                      | Effect                                                        |
| ----------------------------------------------------------- | ------------------------------------------------------------- |
| `version(major, minor, patch)`                              | Sets the version                                              |
| `expected_gate(Option<TransitStatus>)`                      | Sets the gate decision that the run must reach                |
| `expected_response(Option<Presence>)`                       | Sets whether the run must leave a response                    |
| `tag_filter(Vec<&'static str>)`                             | Sets the spec-wide tag filter                                 |
| `assertion(label, tags, cardinality)`                       | Adds an assertion, or returns a `SpecBuildError`              |
| `assertion_with_value(label, tags, cardinality, value)`     | Adds an assertion with an `Option<AssertionValue>`            |
| `ordering(labels)`                                          | Requires the labels in this order, or returns a `SpecBuildError` |
| `required_events(kinds)` (`instrument`)                     | Requires the event kinds in this order, once each             |
| `event_count(kind, cardinality)` (`instrument`)             | Adds a count, and two counts on one kind must both hold       |
| `description(&'static str)`                                 | Sets the description                                          |
| `schedulability(SchedulabilityAssertion)` (`testing-timing`) | Adds the schedulability assertion                            |
| `build()`                                                   | Returns the `BuiltAssertSpec`                                 |

An assertion order needs the builder, whose `ordering` sets it. `SpecBuildError` has three variants:

| Variant                     | Cause                                        |
| --------------------------- | -------------------------------------------- |
| `DuplicateLabel(Urn)`       | The spec already holds an assertion on the label |
| `UnknownOrderingLabel(Urn)` | The ordering names a label that no assertion holds |
| `InvalidRange(Urn)`         | The cardinality has a maximum below its minimum |

```rust
use tightbeam::testing::macros::AssertSpecBuilder;
use tightbeam::testing::TBSpec;
use tightbeam::trace::ExecutionMode;
use tightbeam::urn::Urn;
use tightbeam::{exactly, urn};

const OPEN: Urn<'static> = urn!("doc", "event:builder/open");
const CLOSE: Urn<'static> = urn!("doc", "event:builder/close");

let builder = AssertSpecBuilder::new("OpenThenClose", ExecutionMode::Accept).version(1, 2, 0);
let builder = builder.assertion(OPEN, vec![], exactly!(1))?;
let builder = builder.assertion(CLOSE, vec![], exactly!(1))?;
let spec = builder.ordering([OPEN, CLOSE])?.build();

assert_eq!(spec.version(), (1, 2, 0));
assert_eq!(spec.required_assertions().len(), 2);
# Ok::<(), Box<dyn core::error::Error>>(())
```

`BuiltAssertSpec` implements `TBSpec`, the trait that Layer 1 grades through. It also returns its `version()`, its `description()`, and its `spec_hash()`. The hash frames each field that [README §12.2.2](../README.md#1222-specification-tb_assert_spec-syntax) lists:

- A text field takes its byte length first, so two texts that join to one byte string hash apart.
- A count is a big-endian `u32`, and an optional field takes a presence byte.
- Tags, assertions, event counts, and tasks hash in sorted order, so a set hashes the same in any order.
- The assertion order and the required events hash in their own order, because the order is the contract.

### Cardinality

Each cardinality macro calls one constructor of `Cardinality`:

| Macro              | Constructor                         | Bounds          | Check                                                       |
| ------------------ | ----------------------------------- | --------------- | ----------------------------------------------------------- |
| `exactly!(n)`      | `Cardinality::exactly(n)`           | `n` to `n`      |                                                             |
| `at_least!(n)`     | `Cardinality::at_least(NonZeroU32)` | `n` and up      | A bound of zero fails to compile                            |
| `at_most!(n)`      | `Cardinality::at_most(n)`           | 0 to `n`        |                                                             |
| `between!(lo, hi)` | `Cardinality::between(lo, hi)`      | `lo` to `hi`    | Panics when `hi` is below `lo`, at build time in a constant |
| `present!()`       | `Cardinality::present()`            | 1 and up        |                                                             |
| `absent!()`        | `Cardinality::absent()`             | 0 to 0          |                                                             |

`Cardinality::is_satisfied_by` widens the count and the bounds to `u64`, so a count past `u32::MAX` exceeds every maximum.

### Assertion values

`equals!(value)` expands to `Some(AssertionValue::from(value))`. A recorded value matches when it equals the expected value, and every record that the assertion counts must match. The conversions into `AssertionValue`:

| Input type                       | Variant           | Matches                                         |
| -------------------------------- | ----------------- | ----------------------------------------------- |
| `String`, `&str`                 | `String`          | The same text                                   |
| `bool`                           | `Bool`            | The same flag                                   |
| `u8`, `u32`, `u64`, `i32`, `i64` | One per type      | The same number of the same type                |
| `usize`, `NonZeroUsize`          | `U64`             | The same count, saturated at `u64::MAX`         |
| `MessagePriority`, `Version`     | One per type      | The same variant                                |
| `TransitStatus` (`policy`)       | `TransitStatus`   | The same status                                 |
| `Option<T>`                      | `Some` or `IsNone` | `Some(x)` boxes the value of `x`               |
| `IsSome`, `IsNone`               | `IsSome`, `IsNone` | `IsSome` matches any `Some`, and `IsNone` matches `None` |
| `Presence`                       | `IsSome`, `IsNone` | `Present` reads as `IsSome`, and `Absent` reads as `IsNone` |
| `(u64, u64)`                     | `RatioActual`     | An equal ratio                                  |
| `RatioLimit(n, d)`               | `RatioLimit`      | An actual ratio at or below the limit           |

An integer literal with no suffix takes the type `i32`, so `equals!(3_600)` matches a recorded `i32` alone. Three more macros build values: `truthy!(x)` is `Bool(x != 0)`, `falsy!(x)` is `Bool(x == 0)`, and `ratio!(n, d)` is `RatioLimit(n, d)`.

### Recording events

`TraceCollector` records each assertion through its event API:

| Method                                         | Returns                                         | Records                                                          |
| ---------------------------------------------- | ----------------------------------------------- | ---------------------------------------------------------------- |
| `event(label)`                                 | `Result<EventBuilder<'_>, TightBeamError>`      | The label with no tags and no value                              |
| `event_with(label, tags, value)`               | `Result<EventBuilder<'_, EventValue>, TightBeamError>` | The label, its tags, and the value, or no value for `()`  |
| `recorded(label)`                              | `usize`                                         | Nothing. It counts the records of the label and leaves them recorded |

- A label is an `impl IntoEventLabel`, which `Urn`, `&Urn`, and the CSP `Event` implement. A string literal fails to compile.
- The `EventBuilder` records when it drops, so `trace.event(LABEL)?;` records at the end of the statement.
- `tags` is any `Into<Cow<'static, [&'static str]>>`, so a static slice records with no allocation.
- With `testing-fault`, both record calls return the injected error of the runtime fault model ([Fault injection](#fault-injection)).

## Process specifications

`tb_process_spec!` and `tb_compose_spec!` build the CSP processes of Layer 2 ([README §12.3](../README.md#123-layer-2-process-specifications-csp)). Both need `testing-csp`, and the process types live in `tightbeam::testing::specs::csp`.

### tb_process_spec!

A spec names its type, then its `events` block and its `states` block, then the optional blocks in this order:

| Block                              | Content                                                 | Feature                  |
| ---------------------------------- | ------------------------------------------------------- | ------------------------ |
| `terminal { S, .. }`               | The terminal states                                     | `testing-csp`            |
| `choice { S, .. }`                 | The states of internal choice                           | `testing-csp`            |
| `annotations { description: "" }`  | The description of the process                          | `testing-csp`            |
| `clocks: { c, .. }`                | The clocks that a guard or a reset names                | `testing-timing`         |
| `timing { .. }`                    | Any of `wcet:`, `jitter:`, and `deadline:`, with commas between | `testing-timing` |
| `schedulability { .. }`            | `scheduler: NAME, periods: { EVENT => Duration, .. }`   | `testing-schedulability` |

Each state takes one definition, and a state defined twice fails to compile. The first state in source order is the initial state. A transition takes one of three forms:

- `EVENT => STATE` is a plain transition.
- `EVENT [ GUARD ] => STATE` is a transition that a timing guard enables.
- `EVENT [ GUARD, reset: [CLOCK, ..] ] => STATE` also resets the clocks it names.

A bracket after an event is its guard, so an event that is an index expression takes parentheses. The macro emits a unit struct with three parts:

- `Default`.
- `process()`, which returns `Result<Process, ProcessBuildError>`.
- `ProcessSpec`, whose `to_process_cow` calls `process()`.

`ProcessBuildError` has four variants:

| Variant                         | Cause                                                       |
| ------------------------------- | ----------------------------------------------------------- |
| `MissingInitialState`           | The `states` block names no state                           |
| `UndeclaredClock { clock }`     | A guard or a reset names a clock that `clocks:` lacks       |
| `ConflictingTiming { event }`   | The `timing` block gives one event two bounds that disagree |
| `InvalidDeadline { start, end }` | The slack of a deadline passes its duration                |

### Timing macros

The timing blocks and the guards take four macros, and each needs `testing-timing`:

| Macro                                            | Builds                                                         |
| ------------------------------------------------ | -------------------------------------------------------------- |
| `wcet!(d)`                                       | A `WcetConfig` that bounds every run of the event              |
| `wcet!(d, percentile: p)`                        | A `WcetConfig` that bounds the percentile `p` of the runs      |
| `wcet!(d, percentile: p, analyzer: a)`           | The same with a statistical analyzer, in either key order      |
| `jitter!(d)`, `jitter!(d, calculator)`           | A jitter bound, measured by `MinMaxJitter` or by `calculator`  |
| `deadline!(duration: d)`, `deadline!(duration: d, slack: s)` | The `DeadlineParams` of a deadline, in parentheses or braces |
| `guard!(x < d)`, and `<=`, `>`, `>=`, `==`       | A `TimingGuard` on the clock `x`                               |
| `guard!(lo <= x <= hi)`                          | A `TimingGuard::ClockInRange`, where each bound is one token tree |

`wcet!(d, analyzer: a)` fails to compile, because an analyzer computes a percentile.

### tb_compose_spec!

A composition names its type, two `processes:` operands, and a `composition:` operator, then an optional `properties:` block and an optional `annotations` block:

| Operator                                    | CSP                  | `CompositionOperator` variant             |
| ------------------------------------------- | -------------------- | ----------------------------------------- |
| `Synchronized`                              | `P \|\| Q`           | `Synchronized`                            |
| `Interleaved`                               | `P \|\|\| Q`         | `Interleaved`                             |
| `Interface { events: ["label", ..] }`       | `P [\| A \|] Q`      | `Interface { events }`                    |
| `Alphabetized { left: [..], right: [..] }`  | `P [\| αP \| αQ \|] Q` | `Alphabetized { left, right }`          |

- An operand is a `tb_process_spec!` type or another composition, which needs `CompositionSpec` in scope.
- The `Interface` and `Alphabetized` lists take each event as the string of its full URN rendering, such as `"urn:doc:event:compose/ping"`.
- The `properties:` block claims any of `deadlock_free`, `livelock_free`, and `deterministic`, each `true` or `false`.

The macro emits a unit struct with `Default` and `CompositionSpec`:

| Function              | Returns                                          | Behavior                                                       |
| --------------------- | ------------------------------------------------ | -------------------------------------------------------------- |
| `process()`           | `Result<Process, CompositionError>`              | Builds both operands and composes them                         |
| `metadata()`          | `Result<CompositionMetadata, CompositionError>`  | The name, the operands, the sync alphabet, and the claims      |
| `verify_properties()` | `Result<(), CompositionError>`                   | Checks the claims of this composition and of each operand      |

`CompositionError` names each refusal:

| Variant                               | Cause                                                       |
| ------------------------------------- | ----------------------------------------------------------- |
| `AlphabetMismatch { expected, actual }` | A declared alphabet holds an event outside its operands   |
| `DeadlockDetected { state }`          | A claim of deadlock freedom fails at `state`                |
| `LivelockDetected { cycle }`          | A claim of livelock freedom fails on a τ cycle              |
| `NonDeterminismDetected { state, events }` | A claim of determinism fails at `state`                |
| `PropertyHolds { property }`          | The spec claims that the process lacks a property it holds  |
| `InvalidComposition { reason }`       | The structure of the composition is invalid                 |

## Refinement checking

`FdrConfig` configures Layer 3, and `FdrVerdict` reports it ([README §12.4](../README.md#124-layer-3-refinement-checking-fdr)). Both need `testing-fdr` and live in `tightbeam::testing::fdr`.

### FdrConfig

| Field              | Type                          | Default    | Feature         | Meaning                                                                 |
| ------------------ | ----------------------------- | ---------- | --------------- | ----------------------------------------------------------------------- |
| `seeds`            | `u32`                         | 64         | `testing-fdr`   | The number of exploration seeds, each of which runs another schedule    |
| `max_depth`        | `usize`                       | 128        | `testing-fdr`   | The longest trace, in observable events, that exploration follows       |
| `max_internal_run` | `usize`                       | 32         | `testing-fdr`   | The most hidden events in one run. A longer run is a divergence         |
| `timeout_ms`       | `u64`                         | 5000       | `testing-fdr`   | The time budget of each search of the refinement checker               |
| `specs`            | `Vec<Process>`                | empty      | `testing-fdr`   | The specs that the subject must refine                                  |
| `fail_fast`        | `bool`                        | `true`     | `testing-fdr`   | Whether each refinement pass returns at its first counterexample        |
| `scheduler`        | `Option<SchedulerConstraint>` | `None`     | `testing-fault` | The resource-constraint model of the run                                |
| `fault_model`      | `Option<FaultModel>`          | `None`     | `testing-fault` | The faults that exploration injects                                     |
| `fmea_config`      | `Option<FmeaConfig>`          | `None`     | `testing-fmea`  | The FMEA that a run with injected faults reports                        |

The time budget covers the trace, failure, and divergence searches of a process, and the search of a spec for the traces of the subject. A search that spends it stops, and a check it cut short decides `Unknown`. With `fail_fast` off, a pass checks every spec, and the verdict keeps the witness of the last violation.

The specs and the fault model select the exploration:

| Specs | Fault model | Exploration                                  |
| ----- | ----------- | -------------------------------------------- |
| None  | Any         | The subject runs over every seed             |
| Some  | None        | The subject refines against each spec        |
| Some  | Some        | Each spec runs under the faults of the model |

`SchedulerConstraint::new(model, SchedulerCounts { schedulers, processes })` builds the constraint. Both counts are `NonZeroU32`, the model is `SchedulerModel::Cooperative` or `SchedulerModel::Preemptive`, and the constructor returns an `FdrConfigError` for more schedulers than processes.

`DefaultFdrExplorer::with_defaults(&process, config).explore()` runs Layer 3 over one process outside a scenario:

```rust
use tightbeam::testing::fdr::{Decision, DefaultFdrExplorer, FdrConfig};
use tightbeam::urn::Urn;
use tightbeam::{tb_process_spec, urn};

const SEND: Urn<'static> = urn!("doc", "event:explore/send");
const ACK: Urn<'static> = urn!("doc", "event:explore/ack");

tb_process_spec! {
	pub Exchange,
	events { observable { SEND, ACK } hidden { } }
	states {
		Idle => { SEND => Waiting },
		Waiting => { ACK => Idle }
	}
	terminal { Idle }
}

let process = Exchange::process()?;
let config = FdrConfig { seeds: 8, specs: vec![Exchange::process()?], ..FdrConfig::default() };
let verdict = DefaultFdrExplorer::with_defaults(&process, config).explore()?;

assert_eq!(verdict.trace_refines, Decision::Holds);
assert_eq!(verdict.outcome(), Decision::Holds);
# Ok::<(), Box<dyn core::error::Error>>(())
```

### FdrVerdict

The verdict holds one `Decision` per assertion:

| Field                | Asserted when                                                     |
| -------------------- | ----------------------------------------------------------------- |
| `divergence_free`    | The run names no spec and no fault model, and explores the process over every seed |
| `deadlock_free`      | As `divergence_free`                                              |
| `schedulable`        | A configured spec has a schedulability block (`testing-schedulability`) |
| `trace_refines`      | The run names a spec and no fault model                           |
| `failures_refines`   | As `trace_refines`, for a subject whose refusals are known        |
| `divergence_refines` | As `failures_refines`                                             |

A scenario with a CSP process and FDR specs runs both: the process answers divergence and deadlock freedom, and the recorded trace answers refinement against the specs.

`outcome()` folds the six decisions, and the firmest one wins. The rest of the verdict is evidence:

| Field                           | Type                          | Content                                                              |
| ------------------------------- | ----------------------------- | -------------------------------------------------------------------- |
| `is_deterministic`              | `bool`                        | Whether the structural proof of determinism holds                    |
| `determinism_witness`           | `Option<(State, Event)>`      | The first pair with a hidden action or more than one target          |
| `trace_refinement_witness`      | `Option<Trace>`               | A trace of the subject that the spec lacks                           |
| `failures_refinement_witness`   | `Option<Failure>`             | A trace and a refusal set that the spec does not allow               |
| `divergence_refinement_witness` | `Option<Trace>`               | A divergent trace of the subject that the spec lacks                 |
| `divergence_witness`            | `Option<(u64, Vec<Event>)>`   | The seed and the hidden events of a run that diverges                |
| `deadlock_witness`              | `Option<(u64, Trace, State)>` | The seed, the trace, and the state of a deadlock                     |
| `unmodelled_events`             | `Vec<Event>`                  | The events of the subject that no spec models, which refinement projects away |
| `traces_explored`               | `usize`                       | The traces that the seeds explored                                   |
| `states_visited`                | `usize`                       | The distinct states of the runs that the verdict judges              |
| `seeds_completed`               | `u32`                         | The seeds that ended with neither a deadlock nor a divergence        |
| `failing_seed`                  | `Option<u64>`                 | The seed of the last deadlock or divergence                          |
| `timing_pruned`                 | `usize`                       | The branches that exploration pruned for a timing violation          |
| `faults_injected`               | `Vec<InjectedFaultRecord>`    | The faults that exploration injected (`testing-fault`)               |
| `error_recovery_successful`     | `usize`                       | The seeds that ran to their end after a fault (`testing-fault`)      |
| `error_recovery_failed`         | `usize`                       | The seeds that deadlocked or diverged after a fault (`testing-fault`) |
| `fmea_report`                   | `Option<FmeaReport>`          | The FMEA report of a run that injected a fault (`testing-fmea`)      |

`Trace` is `Vec<Event>`, `RefusalSet` and `AcceptanceSet` are `HashSet<Event>`, and `Failure` is `(Trace, RefusalSet)`.

### Decision

| Variant       | Rank | Meaning                                                   |
| ------------- | ---- | --------------------------------------------------------- |
| `NotAsserted` | 0    | The run left the assertion out, which is the default      |
| `Holds`       | 1    | The check completed, and everything it searched satisfied it |
| `Unknown`     | 2    | The check stopped at a bound before it decided            |
| `Refuted`     | 3    | The check found a counterexample                          |

`a.and(b)` returns the higher rank of the two. `refute()` turns an asserted decision into `Refuted` and keeps `NotAsserted`.

## CSP export and trace analysis

The tools of [README §12.5](../README.md#125-formal-csp-theory) live in `tightbeam::testing::fdr` and need `testing-fdr`.

### CspmExporter

`CspmExporter::new(&process).export(&mut writer)` writes the process as CSPM to any `std::io::Write`. The output has five parts:

1. A comment header with the process name and its description.
2. `datatype Observable`, `datatype Hidden` when the process has hidden events, and `datatype States`.
3. `channel obs : Observable` and `channel hid : Hidden`, in every export.
4. One equation per state. A terminal state is `SKIP`, a state with no enabled action is `STOP`, and any other state is an external choice of `obs.e -> NextProcess` and `hid.e -> NextProcess` terms.
5. The main process, `Name = InitialProcess \ {| hid |}`.

The equations follow three rules:

- Each datatype constructor is the full URN rendering of its event, such as `urn:test:event:probe/a`.
- A terminal state exports as `SKIP`, whatever transitions it has.
- A nondeterministic transition exports its first target.

`CspmExporter::export_composition(&expr, &mut writer)` writes a process expression of a composition.

### FdrTraceExt

`FdrTraceExt` extends `ConsumedTrace`, the trace that a hook reads:

| Method                               | Returns                    | Behavior                                                             |
| ------------------------------------ | -------------------------- | -------------------------------------------------------------------- |
| `csp_valid()`                        | `bool`                     | A run whose gate accepted must record an assertion or a response     |
| `terminated_in_valid_state()`        | `bool`                     | An accepted run must leave a response or an assertion, a rejection is terminal, and an unknown status is not |
| `assertion_count(label)`             | `usize`                    | The assertions whose label is `label`                                |
| `project_to_observable()` (`instrument`) | `Vec<String>`          | The labels of the observable instrumentation events                  |
| `project_to_hidden()` (`instrument`) | `Vec<String>`              | The labels of the hidden instrumentation events                      |
| `export_cspm(&mut writer)`           | `std::io::Result<()>`      | The observable events as the CSPM sequence `Trace`                   |
| `to_process()`                       | `Process`                  | A linear process of the assertion events                             |
| `to_process_with_mode(mode)`         | `Process`                  | A linear process of the events that `mode` selects                   |

A run with no gate decision passes both checks. `TraceProcessMode` selects the events of `to_process_with_mode`:

| Mode                            | Events                                                                  | Feature      |
| ------------------------------- | ----------------------------------------------------------------------- | ------------ |
| `AssertionsOnly`                | The assertion events                                                    | `testing-fdr` |
| `WithObservableInstrumentation` | The assertions and the observable instrumentation events                | `instrument` |
| `FullInstrumentation`           | The assertions and the observable and hidden instrumentation events     | `instrument` |

A trace captures the hidden events only when its instrumentation sets `enable_internal_detail: true`.

### RequestPathState

`RequestPathState` models the house request path. `acceptance()` returns the events a state accepts, and `refuses(label)` holds for every other event:

| State        | `as_str()`     | Accepts                     |
| ------------ | -------------- | --------------------------- |
| `Initial`    | `initial`      | `request`                   |
| `GateAccept` | `gate_accept`  | `handler_enter`             |
| `Handler`    | `handler`      | `handler_exit`, `response`  |
| `GateReject` | `gate_reject`  | Nothing                     |
| `Terminal`   | `terminal`     | Nothing                     |

## Fault injection

The fault model of [README §12.6](../README.md#126-fault-injection) needs `testing-fault`. `FaultModel`, `InjectionStrategy`, and `InjectedFaultRecord` live in `tightbeam::testing::fdr`, and `tightbeam::testing` re-exports them.

### FaultModel

| Constructor or method                                  | Effect                                                                |
| ------------------------------------------------------ | --------------------------------------------------------------------- |
| `FaultModel::default()`                                | The deterministic strategy, no injection point, and the seed `0xDEADBEEF` |
| `FaultModel::from(strategy)`                           | The same with `strategy`                                              |
| `with_fault(state, event, error_fn, probability)`      | An injection point of FDR exploration at one state and one event      |
| `with_event_fault(event, error_fn, probability)`       | An injection point at each runtime record of the event, in every state |
| `with_seed(seed)`                                      | The seed of the random strategy                                       |

- `state` is a `ProcessState`, and `event` is a `ProcessEvent`.
- `error_fn` is a `Fn() -> E + Send + Sync + 'static`, where `E: Into<TightBeamError>`.
- `probability` is a `BasisPoints`, 0 to 10000, and `tightbeam::bps!(n)` checks the range at compile time.

`TraceCollector::with_fault_model(model)` installs a model as the runtime fault model of every handle that shares the trace. A model installed later replaces the one before it.

### InjectionStrategy

| Strategy        | A point injects at a record when                                              |
| --------------- | ----------------------------------------------------------------------------- |
| `Deterministic` | `count × probability mod 10000 < probability`, where `count` is the record number of the label |
| `Random`        | The next draw of the seeded LCG, modulo 10000, is below the probability       |

The deterministic rule spreads the injections over the records of each label. At 3000 basis points, it injects on records 4, 7, and 10 of 10.

The strategy and the seed of the model decide runtime injection. FDR exploration draws each injection from the generator of its own exploration seed, so a point injects when that draw, modulo 10000, is below its probability.

### ProcessState and ProcessEvent

The two traits key an injection point:

| Trait          | Methods                                                    | Key                    |
| -------------- | ---------------------------------------------------------- | ---------------------- |
| `ProcessState` | `process_name()`, `state_name()`, and the provided `full_key()` | `Process.State`   |
| `ProcessEvent` | `event_label()`                                            | The label of the event |

`Urn<'static>` implements `ProcessEvent` with its full rendering, so a fault keyed on a URN matches the label that the trace records. `tb_gen_process_types!(Name, State, ..)` emits a module named after the process in snake case, with a `States` enum that implements `ProcessState` and an `Event(Urn<'static>)` wrapper that implements `ProcessEvent` with the label of its URN.

### InjectedFaultRecord

| Field             | Type     | Content                                       |
| ----------------- | -------- | --------------------------------------------- |
| `csp_state`       | `String` | The state of the injection, as `Process.State` |
| `event_label`     | `String` | The label of the event at which the fault fired |
| `error_message`   | `String` | The message of the injected error             |
| `probability_bps` | `u16`    | The probability of the point, in basis points |

## Scenarios

`tb_scenario!` runs the layers of a scenario under one environment ([README §12.7](../README.md#127-unified-testing-tb_scenario-macro)). The configuration types live in `tightbeam::testing`.

### Environments

A named scenario expands to one test function:

| Environment     | Closure keys                                                  | Closure parameters                         | Test attribute       |
| --------------- | ------------------------------------------------------------- | ------------------------------------------ | -------------------- |
| `Bare`          | `exec`                                                        | `SetupEnv`                                 | `#[test]`, or `#[tokio::test]` for an `async move` body |
| `Pipeline`      | `exec`                                                        | `PipelineBuilder`                          | `#[test]`            |
| `Worker`        | `setup`, then `stimulus`                                      | `SetupEnv`, then `WorkerEnv`               | `#[tokio::test]`     |
| `Servlet`       | `start`, an optional `setup`, then `client`                   | `SetupEnv`, `ClientEnv`, then `ServletEnv` | `#[tokio::test]`     |
| `ServiceClient` | An optional `worker_threads: N`, then `server` and `client`   | `SetupEnv`, then `ClientEnv`               | `#[tokio::test]`, multi-threaded with `worker_threads` |
| `Cluster`       | `start`, an optional `hives`, then `client`                   | `SetupEnv`, then `ClusterEnv`              | `#[tokio::test]`     |
| `Hive`          | `start`, then `client`                                        | `SetupEnv`, then `HiveEnv`                 | `#[tokio::test]`     |

- Every environment but `Pipeline` takes an optional `context:` key before its closures. The test evaluates it once and shares it as `Arc<C>`, and a block with no `context:` shares `Arc<()>`.
- `Worker` setup returns the worker builder, and the runner starts it on the scenario trace.
- A `Servlet` with no `setup:` connects a cleartext `TokioListener` client.
- The `ServiceClient` server returns `(JoinHandle<T>, TightBeamSocketAddr)`, where `T` implements `ServerOutcome`. The runner aborts the server at teardown, and a server that failed or panicked fails the test.
- Each async closure returns `Result<T, TightBeamError>`.

### Environment structs

| Struct                   | Fields                                   |
| ------------------------ | ---------------------------------------- |
| `SetupEnv<C, T>`         | `trace: T`, `context: Arc<C>`            |
| `ClientEnv<C, A, T>`     | `trace`, `context`, `addr: A`            |
| `WorkerEnv<C, W>`        | `trace: TraceCollector`, `context`, `worker: W` |
| `ServletEnv<C, K, T>`    | `trace`, `context`, `client: K`          |
| `ClusterEnv<C, G, T>`    | `trace`, `context`, `cluster: G`         |
| `HiveEnv<C, H, T>`       | `trace`, `context`, `hive: H`            |

`T` is a `TraceCollector` share, or a `FuzzTraceCollector` share under `fuzz: afl`.

### ScenarioConfig

`ScenarioConfig::builder()` returns a `ScenarioConfigBuilder`:

| Method                     | Sets                                                          | Feature       |
| -------------------------- | ------------------------------------------------------------- | ------------- |
| `with_spec(spec)`          | Adds one `&'static BuiltAssertSpec`                           | `testing`     |
| `with_specs(specs)`        | Replaces the spec list, such as with `MySpec::all()`          | `testing`     |
| `with_csp(process)`        | The CSP spec of Layer 2, any `ProcessSpec`                    | `testing-csp` |
| `with_fdr(config)`         | The `FdrConfig` of Layer 3                                    | `testing-fdr` |
| `with_trace(collector)`    | The `TraceCollector` of the run                               | `testing`     |
| `with_hooks(hooks)`        | The `TestHooks`                                               | `testing`     |
| `with_expect(expect)`      | `Expect::Pass`, the default, or `Expect::Violation(layer)`    | `testing`     |

`build()` returns `Result<ScenarioConfig, ScenarioConfigError>`. It builds the CSP process once and checks each claim of its spec:

| Variant                                 | Cause                                                          |
| --------------------------------------- | -------------------------------------------------------------- |
| `NoEffectiveVerifier`                   | No configured layer can reject a run                           |
| `ExpectViolationWithoutVerifier(layer)` | The expectation names a layer that cannot reject this configuration |
| `CspNamedTwice`                         | A guided fuzz run names its process in `csp:` and in its configuration |
| `CspRefused(CompositionError)`          | The CSP process does not build, or a claim of it fails         |

`Layer` names the three layers, `Assertion`, `Csp`, and `Refinement`, in grading order. A scenario that names `Expect::Violation(layer)` passes when that layer rejects the run and every other layer accepts it.

### Hooks

`TestHooks` holds two observers. The harness grades the run, calls the observer of the outcome, and then panics on a rejection:

| Constructor or method | Observer                                   |
| --------------------- | ------------------------------------------ |
| `TestHooks::on_pass(f)` | `Fn(&HookContext)`, for an accepted run  |
| `TestHooks::on_fail(f)` | `Fn(&HookContext, &Violations)`, for a rejected run |
| `with_on_fail(f)`     | Adds the rejection observer                |
| `with_on_pass(f)`     | Adds the acceptance observer               |

`HookContext` reads the graded run:

| Method                                    | Returns                                                 |
| ----------------------------------------- | ------------------------------------------------------- |
| `trace()`                                 | `&ConsumedTrace`, the trace that the run recorded       |
| `assert_spec()`                           | The first assertion spec of the configuration           |
| `verdict()`                               | `&ScenarioVerdict`                                      |
| `outcome()`                               | `Result<(), &Violations>`, the outcome against the expectation |
| `process()` (`testing-csp`)               | The CSP process of Layer 2                              |
| `timing_constraints()` (`testing-timing`) | The timing constraints of the first FDR spec            |

`ScenarioVerdict` returns each layer: `spec()` the Layer 1 violation, `csp()` the Layer 2 result, `fdr()` the `FdrVerdict`, and `exploration()` the events that the exploration of Layer 3 recorded into a trace of its own. `outcome(expect)` grades every layer together.

### Panics

A scenario panics, and so fails its test, at each of these:

- `build()` or `guided_by` refuses its configuration.
- The process of a guided fuzz run does not build.
- A setup closure fails, such as a worker, a servlet, a server, a cluster, or a hive that does not start.
- The server task of a `ServiceClient` run fails or panics.
- The grade refuses an exploration event, or a layer decides against what the scenario expects.

## Fuzz harness

The fuzz harness of [README §12.8](../README.md#128-coverage-guided-fuzzing-with-afl) needs `testing-fuzz`, and its types live in `tightbeam::testing::fuzz`.

### The fuzz arms of tb_scenario!

A fuzz arm emits `fn main()`, and `cargo afl build` compiles it into a target:

| Form                                                          | Target                                                          |
| ------------------------------------------------------------- | --------------------------------------------------------------- |
| `fuzz: afl, raw: \|data\| { .. }`                             | Hands each input to the closure, with no oracle and no grade    |
| `fuzz: afl, csp: P, spec: S, environment E { .. }`            | Grades the run against the latest version of `S` and the process `P` |
| `fuzz: afl, csp: P, config: C, environment E { .. }`          | Grades the run against `C` and the process `P`                  |

- A guided arm takes `Bare`, `Servlet`, `Hive`, or `Cluster`. `Bare` takes one sync `exec:`, and the other three need `tokio`.
- A guided arm without `csp:` fails to compile, and a configuration that also names a process fails the run at start with `CspNamedTwice`.
- Under `--cfg fuzzing`, `main` wraps `afl::fuzz!` and builds a `FuzzTraceCollector` over each input. Without it, `main` runs one iteration over an empty input, so `cargo check` and a smoke build compile the target.
- An iteration whose body returns `FuzzInputExhausted` ends ungraded.

### FuzzTraceCollector

`FuzzTraceCollector::new(input, process)` builds the collector of one iteration. Each closure receives a share of it as its `trace`:

| Method                         | Returns                                                         |
| ------------------------------ | --------------------------------------------------------------- |
| `oracle()` (`OracleAccess`)    | `&FuzzContext`, the oracle of the iteration                     |
| `collector()`                  | `&TraceCollector`, whose records step the oracle live           |
| `share()`                      | A handle that records into the same state and reads the same oracle |

`FuzzContext` wraps a `CspOracle` and the input cursor in a mutex:

| Method                                          | Behavior                                                     |
| ----------------------------------------------- | ------------------------------------------------------------ |
| `fuzz_from_bytes()`                             | Runs the oracle over the whole input                         |
| `trace()`, `current_state()`, `valid_events()`, `is_terminal()` | Read the oracle                              |
| `coverage_score()`, `track_state()`, `crash_context()` | Read the coverage and the context of a crash          |
| `step_event(&event)`                            | Steps the oracle on one event                                |
| `fuzz_u8()`, `fuzz_u16()`, `fuzz_u32()`, `fuzz_u64()`, `fuzz_bytes(n)` | Consume input bytes, big-endian    |
| `fuzz_input()`, `fuzz_has_bytes(n)`, `fuzz_remaining()`, `fuzz_peek_u8()`, `fuzz_peek_bytes(n)` | Read the input and leave the cursor |

A consuming reader returns `TestingError::FuzzInputExhausted` when too few bytes remain. On a poisoned mutex, a method that returns a `Result` returns `TestingError::FuzzInputLockPoisoned`, and a method that returns a plain value returns its empty value, such as `false`, `None`, or an empty list.

### CspOracle

`CspOracle::fuzz_from_bytes(input)` resets the oracle and reads the input one byte per choice:

1. At each non-terminal state, it lists the enabled observable events, sorted by label.
2. It picks the event at `byte % events.len()`.
3. When the event has more than one target, it reads one more byte and picks the target at `byte % targets.len()`, over the targets sorted by name.
4. It takes the transition and records the state, the transition, and the event.
5. It stops at a terminal state, or when the input runs out.

The oracle returns `FuzzError`, and `FuzzContext` maps each variant to its `TestingError`:

| `FuzzError`                   | Cause                                                  | `TestingError`              |
| ----------------------------- | ------------------------------------------------------ | --------------------------- |
| `Deadlock { state }`          | A non-terminal state has no valid event                | `FuzzDeadlock(state)`       |
| `InputExhausted { state }`    | The input ran out before a terminal state              | `FuzzInputExhausted`        |
| `EventRejected { state, event }` | The oracle refused an event it listed as valid      | `FuzzEventRejected(event)`  |

With `testing-fuzz-ijon` under `--cfg fuzzing`, each step reports `afl::ijon_set!(track_state)` and `afl::ijon_max(coverage_score)` to AFL.

### Fuzz targets

Each target is a `[[bin]]` of `tightbeam/Cargo.toml`, and `make fuzz-build` builds each one with its own features:

| Target                  | Source                         | Required features                              |
| ----------------------- | ------------------------------ | ---------------------------------------------- |
| `fuzz_simple_workflow`  | `fuzz/simple_workflow.rs`      | `std`, `testing-fuzz`                          |
| `fuzz_complex_workflow` | `fuzz/complex_workflow.rs`     | `std`, `testing-fuzz`                          |
| `fuzz_chess`            | `fuzz/chess/mod.rs`            | `full`, `testing-fuzz`                         |
| `fuzz_frame_der`        | `fuzz/frame_der.rs`            | `std`, `testing-fuzz`                          |
| `fuzz_envelope_der`     | `fuzz/envelope_der.rs`         | `std`, `testing-fuzz`, `transport`             |
| `fuzz_colony`           | `fuzz/colony/mod.rs`           | `full`, `testing-fuzz`, `testing-fuzz-ijon`    |

## FMEA reports

The FMEA of [README §12.10.5](../README.md#12105-fmeafmeca-mil-std-1629-iso-26262) needs `testing-fmea`, and its types live in `tightbeam::testing::fmea`.

### FmeaConfig

| Field                    | Type            | Default      | Meaning                                                     |
| ------------------------ | --------------- | ------------ | ----------------------------------------------------------- |
| `severity_scale`         | `SeverityScale` | `MilStd1629` | The scale of every rating                                   |
| `rpn_critical_threshold` | `u32`           | 100          | The RPN above which a failure mode is critical              |
| `auto_generate`          | `bool`          | `true`       | Whether a run that injects a fault puts the report in its verdict |

`SeverityScale::MilStd1629` rates from 1 to 10, and `SeverityScale::Iso26262` rates from 1 to 4.

### FmeaReport and FailureMode

| `FmeaReport` field  | Type               | Content                                                      |
| ------------------- | ------------------ | ------------------------------------------------------------ |
| `failure_modes`     | `Vec<FailureMode>` | One failure mode per injected fault record                   |
| `severity_scale`    | `SeverityScale`    | The scale of the ratings                                     |
| `total_rpn`         | `u32`              | The sum of the RPN of every failure mode                     |
| `critical_failures` | `Vec<usize>`       | The index of each failure mode whose RPN exceeds the threshold |

| `FailureMode` field | Type          | Content                                                   |
| ------------------- | ------------- | --------------------------------------------------------- |
| `component`         | `String`      | The state of the fault, as `Process.State`                |
| `failure`           | `String`      | The event label of the fault                              |
| `effects`           | `Vec<String>` | The effects that the reachability of the fault state finds |
| `severity`          | `u8`          | From the reachability of the fault state                  |
| `occurrence`        | `u16`         | From the probability of the injection point               |
| `detection`         | `u8`          | From the error-recovery counts of the verdict             |
| `rpn`               | `u32`         | `severity × occurrence × detection`                       |

`FailureMode::new` computes the RPN, and `FmeaReport::new(modes, scale, threshold)` computes the total and the critical indices.

### Ratings

| Rating     | Function                                  | Rule                                                                 |
| ---------- | ----------------------------------------- | -------------------------------------------------------------------- |
| Severity   | `InjectedFaultRecord::severity(&process, scale)` | The reachability rule of the README. A state outside the process rates at the midpoint of the scale |
| Occurrence | `SeverityScale::occurrence(bps)`          | `bps / 1000 + 1` or `bps / 2500 + 1`, capped at the maximum of the scale |
| Detection  | `FdrVerdict::detection(scale)`            | `(1 - recovered / attempts) × (max - 1) + 1`, truncated, or the midpoint with no attempt |

`FdrVerdict::fmea_report(processes, config)` builds the report from the faults of the verdict. Each fault rates at the state it names in the first of `processes` that holds that state, and a fault whose state no process holds rates as a fault in an unknown state. A run that injects a fault under `auto_generate` passes the processes that its faults fired in:

- A run that explores each spec under a fault model passes its specs.
- A run that explores the subject over every seed passes the subject process.

`FmeaArtifact::new(evidence, report)` wraps a report in a DER artifact beside its `EvidenceArtifact`.

```rust
use tightbeam::testing::fdr::{DefaultFdrExplorer, FdrConfig};
use tightbeam::testing::{FaultModel, FmeaConfig};
use tightbeam::urn::Urn;
use tightbeam::{tb_gen_process_types, tb_process_spec, urn, TightBeamError};

const SEND: Urn<'static> = urn!("doc", "event:fmea/send");
const ACK: Urn<'static> = urn!("doc", "event:fmea/ack");

tb_process_spec! {
	pub Link,
	events { observable { SEND, ACK } hidden { } }
	states {
		Ready => { SEND => Sent },
		Sent => { ACK => Done }
	}
	terminal { Done }
}

tb_gen_process_types!(Link, Ready, Sent, Done);

let fault = || TightBeamError::ChannelClosed;
let fault_model = FaultModel::default().with_fault(link::States::Ready, SEND, fault, tightbeam::bps!(10000));
let config = FdrConfig {
	seeds: 1,
	specs: vec![Link::process()?],
	fault_model: Some(fault_model),
	fmea_config: Some(FmeaConfig::default()),
	..FdrConfig::default()
};

let process = Link::process()?;
let verdict = DefaultFdrExplorer::with_defaults(&process, config).explore()?;
let report = verdict.fmea_report.ok_or("the run injected a fault")?;

assert_eq!(report.failure_modes.len(), 1);
assert_eq!(report.failure_modes[0].component, "Link.Ready");
assert_eq!(report.failure_modes[0].effects, ["Can reach terminal state(s): Done"]);
assert_eq!(report.failure_modes[0].occurrence, 10);
# Ok::<(), Box<dyn core::error::Error>>(())
```

## Sources

- C. A. R. Hoare, "Communicating Sequential Processes," Communications of the ACM 21(8), 1978: <https://doi.org/10.1145/359576.359585>
- A. W. Roscoe, Understanding Concurrent Systems, Springer, 2010, § 10.5, the structural test of determinism: <https://doi.org/10.1007/978-1-84882-258-0>
- University of Oxford, FDR4 User Manual, the CSPM language: <https://www.cs.ox.ac.uk/projects/fdr/>
- AFL.rs, the Rust port of American Fuzzy Lop: <https://github.com/rust-fuzz/afl.rs>
- C. Aschermann et al., "IJON: Exploring Deep State Spaces via Fuzzing," IEEE S&P 2020: <https://doi.org/10.1109/SP40000.2020.00117>
- MIL-STD-1629A, Procedures for Performing a Failure Mode, Effects and Criticality Analysis: <https://everyspec.com/MIL-STD/MIL-STD-1600-1699/MIL_STD_1629A_1556/>
- ISO 26262-1:2018, Road vehicles, Functional safety: <https://www.iso.org/standard/68383.html>
