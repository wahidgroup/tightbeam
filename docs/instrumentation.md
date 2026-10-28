# Instrumentation and Utilities

This page specifies the Rust layer of tightbeam's instrumentation and of its utilities:

- the trace collector, its configuration, and its event sinks
- the event record and the evidence artifact
- the log backends and the severity levels
- URNs, jobs, and job pipelines

It drills down from [README §10](../README.md#10-instrumentation) and [README §11](../README.md#11-misc) for engineers who emit events, read a trace, write a sink or a log backend, or build on the utilities. The README states what each part is, why it has its shape, and the rules it follows. This page names the types, traits, methods, fields, and errors that carry those rules.

## Contents

- [The trace collector](#the-trace-collector)
- [Objectives](#objectives)
- [Event kind taxonomy](#event-kind-taxonomy)
- [Event structure](#event-structure)
- [Payload representation](#payload-representation)
- [Configuration](#configuration)
- [Evidence artifact format](#evidence-artifact-format)
- [Failure handling](#failure-handling)
- [Logging subsystem](#logging-subsystem)
- [Utilities](#utilities)
- [Sources](#sources)

## The trace collector

`TraceCollector` (`tightbeam::trace`) collects the events and the assertions of one run. It builds with `std`, and each feature adds a part ([README §10](../README.md#10-instrumentation)):

| Feature         | Adds                                                                                                                           |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `std`           | `TraceCollector`, `TraceConfig`, `EventBuilder`, and `tightbeam::instrumentation` with `TbEvent`, `TbInstrumentationConfig`, and the `events` inventory |
| `instrument`    | The event sink, the sequence numbers, the trace clock, `EvidenceArtifact`, and the `emit` methods                              |
| `logging`       | The log backend of a trace, and the level and the component of an event                                                        |
| `testing`       | The assertion log that a spec reads, `ConsumedTrace`, `EvidenceArtifact::of`, and `PipelineBuilder`                           |
| `testing-fault` | `TraceCollector::with_fault_model`, which injects an error where an event records                                              |
| `colony`        | The emit path of a gateway and a hive, which records the assertion in a `testing` build and the event in an `instrument` build |

### Constructors

| Item                                  | Gives                                                                                                                       |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `TraceCollector::new()`, `Default`    | A trace of the default settings, with a bounded sink of 1024 events and the host clock ([The trace clock](#the-trace-clock)) |
| `TraceCollector::from(TraceConfig)`   | A trace of the settings, the sink, and the logger that the configuration names ([Configuration](#configuration))            |
| `share()`                             | Another handle on the same state, so every handle records into one trace                                                    |
| `with_clock(Arc<dyn Clock>)`          | The trace on another clock, with a new origin that the next event records (`instrument`)                                    |
| `with_logger(LoggerConfig)`           | The trace with a log backend, or `TraceStateShared` when another handle shares the state (`logging`)                        |
| `with_fault_model(FaultModel)`        | The trace with a runtime fault model, which every handle and the connection trace share (`testing-fault`)                   |
| `instrumented()`                      | Whether the build records events, which the `instrument` feature decides                                                    |

### Recording methods

Each method records one event. The event API is the three `emit_event` methods: each stamps its record on the trace clock and sets `TbEvent::FROM_EVENT_API`.

| Method                                         | Files the record under                                | Label             | Clock stamp | Assertion in a `testing` build    |
| ---------------------------------------------- | ----------------------------------------------------- | ----------------- | ----------- | --------------------------------- |
| `event(urn)?` then `emit()`                    | `assert/label`, or `timing/wcet` after `with_timing`  | The rendered `urn` | None        | `urn`                             |
| `event_with(urn, tags, value)?` then `emit()`  | `assert/payload`, with the rendered value as payload  | The rendered `urn` | None        | `urn`, with its tags and its value |
| `emit_event(urn)?`                             | `urn`                                                 | None              | Yes         | `urn`                             |
| `emit_event_with_evidence(urn, label, payload)?` | `urn`                                               | `label`           | Yes         | `urn`                             |
| `emit_event_with_value(urn, label, value)?`    | `urn`                                                 | `label`           | Yes         | `urn`, with its value             |
| `emit(urn, label)`                             | `urn`                                                 | `label`           | None        | None                              |
| `emit_with_payload(urn, label, payload)`       | `urn`                                                 | `label`           | None        | None                              |
| `emit_with_timing(urn, label, duration)`       | `urn`, with `duration_ns`                             | `label`           | None        | None                              |
| `emit_with_timestamp(urn, label, timestamp)`   | `urn`, with `timestamp_ns` set to `timestamp`         | `label`           | None        | None                              |

- `event` and `event_with` take an `IntoEventLabel`, which `Urn` and `&Urn` implement, so each label resolves to a URN of an inventory and a raw string fails to compile.
- An `EventBuilder` emits once, on `emit()` or on drop. It chains `with_timing(Duration)`, `with_log_level(LogLevel)`, and `with_component(name)`, and a builder of no value also chains `with_payload(&bytes)`.
- Under `testing`, the event API writes the assertion before the record, so a spec and a CSP alphabet read the same URN.
- Under `testing-fault`, `event`, `event_with`, and the event API return the error that the fault model injects at the label.

### Reading methods

| Method                                    | Gives                                                                              | Feature      |
| ----------------------------------------- | ---------------------------------------------------------------------------------- | ------------ |
| `drain_events()`                          | Removes and returns the events that the sink retains                               | `instrument` |
| `overflowed()`                            | The sticky latch of the sink                                                       | `instrument` |
| `recorded(label)`                         | The count of the assertions of `label`, which stay recorded                        | `testing`    |
| `drain_assertions()`                      | Removes and returns the assertions                                                 | `testing`    |
| `record_exchange(Exchange)`               | Records how the peer of the run answered one request                               | `testing`    |
| `ConsumedTrace::populate_from_collector`  | Moves the assertions, the exchanges, and the events of a collector into the trace  | `testing`    |

### The connection trace

A hive's control plane and a gateway's server record the connections they accept on one connection trace, which the crate-private `TraceCollector::connections` splits from the owner's trace:

- It shares the assertion log, the logger, the fault model, and the clock of the owner's trace.
- It numbers its events from 0, and its clock records an origin of its own.
- Its sink is the one that `EventSink::sibling` of the owner's sink names, or a new bounded sink of `max_events`.

## Objectives

Each objective of [README §10.1](../README.md#101-objectives) has one mechanism:

| Objective                              | Mechanism                                                                                                                                                                                  |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Amortized O(1) emission                | One relaxed atomic add takes the sequence number. The sink answers `retains` before the collector builds the event, so an event that the sink refuses allocates nothing. A sink MUST keep `emit` and `retains` amortized O(1) |
| Increasing sequence numbers            | Each trace state holds one `AtomicU32` counter from 0. A dropped event consumes its number, so the overflow warning or a gap marks it. The counter wraps past `u32::MAX` |
| Deterministic, hash-stable evidence    | The events encode as DER with EXPLICIT tags, and the hashes cover that DER. The event API stamps `timestamp_ns`, and `trace/clock-origin` carries the Unix time, so two runs give one hash when their clocks read the same values, as a `ManualClock` does |
| Feature-gated detail                   | `instrument` compiles the records, and each flag of `TbInstrumentationConfig` turns on one kind of detail                                                                                  |
| Payload privacy                        | The collector keeps the SHA3-256 hash of a payload, and the raw bytes reach no sink                                                                                                        |

## Event kind taxonomy

The module `tightbeam::instrumentation::events` holds one `Urn<'static>` constant per event, each built by `urn!` under the NID `TIGHTBEAM_NID`, which is `tightbeam`. Section comments group the constants by plane, and the doc of each constant names its label, its value, its payload, and its emit sites. [README §10.2](../README.md#102-event-kind-taxonomy) lists the refusal and decision events.

### Records of the collector

The collector writes four records of the inventory itself:

| Constant             | URN                        | Record                                                                                                                             |
| -------------------- | -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `ASSERT_LABEL`       | `event:assert/label`       | The record of an `event(urn)` builder, whose label is `urn`                                                                        |
| `ASSERT_PAYLOAD`     | `event:assert/payload`     | The record of an `event_with(urn, tags, value)` builder, whose payload is the rendered value                                       |
| `TIMING_WCET`        | `event:timing/wcet`        | The record of an `event(urn)` builder that carries a duration                                                                      |
| `TRACE_CLOCK_ORIGIN` | `event:trace/clock-origin` | The origin of the trace clock, before the first event that counts from it. Its label is the origin in Unix-epoch nanoseconds, and its `timestamp_ns` is 0 |

The default sink writes `WARN` (`event:core/warn`) itself, in place of the first event past its bound ([`BoundedMemorySink`](#boundedmemorysink)). Its label is the URN of the event it replaces.

`ConsumedTrace::count_event_urn` counts records by URN, so it finds the event API under the URN of each event and the builder records under `assert/label`. A spec of assertions reads the URN of either path as the label.

### Internal events

The crate-private `InternalEvent` closes the set of internal events, and `TraceCollector::emit_internal_event` is the one reader of `enable_internal_detail`. With the flag off, it returns at its first branch.

| Variant        | URN                    | Label           | Step                                                                     |
| -------------- | ---------------------- | --------------- | ------------------------------------------------------------------------ |
| `HandlerEnter` | `event:handler/enter`  | `handler_enter` | The entry into the application handler of an admitted call               |
| `HandlerExit`  | `event:handler/exit`   | `handler_exit`  | The exit from the application handler of an admitted call                |
| `PolicyEval`   | `event:policy/eval`    | `policy_eval`   | A collector gate that evaluates one inbound call                         |
| `RouteStep`    | `event:route/step`     | `route_step`    | A peer stream that the mux responder routes to the method of its kind    |
| `CryptoStep`   | `event:crypto/step`    | `crypto_step`   | A frame body that a servlet decrypts for typed delivery                  |
| `CompressStep` | `event:compress/step`  | `compress_step` | A cleartext frame body that a servlet inflates for typed delivery        |

The trace analysis of FDR reads these six URNs as hidden steps.

### Exploration events

`FdrExplorer::explore_into(&TraceCollector)` records the exploration events that the settings of the trace ask for:

| Setting                 | Constant             | URN                          |
| ----------------------- | -------------------- | ---------------------------- |
| `sample_enabled_sets`   | `ENABLED_SET_SAMPLE` | `event:fdr/enabled-set-sample` |
| `sample_refusals`       | `REFUSAL_SNAPSHOT`   | `event:fdr/refusal-snapshot` |
| `divergence_heuristics` | `DIVERGENCE_DETECT`  | `event:fdr/divergence-detect` |

- A scenario explores into a trace that the crate-private `TraceCollector::sibling` builds, with a state and a default sink of its own, under the settings and the clock of the scenario's trace.
- `ScenarioVerdict::exploration` returns that trace as a `ConsumedTrace`.
- `FdrConfig::max_internal_run`, 32 by default, is the longest hidden run that exploration takes. A divergence refutes `FdrVerdict::divergence_free`.

## Event structure

`TbEvent` (`tightbeam::instrumentation`) is one record of a trace. It derives `Clone`, `Debug`, and `PartialEq`.

| Field          | Type                        | Holds                                                                       | Set by                                                         |
| -------------- | --------------------------- | --------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `seq`          | `u32`                       | The number that the counter of the trace gave it                            | Every record                                                   |
| `urn`          | `Urn<'static>`              | The event kind                                                              | Every record                                                   |
| `label`        | `Option<Cow<'static, str>>` | Why the event fired. A static label stays borrowed, and a decoded one is owned | Each method that takes a label, and the `event` builders     |
| `payload_hash` | `Option<[u8; 32]>`          | The SHA3-256 hash of the payload                                            | A payload, when `enable_payloads` is on                        |
| `duration_ns`  | `Option<u64>`               | The span length that the caller measured                                    | `with_timing` and `emit_with_timing`, when `record_durations` is on |
| `timestamp_ns` | `Option<u64>`               | The nanoseconds on the trace clock since its origin                         | The event API, and `emit_with_timestamp`                       |
| `flags`        | `u32`                       | Bit 0 is `TbEvent::FROM_EVENT_API`, and every other bit is zero             | The event API sets bit 0                                       |
| `extras`       | `Option<Vec<u8>>`           | Opaque extension bytes                                                      | The collector writes `None`                                    |

`TbEvent::is_from_event_api()` reads bit 0. The flag is set the same way in every build, so a run writes one record and one evidence hash with `testing` on or off.

### The trace clock

- A collector adopts `SystemClock` where the host has one, which is a `std` build on any target but `wasm32-unknown-unknown`. `with_clock` adopts another, such as `ManualClock` (`tightbeam::utils::time`).
- Each adoption takes a new origin, and the next event of the event API records `trace/clock-origin` first, once per origin.
- The origin is in Unix-epoch nanoseconds, at the millisecond precision of the clock.
- A build with no host clock stamps its events once a clock is adopted.

The first record of a trace is the origin of its clock:

```rust
use tightbeam::instrumentation::{events, TbInstrumentationConfig};
use tightbeam::trace::{TraceCollector, TraceConfig};

let settings = TbInstrumentationConfig { enable_payloads: true, ..Default::default() };
let trace = TraceCollector::from(TraceConfig::with_instrumentation(settings));
trace.emit_event_with_evidence(events::GATE_REJECT, "PermissionDenied", Some(b"peer key"))?;

let records = trace.drain_events();
let urns: Vec<_> = records.iter().map(|record| &record.urn).collect();
assert_eq!(urns, [&events::TRACE_CLOCK_ORIGIN, &events::GATE_REJECT]);

let reject = records.iter().find(|record| record.urn == events::GATE_REJECT);
assert!(reject.is_some_and(|record| record.is_from_event_api() && record.payload_hash.is_some()));
# Ok::<(), tightbeam::TightBeamError>(())
```

## Payload representation

A payload enters a trace as bytes, through `EventBuilder::with_payload`, `emit_with_payload`, or `emit_event_with_evidence` ([README §10.4](../README.md#104-payload-representation)):

- With `enable_payloads` on, the collector keeps the SHA3-256 hash of the payload as `payload_hash`. With it off, `payload_hash` stays `None`.
- The collector renders a payload only when its sink retains the event and its settings keep payloads, so a crate-private emit site that renders its evidence pays for the render only then.
- A value of `event_with` or `emit_event_with_value` reaches the assertion as an `AssertionValue`. In the builder record under `assert/payload`, the one-line render of the value fills the payload, so the collector hashes it as it hashes any payload, an integer value included.
- `EventValue` is `None` or `Value(AssertionValue)`. It converts from `()` and from each type that `AssertionValue` converts from.

## Configuration

[README §10.5](../README.md#105-configuration) states the defaults and the overflow rule.

### `TbInstrumentationConfig`

The settings of a trace (`tightbeam::instrumentation`). The struct derives `Clone`, `Copy`, `Debug`, and `Default`, and it builds with `std`. A build without `instrument` records no event, so every setting gives the same trace there.

| Field                    | Type   | Default | Effect                                                                     |
| ------------------------ | ------ | ------- | -------------------------------------------------------------------------- |
| `enable_payloads`        | `bool` | `false` | Each event keeps the SHA3-256 hash of its payload                          |
| `enable_internal_detail` | `bool` | `false` | The trace records the six [internal events](#internal-events)              |
| `sample_enabled_sets`    | `bool` | `false` | Exploration records the observable events that each visited state offers   |
| `sample_refusals`        | `bool` | `false` | Exploration records the refusal set of each visited stable or accepting state |
| `divergence_heuristics`  | `bool` | `false` | Exploration records the hidden run of each divergence it finds             |
| `max_events`             | `u32`  | 1024    | The capacity of the default bounded sink                                   |
| `record_durations`       | `bool` | `false` | Each event keeps the duration that its caller measured                     |

### `TraceConfig`

The configuration that `TraceCollector::from` takes:

| Item                                           | Gives                                                                      |
| ---------------------------------------------- | -------------------------------------------------------------------------- |
| `TraceConfig::default()`                       | The default settings, the default sink, and no log backend                 |
| `TraceConfig::with_instrumentation(settings)`, `From<TbInstrumentationConfig>` | A configuration of `settings` (`instrument`) |
| `instrumentation()`                            | The settings, which are the defaults when the configuration names none     |
| `with_sink(sink)`                              | The configuration with `sink` in place of the bounded buffer (`instrument`) |
| `with_logger(LoggerConfig)`                    | The configuration with a log backend (`logging`)                           |

### `EventSink`

The retention policy of a trace (`tightbeam::instrumentation`, `instrument`). The trait is `Send + Sync`, and the collector delivers every event to exactly one sink.

| Method                                         | Default  | Contract                                                                                                     |
| ---------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------ |
| `emit(&self, event: TbEvent)`                  | Required | Retains or forwards one event                                                                                |
| `drain(&self) -> Vec<TbEvent>`                 | Required | Removes and returns the retained events, ordered by `seq`. A sink that forwards each event returns an empty vector |
| `overflowed(&self) -> bool`                    | Required | A sticky latch that reads `true` once the sink drops any event                                               |
| `retains(&self) -> bool`                       | `true`   | Whether the sink keeps the next event, or the overflow warning in its place. A sink that answers `false` drops that event, and `overflowed` MUST then read `true` |
| `sibling(&self) -> Option<Arc<dyn EventSink>>` | `None`   | The sink of the [connection trace](#the-connection-trace). A sink that forwards each event returns its destination |

- The collector asks `retains` after it takes the sequence number and before it builds the event.
- A sink that drops events MUST keep `TbEvent::into_overflow_warning` of the first event it drops, in place of that event, so the record it drains or forwards shows where the truncation began. It answers `retains` with `true` until it holds the warning, so the collector builds the event that the warning replaces.
- `emit` and `retains` run on the control-plane hot path, so an implementation MUST be amortized O(1) and MUST NOT block on I/O. A sink buffers its I/O and defers it.
- `emit` runs after the trace clock releases its lock, so it MAY adopt a clock. It MUST NOT emit into the collector that called it, because the record of a clock origin runs in a `Once` that the second emit enters again, which deadlocks.
- A servlet, a hive, or a gateway that runs for a long time needs a sink that forwards each event, as the warning of [README §10.2](../README.md#102-event-kind-taxonomy) states. A forwarding sink also returns its destination from `sibling`, so the connection trace forwards too.

### `BoundedMemorySink`

The default sink, a bounded buffer with a sticky overflow latch:

- `BoundedMemorySink::new(max_events)` sizes it, and `Default` sizes it at 1024.
- It keeps the oldest `max_events` events and drops each later one.
- In place of the first event it drops, it keeps the overflow warning, a `WARN` record with the sequence number and the clock stamp of that event, and sets the latch.
- `retains` answers from the same state, under the lock that `emit` takes, so concurrent emitters stay within the bound and its one warning.
- `drain` frees capacity and keeps the latch set, so the sink keeps the warning once.

A sink of one event keeps the first event, then the warning in place of the second, and drops the third:

```rust
use tightbeam::instrumentation::{events, TbInstrumentationConfig};
use tightbeam::trace::{TraceCollector, TraceConfig};

let config = TbInstrumentationConfig { max_events: 1, ..Default::default() };
let trace = TraceCollector::from(TraceConfig::with_instrumentation(config));
trace.emit(events::GATE_ACCEPT, "Ok");
trace.emit(events::GATE_REJECT, "PermissionDenied");
trace.emit(events::GATE_REJECT, "PermissionDenied");

let kept: Vec<_> = trace.drain_events().into_iter().map(|event| (event.seq, event.urn)).collect();
assert_eq!(kept, [(0, events::GATE_ACCEPT), (1, events::WARN)]);
assert!(trace.overflowed());
```

## Evidence artifact format

`EvidenceArtifact` (`tightbeam::instrumentation`, `instrument`) is the evidence that a trace gives for a spec, as ASN.1 DER ([README §10.6](../README.md#106-evidence-artifact-format)).

| Item                                                     | Gives                                                                                                        |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `EvidenceArtifact::of(spec_hash: [u8; 32], trace: &ConsumedTrace)` | The artifact of the instrument events of `trace`, with `overflow` set when `trace.is_complete()` reads `false` (`testing`) |
| `spec_hash()`                                            | The 32 bytes that the caller passed, as `&OctetString`                                                       |
| `trace_hash()`                                           | The SHA3-256 hash of the DER of `events()`, as `&OctetString`                                                |
| `evidence_hash()`                                        | The SHA3-256 hash of `spec_hash` followed by `trace_hash`, as `&OctetString`                                 |
| `events()`                                               | The events that the trace hash covers, in the order of the trace                                             |
| `overflow()`                                             | Whether the trace misses events of its run                                                                   |

- The fields are private, so `of` and the DER decode are the two ways to build an artifact.
- `of` streams the DER of the events into the digest as it encodes them. It returns `TightBeamError::SerializationError` when that DER passes the length that DER encodes.
- The artifact derives `Beamable`, so a frame can carry it as its message.
- `overflow` sits outside both hashes.

### DER of an event

`TbEvent` and `EvidenceArtifact` write their DER by hand: the `Sequence` derive takes no `Urn<'static>` field, and the decode of an artifact recomputes both hashes. `urn` encodes as a UTF8String of its full form, and each OPTIONAL field of an event carries an EXPLICIT context tag:

| Field         | Tag                          |
| ------------- | ---------------------------- |
| `label`       | `[0] EXPLICIT UTF8String`    |
| `payloadHash` | `[1] EXPLICIT OCTET STRING`  |
| `durationNs`  | `[2] EXPLICIT INTEGER`       |
| `timestampNs` | `[3] EXPLICIT INTEGER`       |
| `extras`      | `[4] EXPLICIT OCTET STRING`  |

The tags set `duration_ns` apart from `timestamp_ns`, and `payload_hash` apart from `extras`, whichever subset is absent.

### Decode refusals

Each event reads inside the length that its header declares. The decode refuses:

| Input                                                       | Error                                   |
| ----------------------------------------------------------- | --------------------------------------- |
| A `payloadHash` of another length than 32 octets            | The length error of `OCTET STRING`      |
| A `specHash` of another length than 32 octets               | The length error of `OCTET STRING`      |
| A `traceHash` or an `evidenceHash` that differs from the hash of the decoded fields | The value error of `OCTET STRING` |
| A `urn` that is no valid URN                                | The value error of `UTF8String`         |

A decoded artifact is therefore one that `of` could build from the same spec hash and events:

```rust
use tightbeam::der::{Decode, Encode};
use tightbeam::instrumentation::{events, EvidenceArtifact};
use tightbeam::trace::{ConsumedTrace, TraceCollector};

let collector = TraceCollector::new();
collector.emit_event(events::GATE_ACCEPT)?;

let mut trace = ConsumedTrace::new();
trace.populate_from_collector(&collector);

let artifact = EvidenceArtifact::of([7u8; 32], &trace)?;
let decoded = EvidenceArtifact::from_der(&artifact.to_der()?)?;
assert_eq!(decoded, artifact);
# Ok::<(), Box<dyn core::error::Error>>(())
```

## Failure handling

The trace keeps recording through each failure of [README §10.7](../README.md#107-failure-handling):

| Failure                                   | What the trace does                                                                                         |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| The sink is full                          | The sink keeps the overflow warning in place of the first event past its bound, drops each later event, and sets its latch. The sequence number of each dropped event stays taken |
| A panic poisoned a lock of the trace      | Each lock reads through the poison, because each write under it leaves a whole value                        |
| A log backend refuses a record            | The trace drops the outcome of the log write, and the event stays on the trace                              |
| A fault model injects at a label          | `event`, `event_with`, and the event API return the injected error (`testing-fault`)                        |
| A job event fails to record               | `TracedResult::then_job` passes the error on as the error of the step                                       |
| The drained record misses an event        | `ConsumedTrace::is_complete` reads `false`, `count_event_urn` returns `EventRecordTruncated`, and `EvidenceArtifact::of` sets `overflow` |

`ConsumedTrace::populate_from_collector` marks the trace incomplete when the drained record misses an event that the collector sequenced:

- The sink dropped the event.
- The sink forwards each event and keeps none.
- A reader drained the collector first, a second drain of one collector included.

On overflow, the trace records the truncation in three places:

- The latch of the sink reads `true`.
- `is_complete` reads `false`, so `EvidenceArtifact::of` sets `overflow`, which sits outside both hashes.
- The `WARN` record (`event:core/warn`) takes the place and the sequence number of the first event that the sink dropped, inside the events that the trace hash covers.

## Logging subsystem

[README §10.8](../README.md#108-logging-subsystem) holds the severity table and the built-in backends. Every item here is in `tightbeam::trace` under `logging`.

### Severity levels

`LogLevel` is an alias of `SyslogSeverity` (`tightbeam::standards::rfc5424`), a `#[repr(u8)]` enum of the eight severities of RFC 5424 § 6.2.1:

| Conversion                       | Behavior                                                                                                       |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `u8::from(level)`                | The number of the severity                                                                                     |
| `SyslogSeverity::try_from(u8)`   | The severity of a number, or `RFC5424Error::InvalidSeverityValue` for a number past 7                          |
| `FromStr`                        | A name in upper, title, or lower case, a short form such as `warn` or `INFO`, or a number. Other text gives `RFC5424Error::InvalidSeverityName` |
| `Display`                        | The upper-case name, such as `WARNING`                                                                         |
| DER                              | An ENUMERATED of the number. A number past 7 is a value error of the ENUMERATED tag                            |
| `Ord`                            | A lower number sorts first, so `Emergency < Debug`                                                             |

### `LogBackend`

A backend writes the records to its output target. The trait is `Send + Sync`.

| Method                                              | Default  | Contract                                                         |
| --------------------------------------------------- | -------- | ---------------------------------------------------------------- |
| `emit(&self, record: &LogRecord) -> Result<(), LogError>` | Required | Writes one record                                          |
| `accepts(&self, level: LogLevel) -> bool`           | Required | Whether the backend takes records at `level`, by its own criteria. `MultiplexBackend` reads it for each inner backend |
| `flush(&self) -> Result<(), LogError>`              | `Ok(())` | Flushes the buffered records of an async backend                 |

`LogError` has three variants: `IoError`, `BufferFull`, and `BackendUnavailable`.

### `LogRecord`

A backend receives a `LogRecord<'a>`. The record of a trace event takes these values:

| Field       | Type                             | Value in the record of an event                                                                               |
| ----------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `level`     | `LogLevel`                       | The level of `with_log_level`, else the default level of the logger. An event with neither writes no record   |
| `timestamp` | `Option<u64>`                    | The Unix time in milliseconds on the trace clock. A `logging` build without `instrument` reads the host clock |
| `component` | `Option<&'a str>`                | The name of `with_component`, which also selects the override of the filter                                  |
| `message`   | `&'a str`                        | The label of the event, which is its rendered URN                                                             |
| `metadata`  | `Option<&'a [(&'a str, &'a str)]>` | `None`                                                                                                      |

### `LogFilter` and `LoggerConfig`

| Item                                        | Behavior                                                                               |
| ------------------------------------------- | -------------------------------------------------------------------------------------- |
| `LogFilter::new(min_level)`                 | A filter that admits `min_level` and each more severe level                            |
| `LogFilter::default()`                      | A filter of the minimum level `Informational`                                          |
| `with_component(name, level)`               | A minimum level of its own for the component `name`                                    |
| `should_log(level, component)`              | Whether `level` is as severe as the threshold or more, where the threshold is the override of `component` or the minimum level |
| `LoggerConfig::new(backend, filter)`        | A logger of a backend and a filter, with no default level                              |
| `with_default_level(level)`                 | The level of an event that names none                                                  |

The fields of `LoggerConfig` are public: `backend: Box<dyn LogBackend>`, `filter: LogFilter`, and `default_level: Option<LogLevel>`.

### Built-in backends

| Backend                                          | Writes                                                                                                        | `accepts`                       |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| `StdoutBackend`                                  | One line per record to the locked standard output, `[<timestamp>] [<LEVEL>] <component>: <message>`, then one line `  <key>: <value>` per metadata pair. A record of no component names `app`, and a record of no timestamp has no timestamp prefix. A failed write is `LogError::IoError` | Every level |
| `MultiplexBackend::new(Vec<Box<dyn LogBackend>>)` | Each record to each inner backend that accepts its level, in order. The first error ends the fan-out, and `flush` flushes each inner backend the same way | When an inner backend accepts |

### Attach a logger

- `TraceConfig::with_logger` names the logger when the trace is built.
- `TraceCollector::with_logger` sets it on a trace that no other handle shares, so call it before `share`. A shared trace returns `TraceStateShared`, and `into_collector` hands the handle back.
- The connection trace shares the logger of its owner.

A backend of its own, attached to a trace:

```rust
use std::sync::{Arc, Mutex};

use tightbeam::trace::{LogBackend, LogError, LogFilter, LogLevel, LogRecord, LoggerConfig, TraceCollector, TraceConfig};
use tightbeam::urn::Urn;

/// A backend that keeps the message of each record.
struct Kept(Arc<Mutex<Vec<String>>>);

impl LogBackend for Kept {
    fn emit(&self, record: &LogRecord) -> Result<(), LogError> {
        let mut messages = self.0.lock().map_err(|_| LogError::BackendUnavailable)?;
        messages.push(record.message.to_string());
        Ok(())
    }

    fn accepts(&self, _level: LogLevel) -> bool {
        true
    }
}

const LOGIN: Urn<'static> = tightbeam::urn!("example", "event:security/login");

let messages = Arc::new(Mutex::new(Vec::new()));
let logger = LoggerConfig::new(Kept(Arc::clone(&messages)), LogFilter::new(LogLevel::Warning));
let trace = TraceCollector::from(TraceConfig::default().with_logger(logger));
trace.event(LOGIN)?.with_log_level(LogLevel::Error).emit();
trace.event(LOGIN)?.with_log_level(LogLevel::Debug).emit();

assert_eq!(*messages.lock()?, ["urn:example:event:security/login"]);
# Ok::<(), tightbeam::TightBeamError>(())
```

## Utilities

[README §11.1](../README.md#111-utilities) names the three utilities and states the URN forms.

### URNs

`Urn<'a>` (`tightbeam::urn`) holds a NID and an NSS as `Cow<'a, str>`, so a URN borrows its input. Equality and hashing compare both parts byte for byte.

| Item                              | Behavior                                                                                                            |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `urn!(nid, nss)`                  | A `Urn<'static>` from literals, checked in a `const` block, so a malformed literal fails the build                  |
| `Urn::from_parts(nid, nss)`       | A `Urn<'static>` from parts known at run time, under the same checks                                                |
| `FromStr` for `Urn<'static>`      | Splits the text after a lower-case `urn:` at its first `:` into the NID and the NSS. Text of another shape gives `InvalidUrnSyntax` |
| `nid()`, `nss()`                  | The two parts                                                                                                       |
| `verify::<S>()`                   | Checks the URN against the spec `S`, as [URN specs](#urn-specs) states                                              |
| `Urn::validate_nid(nid)`          | A `const fn`: 2 to 32 ASCII letters, digits, and hyphens, with a letter first and a letter or a digit last          |
| `Urn::validate_nss(nss)`          | A `const fn`: the NSS holds at least one character                                                                  |
| `into_owned()`                    | A `Urn<'static>` that owns its parts                                                                                |
| `Display`                         | `urn:<nid>:<nss>`                                                                                                   |
| DER                               | A UTF8String of the full form. The decode parses it, so a decoded URN passes the same checks                        |

The NID rule is the house's own: RFC 8141 § 2 also admits a digit first. `validate_nss` reads the length of the NSS alone, so every character passes it.

### `UrnBuilder`

`UrnBuilder<'a>` (`tightbeam::urn`) builds a URN and validates it:

| Method                          | Behavior                                                                          |
| ------------------------------- | --------------------------------------------------------------------------------- |
| `UrnBuilder::default()`         | An empty builder                                                                  |
| `UrnBuilder::from(spec)`        | A builder with the NID of the spec, in the spec mode                              |
| `with_nid(nid)`                 | Sets the NID                                                                      |
| `set(key, value)`, `get(key)`   | A component by key. A key can be dotted, such as `resource.type`                  |
| `with_nss(nss)`                 | The direct mode. A later call replaces the NSS                                    |
| `with_spec::<S>()`              | The spec mode. A later call replaces the spec                                     |
| `build()`                       | The URN, or the first error                                                       |

`build` checks the NID before the mode runs, so a malformed NID reports its own error first. The mode then gives the NSS:

| Mode    | Set by                        | NSS                                                                 |
| ------- | ----------------------------- | ------------------------------------------------------------------- |
| Direct  | `with_nss`                    | The given string                                                    |
| Spec    | `with_spec` or `From<S>`      | `S::transform`, then `S::validate`, then `S::build_nss`             |
| Default | Neither                       | The component values in key order, joined by `:`                    |
| Both    | `with_nss` and a spec         | `ConflictingNssModes`                                               |

Under `builder`, `UrnBuilder` also implements `TypeBuilder<Urn>`.

### URN specs

`UrnSpec` (`tightbeam::urn`) is the specification of one namespace:

| Item                                          | Contract                                                                     |
| --------------------------------------------- | ---------------------------------------------------------------------------- |
| `const NID: &'static str`                     | The NID of the namespace                                                     |
| `type Components<'a>: UrnComponents<'a>`      | What the spec reads an NSS into. A spec of `urn_spec!` uses `UrnBuilder`     |
| `components(nss)`                             | Reads `nss` into components, each borrowed from `nss`                        |
| `transform(&mut dyn UrnComponents)`           | Edits the components before validation. The default leaves them as they are |
| `validate(&dyn UrnComponents)`                | Checks each required field and each constraint                               |
| `build_nss(&dyn UrnComponents)`               | Builds the NSS from the components                                           |

`UrnComponents<'a>` gives `get_component`, `set_component`, `remove_component`, `iter`, and `iter_mut`. The iterators are boxed, so the trait stays dyn-compatible.

`Urn::verify::<S>` runs these steps:

1. Compare the NID with `S::NID`, and check it with `validate_nid`.
2. Read the NSS with `S::components`.
3. Run `S::transform` and `S::validate` on the components.
4. Build the NSS again with `S::build_nss`, and return `NssMismatch` when it differs from the NSS of the URN.

`urn_spec!` declares a spec. Each field of its `nss_structure` takes these options:

| Option                    | Effect                                                         | `UrnSpecBuilder` call    |
| ------------------------- | -------------------------------------------------------------- | ------------------------ |
| `value: "literal"`        | The field equals one constant                                  | `field_const`            |
| `values: ["a", "b"]`      | The field is one of the values                                 | `field_oneof`            |
| `pattern: Pattern::Alpha` | The field matches the class of the pattern                     | `field_pattern`          |
| `required: false`         | The field is optional. Each field is required by default       | `field_optional`         |
| `sep: "/"`                | The separator before the field, in a join format               | `field_nss_separator`    |

- An `nss_format` such as `"{}:{}/{}"` places the field values in order. With none, the values join with `:`, or with the `sep` of each field.
- A `transform` closure edits the components in place of the default `UrnSpec::transform`.
- `UrnSpecBuilder::from(nid)` builds the same spec at run time, with `nss_format`, `validate`, `build_nss`, `parse_nss`, `nid`, and `fields`.

`Pattern` (`tightbeam::urn::builders::spec`) admits a non-empty run of one ASCII class:

| Variant              | Admits          |
| -------------------- | --------------- |
| `Alpha`              | `[a-zA-Z]+`     |
| `Numeric`            | `[0-9]+`        |
| `AlphaNumeric`       | `[a-zA-Z0-9]+`  |
| `AlphaNumericHyphen` | `[a-zA-Z0-9-]+` |

A spec of a namespace of its own, which builds a URN and verifies one that it parsed:

```rust
use tightbeam::urn::builders::spec::Pattern;
use tightbeam::urn::{Urn, UrnBuilder, UrnValidationError};

tightbeam::urn_spec! {
    /// The spec of `urn:example:<kind>/<id>`.
    pub OrderSpec,
    nid: "example",
    nss_structure {
        kind: { values: ["order", "invoice"] },
        id: { pattern: Pattern::AlphaNumericHyphen, sep: "/" }
    }
}

let built = UrnBuilder::from(OrderSpec).set("kind", "order").set("id", "a-17").build()?;
assert_eq!(built.to_string(), "urn:example:order/a-17");

let parsed: Urn<'static> = "urn:example:invoice/b-2".parse()?;
assert_eq!(parsed.verify::<OrderSpec>(), Ok(()));

let refused = UrnBuilder::from(OrderSpec).set("kind", "refund").set("id", "a-17").build();
assert!(matches!(refused, Err(UrnValidationError::InvalidFormat { field: "kind", .. })));
# Ok::<(), UrnValidationError>(())
```

### `UrnValidationError`

| Variant                       | Cause                                                                                  |
| ----------------------------- | -------------------------------------------------------------------------------------- |
| `RequiredFieldMissing(name)`  | A required field, the NID, or the NSS is absent, or the NSS is empty                   |
| `InvalidFormat { field, pattern }` | A field breaks a constraint, or its pattern when `pattern` is `Some`              |
| `ForbiddenFieldPresent(name)` | A forbidden field is present                                                           |
| `NidMismatch`                 | The NID differs from the NID of the spec                                               |
| `RealmMismatch`               | The realm segment of a colony URN differs from the realm of its namespace              |
| `InvalidNidLength`            | The NID is shorter than 2 or longer than 32 characters                                 |
| `InvalidNidStart`             | The first character of the NID is no letter                                            |
| `InvalidNidCharacters`        | A character of the NID is no letter, digit, or hyphen, or the NID ends with a hyphen   |
| `InvalidUrnSyntax`            | The text is not of the form `urn:<nid>:<nss>`                                          |
| `ConflictingNssModes`         | The builder holds both a direct NSS and a spec                                         |
| `NssMismatch`                 | The spec builds another NSS from the components that it reads                          |

`TightBeamError` converts from it, as its `UrnValidationError` variant.

### `TightbeamUrnSpec`

The spec of the instrumentation label form, `urn:tightbeam:instrumentation:<resource_type>/<resource_id>`, with the NSS format `{}:{}/{}`:

| Field           | Rule                                                                       |
| --------------- | -------------------------------------------------------------------------- |
| `category`      | `instrumentation`                                                          |
| `resource_type` | `trace`, `event`, `seed`, or `verdict`, which the transform lowercases first |
| `resource_id`   | `Pattern::AlphaNumericHyphen`                                              |

The module `tightbeam::urn::specs` compiles under `cfg(test)`, so the spec builds in the unit tests of the crate. A crate that checks this form declares the same spec with `urn_spec!`.

### Jobs

`Job` and `AsyncJob` (`tightbeam::utils::task`) are the traits of a stateless unit of work:

| Item          | `Job`                                     | `AsyncJob`                                                               |
| ------------- | ----------------------------------------- | ------------------------------------------------------------------------ |
| `type Input`  | One input value, often a tuple            | One input value, often a tuple                                           |
| `type Output` | Typically `Result<T, TightBeamError>`     | Typically `Result<T, TightBeamError>`                                    |
| `const NAME`  | The name of the struct                    | The name of the struct                                                   |
| `run`         | `fn run(input: Self::Input) -> Self::Output` | `fn run(input: Self::Input) -> impl Future<Output = Self::Output> + Send` |

`job!` has four forms:

| Form                                     | Implements  | `Input`  | Call                         |
| ---------------------------------------- | ----------- | -------- | ---------------------------- |
| `fn run((a, b): (A, B)) -> R { .. }`     | `Job`       | `(A, B)` | `Name::run((a, b))`          |
| `fn run() -> R { .. }`                   | `Job`       | `()`     | `Name::run()`                |
| `async fn run((a, b): (A, B)) -> R { .. }` | `AsyncJob` | `(A, B)` | `Name::run((a, b)).await`   |
| `async fn run() -> R { .. }`             | `AsyncJob`  | `()`     | `Name::run().await`          |

- The parameter is a tuple pattern with its tuple type, so a job of one input takes `(x,): (X,)`, and a call passes `(x,)`.
- Each form declares `pub struct Name;` with a `pub fn run` that calls the trait's, so a caller needs no trait import. Each type in the signature is public, or the build fails with E0446.
- The attributes and the docs ahead of `name:` go onto the struct, and `NAME` is `stringify!(Name)`.
- `test_job!` defines a `#[test]` function that binds the output of a job and runs a block of assertions on it. An `async move` block defines a `#[tokio::test]` function.

Code that takes any job reads the trait:

```rust
use tightbeam::utils::task::Job;
use tightbeam::{job, TightBeamError};

job! {
    /// Adds two numbers.
    name: AddNumbers,
    fn run((a, b): (u32, u32)) -> Result<u32, TightBeamError> {
        Ok(a.saturating_add(b))
    }
}

/// Runs any job whose input is a pair of numbers.
fn run_pair<J: Job<Input = (u32, u32)>>(pair: (u32, u32)) -> J::Output {
    J::run(pair)
}

assert_eq!(run_pair::<AddNumbers>((1, 2))?, 3);
assert_eq!(<AddNumbers as Job>::NAME, "AddNumbers");
# Ok::<(), TightBeamError>(())
```

### Job pipelines

`Pipeline` (`tightbeam::utils::task`) chains computations on a `Result`. The trait is `Sized`:

| Item                         | Contract                                                                          |
| ---------------------------- | --------------------------------------------------------------------------------- |
| `type Output`, `type Error`  | The success type and the error type                                               |
| `and_then(f)`                | Chains `f`, a `FnOnce(Output) -> Result<U, Error>`, as `Result::and_then` does    |
| `map(f)`                     | Maps the success value, as `Result::map` does                                     |
| `or_else(f)`                 | Handles an error with `f`, a `FnOnce(Error) -> Result<Output, Error>`, as `Result::or_else` does |
| `run()`                      | The `Result<Output, Error>` of the pipeline                                       |

| Implementation                | Behavior                                                                                                  |
| ----------------------------- | --------------------------------------------------------------------------------------------------------- |
| `Result<T, E>`                | Each step is the `Result` method of its name, and `run` returns the result                                |
| `F: FnOnce() -> Result<T, E>` | Each step calls the closure first, and `run` calls it                                                     |
| `Join<P1, P2>`, from `join(p1, p2)` | `run` runs `p1`, then `p2`, and pairs their outputs. The first error ends the run. `P2` has the error type of `P1`, and each step runs the join first |
| `TracedResult<T, E>`          | Each step keeps the trace and returns a `TracedResult`, so `then_job` can follow a plain step (`testing`) |

On a `Result`, the inherent methods `and_then`, `map`, and `or_else` take precedence over those of the trait, with the same result. `run` needs `Pipeline` in scope.

### Traced pipelines

Under `testing`, a traced pipeline records the lifecycle of each job:

| Item                                   | Behavior                                                                                                   |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `PipelineBuilder::new(Arc<TraceCollector>)` | A builder that reports to the trace                                                                   |
| `PipelineBuilder::start::<T, E>(value)` | A `TracedResult` of `Ok(value)`                                                                           |
| `TracedResult::new(result, trace)`     | A traced result of `result`                                                                                |
| `TracedResult::trace()`                | The trace that its jobs report to                                                                          |
| `TracedResult::then_job::<J, U>()`     | Runs `J` on a success, and records the `start` event, then `success` or `error`. It needs `E: From<TightBeamError>` and `J: Job<Input = T, Output = Result<U, E>>` |

A step records each event through `TraceCollector::event`, so the job URN is the label of an assertion and of an `assert/label` record. A spec asserts it by its label, as [README §11.1.3](../README.md#1113-job-pipelines) shows.

The URN of a job event comes from `Job::NAME` in four steps:

1. Put an underscore before each uppercase letter after the first.
2. Lowercase each letter.
3. Replace each underscore with a hyphen.
4. Build `urn:tightbeam:event:job/<name>-<suffix>` with `Urn::from_parts`, where the suffix is `start`, `success`, or `error`.

| `Job::NAME`              | Name in the URN            |
| ------------------------ | -------------------------- |
| `CreateHandshakeRequest` | `create-handshake-request` |
| `ValidateConfig`         | `validate-config`          |
| `HTTPRequest`            | `h-t-t-p-request`          |

A job that fails records its `error` event, and the step passes its error on:

```rust
use std::sync::Arc;

use tightbeam::trace::TraceCollector;
use tightbeam::urn::Urn;
use tightbeam::utils::task::{Pipeline, PipelineBuilder};
use tightbeam::{job, TightBeamError};

job! {
    /// Refuses an empty body.
    name: RejectEmpty,
    fn run((body,): (Vec<u8>,)) -> Result<Vec<u8>, TightBeamError> {
        if body.is_empty() {
            return Err(TightBeamError::InvalidBody);
        }

        Ok(body)
    }
}

const REJECT_EMPTY_ERROR: Urn<'static> = tightbeam::urn!("tightbeam", "event:job/reject-empty-error");

let trace = Arc::new(TraceCollector::new());
let outcome = PipelineBuilder::new(Arc::clone(&trace)).start((Vec::new(),)).then_job::<RejectEmpty, _>().run();

assert!(matches!(outcome, Err(TightBeamError::InvalidBody)));
assert_eq!(trace.recorded(REJECT_EMPTY_ERROR), 1);
```

## Sources

- RFC 8141, Uniform Resource Names (URNs), § 2: <https://www.rfc-editor.org/rfc/rfc8141#section-2>
- RFC 5424, The Syslog Protocol, § 6.2.1: <https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.1>
- ITU-T X.690, ASN.1 encoding rules, § 8.4, § 8.10, and § 8.14: <https://www.itu.int/rec/T-REC-X.690>
- FIPS 202, SHA-3 Standard: <https://doi.org/10.6028/NIST.FIPS.202>
