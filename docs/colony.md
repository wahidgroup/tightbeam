# The TightBeam Colony

This page specifies the four parts of a colony at the level of their types:

- the macros that declare each part, and the items each macro generates
- the traits each part implements, with their errors
- every configuration field and builder method, with its default
- the scenario environment that tests each part

It drills down from [README §9.3](../README.md#93-components) for engineers who build a colony or review one. The README holds what each part is, why it has its shape, and the usage examples.

## Contents

- [Workers](#workers)
- [Servlets](#servlets)
- [Hives](#hives)
- [Clusters](#clusters)
- [Sources](#sources)

## Workers

A worker is one message handler behind a bounded queue. [README §9.3.1](../README.md#931-e-workers) states its design constraints.

### The `worker!` macro

`worker!` takes these keys, in this order:

| Key | Required | Meaning |
| --- | --- | --- |
| `name: Name<Input, Output>` | Yes | The worker type, the message it consumes, and the value it produces |
| `queue: expr` | No | The bound of the request queue, 64 by default |
| `config: { field: Type, .. }` | No | The fields of the generated `NameConfig` struct |
| `policies: { with_receptor_gate: [Gate, ..] }` | No | The receptor gates, which run in order before the handler. The key may also come before `config` |
| `handle:` | Yes | An `async move` closure over the message, the trace, and the config. A worker with no `config` takes a closure over the message and the trace |

The handler receives the message as `Arc<Input>`, the trace as `Arc<TraceCollector>`, and the config as `&NameConfig`. It returns `Output`.

The macro generates these items:

| Item | Shape |
| --- | --- |
| `NameConfig` | A `Clone` struct with one `pub` field per `config` entry. A worker with no `config` has none, and its `new` takes `()` |
| `Name::new(config)` | An unstarted worker, with no queue and no run loop |
| `Name::start(self, trace)` | The inherent start, which opens the queue, spawns the run loop on the Tokio runtime, and returns the started worker |
| `impl Worker for Name` | The trait that a servlet and a scenario drive |

### The `Worker` trait

| Item | Contract |
| --- | --- |
| `type Input` | The message type that the handler consumes |
| `type Output` | The value type that the handler produces |
| `type Config` | The configuration taken at construction, `()` for a worker with no `config` block |
| `new(config)` | Constructs an unstarted worker. A relay before the start fails with `QueueClosed` |
| `start(self, trace)` | Opens the queue, spawns the run loop, and resolves to the started worker. A start of a started worker returns it unchanged |
| `relay(&self, Arc<Input>)` | Enqueues a message and awaits the handler's output |
| `kill(&self)` | Closes the queue, lets the run loop answer each request in flight, and awaits its join. A relay after the kill fails with `QueueClosed` |
| `queue_capacity(&self)` | The `queue:` value while the worker runs, and `0` before the start and after the kill |

The run loop takes one request at a time. The receptor gates run in order, and the first refusal answers the relay with that gate's status. A message that every gate admits reaches the handler. A started worker that drops before its kill aborts its run loop.

### Relay errors

| `WorkerRelayError` | Cause |
| --- | --- |
| `QueueClosed` | The worker never started, or a kill closed its queue |
| `Rejected(TransitStatus)` | A receptor gate refused the message, under the gate's status |
| `ResponseDropped` | The run loop ended before it answered |

`ServletContext::relay` returns `TightBeamError::WorkerRelay` with the worker's error, and `TightBeamError::MissingConfiguration` when the servlet holds no worker of the type. `kill` fails with `TightBeamError::JoinError` when the run loop task fails to join.

### Macro-free worker

`WorkerRuntime<Input, Output, Config>` is the runtime that `worker!` wraps:

1. `WorkerRuntime::new(config)` builds the unstarted runtime.
2. `WorkerRuntime::start(trace, queue_capacity, policies, handler)` opens the queue and spawns the loop. The handler is a `Fn(Arc<Input>, Arc<TraceCollector>, Arc<Config>)` that returns a future of `Output`.
3. `WorkerPolicyBuilder::default().with_receptor_gate([gate]).build()` builds the policies.
4. A wrapper type implements `Worker` by delegating to the runtime, the shape that `worker!` expands to.

### Worker scenarios

`environment Worker` takes these keys:

| Key | Closure | Parameter |
| --- | --- | --- |
| `context` | None, an expression evaluated once | Shared as `Arc<C>` with each closure, `Arc<()>` when omitted |
| `setup` | Sync, returns the unstarted worker | `SetupEnv { trace, context }` |
| `stimulus` | Async, drives the started worker | `WorkerEnv { trace, context, worker }` |

The scenario starts the worker on its trace between `setup` and `stimulus`.

## Servlets

A servlet is one listener that decodes one message type and dispatches it to its workers. [README §9.3.2](../README.md#932-e-servlets) states the single message type rule and the cleartext rule.

### The `servlet!` macro

`servlet!` declares `Name<Input, EnvConfig = Env>` and `protocol: P`, then one arm or more:

- `handle: |message, frame, ctx|` is typed unary delivery, the default. The arm decrypts or inflates the body in place, then decodes `Input`.
- `handle: raw |frame, ctx|` hands over the frame, and the handler owns its lifecycle.
- `stream: |body, ctx|` reads a chunked `StreamBody` on a multiplexed connection and may answer with one frame.
- `duplex: |body, reply, ctx|` exchanges request and reply chunks on one stream through a `ReplySink`.

A unary or stream handler resolves to `Result<Option<Frame>, TightBeamError>`. The servlet refuses a request kind with no arm with `Unimplemented`, and a declaration with no arm fails to compile.

The macro generates these items:

| Item | Shape |
| --- | --- |
| `struct Name` | Derefs to `ServletRuntime<P>` |
| `Name::start(trace, config)` | The inherent start, with no `Servlet` import at the call site |
| `Name::stop(self)` and `Name::join(self)` | The by-value stop and join that `Deref` cannot forward |
| `impl Servlet<Input, Env> for Name` | The lifecycle trait: `start`, `addr`, `stop`, and `join` |
| `impl ServletBox for Name` | The erased form that a hive registers |

### `ServletConfig` builder

`ServletConfig::<P, Input>::builder()` starts a builder in `NoAcceptState`. The accept state decides which methods exist:

| State | Entered by | `build` | `with_mux_offer` |
| --- | --- | --- | --- |
| `NoAcceptState` | `ServletConfig::builder()` | No | No |
| `Cleartext` | `allow_cleartext()` | Yes | No |
| `WithCertificate` | `with_certificate(certificate, key, validators)` or `with_identity(identity, validators)` | Yes | Yes |

- `with_certificate` binds the certificate to its key under the reference provider. It fails with a `TightBeamError` when the certificate or the key does not decode, or when the key differs from the certificate's public key.
- `with_identity` takes a `SigningIdentity` of any signing provider.
- A non-empty `validators` turns on mutual authentication, and every validator must accept the client certificate. An empty one turns client authentication off.
- `allow_cleartext` sends frames in the clear and accepts every client. It names no signer, so the servlet's hive gives it no route.
- `ServletConfig::cleartext()` builds the cleartext state over `Env::default()`.

These methods exist in every state:

| Method | Effect | Default |
| --- | --- | --- |
| `with_config(Arc<Env>)` | Sets the env, and with it the env type the handlers read | `()` |
| `with_clock(Arc<dyn Clock>)` | Sets the clock the accept loop paces its retries on | `SystemClock` |
| `with_worker(worker)` | Registers the worker under its type. A second worker of one type replaces the first | None |
| `with_collector_gate(gate)` | Appends a `GatePolicy` that runs before the handler | None |
| `with_hive_context(ctx)` | Attaches the hive context for intra-hive calls | None |
| `with_message_decryptor(decryptor)` | Enables typed delivery of encrypted bodies | None |
| `with_message_inflator(inflator)` | Enables typed delivery of compressed bodies | None |
| `with_utilization(Arc<G>)` | Installs the load gauge that the hive reads when it scales | None |

### `ServletContext`

| Method | Returns |
| --- | --- |
| `trace()` | The trace the servlet records into at the call. `ServletRuntime::set_trace` replaces it on a live servlet |
| `env_config()` | The env as `&Env` |
| `hive_context()` | The intra-hive handle, when the servlet runs in a hive |
| `worker::<W>()` | The worker of type `W`, when the servlet holds one |
| `relay::<W>(Arc<W::Input>)` | The worker's output, or the errors of [Relay errors](#relay-errors) |

### `ServletRuntime`

| Method | Effect |
| --- | --- |
| `start(trace, config, service)` | Binds the protocol's default address, starts the workers, and spawns the accept loop |
| `addr()` and `addr_bytes()` | The bound address, as the protocol address and as shared bytes |
| `set_trace(trace)` | Replaces the trace of the live servlet |
| `stop(self)` | Aborts the accept loop, and the workers end by abort |
| `join(self)` | Waits for the accept loop to end |
| `drain(self)` | Ends the accept loop, then kills each worker, so each worker answers every message its queue holds |

`start` fails with `TightBeamError::TransportError` when the protocol forms no default bind address or the listener fails to bind, and with the worker's error when a worker fails to start.

### Macro-free servlet

1. Build the handlers with `ServletHandlers::default()` and `on_unary`, `on_streaming`, `on_duplex`, or `on_typed_unary`. A type can implement `ServletService` instead, whose three methods each refuse with `Unimplemented` by default.
2. Pass the config and the handlers to `ServletRuntime::start`. The handlers' `Env` must equal the config's `Env`, so a handler that names another env fails to compile.
3. A call site bounded on `Servlet<I, Env>` passes a `RuntimeServletConf { config, service }`.

`Frame::prepare_typed` decrypts or inflates a body in place. `Frame::dispatch_typed_unary` and the typed arm of `servlet!` first hold the Frame, as it arrived, to the requirements of the message type through `Frame::validate_for`, and then run `Frame::prepare_typed` before the decode. A body with no matching transform fails closed with `RouterError::ConfidentialFrame` or `RouterError::CompressedFrame`.

This servlet echoes each `TestMessage` it receives:

```rust,no_run
use std::sync::Arc;

use tightbeam::colony::servlet::{ServletConfig, ServletHandlers, ServletRuntime};
use tightbeam::testing::TestMessage;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::TokioListener;
use tightbeam::TightBeamError;

# async fn start_echo() -> Result<(), TightBeamError> {
let handlers = ServletHandlers::<()>::default().on_typed_unary(|message: TestMessage, frame, _ctx| async move {
	let reply = tightbeam::compose! { V0: id: frame.metadata().id(), message: message }?;
	Ok(Some(reply))
});

let config = ServletConfig::<TokioListener, TestMessage>::cleartext();
let servlet = ServletRuntime::<TokioListener>::start(Arc::new(TraceCollector::new()), config, handlers).await?;
servlet.stop();
# Ok(())
# }
```

### Servlet scenarios

`environment Servlet` takes these keys:

| Key | Closure | Parameter |
| --- | --- | --- |
| `context` | None, an expression evaluated once | Shared as `Arc<C>` with each closure, `Arc<()>` when omitted |
| `start` | Async, returns the started servlet | `SetupEnv { trace, context }` |
| `setup` | Async and optional, returns a connected client. Without it, a plain `TokioListener` client connects | `ClientEnv { trace, context, addr }` |
| `client` | Async, sends requests and asserts each response | `ServletEnv { trace, context, client }` |

## Hives

A hive registers servlets, scales each servlet type, and serves a control plane for its cluster. [README §9.3.3](../README.md#933-i-hives) states its operating modes and its resilience rules.

### The `hive!` macro

`hive! { pub Name, protocol: P }` names `pub type Name = HiveRuntime<P>`, and the form without `pub` names a private alias.

`HiveRuntime<P, R = HashMapRegistry>` has two constructors:

- `HiveRuntime::new(config)` takes an `Option<HiveConfig>`, where `None` takes `HiveConfig::default()`, and builds the default registry.
- `HiveRuntime::with_registry(config, registry)` takes a `ServletRegistry` of the caller's.

Both fail with `HiveError::OccupiedRegistry` when the registry already holds a registration.

### The `Hive` trait

| Method | Contract |
| --- | --- |
| `register(servlet_type, servlet, spawner)` | Registers a started servlet under its type URN, with the spawner that auto-scaling calls. Registration closes at `establish` |
| `establish(trace)` | Starts the auto-scaling task and, for a hive with `hive_tls`, the control server and the re-registration beat |
| `context()` | The shared `HiveContext` for intra-hive calls: `call`, `open_stream`, and `open_duplex` |
| `addr()` | The control address a cluster dials, `None` before `establish` and for a hive with no `hive_tls` |
| `connection_trace()` | The trace that records each connection of the control plane |
| `servlet_addresses()` | Each registered servlet as a pair of type URN and address bytes |
| `register_with_cluster(addr)` | Sends a `RegisterHiveRequest` with the servlet slate to a gateway |
| `drain()` | Drains the commands in flight, then the servlets, within the drain timeout |
| `is_draining()` | Whether the drain began |
| `stop(self)` | Stops the hive, its control server, its scaling task, its connections, and every servlet |
| `join(self)` | Waits for the control server to end |

These errors come from the trait:

| Error | Raised by |
| --- | --- |
| `TightBeamError::AlreadyEstablished` | `register` or `establish` on an established hive |
| `TightBeamError::UrnValidationError` | `register` with a type outside the hive's namespace, a type that names an instance, or an address that is not UTF-8 |
| `TightBeamError::WorkRefused` | `register` on a type at its instance bound (`ResourceExhausted`) or on a draining hive (`Unavailable`). The servlet stops |
| `TightBeamError::NotEstablished` | `register_with_cluster` on a hive with no control address |
| `TightBeamError::MissingResponse` | `register_with_cluster` when the gateway answers with no frame |

A drain takes five steps:

1. The hive refuses every later command but the heartbeat, and stops its background beats.
2. It waits until no command is in flight, or until the drain timeout passes.
3. Each servlet drains through `ServletBox::drain_boxed` within what remains of the timeout.
4. A servlet that still drains when the timeout passes drops unfinished.
5. The hive announces its empty slate, so gateways retire its routes, and records each gateway's answer as `HIVE_REREGISTERED`.

### `HiveConfig`

| Field | Type | Default | Role |
| --- | --- | --- | --- |
| `namespace` | `ColonyNamespace` | `ColonyNamespace::default()` | The scope that `register` validates each type URN against |
| `scaling` | `HiveScalingConfig` | [Scaling](#scaling) | The auto-scale cadence and the per-type bounds |
| `control` | `HiveControlConfig` | [`HiveControlConfig`](#hivecontrolconfig) | Admission, drain, and re-registration |
| `pool` | `PoolConfig` | 8 connections, a 30 s idle timeout, no mux offer | The pool of the hive's calls to its servlets, and the mux offer of the control server |
| `trust_store` | `Option<Arc<dyn CertificateTrust>>` | `None` | Authenticates cluster commands and the servlets the hive dials. With `None`, the hive rejects every cluster command |
| `hive_tls` | `Option<Arc<HiveTlsConfig>>` | `None` | The identity the hive signs with and serves its control plane under. With `None`, the hive binds no control plane |
| `clock` | `Arc<dyn Clock>` | `SystemClock` | Every freshness, cooldown, drain, scaling, and retry decision of the hive |

A pool connection multiplexes only when the servlet also advertises through `ServletConfigBuilder::with_mux_offer`.

### `HiveControlConfig`

| Field | Type | Default | Role |
| --- | --- | --- | --- |
| `backpressure_threshold` | `BasisPoints` | 9000 (90%) | The utilization that trips backpressure on the manage path |
| `drain_timeout` | `Duration` | 30 s | The bound of the two waits of a drain |
| `reregister_interval` | `Option<Duration>` | 5 s | The beat that re-announces the signed servlet slate to each gateway. `None` turns it off |
| `circuit_breaker_threshold` | `u8` | 3 | The consecutive authentication failures of one signer that open its circuit |
| `circuit_breaker_cooldown` | `Duration` | 30 s | The time an open circuit refuses the signer |
| `command_freshness_window` | `Duration` | 30 s | The window around the hive clock that a command's issue time must fall inside |
| `notify_retry` | `Arc<dyn CoreRetryPolicy>` | Exponential backoff: 3 attempts, a 500 ms base delay, decorrelated jitter | The retry of the scaling updates the hive fans out to gateways |

### Scaling

`HiveScalingConfig` holds three fields:

| Field | Default | Role |
| --- | --- | --- |
| `default_scale` | `ServletScaleConfig::DEFAULT` | The bounds of a type with no override |
| `overrides` | Empty | The bounds of each type, keyed by its type URN |
| `cooldown` | 5 s | The least wait between two scaling cycles |

`ServletScaleConfig::new(min, max, scale_up, scale_down)` checks its two pairs:

| `ScaleConfigRefusal` | Cause |
| --- | --- |
| `InstanceBounds` | `min` is 0, or `min` exceeds `max` |
| `OverlappingThresholds` | `scale_down` is not below `scale_up` |

`ServletScaleConfig::DEFAULT` holds 1 to 10 instances, scales up above 8000 basis points, and scales down below 2000. Each config waits 30 s after a scale-up and 60 s after a scale-down, and `with_cooldowns(ScaleCooldowns { after_scale_up, after_scale_down })` replaces the two waits.

This override scales the `ping` type between 2 and 4 instances:

```rust
use core::time::Duration;

use tightbeam::colony::hive::{HiveConfig, ScaleCooldowns, ServletScaleConfig};
use tightbeam::colony::urn::ColonyNamespace;

let ping = ColonyNamespace::default().servlet("ping")?;
let bounds = ServletScaleConfig::new(2, 4, tightbeam::bps!(7000), tightbeam::bps!(3000))?;
let cooldowns = ScaleCooldowns { after_scale_up: Duration::from_secs(10), after_scale_down: Duration::from_secs(120) };

let mut hive_conf = HiveConfig::default();
hive_conf.scaling.overrides.insert(ping, bounds.with_cooldowns(cooldowns));
# Ok::<(), Box<dyn core::error::Error>>(())
```

### `HiveTlsConfig`

- `HiveTlsConfig::new(certificate, key, authentication)` decodes the certificate, binds it to its key, and installs the identity under `KeyPurposes::HOUSE`.
- `HiveTlsConfig::from_identity(identity, authentication, key_purposes)` takes an identity and its key purposes. The certificate MUST name the signer purpose or `anyExtendedKeyUsage`, or carry no `extendedKeyUsage` (RFC 5280 §4.2.1.12).
- `client_authentication` is the `PeerAuthentication` of the control plane. A hive with a `trust_store` adds the store to it, so the control plane then demands a client certificate.

### Control-plane gates

The hive builds its control-plane gates from `HiveConfig`:

| Gate | Rule |
| --- | --- |
| `ClusterSecurityGate` | Verifies each command against the trust store, under the `GateLimits` that `control` names |
| `ReplayGuard` | Records each signature per signer, for as long as its frame is fresh (CWE-294), and refuses a second frame of one signer at a recorded `order` (README §5.7.1) |
| `ClusterCircuitBreaker` | Keeps one circuit per signer, keyed on the handshake-proven peer. Only the failures of a known signer count (CWE-645) |
| `BackpressureGate` | Refuses manage commands at or over `backpressure_threshold` |

The hive reads a command through `Frame::decode_message`, so a frame that fails a requirement of `ClusterCommand`, such as its frame integrity, carries no command. The gateway reads each colony protocol type through the same call ([security.md](security.md#enforcement)).

### Hive scenarios

`environment Hive` takes these keys:

| Key | Closure | Parameter |
| --- | --- | --- |
| `context` | None, an expression evaluated once | Shared as `Arc<C>` with each closure, `Arc<()>` when omitted |
| `start` | Async, returns the established hive | `SetupEnv { trace, context }` |
| `client` | Async, owns the hive, asserts behavior, and stops it | `HiveEnv { trace, context, hive }` |

## Clusters

A cluster gateway routes work to hives and federates with peer gateways. [README §9.3.4](../README.md#934-c-clusters) states its planes, its federation rules, and its export boundary.

### The `cluster!` macro

`cluster! { pub Name, protocol: P }` names `pub type Name = ClusterGateway<P>`. `cluster! { pub Name, protocol: P, edge: E }` adds the edge protocol `E`, which defaults to `P`. The edge plane binds only when `edge_bind_addr` is set, and it admits `Work` frames alone.

The gateway digests under `<P as Protocol>::CryptoProvider`.

### The `Cluster` trait

| Method | Contract |
| --- | --- |
| `start(trace, config)` | Binds the accept planes, spawns the accept and background loops, and returns the gateway |
| `addr()` | The address the gateway listens on |
| `available_servlets()` | The servlet types that registered local hives offer |
| `peer_servlets()` | The servlet types the peer routes reach |
| `peer_routes()` | Each learned peer route, with its dial address and peer identity |
| `hive_count()` | The number of registered hives |
| `trace()` | The trace that files the gateway's audit records |
| `connection_trace()` | The trace of each connection of the colony and edge planes |
| `stop(self)` | Aborts the accept and background tasks |
| `join(self)` | Waits for the accept loops to end |

`start` fails with `TightBeamError::TransportError` when a plane fails to bind. It fails with `TightBeamError::ClusterError` in three cases:

- `bind_addr` or `edge_bind_addr` does not parse (`ClusterError::InvalidAddress`).
- The gossip ingress is no bare servlet type of `namespace`, as `ClusterConfig::gossip_ingress_key` decides (`ClusterError::UnknownServletType`).
- A federating gateway binds a wildcard address with no advertise address (`ClusterError::AdvertiseAddressRequired`).

The registry reads fail with `ClusterError::LockPoisoned`. A poisoned lock also ends the background loop that reads it, which traces `CLUSTER_LOOP_POISONED`.

`ClusterHeartbeat` extends `Cluster` with `registry()`, `heartbeat_config()`, and `send_heartbeat(addr)`, so a work-only consumer needs the work surface alone.

### `ClusterTlsConfig`

| Item | Role | Default |
| --- | --- | --- |
| `new(certificate, key)` | Decodes the certificate and binds it to its key under `KeyPurposes::HOUSE` | |
| `from_identity(identity, key_purposes)` | Serves every plane under `identity`. The certificate MUST name the signer purpose or `anyExtendedKeyUsage`, or carry no `extendedKeyUsage` (RFC 5280 §4.2.1.12) | |
| `validators`, `with_validators` | The server policy of each outbound dial on both planes | Empty |
| `client_authentication`, `with_client_authentication` | How the accept planes authenticate their clients | `PeerAuthentication::Anonymous` |
| `hive_trust`, `with_hive_trust` | Validates each hive and servlet dial, verifies hive control frames, and marks a first-party caller | `None` |
| `peer_trust`, `with_peer_trust` | Verifies peer advertisements and relayed gossip. It wins over `hive_trust`, so a key in both stays a peer | `None` |

### Resource URNs

`ColonyNamespace` mints and validates every resource URN of a deployment, in the grammar `urn:{nid}:{realm}:{resource-type}:{resource-id}`.

- `validate` refuses a URN that carries an r-, q-, or f-component with `UrnValidationError::ForbiddenFieldPresent`, because the grammar defines none.
- The NID compares in any case. The realm compares octet by octet, with the hex digits of each percent-encoded triplet in any case (RFC 8141 §3.1).
- Each registry and route key is `Urn::canonical_bytes`: `urn:`, the NID in lower case, `:`, and the NSS with the hex digits of each triplet in upper case. Two URN-equivalent names key one resource.
- A hive address and a servlet instance locator are NSS text, with each byte outside the NSS production percent-encoded. `ColonyResource` carries each as an `NssText`, and `NssText::decoded` gives the address.

### `ClusterConfig`

`ClusterConfig::builder(tls)` starts the builder, and `ClusterConfig::new(tls)` builds it with every default. `build` derives colony membership from the URN in the certificate's URI SAN (RFC 5280 §4.2.1.6), which `ClusterConfig::colony_urn()` reads.

| Setting | Builder method | Default |
| --- | --- | --- |
| Resource URN namespace | `with_namespace` | `ColonyNamespace::default()` |
| Gateway bind address | `with_bind_addr` | `None`, the protocol default |
| Edge bind address | `with_edge_bind_addr` | `None`, no edge plane |
| Freshness window for hive control frames | `with_control_freshness_window` | 30 s |
| Load balancer | `with_load_balancer` | `StochasticForager` |
| Heartbeats | `with_heartbeat_config` | `HeartbeatConfig::default()` |
| Pheromone trails | `with_pheromone_config` | `PheromoneConfig::default()` |
| Gate policies | `with_gate_policy` | None |
| Exported types | `with_exported_types`, `with_export_allowlist` | Every type |
| Export grants and gates | `with_export_grant`, `with_export_gate` | None |
| Connection pools | `with_pool_config` | `PoolConfig::default()` |
| Peer plane, whole | `with_peer_config` | `PeerConfig::default()` |
| Peer dial list | `with_peers` | Empty |
| Advertise beat | `with_advertise_interval` | Off |
| Advertised address | `with_advertise_addr` | The bound address |
| Claimed-address allowlist | `with_peer_dial_allowlist` | None |
| Hop budget | `with_max_hops` | 1 |
| Advertisement rumor refresh | `with_rumor_refresh` | 30 s |
| Learned-peer store | `with_peer_store` | `MemoryPeerStore` |
| Tried entries per signer certificate | `with_tried_per_signer` | No cap |
| Gossip | `with_gossip_config`, `with_gossip_admission`, `with_gossip_ingress` | `GossipConfig::default()` |
| Clock | `with_clock` | `SystemClock` |

Four methods check their input:

- `with_peers`, `with_advertise_addr`, and `with_peer_dial_allowlist` fail with `ClusterError::InvalidPeerAddress` on an entry that names no socket.
- `with_gossip_ingress` fails with `ClusterError::UnknownServletType` on a URN that is no bare servlet type of the namespace it names. `GossipConfig::ingress` holds the URN. `ClusterConfig::gossip_ingress_key` mints its route key under `namespace`, and `start` mints it there once and refuses an ingress outside the gateway's `namespace`, so `with_namespace` and `with_gossip_ingress` take effect in either call order.

`with_peer_config` replaces the peer section, and `with_gossip_config` replaces the gossip section. A method that sets one field of a section wins over the section in either call order: `build` applies the section first and each field method after it, in call order.

### Peer federation

`PeerConfig` holds the peer plane:

| Field | Role |
| --- | --- |
| `advertise_interval` | The cadence of the advertise beat, or no beat for `None` |
| `max_hops` | The cap on the relay budget of inbound work and routed stream opens. `0` turns forwarding off, and `2` turns on relay-trail fallback |
| `exported_types` | The `ExportAllowlist` of both planes of the export boundary, or every local type for `None` |

The dial list, the advertised address, the dial allowlist, the discovery table, the per-signer cap, and the rumor refresh are private, and their builder methods set them. A relay trail lives for three rumor refresh intervals with no refresh, and never less than 30 s.

`PeerConfig::admit_dial` decides each address a peer claims, and only the `AdmittedDial` it returns reaches a dial (CWE-918):

| `DialRefusal` | Address |
| --- | --- |
| `Unspecified` | `0.0.0.0` or `[::]` |
| `NotUnicast` | A multicast, broadcast, or reserved address, or one in `0.0.0.0/8` |
| `OffAllowlist` | An address the allowlist omits, when the allowlist is set |

### Export boundary

| Type | Role |
| --- | --- |
| `ExportAllowlist` | The trait of the export list: `contains(target)` and `allows_canonical(key)` |
| `StaticExportList` | The fixed list that `with_exported_types` installs |
| `DynamicExportList` | A list that `set`, `insert`, and `remove` change while the gateway runs |
| `ExportGrant` | `grants(target, session, relayed)` widens the boundary for selected callers |
| `ExportGate` | `evaluate(target, session, planes, relayed)` narrows it, and every gate must pass |
| `TrustPlanes` | The two trust stores as one classifier. `classify_session` answers a `Party`: `FirstParty`, `Peer`, or `Untrusted` |

### Heartbeats

| `HeartbeatConfig` field | Builder method | Default |
| --- | --- | --- |
| `interval` | `with_interval` | 5 s |
| `timeout` | `with_timeout` | 15 s |
| `max_concurrent` | `with_max_concurrent` | 10, a `NonZeroUsize`, so each cycle dials every hive in turn (CWE-835) |
| `max_failures` | `with_max_failures` | 3 |
| `on_heartbeat` | `with_callback` | `None` |

`HeartbeatCallback` is `Arc<dyn Fn(HeartbeatEvent) + Send + Sync>`, because concurrent tasks call it. A `HeartbeatEvent` carries three fields:

- `hive_addr`: the control address the heartbeat dialed.
- `success`: whether the hive answered within policy.
- `utilization`: the load the hive reported, when it answered with a heartbeat result.

### Load balancers

`LoadBalancer::select(candidates)` picks an index into a slice of `InstanceMetrics`, or `None` for an empty slice. The gateway guards the index, because an operator's balancer is untrusted.

| Balancer | Pick |
| --- | --- |
| `StochasticForager` | In proportion to each route's pheromone, the default |
| `PowerOfTwoChoices` | The stronger trail of two distinct random routes |
| `RoundRobin` | Each route in order, with no regard to pheromone |

| `PheromoneConfig` field | Default | Role |
| --- | --- | --- |
| `evaporation_rate` | 1000 basis points (10%) | The decay of each evaporation cycle |
| `evaporation_interval` | 30 s | The time between evaporation cycles |
| `initial_pheromone` | 5000 | The level of a new route |
| `abandonment_limit` | 5 | The consecutive failures that abandon a route |
| `reinforcement_boost` | 500 | The gain of a successful request |
| `weakening_penalty` | 0 | The loss of a failed request. At 0, a failure counts toward `abandonment_limit` alone |

### Gossip

| `GossipConfig` field | Default | Role |
| --- | --- | --- |
| `seen_ttl` | 120 s | The freshness window of a rumor's issue time, to each side of the clock. Startup clamps it to the journal's retention (CWE-294) |
| `ttl` | 8 | The hop radius of an origin publish, clamped to `MAX_GOSSIP_TTL` (8) |
| `ingress` | `None` | The servlet type that receives admitted rumors. `None` only journals and refloods |
| `journal` | `MemoryGossipJournal`, 120 s retention | Deduplicates and retains rumors |
| `admission` | `TokenBucketAdmission`, a burst of 128 and one token back per 250 ms | The per-signer rate admission before record and reflood |

### Work submission

`SubmitWork::submit_work_to(servlet_type, work)` nests the complete `work` frame in a hop-local `ClusterWorkRequest` and returns the servlet's complete reply frame. `GenericClient` and `PooledClient` implement it. A refusal is `TightBeamError::WorkRefused` with the gateway's `TransitStatus`. Verify the reply with `Frame::verify` before you read its message.

### Cluster scenarios

`environment Cluster` takes these keys:

| Key | Closure | Parameter |
| --- | --- | --- |
| `context` | None, an expression evaluated once | Shared as `Arc<C>` with each closure |
| `start` | Async, returns the gateway or a peered topology | `SetupEnv { trace, context }` |
| `hives` | Optional, returns hive futures. The scenario awaits each one and registers it with the gateway | `SetupEnv { trace, context }` |
| `client` | Async, owns the cluster, asserts behavior, and stops it | `ClusterEnv { trace, context, cluster }` |

### Manual clock

`ManualClock` (`tightbeam::clock`, feature `testing`) moves only when `advance(span)` moves it, and an advance wakes each sleep it ends. Each part that reads time takes the clock through its own setter:

| Part | Setter |
| --- | --- |
| Gateway | `ClusterConfigBuilder::with_clock`, or the `ClusterConfig::clock` field |
| Hive | The `HiveConfig::clock` field |
| Servlet | `ServletConfigBuilder::with_clock` |
| Connection pool | `ConnectionPoolBuilder::new(config, clock)` or `ConnectionPoolBuilder::with_clock` |
| Trace collector | `TraceCollector::with_clock`, feature `instrument` |

The work of a woken beat runs on its own task. `TraceCollector::recorded(label)` counts the events of a label, so a scenario polls it for the event it expects.

One manual clock drives a gateway, a hive, a servlet, and a trace:

```rust
use core::time::Duration;
use std::sync::Arc;

use tightbeam::clock::{Clock, ManualClock};
use tightbeam::colony::cluster::{ClusterConfig, ClusterTlsConfig};
use tightbeam::colony::hive::HiveConfig;
use tightbeam::colony::servlet::ServletConfig;
use tightbeam::crypto::key::Secp256k1KeyProvider;
use tightbeam::crypto::x509::CertificateSpec;
use tightbeam::testing::{TestCertificate, TestKey, TestMessage};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::TokioListener;

let clock = Arc::new(ManualClock::default());
let shared: Arc<dyn Clock> = Arc::clone(&clock) as Arc<dyn Clock>;

let key = TestKey::insecure_fixed_signing();
let certificate = CertificateSpec::Built(Box::new(TestCertificate::self_signed(&key)));
let tls = ClusterTlsConfig::new(certificate, Arc::new(Secp256k1KeyProvider::from(key)))?;

let gateway_conf = ClusterConfig::builder(tls).with_clock(Arc::clone(&shared)).build();
let hive_conf = HiveConfig { clock: Arc::clone(&shared), ..HiveConfig::default() };
let servlet_builder = ServletConfig::<TokioListener, TestMessage>::builder().with_clock(Arc::clone(&shared));
let servlet_conf = servlet_builder.allow_cleartext().build();
let trace = TraceCollector::new().with_clock(shared);

clock.advance(Duration::from_secs(5));
# drop((gateway_conf, hive_conf, servlet_conf, trace));
# Ok::<(), tightbeam::TightBeamError>(())
```

## Sources

- RFC 5280, "Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile," §4.2.1.6 and §4.2.1.12. [rfc-editor.org/rfc/rfc5280](https://www.rfc-editor.org/rfc/rfc5280)
- RFC 8141, "Uniform Resource Names (URNs)," §2 and §3.1. [rfc-editor.org/rfc/rfc8141](https://www.rfc-editor.org/rfc/rfc8141)
- CWE-294, "Authentication Bypass by Capture-replay." [cwe.mitre.org/data/definitions/294.html](https://cwe.mitre.org/data/definitions/294.html)
- CWE-645, "Overly Restrictive Account Lockout Mechanism." [cwe.mitre.org/data/definitions/645.html](https://cwe.mitre.org/data/definitions/645.html)
- CWE-835, "Loop with Unreachable Exit Condition ('Infinite Loop')." [cwe.mitre.org/data/definitions/835.html](https://cwe.mitre.org/data/definitions/835.html)
- CWE-918, "Server-Side Request Forgery (SSRF)." [cwe.mitre.org/data/definitions/918.html](https://cwe.mitre.org/data/definitions/918.html)
