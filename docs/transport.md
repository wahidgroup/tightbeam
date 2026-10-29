# The TightBeam Transport

This page specifies the types that carry TightBeam frames between endpoints:

- the traits a byte protocol implements
- the wire envelopes, their size ceilings, and their record limits
- the TCP transport and the `server!` accept loop
- the gate, receptor, and restart policies
- the multiplexed plane, its budgets, and its receipts
- the connection pool
- the audit trail

It drills down from [README §8](../README.md#8-transport-layer) for engineers who build on the transport or review it. The README holds what each part is for and the standards it follows. The handshake has its own page, [The TightBeam Handshake](handshake.md).

## Contents

- [Transport traits](#transport-traits)
- [Wire envelopes](#wire-envelopes)
- [TCP transport](#tcp-transport)
- [Transport policies](#transport-policies)
- [Multiplexing](#multiplexing)
- [Connection pooling](#connection-pooling)
- [Audit trail](#audit-trail)
- [Sources](#sources)

## Transport traits

Each role of [README §8.1](../README.md#81-transport-architecture) is one trait of `tightbeam::transport`, and another crate implements it to bring its own byte protocol:

| Role                       | Trait                                       | Items an implementation supplies                                                                                                                                 |
| -------------------------- | ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Connection setup           | `Protocol`                                  | The types `Listener`, `Stream`, `Transport`, `Error`, `Address`, and `CryptoProvider`, and `default_bind_address`, `bind_cleartext`, `connect`, and `create_transport` |
| Encrypted connection setup | `EncryptedProtocol: Protocol`               | The types `Encryptor` and `Decryptor`, and `bind_with(addr, TransportEncryptionConfig)`                                                                           |
| Envelope I/O               | `MessageIO`                                 | `clock`, `read_envelope_bytes`, and `write_envelope_bytes`                                                                                                       |
| Encrypted envelope I/O     | `EncryptedMessageIO: MessageIO`             | Defaults alone: `collect_step`, the client and server handshake drivers, and the seal and open of each envelope                                                  |
| Receive path               | `MessageCollector: MessageIO + GateAudit`   | The type `CollectorGate`, `collector_gate`, and `send_response`                                                                                                  |
| Send path                  | `MessageEmitter: MessageIO`                 | The types `EmitterGate` and `RestartPolicy`, their two accessors, and `perform_send_receive`                                                                      |

The provided methods carry the shared behavior:

- `Protocol::connect_within(addr, budget)` calls `connect`. A protocol whose connect blocks its thread MUST override it and bound the connect itself.
- `MessageCollector::collect_message` reads one envelope, evaluates the collector gate, and returns the frame with its `TransitStatus`. `try_collect_message` returns `Ok(None)` at EOF.
- `MessageEmitter::emit(frame, attempt)` evaluates the emitter gate, sends, and retries as the restart policy answers.
- `Transport` names `MessageEmitter + MessageCollector`, and every type that implements both implements it.

A split connection reads and writes through two halves. `EnvelopeSource::read_envelope` and `EnvelopeSink::write_envelope` are the traits the multiplexed drivers take, and `TcpTransport::into_split` yields the TCP halves, `TransportReader` and `TransportWriter`.

Four traits attach policies to a transport, one per kind: `RestartConfig::with_restart`, `EmitterGateConfig::with_emitter_gate`, `CollectorGateConfig::with_collector_gate`, and `TimeoutConfig::with_timeout`. `PolicyConfig` names all four.

### Endpoint configuration

Every transport constructor takes one `EndpointConfig<P>`: the provisioning, the negotiation input, the limits, and the clock. Each handshake of the transport reads the validity period of a peer certificate on that clock.

| Type                           | Constructor                                     | Setters                                                                    |
| ------------------------------ | ----------------------------------------------- | -------------------------------------------------------------------------- |
| `EndpointConfig<P>`            | `new(encryption, clock)`, and `cleartext()`     | `with_limits`, `with_clock`, and `with_trace` under `instrument`           |
| `TransportEncryptionConfig<P>` | `new(identity)`, which takes a `SigningIdentity` | `with_client_validators`, `with_peer_authentication`, `with_key_purposes`, `with_limits`, and `with_key_agreement` for a CMS server |

`DialableEncryption::new` turns a configuration into provisioning, and it is the one place that applies the dialer rule. A client with no trust in a server and no call to `allow_cleartext` fails there with `TransportError::PeerAuthenticationUnconfigured`, before it opens a socket.

## Wire envelopes

[README §8.2](../README.md#82-wire-format) names the two envelope layers. Both are DER types of `tightbeam::transport::envelopes`.

`WireEnvelope` is a CHOICE with an explicit tag on each arm:

| Arm                                 | Tag   | Carries                                                                     |
| ----------------------------------- | ----- | --------------------------------------------------------------------------- |
| `Cleartext(TransportEnvelope)`      | `[0]` | A handshake container, or every envelope of a cleartext endpoint            |
| `Encrypted(AuthEnvelopedData)`      | `[1]` | One record, sealed as [The TightBeam Handshake](handshake.md#records) states |

`TransportEnvelope` is a CHOICE of context-specific tags:

| Variant                     | Tag   | Carries                                                         |
| --------------------------- | ----- | --------------------------------------------------------------- |
| `Request(RequestPackage)`   | `[0]` | A single-flight request frame                                   |
| `Response(ResponsePackage)` | `[1]` | The status and the optional frame of a single-flight response   |
| `SignedData`                | `[3]` | A signed handshake container, with the bytes that carried it    |
| `Mux(MuxEnvelope)`          | `[4]` | A multiplexing message, under `transport-multiplex`             |
| `AuthEnvelopedData`         | `[7]` | A sealed handshake container, with the bytes that carried it    |
| `Data`                      | `[8]` | The HPKE hello, a `ContentInfo` of type `id-data`               |

Tags 2, 5, and 6 stay reserved, so an archived capture keeps its meaning. `RequestPackage::new(frame)` and `ResponsePackage::new(status, frame)` build the two packages, and each holds its frame behind an `Arc`.

### Size ceilings

`TransportLimits` holds every ceiling of one endpoint. Each field is a plain value, and `Default` chooses them all:

| Field               | Default                                   | Bounds                                          |
| ------------------- | ----------------------------------------- | ----------------------------------------------- |
| `cleartext_envelope`| 128 KiB, `DEFAULT_MAX_CLEARTEXT_ENVELOPE` | A cleartext wire envelope                       |
| `encrypted_envelope`| 256 KiB, `DEFAULT_MAX_ENCRYPTED_ENVELOPE` | An encrypted wire envelope                      |
| `handshake_wire`    | 16 KiB, `DEFAULT_HANDSHAKE_MAX_WIRE`      | One handshake message                           |
| `operation_timeout` | 30 s, `DEFAULT_OPERATION_TIMEOUT`         | A dial, and one read or write                   |
| `handshake_timeout` | 10 s, `DEFAULT_HANDSHAKE_TIMEOUT`         | The whole handshake exchange                    |

A reader admits `max_envelope()`, the larger of the two envelope ceilings, before the parse, and it checks the ceiling of the arm after it. An envelope past the ceiling of its mode fails with `OperationFailed(SizeExceeded)`. A handshake message whose transport envelope passes `handshake_wire` fails with `InvalidMessage` before the write, and a handshaking reader caps the same envelope.

`TransportEncryptionConfig::with_limits` and `EndpointConfig::with_limits` replace the ceilings once `TransportLimits::checked` admits them. The check returns a `CheckedLimits`, the form that both configurations, every transport, and `EnvelopeBuilder::with_limits` hold, so a set whose ceilings disagree reaches no transport. It fails with `TransportError::InvalidLimits`, and its `LimitsRefusal` names the rule that the set breaks:

| Refusal                  | Set                                                                                    |
| ------------------------ | -------------------------------------------------------------------------------------- |
| `ZeroCeiling`            | A ceiling or a deadline is zero, so it refuses everything it bounds                    |
| `HandshakePastCleartext` | A handshake message of `handshake_wire` octets passes `cleartext_envelope` on the wire |

```rust
use core::time::Duration;

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::testing::TestIdentity;
use tightbeam::transport::{TransportEncryptionConfig, TransportLimits};

// A server that admits a handshake message of 8 KiB at most, and gives each
// handshake 5 seconds.
let limits = TransportLimits {
    handshake_wire: 8 * 1024,
    handshake_timeout: Duration::from_secs(5),
    ..TransportLimits::default()
};
let identity = TestIdentity::insecure_fixed();
let config = TransportEncryptionConfig::<DefaultCryptoProvider>::new(identity).with_limits(limits)?;
# drop(config);
# Ok::<(), Box<dyn std::error::Error>>(())
```

A client or a pool takes its `with_timeout` value through the same check before it dials.

### Record limits

Each directional key of a session has a record limit ([The TightBeam Handshake](handshake.md#records)). The sender and the receiver of a key fail with two different failures, so an error tells a routine end of keys from a fault of the inbound stream:

| Failure                | Raised by    | Cause                                                    |
| ---------------------- | ------------ | -------------------------------------------------------- |
| `RekeyRequired`        | The sender   | Its send cipher is at its record limit                   |
| `RenewalBoundExceeded` | The receiver | A record arrived past a renewal bound of the receive key |

- A send at the limit fails with `MessageNotSent(frame, RekeyRequired)` before the write, and the emit returns it at once under every restart policy.
- A collect on a server whose send cipher is spent fails with `OperationFailed(RekeyRequired)` before it reads, so a request on its way reaches no handler.
- A pool discards a connection whose send cipher is spent.
- A read past a renewal bound fails with `OperationFailed(RenewalBoundExceeded)` and ends the session: a single-flight session resets, and a multiplexed connection ends.

## TCP transport

[README §8.3](../README.md#83-tcp-transport) maps a byte stream to the Frame API. The types live in `tightbeam::transport::tcp`:

| Type                         | Module      | Role                                                                                                   |
| ---------------------------- | ----------- | ------------------------------------------------------------------------------------------------------ |
| `TcpTransport<S, P>`         | `r#async`   | The async transport over a stream `S`, under the provider `P`                                          |
| `TokioListener<P>`           | `r#async`   | The tokio listener. `accept` returns a transport and the peer address                                  |
| `TokioStream`                | `r#async`   | The tokio stream, which splits into `TokioReadHalf` and `TokioWriteHalf`                               |
| `TcpListener<L, P>`          | `sync`      | The blocking listener over `std::net`: `from_listener_cleartext`, `from_listener_with`, and `accept`    |
| `TcpTransport<S, P>`         | `sync`      | The blocking transport over a `ProtocolStream`                                                         |
| `TightBeamSocketAddr`        | `tcp`       | The address, a `SocketAddr` that parses from a string                                                  |

`P` defaults to `DefaultCryptoProvider`, so `TokioListener` alone in a type position names the house provider. In an expression the compiler infers `P` from the calls, so a call names it where no other type does, such as `TransportEncryptionConfig::<DefaultCryptoProvider>::new(identity)`.

A `TcpTransport` exposes its session and its server hooks:

| Method                                    | Answers or sets                                                                    |
| ----------------------------------------- | ---------------------------------------------------------------------------------- |
| `peer_certificate`                        | The validated peer certificate of the established session                          |
| `negotiated_mux`                          | The `MuxSettings` of the session, or `None` for a single-flight session            |
| `session_receipt`                         | The dual-signed receipt of a budget-bearing session                                |
| `with_transport_authorizer`               | The server's budget-grant policy, a `TransportAuthorizer`                          |
| `with_session_observer`                   | The server's observer of receipt outcomes, a `SessionObserver`                     |
| `with_receipt_approver`                   | The client's approver of challenge-bearing receipts, a `ReceiptApprover`           |
| `with_handshake_protocol`                 | `HandshakeProtocolKind::Hpke`, the default, or `HandshakeProtocolKind::Cms`        |
| `with_mux_offer`                          | The local multiplexing offer, which the handshake binds into its transcript        |
| `into_split` and `into_mux`               | The two halves, or the multiplexed plane ([Multiplexing](#multiplexing))           |
| `with_trace` and `trace`                  | The instrumentation collector of the connection, under `instrument`                |

### The server macro

`server!` serves a listener: it accepts each connection, applies the policies, and runs the handler. The keys of an invocation:

| Key                                     | Takes                                                                                                  |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `protocol P: listener`                  | A bound listener. The loop runs on a task under `tokio`, or on a thread under `std`, and the macro returns at once |
| `protocol P: bind_cleartext addr`       | An address, which the macro binds as a cleartext listener first                                        |
| `P: listener`, with no `protocol`       | The blocking form, which runs the handler on a thread outside any runtime                              |
| `policies: { name: [expr, ..] }`        | A transport method per name, which the loop calls with each expression on every accepted connection   |
| `handle: \|frame\|` or `\|frame, session\|` | The handler closure. The two-argument form reads the `SessionContext` of its connection             |
| `service: S`                            | A `MuxService`, which answers unary, streaming, and duplex streams                                     |
| `channels: { error: tx, ok: tx }`       | The error and success notification channels                                                            |

The loop evaluates each policy expression once per connection, so an expression that shares one value clones it, as `with_trace: [trace.share()]` does. `max_connections: [n]` sets the cap of live connections instead, `DEFAULT_MAX_SERVER_CONNECTIONS` (1024) by default. A literal cap of zero fails to compile.

```rust,no_run
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::{EncryptedProtocol, TransportEncryptionConfig};
use tightbeam::{server, Frame};

/// Serve echo on a free loopback port, under `identity`, for 64 connections at most.
async fn serve(identity: SigningIdentity) -> Result<(), Box<dyn std::error::Error>> {
    let config = TransportEncryptionConfig::<DefaultCryptoProvider>::new(identity);
    let (listener, _addr) = TokioListener::bind_with("127.0.0.1:0".parse()?, config).await?;

    let accept_loop = server! {
        protocol TokioListener: listener,
        policies: { max_connections: [64] },
        handle: |frame: Frame| async move { Ok(Some(frame)) }
    };

    accept_loop.await?;
    Ok(())
}
```

## Transport policies

[README §8.4](../README.md#84-transport-policies) states what each policy decides. Every policy trait is `Send + Sync` and has one method:

| Trait                                        | Method                                                                                     |
| -------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `policy::GatePolicy`                         | `evaluate(&self, message: Option<&Frame>, session: &SessionContext) -> TransitStatus`      |
| `policy::ReceptorPolicy<T: Message>`         | `evaluate(&self, message: &T) -> TransitStatus`                                            |
| `transport::policy::RestartPolicy`           | `evaluate(&self, frame: Box<Frame>, failure: &TransportFailure, attempt: usize) -> RetryAction` |

`RetryAction` has two variants. `Retry { frame, delay }` resends `frame` once the caller has waited `delay` on the transport's clock, and `NoRetry` stops and propagates the error.

### Status codes

`TransitStatus` is a `u8` enumeration with the codes of `google.rpc.Code`:

| Code | Variant              | Meaning                                                    |
| ---- | -------------------- | ---------------------------------------------------------- |
| 0    | `Ok`                 | The request was processed                                  |
| 1    | `Cancelled`          | The caller cancelled the operation                         |
| 2    | `Unknown`            | An unclassified failure, and the `Default`                 |
| 3    | `InvalidArgument`    | The request is malformed regardless of system state        |
| 4    | `DeadlineExceeded`   | The peer gave up waiting                                   |
| 5    | `NotFound`           | The requested entity does not exist                        |
| 6    | `AlreadyExists`      | The entity the request would create already exists        |
| 7    | `PermissionDenied`   | The caller is identified and refused authorization         |
| 8    | `ResourceExhausted`  | The receiver lacks capacity, and a retry with backoff may succeed |
| 9    | `FailedPrecondition` | System state must change before a retry can succeed        |
| 10   | `Aborted`            | A concurrency conflict aborted the operation               |
| 11   | `OutOfRange`         | The request walked past the valid range of the operation   |
| 12   | `Unimplemented`      | No handler answers the requested operation                 |
| 13   | `Internal`           | The receiver hit a local fault                             |
| 14   | `Unavailable`        | The receiver is unavailable for a transient reason         |
| 15   | `DataLoss`           | The receiver hit unrecoverable data loss or corruption     |
| 16   | `Unauthenticated`    | The caller lacks valid authentication credentials          |

A gate verdict of `Unknown` is a local bug, so the transport normalizes it to `Internal` before it reaches the wire or the audit trail. `as_str` returns the name of the variant, which an audit event uses as its label.

### Session facts

`SessionContext` holds the authenticated facts of one session. The `Default` context holds none, and cleartext connections, client-side emit paths, and in-process evaluation pass it.

| Method                    | Returns                                                                                       |
| ------------------------- | --------------------------------------------------------------------------------------------- |
| `capture(&transport)`     | A snapshot of the peer and the receipt of an encrypted transport after its handshake          |
| `peer_certificate()`      | The validated peer certificate, the client identity on a mutual-auth server                   |
| `peer_key()`              | The `CanonicalKey` of the peer's key, which a peer list matches                               |
| `proven_peer()`           | A `ProvenPeer`, the one key a per-identity budget MAY count against (CWE-645)                 |
| `session_receipt()`       | The dual-signed receipt of a budget-bearing session                                           |

On the mux serving path each stream builds its context with the live receipt, so a gate sees the receipt of each rekey.

### Gates

The crate ships these gates:

| Gate                       | Module         | Verdict                                                                                                 |
| -------------------------- | -------------- | ------------------------------------------------------------------------------------------------------- |
| `AcceptAllGate`            | `policy`       | `Ok` for every frame                                                                                    |
| `GateChain`                | `policy`       | The first verdict other than `Ok`, in insertion order (`with`, `push`). An empty chain answers `Ok`     |
| `FrameIntegrityGate<D>`    | `policy`       | `Ok` for a frame whose integrity digest recomputes under `D`, and for a stream open with no frame. `PermissionDenied` otherwise |
| `GateMiddleware<G, F>`     | `policy`       | The verdict of `G`, after the closure `F` observes it. `ReceptorMiddleware` does the same for a receptor |
| `PeerListGate`             | `colony::hive` | The verdict of the list for the peer key of the session                                                 |

An `Arc<dyn GatePolicy + Send + Sync>` is a gate too, so a chain or a builder holds a shared gate.

`PeerListGate::new(mode, curves, keys)` builds a list of SPKI DER entries, each read under `KeyCurves`. `allow(keys)` and `deny(keys)` read under `KeyCurves::HOUSE`, the secp256k1 decoder. The verdict depends on the mode and on the peer:

| Mode    | Listed peer        | Unlisted peer      | No authenticated peer |
| ------- | ------------------ | ------------------ | --------------------- |
| `Allow` | `Ok`               | `PermissionDenied` | `Unauthenticated`     |
| `Deny`  | `PermissionDenied` | `Ok`               | `Ok`                  |

A list refuses to build with a `KeyListError` that names the index of the first bad entry:

| Variant     | The entry                                                                         |
| ----------- | --------------------------------------------------------------------------------- |
| `Unreadable`| Is no SubjectPublicKeyInfo DER, or its canonical form exceeds the DER length cap  |
| `NoPoint`   | Names an elliptic-curve key that reads as no point                                 |
| `NoDecoder` | Names a point on a curve that the list's `KeyCurves` holds no decoder for          |

`PublicKeyPinning::new(keys)` and `PublicKeyPinning::with_curves(curves, keys)` read their pins through the same key list, so they refuse the same entries with the same errors.

```rust
use tightbeam::policy::{AcceptAllGate, GateChain, GatePolicy, SessionContext, TransitStatus};

tightbeam::policy! {
    GatePolicy: Busy { TransitStatus::ResourceExhausted }
}

// The chain answers with the first refusal, in the order of `with`.
let chain = GateChain::default().with(AcceptAllGate).with(Busy);
assert_eq!(chain.evaluate(None, &SessionContext::default()), TransitStatus::ResourceExhausted);
```

### Restart policies

| Policy                      | Constructor                                              | Delay before attempt `n`, in milliseconds | Default                                        |
| --------------------------- | -------------------------------------------------------- | ----------------------------------------- | ---------------------------------------------- |
| `NoRestart`                 | `NoRestart`                                              | It answers `NoRetry` at once              | The policy of a new transport                  |
| `RestartLinearBackoff`      | `new(max_attempts, interval, scale_factor, jitter)`      | `scale_factor * interval * (n + 1)`       | 5 attempts, a 1 s interval, `DecorrelatedJitter` |
| `RestartExponentialBackoff` | `new(max_attempts, base_delay, jitter)`                  | `base_delay * 2^n`                        | 5 attempts, a 1 s base delay, `DecorrelatedJitter` |

- Both backoff policies answer `NoRetry` once `attempt` reaches `max_attempts`.
- `interval` and `base_delay` are each a `Duration`, and each policy reads it in whole milliseconds at each delay.
- A `JitterStrategy` maps each computed delay to the one the policy waits. `DecorrelatedJitter` draws it between a third of the delay and the delay, so peers that fail together retry apart.
- `CoreRetryPolicy` exposes `max_attempts` and `delay_ms(attempt)`, so a caller that retries its own operation reads the same schedule.

```rust
use core::time::Duration;

use tightbeam::testing::TestFrame;
use tightbeam::transport::policy::{CoreRetryPolicy, RestartLinearBackoff, RestartPolicy, RetryAction};
use tightbeam::transport::TransportFailure;

let restart = RestartLinearBackoff::new(3, Duration::from_millis(1000), 1, None);
assert_eq!(restart.delay_ms(2), 3000);

// The fourth failure meets the limit of three attempts.
let frame = Box::new(TestFrame::v0(Some("refused"), None));
assert_eq!(restart.evaluate(frame, &TransportFailure::Unavailable, 3), RetryAction::NoRetry);
```

### The policy macro

`policy!` declares one unit struct per entry, with `Default` and the trait the entry names. An optional visibility sits before the name:

| Entry                                     | Closure                                  | Implements                 |
| ----------------------------------------- | ---------------------------------------- | -------------------------- |
| `GatePolicy: vis Name`                    | `\|frame, session\|`, `\|frame\|`, or none | `GatePolicy`               |
| `ReceptorPolicy<Msg>: vis Name`           | `\|message\|`, or none                    | `ReceptorPolicy<Msg>`      |
| `RestartPolicy: vis Name`                 | `\|frame, failure, attempt\|`             | `RestartPolicy`            |

Macro hygiene hides the argument of an entry with no closure from its body, so that form serves a policy with a fixed verdict.

### Client policies

`ClientBuilder<P>` collects the policies and the trust of one client. `builder()` starts one on the system clock, and `on_clock(clock)` on another clock.

- `with_emitter_gate` and `with_collector_gate` append to a `GateChain` in call order. `with_restart` replaces the restart policy.
- `with_trust_store`, `with_cms_server`, `with_key_purposes`, `with_server_policy`, and `with_handshake_protocol` set the handshake.
- `allow_cleartext` names cleartext as the intent of a client with no trust in a server.
- `ConnectionBuilder` adds `with_timeout`, `with_client_identity`, and `build`.
- `connect(addr)` dials and returns a `GenericClient`, and `adopt(stream)` wraps a stream that the caller opened, under the same dialer rule.

`ClientPolicies` holds the same policies apart from any builder, and `ClientPolicies::apply` attaches them to a transport.

## Multiplexing

[README §8.6](../README.md#86-multiplexing) specifies the stream rules. The types live in `tightbeam::transport::multiplex`, `tightbeam::transport::handshake::negotiation`, and `tightbeam::transport::envelopes`, under the `transport-multiplex` feature.

### Offers and settings

`TransportOffer` is the client's offer and `TransportAccept` the server's answer. Each field advertises what its sender receives:

| Field                         | In                 | Meaning                                                                           |
| ----------------------------- | ------------------ | --------------------------------------------------------------------------------- |
| `mux`                         | Offer and accept   | The sender supports multiplexing                                                  |
| `max_peer_initiated_streams`  | Offer and accept   | The streams the peer MAY open toward the sender                                   |
| `chunk_payload_size`          | Offer and accept   | The largest inbound chunk payload                                                 |
| `credit_unit`                 | Offer and accept   | Bytes per budget credit. The value of the accept wins                             |
| `initial_stream_credit`       | Offer and accept   | The chunk allowance of each inbound stream                                        |
| `requested_budgets`           | Offer              | The `MuxBudgets` the client requests, or `None` for an unmetered session          |
| `authorization`               | Offer              | An opaque token for the server's `TransportAuthorizer`, public data               |
| `granted_budgets`             | Accept             | The `MuxBudgets` of the epoch, or `None`                                          |

`TransportOffer::mux(cap)` builds an offer with the default chunking and credit, and `with_budgets`, `with_authorization`, `with_chunk_payload_size`, `with_credit_unit`, and `with_initial_stream_credit` adjust it. `MuxBudgets` holds `client_to_server` and `server_to_client` in credits, and each chunk debits `ceil(payload_len / credit_unit)` credits from its direction.

Both endpoints derive one `MuxSettings` from the same offer and accept. Its fields are private, and each constructor clamps every term it writes:

- `local_initiated_cap` and `peer_initiated_cap` are the two directional stream caps.
- `send_chunk_size` and `recv_chunk_size` are the two chunk sizes.
- `initial_send_credit` and `initial_recv_credit` are the two stream allowances.
- `send_budget` and `recv_budget` are the two session budgets, `None` when unmetered.
- `drain_reserve_records` is `2 * (local cap + peer cap) + 1`, the records a drain keeps, and `send_budget_reserve` prices them at the worst-case debit.
- `usable_send_budget` is the send budget less that reserve, the credits an invoice sizes against.

`MuxSettings::symmetric(cap)` builds unmetered settings with one cap in both directions, for a cleartext link. `with_chunk_size`, `with_initial_credit`, and `with_send_budget` adjust them.

```rust
use tightbeam::constants::MAX_MUX_STREAM_CAP;
use tightbeam::transport::handshake::negotiation::MuxSettings;

// The cap clamps to the ceiling, and a cleartext link stays unmetered.
let settings = MuxSettings::symmetric(4096);
assert_eq!(settings.local_initiated_cap(), MAX_MUX_STREAM_CAP);
assert_eq!(settings.usable_send_budget(), None);
```

The constants of `tightbeam::constants` set every clamp and default:

| Constant                              | Value                                   | Bounds                                                   |
| ------------------------------------- | --------------------------------------- | -------------------------------------------------------- |
| `MAX_MUX_STREAM_CAP`                  | 1024                                    | Each directional stream cap                              |
| `MIN_MUX_CHUNK_SIZE`, `MAX_MUX_CHUNK_SIZE` | 1 KiB, 64 KiB                      | Each chunk size                                          |
| `DEFAULT_MUX_CHUNK_SIZE`              | 16 KiB                                  | The chunk size of `TransportOffer::mux`                  |
| `DEFAULT_MUX_CREDIT_UNIT`             | 1024 bytes                              | The credit unit of `TransportOffer::mux`                 |
| `MAX_MUX_STREAM_CREDIT`, `DEFAULT_MUX_STREAM_CREDIT` | 4096, 64 chunks          | The initial allowance of a stream                        |
| `MAX_MUX_SESSION_BUDGET`              | Half of `DEFAULT_REKEY_RECORD_LIMIT`    | Each direction's budget, in credits                      |
| `MAX_MUX_REASSEMBLY_BYTES`            | 16 MiB                                  | The bytes one stream reassembles                         |
| `MAX_MUX_CONNECTION_REASSEMBLY_BYTES` | 64 MiB                                  | The bytes one connection reassembles across its streams  |
| `DEFAULT_MUX_CANCEL_BUDGET`           | 1024                                    | The peer cancels that abort in-flight handlers           |
| `DEFAULT_REKEY_DEADLINE_SECS`         | 30                                      | One in-band renewal exchange                             |

### Streams and envelopes

- `StreamId` wraps the `u32` of the wire. `is_client_initiated` answers for odd IDs, and `is_server_initiated` for even IDs and the reserved 0.
- `StreamState` has the five states `Idle`, `Open`, `HalfClosedLocal`, `HalfClosedRemote`, and `Closed`.
- `MuxRole::Client` allocates odd IDs and `MuxRole::Server` even IDs.
- `MuxStreamKind` is the kind the Open record stamps: `Unary` (0), `Streaming` (1), or `Duplex` (2).

`MuxEnvelope` nests under the `[4]` arm of `TransportEnvelope`, and each variant carries one package:

| Tag | Variant         | Package                   |
| --- | --------------- | ------------------------- |
| 0   | `Open`          | `MuxOpenPackage`          |
| 1   | `Data`          | `MuxDataPackage`          |
| 2   | `End`           | `MuxEndPackage`           |
| 3   | `Credit`        | `MuxCreditPackage`        |
| 4   | `Cancel`        | `MuxCancelPackage`        |
| 5   | `GoAway`        | `GoAwayPackage`           |
| 6   | `Ping`          | `MuxPingPackage`          |
| 7   | `RekeyRequest`  | `MuxRekeyRequestPackage`  |
| 8   | `RekeyResponse` | `MuxRekeyResponsePackage` |
| 9   | `RekeyAck`      | `MuxRekeyAckPackage`      |
| 10  | `RekeyDone`     | `MuxRekeyDonePackage`     |

`CancelReason` and `GoAwayReason` convert to and from `u32`. A known code below `MUX_APPLICATION_CODE_FLOOR` (0x1000) decodes to its named variant, and every other code to `Application(code)`. `GoAwayReason::as_str` gives the kebab-case audit label, such as `enhance-your-calm`. A renewal whose settlement or approval is refused with a code below the floor drains with `SettlementFailed`, and a code at or above it drains with `Application(code)`.

### The plane

`MuxTransport<R, W>` assembles the plane over an `EnvelopeSource` and an `EnvelopeSink`:

| Constructor or method                      | Effect                                                                                       |
| ------------------------------------------ | -------------------------------------------------------------------------------------------- |
| `new(reader, writer, role, settings)`      | A plane with no rekey state, which drains through GoAway near the record limit                |
| `with_rekey(reader, writer, context, settings)` | A plane that renews in band, in the role of its `MuxRekeyContext`                       |
| `with_cancel_budget(budget)`               | Replaces `DEFAULT_MUX_CANCEL_BUDGET`                                                         |
| `with_credit_grantor(grantor)`             | Replaces the default `BufferedGrantor`, a `CreditGrantor` that tops a stream up at half its window |
| `with_renewal_deadline(deadline)`          | Replaces `DEFAULT_REKEY_DEADLINE_SECS`, under `tokio`                                        |
| `handle()`                                 | A clone of the handle                                                                        |
| `into_parts()`                             | The `MuxHandle`, the `MuxReaderDriver`, the `MuxWriterDriver`, and the `MuxResponder`        |
| `spawn()`                                  | A `SpawnedMux` with both drivers spawned, under `tokio`                                      |

`SpawnedMux` holds the `handle`, the `responder`, and the `drivers`. A drop of `MuxDrivers` aborts both tasks and ends the connection, and `is_finished` reports a reader that ended.

`TcpTransport::into_mux(role)` reads the negotiated settings, detaches the rekey context, splits, and assembles in one call. It fails with `InvalidState` on a session that negotiated no multiplexing or has not completed its handshake. By hand, `MuxConnector::take_rekey` or `MuxAcceptor::take_rekey` detaches the context before the split, and `with_rekey` assembles with it.

```rust
use tightbeam::transport::handshake::negotiation::MuxSettings;
use tightbeam::transport::multiplex::{MuxConnector, MuxRole, MuxTransport};
use tightbeam::transport::TransportResult;

/// Assemble a dialed connection that negotiated `settings`, in the role of
/// the rekey context its handshake left, or as a client without one.
fn assemble<T: MuxConnector>(
    mut connection: T,
    settings: MuxSettings,
) -> TransportResult<MuxTransport<T::EnvelopeReader, T::EnvelopeWriter>> {
    let rekey = connection.take_rekey()?;
    let (reader, writer) = connection.into_envelope_halves()?;
    let mux = match rekey {
        Some(context) => MuxTransport::with_rekey(reader, writer, context, settings),
        None => MuxTransport::new(reader, writer, MuxRole::Client, settings),
    };
    Ok(mux)
}
```

### The handle

`MuxHandle` is the cloneable initiator side:

| Method                                   | Effect                                                                                        |
| ---------------------------------------- | --------------------------------------------------------------------------------------------- |
| `emit_on_stream(&frame)`                 | Opens a stream, sends the frame in chunks, and awaits the response. A drop of the future cancels the stream |
| `open_stream()`, `open_stream_to(target)`| A `RequestSink` for a streamed request, and the future of its unary response                  |
| `open_duplex()`, `open_duplex_to(target)`| A `RequestSink` and a `StreamBody` that carries the reply as it arrives                       |
| `ping()`                                 | Resolves when the peer acknowledges a probe, off the stream table                             |
| `shutdown()`, `shutdown_with(reason)`    | Sends GoAway, waits for the pending streams, and closes the writer                            |
| `has_stream_headroom()`, `wait_for_stream_slot()` | Whether a new stream would open now, and a future that resolves when one would        |
| `goaway_reason()`                        | The reason of the peer's GoAway                                                               |
| `session_receipt()`                      | The receipt of the current epoch, which each renewal rotates                                  |

`emit_on_stream` fails in these cases:

| Error                                    | Cause                                                                      |
| ---------------------------------------- | -------------------------------------------------------------------------- |
| `OperationFailed(StreamsExhausted)`      | The stream cap that the peer advertised is full                            |
| `OperationFailed(BudgetExhausted)`       | The credits left in the epoch cannot cover the frame                       |
| `OperationFailed(ResourceExhausted)`     | The peer refused the stream                                                |
| `Draining`                               | A GoAway went out or came in, so the connection refuses every new stream   |
| `ConnectionClosed`                       | The connection failed, before the call or before the response              |

`MultiplexedProtocol` names `max_concurrent_streams` and `emit_on_stream`, and `StreamingProtocol` adds `open_stream` and `open_duplex`, so a caller stays generic over the handle.

### The responder

`MuxResponder` answers the streams the peer opens, under the advertised cap:

- `serve(handler)` answers each unary stream with a closure that takes the frame and returns a `ResponsePackage`.
- `serve_streaming(handler)` and `serve_duplex(handler)` answer the streaming and the duplex kind.
- `serve_with(dispatch)` routes each kind to a method of a `MuxDispatch`. Each default method fails with `NotServed`, which the peer reads as `Unimplemented`.
- `set_cancel_budget(budget)` replaces the cancel budget. A peer that spends it receives GoAway(`EnhanceYourCalm`).

`MuxReaderDriver::drive` and `MuxWriterDriver::drive` run the two drivers, and the caller spawns both.

The pool and the accept loop reach the plane through four traits:

| Trait          | Items                                                                                                 |
| -------------- | ----------------------------------------------------------------------------------------------------- |
| `MuxCapable`   | `with_mux_offer`, and `negotiated_mux` of a completed handshake                                       |
| `MuxConnector` | `complete_client_handshake`, `take_rekey`, `handshake_peer_certificate`, and `into_envelope_halves`   |
| `MuxAcceptor`  | `negotiate_mux`, `take_rekey`, `session_context`, `into_gated_halves`, and `serve(settings, service, cancel_budget)` |
| `IntoMuxOffer` | The conversion of an owned or shared offer into `Option<Arc<TransportOffer>>`                         |

`MuxService` is the handler set of `server!` with `service:`. Each method receives a `CallContext`, the session and the route of its stream.

### Budgets, authorization, and receipts

A server's `TransportAuthorizer` runs two hooks inside the handshake, and a third at each renewal:

| Hook                                  | Runs                                              | Answers                                                                                   |
| ------------------------------------- | ------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `authorize(offer)`                    | After the client's offer, before the accept       | An `AuthorizationGrant` of budgets and an optional challenge, or an `AuthorizationRefusal` |
| `settle(receipt, response, client)`   | After the client's countersignature verifies      | `Ok`, or a refusal. The default refuses a challenge with `SETTLEMENT_UNSUPPORTED_CODE` (1) |
| `challenge_renewal(prior)`            | At each in-band renewal                           | The challenge of the epoch receipt, `None` by default                                     |

The handshake clamps a grant to the componentwise minimum of the grant and the request. A server with no authorizer grants that minimum under its local ceiling. The client refuses a grant that breaks its request:

| `NegotiationError`        | The grant                                               |
| ------------------------- | ------------------------------------------------------- |
| `BudgetGrantWithheld`     | Holds no budgets for a session that requested them      |
| `BudgetBeyondRequest`     | Exceeds the request                                     |
| `BudgetBeyondCap`         | Exceeds `MAX_MUX_SESSION_BUDGET`                        |
| `ChallengeWithoutBudgets` | Carries a challenge with no budgets to bind it          |
| `AuthorizationRefused`    | Is a refusal, with the authorizer's code                |

The client's `ReceiptApprover::approve(receipt)` answers before the client countersigns: `Ok(None)` countersigns, `Ok(Some(answer))` attaches a settlement answer, and an `ApprovalRefusal` aborts. A client with no approver countersigns a receipt with no challenge, and aborts on a challenge. The server's `SessionObserver::on_outcome` receives the `SessionOutcome` of every receipt exchange, with its `SessionVerdict`, once the authorizer has made the verdict final.

`SessionReceipt` binds the `transcript_hash`, the `budgets`, the `credit_unit`, and the challenge. `StoredReceipt` is the dual-signed `SignedData` an endpoint keeps:

- `certificate(role)` returns the certificate of the server or the client signer from the artifact.
- `verify(server, client)` checks both signatures against two certificates that the verifier admitted for signing.
- `receipt()`, `ancillary_response()`, `artifact()`, and `to_der()` read the body, the answer, and the artifact.

## Connection pooling

[README §8.7](../README.md#87-connection-pooling) states what the pool does. `ConnectionPool::builder()` returns a `ConnectionPoolBuilder` on the system clock, and `ConnectionPoolBuilder::new(config, clock)` takes another clock.

`PoolConfig` has three public fields:

| Field             | Type                          | Default                               |
| ----------------- | ----------------------------- | ------------------------------------- |
| `idle_timeout`    | `Option<Duration>`            | `None`                                |
| `max_connections` | `NonZeroUsize`                | `DEFAULT_MAX_POOL_CONNECTIONS`, 64    |
| `mux_offer`       | `Option<Arc<TransportOffer>>` | `None`                                |

The builder sets the rest:

- `with_config` and `with_clock` replace the configuration and the clock.
- `with_trust_store`, `with_cms_server`, `with_key_purposes`, `with_server_policy`, and `with_handshake_protocol` set the handshake of every dial.
- `with_client_identity` sets the identity of mutual authentication, and `with_receipt_approver` the approver of every dialed transport.
- `with_timeout` sets the operation timeout of every connection, and `with_trace` the collector under `instrument`.
- `allow_cleartext` names cleartext as the intent of a pool with no trust in a server.

`ConnectionPool::connect(addr)` takes `self: &Arc<Self>` and returns a `PooledClient`. `try_acquire(addr)` leases a connection that is ready now, or returns `None`.

| `PooledClient` method                  | Effect                                                                                     |
| -------------------------------------- | ------------------------------------------------------------------------------------------ |
| `emit(frame, attempt)`                 | Sends on the exclusive connection, or opens a stream on the shared one                     |
| `conn()`                               | The exclusive connection. A multiplexed lease fails with `InvalidState`                    |
| `peer_certificate()`                   | The certificate the handshake pinned. An exclusive lease answers `None` until its handshake completes |
| `session_receipt()`                    | The receipt of the shared connection. An exclusive lease answers `None`                    |
| `open_stream()`, `open_duplex()`       | A stream on the shared connection. An exclusive lease fails with `InvalidState`            |

A drop returns a live exclusive connection to the pool. A multiplexed lease leaves its connection with the pool entry.

An exclusive connection is live while its stream is open, its send cipher has a record left, and no exchange is in flight. `TokioStream` reads the stream by a peek that returns at once and leaves every byte in place, so a peer that sent its FIN, or a stream that failed, makes the connection dead. A drop discards a dead connection, and `connect` evicts one from the idle set.

The pool fails a connect in these cases:

| Error                                   | Cause                                                                          |
| --------------------------------------- | ------------------------------------------------------------------------------ |
| `OperationFailed(ResourceExhausted)`    | `max_connections` connections are live, so the dial stops before the socket    |
| `PeerAuthenticationUnconfigured`        | The pool holds no trust in a server and no call to `allow_cleartext`           |
| `OperationFailed(Internal)`             | The pool map is poisoned                                                       |

On a multiplexed lease, `emit` handles two failures of `emit_on_stream`. `StreamsExhausted` moves the lease to a connection with headroom, or dials one more within `max_connections`, and retries once. `ConnectionClosed` and `Draining` evict the entry, so the next `connect` dials again, and the error returns to the caller.

```rust
use core::time::Duration;
use std::sync::Arc;

use tightbeam::clock::SystemClock;
use tightbeam::constants::DEFAULT_MAX_POOL_CONNECTIONS;
use tightbeam::transport::client::{ConnectionBuilder, ConnectionPoolBuilder};
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::PoolConfig;

// A cleartext pool that drops a connection after 30 idle seconds, at the
// default connection cap.
let config = PoolConfig { idle_timeout: Some(Duration::from_secs(30)), ..PoolConfig::default() };
assert_eq!(config.max_connections, DEFAULT_MAX_POOL_CONNECTIONS);

let builder = ConnectionPoolBuilder::<TokioListener>::new(config, Arc::new(SystemClock));
let pool = Arc::new(builder.allow_cleartext().build());
# drop(pool);
```

## Audit trail

[README §8.8](../README.md#88-audit) states what a deployment with audit obligations MUST do. Each step maps to code under the `instrument` feature:

| Step                       | Code                                                                                                                         |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Attach a trace             | `TraceCollector`, through `with_trace` on a `TcpTransport`, an `EndpointConfig`, or a `ConnectionPoolBuilder`, or the `server!` policy `with_trace: [trace.share()]` |
| Record payload hashes      | `TbInstrumentationConfig::enable_payloads`, so each event carries the SHA3-256 hash of its payload                           |
| Provide a durable sink     | An `EventSink` in `TraceConfig::with_sink`. The default is a `BoundedMemorySink` of `max_events` (1024) events              |
| Map the clock              | `TraceCollector::with_clock(clock)`, which records `TRACE_CLOCK_ORIGIN` once per origin                                      |

The default sink keeps the oldest events up to `max_events`, keeps one `WARN` record in place of the next, and drops each later one, and its `overflowed` latch then reads `true`. The warning takes the sequence number of the event it replaces, and its label is the URN of that event. The warning and the `overflow` field of the evidence, which the evidence hash covers, show where truncation began. The collector asks `EventSink::retains` after it takes the sequence number of an event, so each dropped event still takes its number, and a gap in `seq` before a later retained event marks the events dropped there.

The access and session verdicts are these events of `tightbeam::instrumentation::events`:

| Event                           | URN                                              | Records                                                                                |
| ------------------------------- | ------------------------------------------------ | -------------------------------------------------------------------------------------- |
| `GATE_ACCEPT`                   | `urn:tightbeam:event:gate/accept`                | A frame that a collector gate admits. The payload is the peer's canonical key          |
| `GATE_REJECT`                   | `urn:tightbeam:event:gate/reject`                | A frame that a collector gate refuses, with the normalized status as label and value   |
| `SESSION_CERT_REJECTED`         | `urn:tightbeam:event:session/cert-rejected`      | A refused peer identity. The label names the cause, such as `signature` or `key-confirmation` |
| `SESSION_AUTHORIZATION_REFUSED` | `urn:tightbeam:event:session/authorization-refused` | A session that the authorizer refused, with its code                               |
| `SESSION_RECEIPT_SETTLED`       | `urn:tightbeam:event:session/receipt-settled`    | A budget-bearing session that holds its dual-signed receipt                            |
| `SESSION_RECEIPT_REFUSED`       | `urn:tightbeam:event:session/receipt-refused`    | A handshake that fails on its receipt. The label names the reason                      |
| `TRACE_CLOCK_ORIGIN`            | `urn:tightbeam:event:trace/clock-origin`         | The origin of the trace clock, in Unix-epoch nanoseconds                               |

```rust
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::instrumentation::{BoundedMemorySink, TbInstrumentationConfig};
use tightbeam::trace::{TraceCollector, TraceConfig};
use tightbeam::transport::EndpointConfig;

// Gate verdicts carry the hash of the peer key, into a sink of 65536 events.
let settings = TbInstrumentationConfig { enable_payloads: true, ..TbInstrumentationConfig::default() };
let config = TraceConfig::with_instrumentation(settings).with_sink(BoundedMemorySink::new(65536));
let trace = TraceCollector::from(config);

// Every transport built from this endpoint records into the trace.
let endpoint = EndpointConfig::<DefaultCryptoProvider>::cleartext().with_trace(trace.share());
# drop(endpoint);
```

## Sources

- RFC 9113, HTTP/2, § 5.1 streams, § 7 error codes: <https://datatracker.ietf.org/doc/html/rfc9113>
- RFC 9000, QUIC, § 4.1 stream flow control: <https://datatracker.ietf.org/doc/html/rfc9000#section-4.1>
- RFC 9846, TLS 1.3, § 5.5 record limits: <https://datatracker.ietf.org/doc/html/rfc9846#section-5.5>
- RFC 5652, Cryptographic Message Syntax: <https://datatracker.ietf.org/doc/html/rfc5652>
- RFC 5083, CMS Authenticated-Enveloped-Data Content Type: <https://datatracker.ietf.org/doc/html/rfc5083>
- `google.rpc.Code`, the gRPC canonical status codes: <https://github.com/googleapis/googleapis/blob/master/google/rpc/code.proto>
- CVE-2023-44487, HTTP/2 Rapid Reset: <https://nvd.nist.gov/vuln/detail/CVE-2023-44487>
- CWE-645, Overly Restrictive Account Lockout Mechanism: <https://cwe.mitre.org/data/definitions/645.html>
