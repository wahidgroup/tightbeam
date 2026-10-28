# tightbeam documentation

These pages drill down from the [README](../README.md). Each one specifies one part of tightbeam in full, down to the types and methods that enforce each rule. Every example on a page compiles as a doctest.

| Document | Specifies | Drills down from |
| --- | --- | --- |
| [The TightBeam Frame](frame.md) | The Frame and its metadata in memory: the version gates, the builder and `compose!`, the cryptographic structures, the encoding, the semantic constraints, and the matrix | [README §4](../README.md#4-protocol-specification) and [§5](../README.md#5-asn1-formal-specification) |
| [Security Profiles, Providers, and Keys](security.md) | Security profiles and their message requirements, the crypto provider and its roles, the strength floor, and key management | [README §6](../README.md#6-security-model) and [§7](../README.md#7-implementation) |
| [The TightBeam Transport](transport.md) | The transport traits, the wire envelopes, TCP and `server!`, the policies, multiplexing, pooling, and the audit trail | [README §8](../README.md#8-transport-layer) |
| [The TightBeam Handshake](handshake.md) | The two handshake flows: their messages, keys, certificates, envelopes, and transcript, and the types that enforce each rule | [README §8.5](../README.md#85-handshake-protocols) |
| [DHKEM over secp256k1 in CMS](dhkem-secp256k1.md) | DHKEM(secp256k1, HKDF-SHA256) as the KEM of a CMS `KEMRecipientInfo`, which seals the CMS opening and each frame sealed to a recipient key | [README §8.5.3](../README.md#853-implementation-cms-based-handshake-protocol) |
| [The TightBeam Colony](colony.md) | Workers, servlets, hives, and clusters: their macros, runtimes, gates, and the `HiveConfig` and `ClusterConfig` references | [README §9](../README.md#9-network-theory) |
| [Instrumentation and Utilities](instrumentation.md) | The trace collector, its events and sinks, the evidence artifact, logging, URNs, jobs, and pipelines | [README §10](../README.md#10-instrumentation) and [§11](../README.md#11-misc) |
| [The Testing Framework](testing.md) | The spec macros and their generated API, the FDR configuration and verdicts, fault injection, FMEA, the hooks, and the fuzz harness | [README §12](../README.md#12-testing-framework) |

A new page gets one row here, and the README section it drills down from links to it.
