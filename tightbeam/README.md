# Layer-5 tightbeam Framework

## Abstract

tightbeam is a Layer-5 framework implementing high-fidelity information theory through ASN.1 DER encoding with versioned metadata structures. This specification defines the protocol's core properties: structure, frame versioning, idempotence, ordering, compactness, integrity, confidentiality, priority, lifetime, state management, stage control, and non-repudiation.

## Table of Contents

1. [Introduction](#introduction)
2. [Terminology](#terminology)
3. [Architecture](#architecture)
4. [Protocol Specification](#protocol-specification)
5. [ASN.1 Formal Specification](#asn1-formal-specification)
6. [Implementation](#implementation)
7. [Security Considerations](#security-considerations)
8. [Examples](#examples)
9. [References](#references)

## 1. Introduction

tightbeam addresses the need for a structured, versioned messaging protocol that guarantees information fidelity through applied mathematical constraints where I(t) ∈ (0,1) ∀t ∈ T_t.

### 1.1 Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC2119](https://datatracker.ietf.org/doc/html/rfc2119).

## 2. Terminology

- **Frame**: The complete tightbeam message structure containing version, metadata, and payload
- **Metadata**: Structured information about the message including routing, security, and lifecycle data
- **Version**: Protocol version determining available features and validation rules
- **Message**: The application payload encoded within a Frame

## 3. Architecture

### 3.1 Information Theory Properties

tightbeam implements high-fidelity information transmission through the following properties:

- **STRUCTURE**: Perfect encoding via ASN.1 DER
- **FRAME**: Incremental versioning system
- **IDEMPOTENCE**: Unique message identification
- **ORDER**: Temporal sequencing via 64-bit integers
- **COMPACTNESS**: Enforceable compression
- **INTEGRITY**: Message digest validation
- **CONFIDENTIALITY**: Cipher-based encryption
- **PRIORITY**: 7-level priority system
- **LIFETIME**: 64-bit TTL values
- **STATE**: Previous message chaining
- **STAGE**: 8×8 matrix encoded control flags
- **NONREPUDIATION**: Cryptographic signatures

## 4. Protocol Specification

### 4.1 Version Evolution

- VERSION 0
  - REQUIRED: Message identification (idempotence)
  - REQUIRED: Temporal ordering (64-bit integer)  
  - OPTIONAL: Compression (enforceable compactness)

- VERSION 1
  - Inherits: All V0 features
  - OPTIONAL: Message integrity (digest)
  - OPTIONAL: Confidentiality (cipher)

- VERSION 2
  - Inherits: All V1 features
  - OPTIONAL: Priority levels (7-level enumeration)
  - OPTIONAL: Message lifetime (64-bit TTL)
  - OPTIONAL: State chaining (previous message integrity)
  - OPTIONAL: Stage control (8×8 matrix flags)

### 4.2 Frame Structure

All versions MUST include:
- Identifier
- Frame Version
- Order

All versions MAY include:
- Message payload (bytecode)
- Frame integrity (digest of complete structure)
- Non-repudiation (cryptographic signature)

### 4.3 Metadata Specification

```rust
#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
pub struct Metadata {
    // Core fields (V0+)
    pub id: Vec<u8>,
    pub order: u64,
    pub compactness: CompressionInfo,

    // V1+ fields
    #[asn1(context_specific = "0", optional = "true")]
    pub integrity: Option<IntegrityInfo>,
    #[asn1(context_specific = "1", optional = "true")]
    pub confidentiality: Option<EncryptionInfo>,

    // V2+ fields
    #[asn1(context_specific = "2", optional = "true")]
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub priority: Option<MessagePriority>,
    #[asn1(context_specific = "3", optional = "true")]
    pub lifetime: Option<u64>,
    #[asn1(context_specific = "4", optional = "true")]
    pub previous_frame: Option<IntegrityInfo>,
    #[asn1(context_specific = "5", optional = "true")]
    pub stage: Option<Vec<u8>>,
}
```

### 4.4 Frame Encapsulation
```rust
#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
pub struct Frame {
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub version: Version,
    pub metadata: Metadata,
    pub message: Vec<u8>,
    #[asn1(context_specific = "0", optional = "true")]
    pub integrity: Option<IntegrityInfo>,
    #[asn1(context_specific = "1", optional = "true")]
    pub nonrepudiation: Option<SignatureInfo>,
}
```

## 5. ASN.1 Formal Specification

This section provides the complete ASN.1 definitions for all tightbeam protocol structures, encoded using Distinguished Encoding Rules (DER).

### 5.1 Core Types

#### Version Enumeration
```asn1
Version ::= ENUMERATED {
    v0(0),
    v1(1),
    v2(2)
}
```

#### Message Priority Levels
```asn1
MessagePriority ::= ENUMERATED {
    critical(0),     -- System/security alerts, emergency notifications
    top(1),          -- High-priority interactive traffic, real-time responses
    high(2),         -- Important business messages, time-sensitive data
    normal(3),       -- Standard message traffic (default)
    low(4),          -- Non-urgent notifications, background updates
    bulk(5),         -- Batch processing, large data transfers, logs
    heartbeat(6)     -- Keep-alive signals, periodic status updates
}
```

### 5.2 Compression Structures

#### Compression Algorithm Types
```asn1
CompressionAlgorithm ::= ENUMERATED {
    none(0),
    zstd(1)
}
```

#### Compression Algorithm Information
```asn1
ZstdInfo ::= SEQUENCE {
    level         INTEGER,
    originalSize  INTEGER
}

GzipInfo ::= SEQUENCE {
    level         INTEGER,
    originalSize  INTEGER
}

CompressionInfo ::= CHOICE {
    none  NULL,
    zstd  ZstdInfo,
    gzip  GzipInfo
}
```

### 5.3 Cryptographic Structures

#### Encryption Information
```asn1
EncryptionInfo ::= SEQUENCE {
    algorithm   AlgorithmIdentifier,
    parameters  ANY DEFINED BY algorithm
}
```

#### Integrity Information
```asn1
IntegrityInfo ::= SEQUENCE {
    algorithm   AlgorithmIdentifier,
    parameters  ANY DEFINED BY algorithm
}
```

#### Digital Signature Information
```asn1
SignatureInfo ::= SEQUENCE {
    signatureAlgorithm  AlgorithmIdentifier,
    signature           OCTET STRING
}
```

### 5.4 Message Structure

#### Metadata Structure
```asn1
Metadata ::= SEQUENCE {
    -- Core fields (V0+)
    id               OCTET STRING,
    order            INTEGER,
    compactness      CompressionInfo,
    
    -- V1+ fields (context-specific tags)
    integrity        [0] IntegrityInfo OPTIONAL,
    confidentiality  [1] EncryptionInfo OPTIONAL,
    
    -- V2+ fields (context-specific tags)
    priority         [2] MessagePriority OPTIONAL,
    lifetime         [3] INTEGER OPTIONAL,
    previousFrame    [4] IntegrityInfo OPTIONAL,
    stage            [5] OCTET STRING OPTIONAL
}
```

#### Complete Frame Structure
```asn1
Frame ::= SEQUENCE {
    version         Version,
    metadata        Metadata,
    message         OCTET STRING,
    integrity       [0] IntegrityInfo OPTIONAL,
    nonrepudiation  [1] SignatureInfo OPTIONAL
}
```

### 5.5 External Dependencies

The protocol relies on standard ASN.1 structures:

```asn1
-- From RFC 5652 and related PKCS standards
AlgorithmIdentifier ::= SEQUENCE {
    algorithm    OBJECT IDENTIFIER,
    parameters   ANY DEFINED BY algorithm OPTIONAL
}
```

### 5.6 Encoding Rules

- **Encoding**: Distinguished Encoding Rules (DER) as specified in ITU-T X.690
- **Byte Order**: Network byte order (big-endian) for multi-byte integers
- **String Encoding**: UTF-8 for textual content, raw bytes for binary data
- **Optional Fields**: Absent optional fields MUST NOT be encoded (DER requirement)

### 5.7 Version-Specific Constraints

#### Version 0 (V0)
- REQUIRED: `id`, `order`, `message`
- OPTIONAL: `compactness`, `integrity`, `nonrepudiation`
- FORBIDDEN: All V1+ and V2+ specific fields

#### Version 1 (V1)
- INHERITS: All V0 requirements
- OPTIONAL: `integrity` (metadata level), `confidentiality`
- FORBIDDEN: All V2+ specific fields

#### Version 2 (V2)
- INHERITS: All V1 requirements
- OPTIONAL: `priority`, `lifetime`, `previousFrame`, `stage`

### 5.8 Semantic Constraints

#### Message Ordering
- `order` field MUST be monotonically increasing within a message sequence
- `order` values SHOULD be based on reliable timestamp sources
- Duplicate `order` values within the same `id` namespace are forbidden

#### Compression Requirements
- When `compactness` is not `none`, the `message` field MUST contain compressed data
- `originalSize` in compression info MUST match the uncompressed message size
- Compression level MUST be within algorithm-specific valid ranges

### 5.9 Complete ASN.1 Module

```asn1
tightbeam-Protocol-V2 DEFINITIONS EXPLICIT TAGS ::= BEGIN

-- Import standard algorithm identifier
IMPORTS AlgorithmIdentifier FROM PKCS-1 
        { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) };

-- Core protocol version
Version ::= ENUMERATED {
    v0(0),
    v1(1),
    v2(2)
}

-- Message priority enumeration
MessagePriority ::= ENUMERATED {
    critical(0),
    top(1),
    high(2),
    normal(3),
    low(4),
    bulk(5),
    heartbeat(6)
}

-- Compression structures
CompressionAlgorithm ::= ENUMERATED {
    none(0),
    zstd(1)
}

ZstdInfo ::= SEQUENCE {
    level         INTEGER,
    originalSize  INTEGER
}

GzipInfo ::= SEQUENCE {
    level         INTEGER,
    originalSize  INTEGER
}

CompressionInfo ::= CHOICE {
    none  NULL,
    zstd  ZstdInfo,
    gzip  GzipInfo
}

-- Cryptographic structures
EncryptionInfo ::= SEQUENCE {
    algorithm   AlgorithmIdentifier,
    parameters  ANY DEFINED BY algorithm
}

IntegrityInfo ::= SEQUENCE {
    algorithm   AlgorithmIdentifier,
    parameters  ANY DEFINED BY algorithm
}

SignatureInfo ::= SEQUENCE {
    signatureAlgorithm  AlgorithmIdentifier,
    signature           OCTET STRING
}

-- Core message structures
Metadata ::= SEQUENCE {
    id               OCTET STRING,
    order            INTEGER,
    compactness      CompressionInfo,
    integrity        [0] IntegrityInfo OPTIONAL,
    confidentiality  [1] EncryptionInfo OPTIONAL,
    priority         [2] MessagePriority OPTIONAL,
    lifetime         [3] INTEGER OPTIONAL,
    previousFrame    [4] IntegrityInfo OPTIONAL,
    stage            [5] OCTET STRING OPTIONAL
}

Frame ::= SEQUENCE {
    version         Version,
    metadata        Metadata,
    message         OCTET STRING,
    integrity       [0] IntegrityInfo OPTIONAL,
    nonrepudiation  [1] SignatureInfo OPTIONAL
}

END
```

## 6. Implementation

### 6.1 Requirements

Implementations MUST provide:
- Memory safety and ownership guarantees
- ASN.1 DER encoding/decoding
- Frame and Metadata as specified as ASN.1

Implementations MUST OPTIONALLY provide:
- Abstract Layer-4 transport with async/sync
- Cryptographic abstraction for confidentiality, integrity and non-repudiation

### 6.2 Transport Layer

tightbeam operates over ANY transport protocols:
- TCP (built-in async/sync support)
- Custom transports via trait implementation

## 7. Security Considerations

### 7.1 Cryptographic Requirements

- Integrity MUST use cryptographically secure hash functions
- Confidentiality MUST use authenticated encryption (AEAD)
- Non-repudiation MUST use digital signatures with secure key pairs

### 7.2 Version Security

- V0: No mandatory security features
- V1: Optional integrity and confidentiality support
- V2: Enhanced with priority, lifetime, state chaining, and stage controls

### 7.3 ASN.1 Security Considerations

- DER encoding prevents ambiguous parsing attacks
- Context-specific tags prevent field confusion
- Explicit versioning prevents downgrade attacks
- Optional field handling prevents injection attacks

## 8. Examples

### 8.1 Basic Container Test
```rust
test_container! {
    name: container_gates_basic,
    features: ["testing", "std", "tcp", "tokio"],
    worker_threads: 2,
    protocol: tcp,
    service_policies: {
        gate: policy::AcceptAllGate
    },
    client_policies: {
        restart: policy::RestartExponentialBackoff::default(),
        gate: policy::AcceptAllGate
    },
    service: |message, tx| async move {
        // Echo service implementation
        let result = tx.send(message.clone());
        assert!(result.is_ok());

        let decoded = tightbeam::decode::<RequestMessage, _>(&message.clone().message).ok()?;
        if &decoded.content == "PING" {
            Some(tightbeam::compose! {
                V0: id: message.metadata.id.clone(),
                    order: 1_700_000_000u64,
                    message: ResponseMessage {
                        result: "PONG".into()
                    }
            }.ok()?)
        } else {
            None
        }
    },
    container: |client, channels| async move {
        use tightbeam::transport::MessageEmitter;

        let (rx, ok_rx, reject_rx) = channels;

        // Compose a simple V0 message
        let message = tightbeam::compose! {
            V0: id: b"request",
                order: 1_700_000_000u64,
                message: RequestMessage {
                    content: "PING".into()
                }
        }?;

        // Send and expect acceptance + echo response
        let decoded = if let Some(response) = client.emit(message.clone(), None).await? {
            assert_eq!(response.metadata.id, message.metadata.id);
            tightbeam::decode::<ResponseMessage, _>(&response.message).ok()
        } else {
            panic!("Expected a response from the service");
        };

        match decoded {
            Some(reply) => {
                assert_eq!(reply.result, "PONG");
            },
            None => panic!("Expected a PONG")
        };

        assert_recv!(rx, message, 2, 1);
        assert_recv!(ok_rx, message, 2, 1);
        assert_channels_quiet!(reject_rx);

        Ok(())
    }
}
```

## 9. References

### 9.1 Normative References

- RFC 2119: Key words for use in RFCs to Indicate Requirement Levels
- ITU-T X.690: ASN.1 Distinguished Encoding Rules (DER)
- RFC 5652: Cryptographic Message Syntax (CMS)
- RFC 3280: Internet X.509 Public Key Infrastructure
- RFC 5480: Elliptic Curve Cryptography Subject Public Key Info

### 9.2 Informative References

#### Network Architecture
- Egress/ingress policy management
- Service orchestration via Colony Monodomy/Polydomy patterns  
- Cryptographically chainable message sequences

**See:** [Transport Integration Tests](tightbeam/tests/transport.rs)

#### Testing Framework
- Asynchronous/synchronous containerized end-to-end testing
- Client/server quantum tunneling via MPSC channels

**See:** [Container Integration Test](tightbeam/tests/container.rs)

### 9.3 ASN.1 References

- ITU-T X.680: ASN.1 Specification of basic notation
- ITU-T X.681: ASN.1 Information object specification
- ITU-T X.682: ASN.1 Constraint specification
- ITU-T X.683: ASN.1 Parameterization of ASN.1 specifications
- RFC 3246: Expedited Forwarding PHB (Priority levels inspiration)
- RFC 2474: Differentiated Services Field (Priority levels inspiration)
- X.400/X.420: Message Handling Systems (Priority levels inspiration)

## 10. License

### For Users (Outbound Licensing)

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](../LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](../LICENSE-MIT) or http://opensource.org/licenses/MIT)

**at your option**. You may choose whichever license best fits your needs:

- **Choose MIT** if you prefer simplicity and broad compatibility
- **Choose Apache-2.0** if you want explicit patent protection and retaliation clauses

### For Contributors (Inbound Licensing)

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

**This means contributors grant rights under BOTH licenses**, providing:
- MIT's simplicity for users who prefer it
- Apache-2.0's patent grants for enhanced protection

This dual-licensing strategy ensures maximum compatibility while providing patent protection from all contributors.

### 10.1 Implementation Notes

#### Project Structure

The workspace consists of the following components:

- **core**: Shared library code and common utilities
- **src/main.rs**: Application entry point
- **tests/**: Integration test suites

#### Getting Started

**Requirements:**
- Rust (minimum version TBD)
- System dependencies for cryptographic operations

**Commands:**
```bash
# Basic development
make build                             # Build all projects
make clean                             # Clean build artifacts  
make test                              # Run all tests
make lint                              # Run linters
make lint ARGS="--fix --allow-staged"  # Run linters with fixes
make doc                               # Build documentation

# Feature-specific builds
make build features="std,tcp,tokio"
make build features="aes-gcm,sha3,secp256k1"
make build features="zstd,compress"
make build features="x509,signature"

# Testing with specific features
make test features="testing,std,tcp,tokio" 
make test features="testing" no-default=1

# Development server (from project root)
make dev
```
