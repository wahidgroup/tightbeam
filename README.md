# tightbeam

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

### 1.1 Information Fidelity Constraint

The foundational mathematical principle underlying tightbeam is the information fidelity constraint:

**I(t) ∈ (0,1) ∀t ∈ T_t**

Where:
- **I(t)**: The Frame as an information state at time t
- **(0,1)**: Bounded information fidelity interval
  - Never perfect (1): Acknowledges fundamental limits of information transmission
  - Never absent (0): Guarantees non-zero information content in all valid frames
- **∀t ∈ T_t**: Holds for all time points in the protocol's temporal domain

This constraint reflects applied information theory principles:

1. **Theoretical Foundation**: Information transmission systems exhibit bounded fidelity due to physical limitations, encoding constraints, stochastic noise & shock, and temporal factors
2. **Practical Implications**: tightbeam's design ensures frames always carry bounded information content while acknowledging imperfection inherent in any communication system
3. **Protocol Guarantee**: The constraints provide applied mathematical basis for frame validation and quality assurance

The I(t) constraint informs several protocol design decisions:
- ASN.1 DER encoding for maximum structural fidelity
- Versioned metadata allowing graceful capability evolution
- Optional integrity and confidentiality fields preserving information quality
- Temporal ordering ensuring coherent information flow over time
- Optional cryptographic signing to ensure non-repudiation

### 1.2 Requirements Language

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

### 4.1.1 Security Profiles

tightbeam defines standardized security profiles that reference established cryptographic standards:

- **Profile 0 (Testing)**: No mandatory security features
  - Use case: Development, testing, non-sensitive data
  - Security: Optional per version capabilities

- **Profile 1 (Standard Security)**: TLS 1.3 equivalent security
  - Reference: RFC 8446 cipher suites
  - Mandatory: AES-GCM encryption, SHA-256/384 integrity
  - Key Exchange: Compatible with TLS 1.3 key schedule

- **Profile 2 (High Security)**: NSA Suite B equivalent
  - Reference: RFC 6460, NIST SP 800-56A
  - Mandatory: AES-256-GCM, SHA-384, ECDSA P-384
  - Compliance: FIPS 140-2 Level 3 compatible

- **Profile 3 (Future-Ready)**: Post-quantum resistant
  - Reference: NIST post-quantum standardization
  - Mandatory: Hybrid classical/post-quantum algorithms
  - Migration: Smooth transition path from Profile 2

### 4.1.2 Message-Level Security Requirements

tightbeam supports compile-time security enforcement at the message type level through the `Message` trait:

```rust
pub trait Message: /* trait bounds */ {
    const MUST_BE_NON_REPUDIABLE: bool = false;
    const MUST_BE_CONFIDENTIAL: bool = false;
    const MUST_BE_COMPRESSED: bool = false;
    const MUST_BE_PRIORITIZED: bool = false;
    const MIN_VERSION: Version = Version::V0;
}
```

#### Security Requirement Semantics

- **`MUST_BE_NON_REPUDIABLE`**: When `true`, the message MUST include a digital signature in the Frame's `nonrepudiation` field
- **`MUST_BE_CONFIDENTIAL`**: When `true`, the message MUST be encrypted using the metadata's `confidentiality` field
- **`MUST_BE_COMPRESSED`**: When `true`, the message MUST be compressed using a non-none `compactness` algorithm
- **`MUST_BE_PRIORITIZED`**: When `true`, the message MUST include a `priority` field in V2+ metadata
- **`MIN_VERSION`**: Specifies the minimum protocol version required for this message type

#### Implementation Enforcement

These requirements are enforced at:
- **Compile Time**: Type system prevents composition of messages that don't meet requirements
- **Runtime Validation**: Frame validation ensures required fields are present
- **Profile Compliance**: Security profiles can reference message types with specific requirements

#### Derive Macro Usage

The `#[derive(Beamable)]` macro automatically implements the `Message` trait:

```rust
// This derive macro...
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
#[beam(nonrepudiable, confidential, min_version = "V1")]
struct PaymentInstruction { /* fields */ }

// ...expands to:
impl Message for PaymentInstruction {
    const MUST_BE_NON_REPUDIABLE: bool = true;
    const MUST_BE_CONFIDENTIAL: bool = true;
    const MUST_BE_COMPRESSED: bool = false;
    const MUST_BE_PRIORITIZED: bool = false;
    const MIN_VERSION: Version = Version::V1;
}
```

**Supported attributes:**
- `#[beam(nonrepudiable)]` - Sets `MUST_BE_NON_REPUDIABLE = true`
- `#[beam(confidential)]` - Sets `MUST_BE_CONFIDENTIAL = true`
- `#[beam(compressed)]` - Sets `MUST_BE_COMPRESSED = true`
- `#[beam(prioritized)]` - Sets `MUST_BE_PRIORITIZED = true`
- `#[beam(min_version = "V1")]` - Sets minimum protocol version

#### Example Message Types

```rust
use tightbeam::Beamable;
use der::Sequence;

// High-security financial transaction
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
#[beam(nonrepudiable, confidential, min_version = "V1")]
struct PaymentInstruction {
    account_from: String,
    account_to: String,
    amount: u64,
    currency: String,
}

// Bulk data transfer
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
#[beam(compressed, prioritized, min_version = "V2")]
struct DataTransfer {
    dataset_id: String,
    data: Vec<u8>,
    checksum: [u8; 32],
}

// Development/testing message (no security requirements)
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
struct TestMessage {
    test_id: u32,
    content: String,
}

// Critical system alert (requires all security features)
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
#[beam(nonrepudiable, confidential, compressed, prioritized, min_version = "V2")]
struct SecurityAlert {
    severity: u8,
    source: String,
    description: String,
    timestamp: u64,
}
```

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
    messageIntegrity [0] IntegrityInfo OPTIONAL,
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

#### Message-Level Security Constraints
- When a message type specifies `MUST_BE_NON_REPUDIABLE = true`, the Frame MUST include a `nonrepudiation` field
- When a message type specifies `MUST_BE_CONFIDENTIAL = true`, the Frame's metadata MUST include a `confidentiality` field
- When a message type specifies `MUST_BE_COMPRESSED = true`, the Frame's metadata `compactness` field MUST NOT be `none`
- When a message type specifies `MUST_BE_PRIORITIZED = true`, the Frame's metadata MUST include a `priority` field (V2+ only)
- The Frame's `version` field MUST be >= the message type's `MIN_VERSION` requirement

#### Profile-Message Type Mapping
- Security profiles MAY specify approved message types
- Message types with security requirements SHOULD be used with compatible security profiles
- Profile 0 (Testing) MAY use message types with security requirements for development purposes only

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
- Message-level security requirement enforcement

Implementations MUST OPTIONALLY provide:
- Abstract Layer-4 transport with async/sync
- Cryptographic abstraction for confidentiality, integrity and non-repudiation

### 6.1.1 Message Security Enforcement

Implementations MUST enforce message-level security requirements through:

#### Compile-Time Validation
- Type system integration to prevent unsafe message composition
- Trait-based constraints that enforce security requirements at build time
- Version compatibility checking during message type definition

#### Runtime Validation
- Frame validation against message type requirements during encoding/decoding
- Security profile compliance verification
- Graceful error handling for requirement violations

#### Example Implementation Pattern
```rust
impl<T: Message> FrameBuilder<T> {
    fn validate(&self) -> Result<()> {
        // Check minimum version requirement
        if self.version < T::MIN_VERSION {
            return Err(TightBeamError::UnsupportedVersion(ExpectError::from((
                self.version,
                T::MIN_VERSION,
            ))));
        }

        // Check if encryption is set when required
        #[cfg(feature = "aead")]
        {
            let has_encryption = self.encryptor.is_some();
            if T::MUST_BE_CONFIDENTIAL && !has_encryption {
                return Err(TightBeamError::MissingEncryptionInfo);
            }
        }

        // Check if signature is set when required
        #[cfg(feature = "signature")]
        {
            let has_signer = self.signer.is_some();
            if T::MUST_BE_NON_REPUDIABLE && !has_signer {
                return Err(TightBeamError::MissingSignatureInfo);
            }
        }

        // Check if compression is set when required
        #[cfg(feature = "compress")]
        {
            let has_compression = self.compressor.is_some();
            if T::MUST_BE_COMPRESSED && !has_compression {
                return Err(TightBeamError::MissingCompressionInfo);
            }
        }

        // Check if priority is set when required
        if T::MUST_BE_PRIORITIZED && !self.metadata_builder.has_priority() {
            return Err(TightBeamError::MissingPriority);
        }

        Ok(())
    }
}
```

### 6.2 Transport Layer

tightbeam operates over ANY transport protocols:
- TCP (built-in async/sync support)
- Custom transports via trait implementation

### 6.3 Key Management Integration

tightbeam integrates with existing key management standards and infrastructure:

#### 6.3.1 Public Key Infrastructure
- **Certificates**: X.509 certificates per RFC 5280
- **Certificate Chains**: Standard PKI validation chains
- **Certificate Revocation**: CRL (RFC 5280) or OCSP (RFC 6960)
- **Enterprise Integration**: Compatible with existing CA infrastructure

#### 6.3.2 Key Exchange and Distribution
- **Key Schedule**: Compatible with TLS 1.3 key derivation (RFC 8446)
- **Ephemeral Keys**: ECDHE key exchange per NIST SP 800-56A
- **Key Agreement**: Follows NIST SP 800-56A/B/C recommendations
- **Perfect Forward Secrecy**: Ephemeral key exchange for session keys

#### 6.3.3 Key Lifecycle Management
- **Key Rotation**: Follow NIST SP 800-57 Part 1 guidelines
- **Key Escrow**: Integration with enterprise key management systems
- **Hardware Security**: HSM compatibility for key storage
- **Key Derivation**: HKDF (RFC 5869) for session key derivation

#### 6.3.4 Enterprise Integration
- **PKCS#11**: Hardware token and HSM integration
- **Key Management Systems**: Compatible with enterprise KMS
- **Directory Services**: LDAP/Active Directory certificate lookup
- **Policy Enforcement**: Supports organizational key policies

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

### 7.4 Cryptographic Algorithm Policy

tightbeam follows established cryptographic standards and maintains algorithm agility:

#### 7.4.1 Approved Algorithms
- **Current Standards**: NIST FIPS 140-2/3 approved algorithm lists
- **Symmetric Encryption**: AES (FIPS 197), ChaCha20-Poly1305 (RFC 8439)
- **Hash Functions**: SHA-2 (FIPS 180-4), SHA-3 (FIPS 202)
- **Digital Signatures**: ECDSA (FIPS 186-4), EdDSA (RFC 8032)
- **Key Exchange**: ECDH (NIST SP 800-56A), X25519 (RFC 7748)

#### 7.4.2 Algorithm Deprecation Schedule
- **Transition Guidelines**: NIST SP 800-131A Rev. 2 compliance
- **Legacy Support**: Controlled deprecation with migration periods
- **Vulnerability Response**: Rapid algorithm disabling capability
- **Industry Alignment**: Follow IETF/RFC security considerations

#### 7.4.3 Post-Quantum Cryptography
- **Preparation**: Monitor NIST post-quantum standardization process
- **Hybrid Approach**: Classical + post-quantum algorithm combinations
- **Migration Strategy**: Gradual transition from classical to post-quantum
- **Interoperability**: Maintain backward compatibility during transition

#### 7.4.4 Algorithm Identifier Management
- **OID Registry**: Use standard algorithm OIDs from IANA/ITU-T
- **Parameter Validation**: Enforce minimum key sizes and parameters
- **Algorithm Negotiation**: Support for algorithm capability discovery
- **Security Policy**: Configurable algorithm allow/deny lists

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
- RFC 5280: Internet X.509 Public Key Infrastructure Certificate and CRL Profile
- RFC 5480: Elliptic Curve Cryptography Subject Public Key Info
- RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
- RFC 6460: Suite B Profile for Transport Layer Security (TLS)
- RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- RFC 6960: X.509 Internet Public Key Infrastructure Online Certificate Status Protocol
- RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
- RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
- RFC 7748: Elliptic Curves for Security

### 9.1.1 NIST Standards References

- FIPS 140-2: Security Requirements for Cryptographic Modules
- FIPS 140-3: Security Requirements for Cryptographic Modules
- FIPS 180-4: Secure Hash Standard (SHS)
- FIPS 186-4: Digital Signature Standard (DSS)
- FIPS 197: Advanced Encryption Standard (AES)
- FIPS 202: SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
- NIST SP 800-56A: Recommendation for Pair-Wise Key Establishment Schemes
- NIST SP 800-57: Recommendation for Key Management
- NIST SP 800-131A: Transitioning the Use of Cryptographic Algorithms and Key Lengths

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
