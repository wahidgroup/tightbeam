# tightbeam

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

## Status
> Warning: This project is under active development. Public APIs and file 
formats MAY change WITHOUT notice. It is NOT yet production-ready.
> Warning: Only the `full` feature is currently supported.
> Info: Information documented in this README is functional but unreleased.

## Copyright Notice

   Copyright (C) Tanveer Wahid, WahidGroup, LLC (2025).  All Rights Reserved.

## Abstract

tightbeam is a Layer-5 framework implementing high-fidelity information theory 
through Abstract Syntax Notation One (ASN.1) Distinguished Encoded Rules (DER) 
with versioned metadata structures.

## Table of Contents

1. [Introduction](#introduction)
2. [Terminology](#terminology)
3. [Architecture](#architecture)
4. [Protocol Specification](#protocol-specification)
5. [ASN.1 Formal Specification](#asn1-formal-specification)
6. [Implementation](#implementation)
7. [Security Considerations](#security-considerations)
8. [Transport Layer & Handshake Protocols](#transport-layer--handshake-protocols)
9. [Network Theory](#network-theory)
10. [Testing Framework](#testing-framework)
11. [Examples](#examples)
12. [References](#references)
13. [License](#license)
14. [Implementation Notes](#implementation-notes)

## 1. Introduction

tightbeam defines a structured, versioned messaging protocol with an 
information fidelity constraint: I(t) ∈ (0,1) for all t ∈ T. Sections follow 
a [concept → specification → implementation → testing] pattern.

### 1.1 Information Fidelity Constraint

Question: How well does information maintain fidelity[^fidelity] across time?

The foundational mathematical principle underlying tightbeam is the information 
fidelity constraint:

 **I(t) ∈ (0,1) ∀t ∈ T**

 Where:
- **I(t)**: Information state of a Frame at time t
- **(0,1)**: Strictly bounded information fidelity interval
  - Strictly less than 1 (never perfect): acknowledges fundamental limits of transmission
  - Strictly greater than 0 (never absent): guarantees non-zero information content in valid frames
- **∀t ∈ T**: For every moment in time within the protocol's operational timeframe

This constraint reflects information-theoretic limits:

1. **Theoretical Foundation**: Information transmission systems exhibit bounded fidelity due to physical limitations, encoding constraints, stochastic noise & shock, and temporal factors
2. **Practical Implications**: tightbeam’s design ensures frames always carry bounded information content while acknowledging that no communication system achieves perfect fidelity
3. **Protocol Guarantee**: The constraint provides a mathematical basis for frame validation and quality assurance

The I(t) constraint informs all protocol design decisions.

[^fidelity]: The degree of exactness with which something is copied or reproduced.

### 1.2 Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC2119](https://datatracker.ietf.org/doc/html/rfc2119).

## 2. Terminology
The following project terms MUST be used consistently:
- [tightbeam](https://docs.rs/tightbeam-rs/latest): The project name. Lowercase as tightbeam.
- [Frame](#42-frame-structure): A versioned snapshot (state) at time t.
- [Message](#54-message-structure): A typed application payload serialized within a Frame.
- [Metadata](#43-metadata-specification): Per-message metadata as defined by the protocol.
- [Version](#41-version-evolution): The protocol version identifier.
- [TIP](tips/tip-0001.md): tightbeam Improvement Proposal.
- [Information Theory Properties](#31-information-theory-properties)

Additional terms introduced by proposals MUST be defined in their respective TIPs.

## 3. Architecture

### 3.1 Information Theory Properties

tightbeam implements high-fidelity information transmission through the 
following properties:

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
- **MATRIX**: N×N matrix-encoded control flags
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
  - OPTIONAL: Matrix control (NxN matrix flags)

### 4.1.1 SecurityProfile Trait Architecture

tightbeam uses a trait-based security profile system that separates compile-time 
algorithm constraints from runtime protocol behavior.

#### Design Principles

The `SecurityProfile` trait defines a pure metadata layer that declares algorithm 
identifiers (OIDs) for cryptographic operations:

```rust
pub trait SecurityProfile {
	type DigestOid: AssociatedOid;
	type AeadOid: AssociatedOid + AeadKeySize;
	type SignatureAlg: SignatureAlgorithmIdentifier;
	const KEY_WRAP_OID: Option<ObjectIdentifier>;
}
```

#### Role-Based Provider Traits

tightbeam separates cryptographic concerns through specialized provider traits:

- **`DigestProvider`**: Hash/digest operations (SHA-256, SHA3-256, etc.)
- **`AeadProvider`**: Authenticated encryption (AES-GCM variants)
- **`SigningProvider`**: Signature generation and verification (ECDSA, Ed25519)
- **`KdfProvider`**: Key derivation functions (HKDF)
- **`CurveProvider`**: Elliptic curve operations (secp256k1, P-384)

These traits compose into `CryptoProvider`, allowing components to specify only 
the cryptographic capabilities they require rather than depending on the full provider.

### 4.1.2 Security Profile Types

Applications implement the `SecurityProfile` trait to define their own 
cryptographic algorithm constraints:

#### Implementing Custom Profiles

```rust
// Example: Custom application profile
pub struct MyAppProfile;

impl SecurityProfile for MyAppProfile {
	type DigestOid = Sha3_256;
	type AeadOid = Aes256GcmOid;
	type SignatureAlg = Secp256k1Signature;
	const KEY_WRAP_OID: Option<ObjectIdentifier> = Some(AES_256_WRAP_OID);
}
```

#### Built-in Default Profile

tightbeam provides `TightbeamProfile` as a reference implementation and default:

```rust
pub struct TightbeamProfile;

impl SecurityProfile for TightbeamProfile {
	type DigestOid = Sha3_256;
	type AeadOid = Aes256GcmOid;
	type SignatureAlg = Secp256k1Signature;
	const KEY_WRAP_OID: Option<ObjectIdentifier> = Some(AES_256_WRAP_OID);
}
```

Applications can define multiple profiles for different security contexts (e.g., 
`HighSecurityProfile`, `LegacyProfile`, `QuantumResistantProfile`) and use them 
with different message types.

### 4.1.3 Numeric Security Levels

tightbeam supports numeric security levels (separate from SecurityProfile types) 
that enforce security requirements without algorithm OID validation:

- **Level 1**: Requires confidentiality + non-repudiation (V1+)
  - Use case: FIPS-compliant deployments
  - Reference: TLS 1.3 cipher suites (RFC 8446)

- **Level 2**: Requires confidentiality + non-repudiation (V1+)
  - Use case: High-security applications
  - Reference: NSA Suite B equivalent (RFC 6460, NIST SP 800-56A)

**Important**: Numeric levels (1, 2) only enforce security requirements 
(must encrypt, must sign, etc.). They do NOT enable compile-time algorithm OID 
validation. For OID validation, use type-based profiles (see section 4.1.4).

### 4.1.4 Message-Level Security Requirements

tightbeam supports run-time security profile enforcement at the message type 
level through the `Message` trait and compile-time security enforcement at 
the message composition level:

```rust
pub trait Message: /* trait bounds */ {
	const MIN_VERSION: Version = Version::V0;
	const MUST_BE_NON_REPUDIABLE: bool = false;
	const MUST_BE_CONFIDENTIAL: bool = false;
	const MUST_BE_COMPRESSED: bool = false;
	const MUST_BE_PRIORITIZED: bool = false;
	const MUST_HAVE_MESSAGE_INTEGRITY: bool = false;
	const MUST_HAVE_FRAME_INTEGRITY: bool = false;
	const HAS_PROFILE: bool = false;
	type Profile: SecurityProfile;
}
```

#### Profile-Based Algorithm Constraints

**HAS_PROFILE**: Controls whether the message type enforces algorithm constraints
- When `false` (default): Message uses `TightbeamProfile` but does not enforce algorithm OID matching
- When `true`: FrameBuilder validates that all cryptographic operations use algorithms from the message's `Profile` type

**Profile Type**: Specifies which `SecurityProfile` implementation constrains algorithm selection
- Defaults to `TightbeamProfile` if not specified
- Can be set to any type implementing `SecurityProfile`
- Affects compile-time validation when `HAS_PROFILE = true`

**Algorithm Validation**: When `HAS_PROFILE = true`, the following validations occur at compile time:
- Digest algorithms must match `<Profile::DigestOid as AssociatedOid>::OID`
- AEAD ciphers must match `<Profile::AeadOid as AssociatedOid>::OID`
- Signature algorithms must match `<Profile::SignatureAlg as SignatureAlgorithmIdentifier>::ALGORITHM_OID`

This ensures that message types with specific security profiles can only be 
composed with compatible cryptographic algorithms, preventing algorithm 
substitution attacks.

#### Security Requirement Semantics
- When a message type specifies `MUST_BE_NON_REPUDIABLE = true`, the Frame MUST include a `nonrepudiation` field
- When a message type specifies `MUST_BE_CONFIDENTIAL = true`, the Frame's metadata MUST include a `confidentiality` field
- When a message type specifies `MUST_BE_COMPRESSED = true`, the Frame's metadata `compactness` field MUST NOT be `none`
- When a message type specifies `MUST_BE_PRIORITIZED = true`, the Frame's metadata MUST include a `priority` field (V2+ only)
- The Frame's `version` field MUST be >= the message type's `MIN_VERSION` requirement

#### Profile Validation in FrameBuilder

When composing frames with `FrameBuilder`, profile constraints are enforced at 
compile time if the message type has `HAS_PROFILE = true`:

```rust
// Example: Message with custom profile
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
#[beam(profile(MyAppProfile))]
struct SecureMessage { data: Vec<u8> }

// FrameBuilder validates algorithm OIDs match MyAppProfile
let frame = compose::<SecureMessage>(Version::V1)
	.with_message(msg)
	.with_id(b"msg-001")
	.with_order(timestamp)
	.with_cipher::<Aes256GcmOid, _>(&cipher)        // ✓ Matches MyAppProfile::AeadOid
	.with_signer::<Secp256k1Signature, _>(&signer)  // ✓ Matches MyAppProfile::SignatureAlg
	.build()?;
```

**Validation Rules**:
- `with_message_hasher::<D>()` validates `D::OID == Profile::DigestOid::OID`
- `with_witness_hasher::<D>()` validates `D::OID == Profile::DigestOid::OID`
- `with_cipher::<C, _>()` validates `C::OID == Profile::AeadOid::OID`
- `with_signer::<S, _>()` validates `S::ALGORITHM_OID == Profile::SignatureAlg::ALGORITHM_OID`

**Error Handling**: Algorithm mismatches return `TightBeamError::UnexpectedAlgorithmForProfile` with 
expected and received OIDs for debugging.

#### Implementation Enforcement
These requirements are enforced at:
- **Compile Time**: Type system prevents composition of messages that don't meet requirements
- **Runtime Validation**: Frame validation ensures expected frame shape to meet requirements
- **Profile Compliance**: Security profiles can reference message types with specific requirements

#### Derive Macro Usage

The `#[derive(Beamable)]` macro automatically implements the `Message` trait:

```rust
// This derive macro...
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
#[beam(min_version = "V1", nonrepudiable, confidential)]
struct PaymentInstruction { /* fields */ }

// ...expands to:
impl Message for PaymentInstruction {
	const MIN_VERSION: Version = Version::V1;
	const MUST_BE_NON_REPUDIABLE: bool = true;
	const MUST_BE_CONFIDENTIAL: bool = true;

	const MUST_BE_COMPRESSED: bool = false;
	const MUST_BE_PRIORITIZED: bool = false;
	const MUST_HAVE_MESSAGE_INTEGRITY: bool = false;
	const MUST_HAVE_FRAME_INTEGRITY: bool = false;
}
```

**Supported attributes:**
- `#[beam(message_integrity)]` - Sets `MUST_HAVE_MESSAGE_INTEGRITY = true`
- `#[beam(frame_integrity)]` - Sets `MUST_HAVE_FRAME_INTEGRITY = true`
- `#[beam(nonrepudiable)]` - Sets `MUST_BE_NON_REPUDIABLE = true`
- `#[beam(confidential)]` - Sets `MUST_BE_CONFIDENTIAL = true`
- `#[beam(compressed)]` - Sets `MUST_BE_COMPRESSED = true`
- `#[beam(prioritized)]` - Sets `MUST_BE_PRIORITIZED = true`
- `#[beam(min_version = "V1")]` - Sets minimum protocol version

**Profile attributes** (STABLE):
- `#[beam(profile = 1)]` - Numeric security level 1
  - Automatically sets: `confidential`, `nonrepudiable`, `min_version = "V1"`
  - Does NOT enable algorithm OID validation
  - Does NOT set `HAS_PROFILE = true`
  - Does NOT use any SecurityProfile type
- `#[beam(profile = 2)]` - Numeric security level 2
  - Automatically sets: `confidential`, `nonrepudiable`, `min_version = "V1"`
  - Does NOT enable algorithm OID validation
  - Does NOT set `HAS_PROFILE = true`
  - Does NOT use any SecurityProfile type
- `#[beam(profile(TypeName))]` - Type-based profile with algorithm enforcement
  - Sets `HAS_PROFILE = true` and `type Profile = TypeName`
  - Enables compile-time algorithm OID validation in FrameBuilder
  - `TypeName` must be a type implementing `SecurityProfile` (e.g., `TightbeamProfile`, or your custom profile)
  - Does NOT automatically set security requirements (must specify separately)

**Critical distinction**:
- **Numeric levels (1, 2)**: Enforce what security features must be present (encryption, signing, etc.)
- **Type-based profiles**: Enforce which specific algorithms must be used (based on your SecurityProfile implementation)
- These are independent but **cannot be mixed**: `#[beam(profile = 1, profile(MyAppProfile))]` is invalid
- To get both requirement enforcement AND algorithm validation, use: `#[beam(profile(MyAppProfile), confidential, nonrepudiable, min_version = "V1")]`

**Profile attribute rules**:
- Numeric levels (1-2) override individual security flags
- Cannot specify both numeric (`profile = N`) and type-based (`profile(Type)`)
- Type-based profiles DO NOT automatically set security requirements - you must add them explicitly

#### Example Message Types

```rust
use tightbeam::Beamable;
use der::Sequence;

// Example 1: Numeric security level (requirements only, no OID validation)
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
#[beam(profile = 1)]
struct PaymentInstruction {
	account_from: String,
	account_to: String,
	amount: u64,
}
// Expands to: MUST_BE_CONFIDENTIAL = true, MUST_BE_NON_REPUDIABLE = true, MIN_VERSION = V1
// HAS_PROFILE = false (default), Profile = TightbeamProfile (default)
// No compile-time algorithm OID validation

// Example 2: Type-based profile (algorithm OID validation, no auto-requirements)
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
#[beam(profile(MyAppProfile))]
struct SecureMessage {
	data: Vec<u8>,
}
// Expands to: HAS_PROFILE = true, type Profile = MyAppProfile
// No automatic security requirements! Must add separately if needed.
// Enables compile-time OID validation in FrameBuilder

// Example 3: Type-based profile + explicit requirements (both enforcement types)
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
#[beam(profile(MyAppProfile), confidential, nonrepudiable, min_version = "V1")]
struct HighSecurityTransfer {
	dataset_id: String,
	encrypted_payload: Vec<u8>,
}
// Expands to: HAS_PROFILE = true, type Profile = MyAppProfile
// MUST_BE_CONFIDENTIAL = true, MUST_BE_NON_REPUDIABLE = true, MIN_VERSION = V1
// Both requirement enforcement AND algorithm OID validation
```

### 4.1.5 CryptoProvider System

The `CryptoProvider` trait composes role-based provider traits to bind concrete 
cryptographic implementations to `SecurityProfile` metadata:

```rust
pub trait CryptoProvider: 
	Default + Clone + 
	DigestProvider + 
	AeadProvider + 
	SigningProvider + 
	KdfProvider + 
	CurveProvider 
{
	type Profile: SecurityProfile + Default;
	fn profile(&self) -> &Self::Profile;
}
```

**DefaultCryptoProvider**: Reference implementation combining:
- **Digest**: SHA3-256 (Keccak-based hash)
- **AEAD**: AES-256-GCM (authenticated encryption)
- **Signature**: secp256k1 ECDSA (Bitcoin/Ethereum curve)
- **KDF**: HKDF-SHA3-256 (key derivation)
- **Curve**: secp256k1 (elliptic curve operations)

**Role-based traits** enable flexible bounds:
```rust
// Function only requires digest capability
fn hash_data<P: DigestProvider>(provider: &P, data: &[u8]) -> DigestInfo {
	let digestor = provider.as_digestor();
	digestor(data).unwrap()
}
```

This design allows components to depend on specific cryptographic capabilities 
rather than requiring the full `CryptoProvider` interface.

### 4.2 Frame Structure

All versions MUST include:
- Identifier
- Frame Version
- Order
- Message payload (bytecode)

All versions MAY include:
- Frame integrity (digest of envelope: version + metadata; excludes message)
- Non-repudiation (cryptographic signature)

### 4.3 Metadata Specification

```rust
#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
pub struct Metadata {
	// Core fields (V0+)
	pub id: Vec<u8>,
	pub order: u64,
	#[asn1(optional = "true")]
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	pub compactness: Option<CompressedData>,

	// V1+ fields
	#[asn1(context_specific = "0", optional = "true")]
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	pub integrity: Option<DigestInfo>,
	#[asn1(context_specific = "1", optional = "true")]
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	pub confidentiality: Option<EncryptedContentInfo>,

	// V2+ fields
	#[asn1(context_specific = "2", optional = "true")]
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	pub priority: Option<MessagePriority>,
	#[asn1(context_specific = "3", optional = "true")]
	pub lifetime: Option<u64>,
	#[asn1(context_specific = "4", optional = "true")]
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	pub previous_frame: Option<DigestInfo>,
	#[asn1(context_specific = "5", optional = "true")]
	pub matrix: Option<Asn1Matrix>,
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
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	pub integrity: Option<DigestInfo>,
	#[asn1(context_specific = "1", optional = "true")]
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	pub nonrepudiation: Option<SignerInfo>,
}
```

## 5. ASN.1 Formal Specification

This section provides the complete ASN.1 definitions for all tightbeam protocol 
structures, encoded using Distinguished Encoding Rules (DER).

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
	critical(0),  -- System/security alerts, emergency notifications
	top(1),       -- High-priority interactive traffic, real-time responses
	high(2),      -- Important business messages, time-sensitive data
	normal(3),    -- Standard message traffic (default)
	low(4),       -- Non-urgent notifications, background updates
	bulk(5),      -- Batch processing, large data transfers, logs
	heartbeat(6)  -- Keep-alive signals, periodic status updates
}
```

### 5.2 Cryptographic Structures

tightbeam uses standard CMS (Cryptographic Message Syntax) structures from
RFC 5652 and PKCS standards for cryptographic operations.

#### Digest Information ([RFC 3447](https://datatracker.ietf.org/doc/html/rfc3447) - PKCS #1)

From RFC 3447 Section 9.2:

```asn1
DigestInfo ::= SEQUENCE {
	digestAlgorithm  AlgorithmIdentifier,
	digest           OCTET STRING
}
```

Used in `Metadata.integrity`, `Metadata.previous_frame`, and `Frame.integrity` fields.

#### Encrypted Content Information ([RFC 5652](https://datatracker.ietf.org/doc/html/rfc5652) - CMS)

From RFC 5652 Section 6.1:

```asn1
EncryptedContentInfo ::= SEQUENCE {
	contentType                 ContentType,
	contentEncryptionAlgorithm  ContentEncryptionAlgorithmIdentifier,
	encryptedContent            [0] IMPLICIT OCTET STRING OPTIONAL
}
```

Used in `Metadata.confidentiality` field for message-level encryption.

#### Signer Information ([RFC 5652](https://datatracker.ietf.org/doc/html/rfc5652) - CMS)

From RFC 5652 Section 5.3:

```asn1
SignerInfo ::= SEQUENCE {
	version                    CMSVersion,
	sid                        SignerIdentifier,
	digestAlgorithm            DigestAlgorithmIdentifier,
	signedAttrs                [0] IMPLICIT SignedAttributes OPTIONAL,
	signatureAlgorithm         SignatureAlgorithmIdentifier,
	signature                  SignatureValue,
	unsignedAttrs              [1] IMPLICIT UnsignedAttributes OPTIONAL
}
```

Used in `Frame.nonrepudiation` field for digital signatures.

#### Compressed Data ([RFC 3274](https://datatracker.ietf.org/doc/html/rfc3274) - CMS)

From RFC 3274 Section 2:

```asn1
CompressedData ::= SEQUENCE {
	version                    CMSVersion,
	compressionAlgorithm       CompressionAlgorithmIdentifier,
	encapContentInfo           EncapsulatedContentInfo
}
```

Used in `Metadata.compactness` field for message compression.

#### Matrix (TightBeam-specific)
```asn1
Matrix ::= SEQUENCE {
	n     INTEGER (1..255),
	data  OCTET STRING (SIZE(1..(255*255)))  -- MUST be exactly n*n octets; row-major
}
```

### 5.4 Message Structure

#### Metadata Structure
```asn1
Metadata ::= SEQUENCE {
	-- Core fields (V0+)
	id               OCTET STRING,
	order            INTEGER,
	compactness      CompressedData OPTIONAL,

	-- V1+ fields (context-specific tags)
	integrity        [0] DigestInfo OPTIONAL,
	confidentiality  [1] EncryptedContentInfo OPTIONAL,

	-- V2+ fields (context-specific tags)
	priority         [2] MessagePriority OPTIONAL,
	lifetime         [3] INTEGER OPTIONAL,
	previous_frame   [4] DigestInfo OPTIONAL,
	matrix           [5] Matrix OPTIONAL
}
```

#### Complete Frame Structure
```asn1
Frame ::= SEQUENCE {
	version         Version,
	metadata        Metadata,
	message         OCTET STRING,
	integrity       [0] DigestInfo OPTIONAL,
	nonrepudiation  [1] SignerInfo OPTIONAL
}
```

### 5.5 External Dependencies

The protocol relies on standard ASN.1 structures from established RFCs.

#### Algorithm Identifier ([RFC 5652](https://datatracker.ietf.org/doc/html/rfc5652))

From RFC 5652 Section 10.1.2:

```asn1
AlgorithmIdentifier ::= SEQUENCE {
	algorithm   OBJECT IDENTIFIER,
	parameters  ANY DEFINED BY algorithm OPTIONAL
}
```

Implemented via the [spki](https://crates.io/crates/spki) crate.

#### Compression Algorithm Identifiers ([RFC 3274](https://datatracker.ietf.org/doc/html/rfc3274))

From RFC 3274 Section 2:

```asn1
CompressionAlgorithmIdentifier ::= AlgorithmIdentifier

-- Standard compression algorithm OID
id-alg-zlibCompress OBJECT IDENTIFIER ::= { iso(1) member-body(2)
	us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 8 }

-- TightBeam also supports zstd compression
id-alg-zstdCompress OBJECT IDENTIFIER ::= { 1 3 6 1 4 1 50274 1 1 }
```

Implemented via the [cms](https://crates.io/crates/cms) crate.

#### Hash and Signature Algorithms ([RFC 5246](https://datatracker.ietf.org/doc/html/rfc5246))

From RFC 5246 Section 7.4.1.4.1 (informative):

```asn1
enum {
	none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
	sha512(6), (255)
} HashAlgorithm;

enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
	SignatureAlgorithm;
```

Note: TightBeam implementations SHOULD use SHA-256 or stronger hash algorithms 
and SHOULD NOT use MD5 or SHA-1 for new deployments.

### 5.6 Encoding Rules

- **Encoding**: Distinguished Encoding Rules (DER) as specified in [ITU-T X.690](https://www.itu.int/rec/T-REC-X.690)
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
- OPTIONAL: `priority`, `lifetime`, ``previous_frame``, `matrix`

### 5.8 Semantic Constraints

#### 5.8.1 Message Ordering
- `order` field MUST be monotonically increasing within a message sequence
- `order` values SHOULD be based on reliable timestamp sources
- Duplicate `order` values within the same `id` namespace MUST be rejected

#### 5.8.2 Compression Requirements
- When `compactness` is present (not `None`), the `message` field MUST contain 
compressed data encoded as `CompressedData` per RFC 3274
- The `encapContentInfo` within `CompressedData` MUST use the `id-data` content 
type OID if the compressed data does not conform to any recognized content type
- Compression algorithm identifiers MUST be valid OIDs (e.g., 
`id-alg-zlibCompress` for zlib, custom OIDs for zstd -- tightbeam uses 
1.2.840.113549.1.9.16.3 pending formal assignment)
- Compression level parameters, when specified in 
`compressionAlgorithm.parameters`, MUST be within algorithm-specific valid ranges

#### 5.8.3 Integrity Semantics: Order of Operations

This section clarifies the relationship between message integrity and frame 
integrity. The goals are: (1) unambiguous validation semantics, and (2) clear 
data retention choices.

- Message Integrity (MI): MI MUST be computed over the message payload bytes. 
When present at the metadata level (i.e., `Metadata.integrity`), MI MUST bind 
the message body.
- Frame Integrity (FI): FI MUST be computed over the envelope only (version + 
metadata; it MUST exclude the message) using DER-canonical encoding. FI MUST 
bind the envelope around the message and the metadata itself.

Important properties:
- FI alone MUST NOT be used to prove message content correctness; it ONLY proves 
the integrity of the envelope (version + metadata).
- MI MUST be used to prove message content correctness. Because MI lives in 
metadata and FI commits to the envelope that contains that metadata, FI 
therefore witnesses MI. When FI is authenticated (e.g., covered by a signature 
via nonrepudiation or finalized via consensus), any tampering with MI MUST cause 
the authenticated FI validation to fail. Receivers SHOULD treat the pair 
(valid MI, authenticated FI) as sufficient evidence that both envelope and 
message are intact. Note: an in-band, unsigned FI MUST NOT be relied upon to 
prevent an active attacker from changing both MI and FI.

Post-consensus retention (optional, system-dependent):
- If an external consensus or commit layer has finalized a frame that included 
valid MI and FI, implementations having already processed the message and
verifying both message and frame integrity MAY discard the message body after 
consensus if application semantics permit.
- Implementations MUST retain the minimal audit artifacts: metadata (including 
MI), FI (if used), and any application-required identifiers/indices. Anyone 
possessing the exact original body can recompute MI and compare against the 
retained MI/FI to verify authenticity later.

##### Message Integrity with AEAD

When confidentiality is enabled, tightbeam implementations MUST use Authenticated 
Encryption with Associated Data (AEAD) ciphers. This requirement is enforced at 
the type system level through trait bounds:

```rust
pub fn with_cipher<C, Cipher>(mut self, cipher: &Cipher) -> Self
where
    Cipher: Aead + Clone + 'static,  // AEAD trait bound required
```

This design ensures MI over plaintext is cryptographically sound:

- **Type-level guarantee**: Non-AEAD ciphers cannot be used (compile-time enforcement)
- **Ciphertext authentication**: AEAD provides built-in authentication tags that prove 
the ciphertext has not been tampered with (e.g., AES-GCM, ChaCha20-Poly1305)
- **MI purpose**: Proves the decrypted plaintext matches the original message content
- **Layered security**: AEAD prevents ciphertext tampering, MI proves plaintext 
correctness, FI witnesses MI in metadata, signatures cover the entire frame

This approach is cryptographically equivalent to Encrypt-then-MAC when AEAD is 
enforced, as AEAD ciphers provide both confidentiality and authenticity of the 
ciphertext. An attacker cannot modify the ciphertext (AEAD authentication fails), 
cannot modify MI without breaking FI (when FI is signed/consensus-finalized), 
and cannot decrypt without the key.

#### 5.8.4 Previous Frame Chaining
- The ``previous_frame`` field creates a cryptographic hash chain linking frames
- Each frame's hash commits to all previous history through transitive hashing
- This enables:
  - **Causal Ordering**: Frames carry proof of their position in the sequence
  - **Tamper Detection**: Any modification to a previous frame breaks all subsequent hashes
  - **Replay Protection**: Receivers can detect out-of-sequence or duplicate frames
  - **Fork Detection**: Multiple frames with the same ``previous_frame`` indicate reality branching
  - **Stateless Verification**: Frame ancestry can be verified without storing the entire chain
- Implementations MAY store any frames to enable full chain reconstruction to their desired root

#### 5.8.5 Nonrepudiation Coverage and Binding

This section specifies what the nonrepudiation signature covers when present.

- Signature scope (MUST): The signature MUST be computed over the canonical 
DER encoding of the Frame fields EXCLUDING the `nonrepudiation` field itself; 
concretely, it MUST cover:
	- `version`
	- `metadata` (including MI when present)
	- `message`
	- `integrity` (FI) when present

- Security consequence: Any modification to version, metadata (including MI), 
message, or FI invalidates the signature. This yields the transitive binding:
	Signature → FI (envelope) → MI (in metadata) → Message body

- Rationale: Because FI commits to the envelope that contains MI, and the 
signature authenticates FI along with the rest of the envelope and message, 
honest nodes can reject any post-signature tampering to MI, FI, or the message body.

#### 5.8.6 Security Property Chain

When all security features are enabled (MI, FI, AEAD encryption, and signatures), 
the complete security property chain operates as follows:

**Sender operations (in order):**
1. Compute MI over plaintext message
- Store DigestInfo in Metadata
2. Optionally compress the plaintext message
- Store CompressedData in Metadata
3. Encrypt with AEAD cipher → produce authenticated ciphertext
- Store EncryptedContentInfo in Metadata
- Store ciphertext in Frame.message
4. Compute FI over envelope (Version + Metadata containing MI)
- Store DigestInfo in Frame
5. Sign the complete frame (Version + Metadata + ciphertext + FI) 
- Store SignerInfo in Frame

**Receiver verification (in order):**
1. Verify signature over complete Frame + Message
2. Verify FI over envelope (Version + Metadata)
3. Verify AEAD authentication tag on ciphertext
4. Decrypt ciphertext to recover plaintext
5. Verify MI matches the decrypted plaintext

This layered approach provides defense in depth:
- AEAD ensures ciphertext authenticity (prevents tampering with encrypted data)
- FI ensures envelope integrity (prevents tampering with metadata including MI)
- MI ensures message integrity (proves plaintext correctness after decryption)
- Signature ensures nonrepudiation (cryptographically binds sender to entire frame)

Any tampering at any layer causes verification to fail, ensuring end-to-end 
integrity and authenticity guarantees.

### 5.9 What is the Matrix?

The Matrix is a compact, flexible structure for transmitting state information. 
It uses a grid of cells, encoded with ASN.1 DER, to represent application-defined 
states with perfect structure, aligning with tightbeam's core constraint: **I(t) ∈ (0,1)**.

#### 5.9.1 Why Use the Matrix?

The matrix enables applications to:
- **Pack Dense State**: Store up to 255×255 values (0-255) in ~63.5 KB.
- **Support Evolution**: Extensible design ensures backward compatibility.
- **Ensure Fidelity**: Deterministic encoding and validation constrain I(t) ∈ (0,1).
- **Enable Advanced Modeling**: Combine with `previous_frame` for causal state tracking.

#### 5.9.2 The Simple View

The matrix is a 2D grid where each cell holds a number from 0 to 255, with
meanings defined by the application (e.g., flags, counters, states, functions).
Mathematically, it is a 2D array **M** of size **n × n** (**n ≤ 255**),
with elements **M[r,c] ∈ {0, ..., 255}**.
Maximum entropy for a full matrix is **H = n² log₂ 256 = 8n²** bits,
assuming uniform distribution. Sparse matrices, using fewer cells, have lower
entropy (e.g., 8k bits for k used cells).

**Key Dimensions**:
1. **Row (r)**: 0 to **n-1**, vertical position.
2. **Column (c)**: 0 to **n-1**, horizontal position.
3. **Value (M[r,c])**: 0 to 255, application-defined dimension.

**Example**: A 2x2 matrix for a game state:
- **M[0,0] = 1** (Player 1 at (0,0))
- **M[1,1] = 2** (Player 2 at (1,1))
- **M[0,1] = 0, M[1,0] = 0** (empty)
- Matrix coordinates can encode structured data like public keys.

#### 5.9.3 Wire Format (Technical Details)

The matrix uses ASN.1 DER for deterministic serialization.

**ASN.1 Schema (full matrix)**:
```asn1
Matrix ::= SEQUENCE {
    n INTEGER (1..255),                 -- Grid size (n x n)
    data OCTET STRING (SIZE(1..65025))  -- Row-major cell values
}
```

**Encoding & Performance**:
- **Layout**: Row-major order, cell (r,c) at index **r · n + c**.
- **Size**: **n ∈ [1, 255]**, data length **n²**, max 65,025 bytes (~63.5 KB).
- **State Space**: **256^(n²)** possible matrices.
- **Entropy**: **H = 8n²** bits (uniform distribution).
- **Complexity**: Encoding/decoding: O(n²). Length validation: O(1).

#### 5.9.4 Usage Rules

To constrain **I(t) ∈ (0,1)**:

- **Encoding**: Encoders MUST set data.len = n², filling cells with values 0-255.
- **Decoding**: Decoders MUST reject matrices where data.len != n² or values exceed 255.
- **Semantics**: Applications MUST define value meanings.
- **Unspecified Cells**: Receivers SHOULD ignore non-zero values in undefined cells to support evolvability.
- **Absent Matrix**: If the matrix field is omitted, applications MAY assume a default state.

#### 5.9.5 Example: Flag System

Set diagonal flags in a 3x3 matrix:

```rust
use tightbeam::Matrix;

// Full 3x3 matrix
let mut matrix = Matrix::<3>::default();
matrix.set(0, 0, 1)?; // Feature A: enabled
matrix.set(1, 1, 1)?; // Feature B: enabled
matrix.set(2, 2, 0)?; // Feature C: disabled

// Embed in a frame
let frame = compose! {
    V1: id: "config-001",
        order: 1000,
        message: my_message,
        matrix: Some(matrix)
}?;
```

**Visualization (full)**:
```
[1, 0, 0]
[0, 1, 0]
[0, 0, 0]
```

This supports up to 255 flags, extensible by adding new diagonal entries.
For structured data, use non-diagonal cells (e.g., **M[0,1] = 10** for a
count, or map public keys to coordinate regions).

#### 5.9.6 Advanced: Modeling with Matrix and Previous Frame

The matrix, combined with the `previous_frame` field, enables sophisticated 
state tracking, modeled as a directed acyclic graph (DAG) of state transitions. 
Mathematically, frames form a Markov chain where each matrix **M_t** at time
t depends on **M_{t-1}**, linked via cryptographic hashes in `previous_frame`.

**State Evolution**:
- **Snapshots**: Each matrix **M_t** is a state snapshot, with entropy up to **8n²** bits.
- **Causal Links**: `previous_frame` hashes ensure a DAG, where **M_t → M_{t-1}** via hash verification.
- **Transitions**: Changes in **M_t[r,c]** across frames model state updates.
- **Branching**: Multiple frames sharing a `previous_frame` but differing in **M_t** represent alternative states.

**Mathematical Model**:
Applications define a transition probability **P(M_t | M_{t-1})**,
where changes reflect logic or noise.
For example, **I(t) = I(M_t; M_{t-1}) / H(M_t) ∈ (0,1)** may measure
fidelity based on shared state, but I(t) is application-defined, constrained
by hash consistency and partial state recovery.

#### 5.9.7 Summary

The matrix supports flexible state representation, from simple flags to 
structured data encoding allowing for dynamic computation.

### 5.10 Complete ASN.1 Module

```asn1
tightbeam-Protocol-V2 DEFINITIONS EXPLICIT TAGS ::= BEGIN

-- Import standard structures from CMS and PKCS
IMPORTS
	AlgorithmIdentifier FROM PKCS-1
		{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) },
	DigestInfo FROM PKCS-1
		{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) },
	CompressedData FROM CMS-2004
		{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) modules(0) cms-2004(24) },
	EncryptedContentInfo, SignerInfo FROM CMS-2004
		{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) modules(0) cms-2004(24) };

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

-- TightBeam-specific matrix structure
Matrix ::= SEQUENCE {
	n     INTEGER (1..255),
	data  OCTET STRING (SIZE(1..(255*255)))  -- MUST be exactly n*n octets; row-major
}

-- Core message structures
Metadata ::= SEQUENCE {
	id               OCTET STRING,
	order            INTEGER,
	compactness      CompressedData OPTIONAL,
	integrity        [0] DigestInfo OPTIONAL,
	confidentiality  [1] EncryptedContentInfo OPTIONAL,
	priority         [2] MessagePriority OPTIONAL,
	lifetime         [3] INTEGER OPTIONAL,
	previous_frame   [4] DigestInfo OPTIONAL,
	matrix           [5] Matrix OPTIONAL
}

Frame ::= SEQUENCE {
	version         Version,
	metadata        Metadata,
	message         OCTET STRING,
	integrity       [0] DigestInfo OPTIONAL,
	nonrepudiation  [1] SignerInfo OPTIONAL
}

END
```

## 6. Implementation

### 6.1 Requirements

Implementations MUST provide:
- Memory safety AND ownership guarantees (Rust)
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
		let has_encryption = self.encryptor.is_some();
		if T::MUST_BE_CONFIDENTIAL && !has_encryption {
			return Err(TightBeamError::MissingEncryptionInfo);
		}

		// Check if signature is set when required
		let has_signer = self.signer.is_some();
		if T::MUST_BE_NON_REPUDIABLE && !has_signer {
			return Err(TightBeamError::MissingSignatureInfo);
		}

		// Check if compression is set when required
		let has_compression = self.compressor.is_some();
		if T::MUST_BE_COMPRESSED && !has_compression {
			return Err(TightBeamError::MissingCompressedData);
		}

		let has_message_integrity = self.metadata_builder.has_hash();
		if T::MUST_HAVE_MESSAGE_INTEGRITY && !has_message_integrity {
			return Err(TightBeamError::MissingDigestInfo);
		}

		let has_frame_integrity = self.witness.is_some();
		if T::MUST_HAVE_FRAME_INTEGRITY && !has_frame_integrity {
			return Err(TightBeamError::MissingDigestInfo);
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

tightbeam MUST operate over ANY transport protocol:
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

## 7. Security Considerations

### 7.1 Cryptographic Requirements

- Integrity MUST use cryptographically secure hash functions
- Confidentiality MUST use authenticated encryption (AEAD)
- Non-repudiation MUST use digital signatures with secure key pairs

### 7.2 Version Security

- V0: No security features
- V1: Optional integrity and confidentiality support
- V2: Enhanced with priority, lifetime, state chaining, and matrix controls

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

#### 7.4.3 Algorithm Identifier Management
- **OID Registry**: Use standard algorithm OIDs from IANA/ITU-T
- **Parameter Validation**: Enforce minimum key sizes and parameters
- **Algorithm Negotiation**: Support for algorithm capability discovery
- **Security Policy**: Configurable algorithm allow/deny lists

## 8. Transport Layer & Handshake Protocols

### 8.1 Transport Architecture

The tightbeam transport layer provides a pluggable framework for moving bytes
between endpoints while enforcing security policies. The transport layer is
responsible for the following:
- Establishing connections
- Sending and receiving messages
- Enforcing security policies
- Managing cryptographic state

#### 8.1.1 Concept: Design Principles


The transport layer follows a trait-based architecture that separates concerns:

1. **Protocol abstraction**: `Protocol` trait defines bind/connect operations
2. **Message I/O**: `MessageIO` trait handles frame serialization and wire protocol
3. **Policy enforcement**: `MessageEmitter` and `MessageCollector` traits add gate and retry policies
4. **Encryption support**: `EncryptedProtocol` and `EncryptedMessageIO` traits enable secure transports

**Design Goals:**
- **Transport Independence**: Same application code works over TCP, UDP, Unix sockets, etc.
- **Composable Policies**: Gate and retry policies attach without modifying transport logic
- **Security by Default**: Encryption and certificate validation built into the protocol layer
- **Type Safety**: Rust's type system enforces correct usage patterns at compile time
- **Zero-Cost Abstractions**: Trait-based design compiles to efficient machine code
- **Zero-Copy**: No unnecessary data cloning for performance

#### 8.1.2 Specification: Core Transport Traits

```rust
/// Protocol abstraction for binding and connecting
pub trait Protocol {
	type Listener: Send;
	type Stream: Send;
	type Transport: Send;
	type Address: TightBeamAddress;
	
	fn bind(addr: Self::Address) 
		-> impl Future<Output = Result<(Self::Listener, Self::Address)>>;
	fn connect(addr: Self::Address) 
		-> impl Future<Output = Result<Self::Stream>>;
}

/// Base message I/O operations
pub trait MessageIO {
	async fn read_envelope(&mut self) -> TransportResult<Vec<u8>>;
	async fn write_envelope(&mut self, buffer: &[u8]) -> TransportResult<()>;
	async fn read_decoded_envelope(&mut self) -> TransportResult<TransportEnvelope>;
}

/// Policy-aware message collection (server-side)
pub trait MessageCollector: MessageIO {
	type CollectorGate: GatePolicy;
	
	async fn collect_message(&mut self) -> TransportResult<(Frame, TransitStatus)>;
	async fn send_response(&mut self, status: TransitStatus, message: Option<Frame>) 
		-> TransportResult<()>;
}

/// Policy-aware message emission (client-side)
pub trait MessageEmitter: MessageIO {
	type EmitterGate: GatePolicy;
	type RestartPolicy: RestartPolicy;
	
	async fn emit(&mut self, message: Frame, attempt: Option<usize>) 
		-> TransportResult<Option<Frame>>;
}
```

**Trait Hierarchy:**
```text
Protocol
  └── EncryptedProtocol (adds bind_with for certificates)

MessageIO (read/write envelopes)
  ├── MessageCollector (server: policies + collect/respond)
  └── MessageEmitter (client: policies + emit/retry)
       └── EncryptedMessageIO (adds encryption/decryption)
```

**Encryption Support Traits:**

```rust
pub trait EncryptedProtocol: Protocol {
	/// Bind listener with transport encryption configuration
	fn bind_with(
		addr: Self::Address,
		config: TransportEncryptionConfig,
	) -> impl Future<Output = Result<(Self::Listener, Self::Address)>>;
}

pub struct TransportEncryptionConfig {
	pub certificate: Certificate,
	pub signatory: ServerKeyManager,
	pub client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	pub handshake_timeout: Duration,
	// ... additional configuration fields
}
```

The `EncryptedMessageIO` trait adds encryption/decryption operations to message I/O:

```rust
pub trait EncryptedMessageIO: MessageIO {
	fn encryptor(&self) -> TransportResult<&RuntimeAead>;
	fn decryptor(&self) -> TransportResult<&RuntimeAead>;
	
	async fn relay_message(&mut self) -> TransportResult<TransportEnvelope>;
	async fn send_envelope(&mut self, envelope: &TransportEnvelope, encrypt: bool) 
		-> TransportResult<()>;
}
```

**Address Abstraction:**

```rust
pub trait TightBeamAddress: Into<Vec<u8>> + Clone + Send {}
```

Implementations provide protocol-specific addressing (e.g., `SocketAddr` for TCP,
custom addressing for other transports).

### 8.2 Message Transport Wire Format

#### 8.2.1 Concept: Framing and Encoding

TightBeam messages traverse the network wrapped in transport envelopes that provide
framing, encryption support, and protocol demultiplexing. The wire format addresses
three key challenges:

1. **Stream framing**: TCP provides byte streams without message boundaries. DER's 
   tag-length-value encoding provides inherent framing.
2. **Encryption transparency**: WireEnvelope supports both cleartext (testing) and 
   encrypted (production) modes without changing application code.
3. **Protocol multiplexing**: TransportEnvelope distinguishes application messages 
   (Request/Response) from handshake messages (EnvelopedData/SignedData).

**Design Principle**: Rely on ASN.1 DER's battle-tested encoding rather than 
inventing custom framing. DER provides automatic length prefixing, corruption 
detection through invalid encoding, and well-understood security properties.

#### 8.2.2 Specification: Wire Envelope Structure

The wire format uses ASN.1 DER encoding with a two-tier envelope structure:

1. **WireEnvelope**: Outer layer that indicates cleartext or encrypted
2. **TransportEnvelope**: Inner layer that distinguishes request, response, and handshake messages

```rust
/// Wire-level envelope (cleartext or encrypted)
#[derive(Choice, Clone, Debug, PartialEq)]
pub enum WireEnvelope {
	#[asn1(context_specific = "0", constructed = "true")]
	Cleartext(TransportEnvelope),
	#[asn1(context_specific = "1", constructed = "true")]
	Encrypted(EncryptedContentInfo),
}

/// Transport envelope wrapping all messages
#[derive(Choice, Clone, Debug, PartialEq)]
pub enum TransportEnvelope {
	#[asn1(context_specific = "0", constructed = "true")]
	Request(RequestPackage),
	#[asn1(context_specific = "1", constructed = "true")]
	Response(ResponsePackage),
	#[asn1(context_specific = "2", constructed = "true")]
	EnvelopedData(EnvelopedData),  // For handshakes
	#[asn1(context_specific = "3", constructed = "true")]
	SignedData(SignedData),        // For handshakes
}
```

**Request and Response Packages:**

```rust
/// Request package containing a TightBeam message
#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
pub struct RequestPackage {
	message: Frame,  // The actual TightBeam message (Section 4)
}

/// Response package containing status and optional message
#[derive(Sequence, Debug, Clone, PartialEq, Eq, Default)]
pub struct ResponsePackage {
	status: TransitStatus,       // Accept/Reject/Retry from policy
	#[asn1(optional = "true")]
	message: Option<Frame>,      // Optional response message
}
```

**DER Length Encoding (ITU-T X.690):**

**Short form** (0-127 bytes):
```
tag | length | content
0x30  0x05     [5 bytes]
```

**Long form** (128+ bytes):
```
tag | 0x80+num_octets | length_bytes | content
0x30  0x82              0x01 0x00      [256 bytes]
```

The transport layer parses DER length on-the-fly to read envelopes incrementally.

**Envelope Size Limits:**

Transport implementations enforce configurable size limits:

- **Cleartext envelopes**: Default 512KB max (`max_cleartext_envelope`)
- **Encrypted envelopes**: Default 512KB max (`max_encrypted_envelope`)
- **Handshake messages**: Fixed 128KB max (`HANDSHAKE_MAX_WIRE`)

Size enforcement prevents resource exhaustion attacks and ensures bounded memory usage.

### 8.3 TCP Transport

#### 8.3.1 Concept: TCP as Layer-5 Transport

TCP provides reliable, ordered byte streams between endpoints. TightBeam's TCP 
transport implementation bridges the byte stream model with the message-oriented 
Frame API through DER length-prefixed envelopes.

**Key Capabilities:**
- **Stream framing**: DER length parsing extracts messages from TCP byte streams
- **Connection management**: Automatic connection handling for client/server patterns
- **Runtime agnostic**: Works with both `std::net` (sync) and `tokio` (async)
- **Encryption ready**: Supports certificate-based encryption via `EncryptedProtocol`

#### 8.3.2 Implementation: Basic TCP Usage

**TCP Server:**

```rust
use std::net::TcpListener;
use tightbeam::{server, compose, MessageIO};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	let listener = TcpListener::bind("127.0.0.1:8080")?;
	server! {
		protocol std::net::TcpListener: listener,
		|message: RequestMessage, tx| async move {
			// Process message and send response
			let response = ResponseMessage {
				data: format!("Received: {}", message.data)
			};
			tx.send(response).await.ok();
		}
	}
	
	Ok(())
}
```

**TCP Client:**

```rust
use std::net::TcpStream;
use tightbeam::{client, compose, MessageEmitter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	let addr = "127.0.0.1:8080".parse()?;
	
	client! {
		connect std::net::TcpStream: addr,
		|mut transport| async move {
			let request = compose! {
				V0: id: b"req-001",
					message: RequestMessage { data: "Hello".to_string() }
			}?;
			
			let response = transport.emit(request, None).await?;
			Ok(())
		}
	}
}
```

**Async TCP with Tokio:**

TightBeam supports Tokio's async runtime with the `tokio` feature:

```rust
use tokio::net::TcpListener;
use tightbeam::{server, MessageCollector};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	let listener = TcpListener::bind("127.0.0.1:8080").await?;
	server! {
		protocol tokio::net::TcpListener: listener,
		|message: RequestMessage, tx| async move {
			// Async processing with Tokio primitives
			tx.send(ResponseMessage { data: "Async response".to_string() }).await.ok();
		}
	}
	
	Ok(())
}
```

**TCP with Policies:**

```rust
use std::net::TcpStream;
use tightbeam::{client, policy, RestartExponentialBackoff};

policy! {
	GatePolicy: RateLimitGate |frame| {
		// Implement rate limiting logic
		TransitStatus::Accepted
	}
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	let addr = "127.0.0.1:8080".parse()?;
	
	client! {
		connect std::net::TcpStream: addr,
		policies: {
			with_emitter_gate: [RateLimitGate],
			with_restart: RestartExponentialBackoff::default(),
		},
		|mut transport| async move {
			// Client with policies applied
			let request = compose! {
				V0: id: b"req-001", message: RequestMessage { /* ... */ }
			}?;
			
			transport.emit(request, None).await
		}
	}
}
```

### 8.3.5 Low-Level Transport Usage

For scenarios requiring direct transport control without macros:

```rust
use std::net::{TcpListener, TcpStream};
use tightbeam::transport::{Protocol, MessageIO, MessageCollector};

// Server: manual transport handling
let listener = TcpListener::bind("127.0.0.1:8080")?;
let (stream, _addr) = listener.accept()?;
let mut transport = <std::net::TcpListener as Protocol>::create_transport(stream);

// Read message
let envelope = transport.read_decoded_envelope().await?;
// Process and respond
transport.send_response(TransitStatus::Accepted, Some(response_frame)).await?;

// Client: manual message sending
let stream = TcpStream::connect("127.0.0.1:8080")?;
let mut transport = <std::net::TcpListener as Protocol>::create_transport(stream);

let frame = compose! { V0: id: b"req-001", message: my_message }?;
transport.write_envelope(&frame.to_der()?).await?;
let response_bytes = transport.read_envelope().await?;
```

### 8.3.6 Address Handling

TCP addresses use `TightBeamSocketAddr` for protocol-agnostic addressing:

```rust
use tightbeam::transport::tcp::TightBeamSocketAddr;

// Parse from string
let addr: TightBeamSocketAddr = "127.0.0.1:8080".parse()?;
// Convert to bytes for wire encoding
let addr_bytes: Vec<u8> = addr.into();
// Access underlying SocketAddr
let socket_addr: std::net::SocketAddr = *addr;
```

### 8.4 Transport Policies

#### 8.4.1 Concept: Policy-Driven Message Control

TightBeam provides policy-based control over message flow at the transport 
layer. Policies are composable, stateless procedures that make decisions about 
message acceptance and retry behavior without modifying core transport logic.

**Design Philosophy:**
- **Separation of concerns**: Transport moves bytes, policies make decisions
- **Composability**: Multiple policies chain together declaratively
- **Stateless**: Policies are pure functions of current message state
- **Performance**: Policy evaluation happens at compile-time bounds, no dynamic dispatch overhead

**Policy Types:**
1. **Gate Policies**: Accept/reject individual messages (rate limiting, authentication, validation)
2. **Restart Policies**: Decide retry behavior after failures (exponential backoff, circuit breakers)
3. **Receptor Policies**: Filter messages at worker/servlet level (business logic filtering)

#### 8.4.2 Specification: Gate Policies

```rust
pub trait GatePolicy: Send + Sync {
	fn evaluate(&self, message: &Frame) -> TransitStatus;
}

pub enum TransitStatus {
	Accepted,      // Message accepted
	Busy,          // System busy, client may retry
	Unauthorized,  // Authentication required
	Forbidden,     // Message rejected
	Timeout,       // Operation timed out
}
```

#### Creating Gate Policies

Use the `policy!` macro for concise policy definitions:

```rust
policy! {
	GatePolicy: AuthGate |frame| {
		if frame.metadata.id.starts_with(b"auth-") {
			TransitStatus::Accepted
		} else {
			TransitStatus::Unauthorized
		}
	}
}
```

#### Emitter vs Collector Gates

- **Emitter gates**: Applied before sending messages (client-side filtering)
- **Collector gates**: Applied when receiving messages (server-side filtering)

Attach gates using transport configuration:

```rust
let transport = TcpTransport::from(stream)
	.with_emitter_gate(ClientAuthGate)
	.with_collector_gate(ServerValidationGate);
```

#### 8.4.3 Specification: Restart Policies

Restart policies determine whether to retry failed message sends, with optional 
backoff and jitter strategies.

**RestartPolicy Trait:**

```rust
pub trait RestartPolicy: Send + Sync {
	fn evaluate(
		&self,
		message: &Frame,
		result: &TransportResult<&Frame>,
		attempt: usize
	) -> RetryAction;
}

pub enum RetryAction {
	RetryWithSame,              // Retry with original message
	RetryWithModified(Frame),   // Retry with modified message
	NoRetry,                    // Stop retrying, return error
}
```

#### Built-in Restart Policies:
```rust
pub struct RestartExponentialBackoff {
	max_attempts: usize,
	scale_factor: u64,  // Base delay in milliseconds
	jitter: Option<Box<dyn JitterStrategy>>,
}

// Usage
let restart = RestartExponentialBackoff::default()
	.with_jitter(DecorrelatedJitter);
```

**Linear Backoff** (constant delay):
```rust
pub struct RestartLinearBackoff {
	max_attempts: usize,
	delay_ms: u64,
}
```

#### Jitter Strategies

Jitter prevents thundering herd problems by randomizing retry delays:

```rust
pub trait JitterStrategy: Send + Sync {
	fn apply(&self, base_delay: u64) -> u64;
}

// Decorrelated jitter: random value between base/3 and base_delay
pub struct DecorrelatedJitter;
```

#### 8.4.4 Specification: Receptor Policies

Receptor policies operate on typed messages (application-level) rather than 
frames. They enable type-safe, domain-specific policy logic:

```rust
pub trait ReceptorPolicy<T: Message>: Send + Sync {
	fn evaluate(&self, message: &T) -> TransitStatus;
}

// Example: Validate message content before processing
policy! {
	ReceptorPolicy<PingMessage>: ValidPingGate |message| {
		if message.payload.len() <= 1024 {
			TransitStatus::Accepted
		} else {
			TransitStatus::Forbidden
		}
	}
}
```

Receptor policies attach to workers and servlets (Section 9.3), providing 
pre-processing filters.

### 8.4.4 Policy Composition

Multiple policies can be chained on a single transport:

```rust
let transport = TcpTransport::from(stream)
	.with_restart(RestartExponentialBackoff::default())
	.with_emitter_gate(RateLimitGate)
	.with_emitter_gate(AuthTokenGate)
	.with_collector_gate(RequestValidationGate)
	.with_collector_gate(AccessControlGate);
```

Policies are evaluated in order:
- **Emitter gates**: All must return `Accepted` for message to be sent
- **Collector gates**: All must return `Accepted` for message to be processed
- **Restart policy**: Single policy determines retry behavior

### 8.4.5 Policy Middleware

Policies support transparent middleware for observability:

```rust
let gate_with_logging = GateMiddleware::new(
	AuthGate,
	|frame, status| {
		eprintln!("Gate evaluated: {:?} -> {:?}", frame.metadata.id, status);
	}
);

transport = transport.with_collector_gate(gate_with_logging);
```

Middleware does not modify policy decisions—it only observes them.

### 8.4.6 Integration with server!/client! Macros

The `server!` and `client!` macros provide ergonomic policy attachment:

```rust
server! {
	protocol std::net::TcpListener: listener,
	policies: {
		with_collector_gate: [AuthGate, ValidationGate],
		with_restart: RestartLinearBackoff::new(3, 100),
	},
	|message: RequestMessage, tx| {
		// Handle message
		tx.send(ResponseMessage { ... }).await
	}
}

client! {
	connect std::net::TcpStream: addr,
	policies: {
		with_emitter_gate: [ClientAuthGate],
		with_restart: RestartExponentialBackoff::default(),
	},
	|transport| async move {
		transport.emit(request, None).await
	}
}
```

### 8.5 Handshake Protocols

#### 8.5.1 Concept: Security Goals and Protocol Selection

TightBeam implements two handshake protocols that establish secure, authenticated 
communication channels before application-level message exchange begins. These 
protocols integrate deeply with the SecurityProfile system (Section 4.1) to 
provide cryptographic agility and forward secrecy.

**Purpose and Security Goals:**

Handshakes serve three critical security functions:

1. **Mutual Authentication**: Both parties verify each other's identities through 
   cryptographic proofs (certificates for CMS, public keys for ECIES). This 
   prevents impersonation attacks and ensures messages are exchanged only with 
   authorized entities.

2. **Key Exchange**: Parties establish a shared session key through key agreement 
   protocols (ECDH-based) that provides perfect forward secrecy. Even if long-term 
   keys are compromised later, past session traffic remains secure.

3. **Cryptographic Negotiation**: Client and server agree on a mutually supported 
   SecurityProfile that defines all cryptographic operations (signature algorithms, 
   key derivation functions, AEAD ciphers). This ensures both parties use 
   compatible, strong cryptography.

#### Threat Model

TightBeam handshakes defend against:

- **Passive eavesdropping**: All session traffic is encrypted with ephemeral keys
- **Active man-in-the-middle**: Transcript integrity prevents tampering
- **Replay attacks**: Nonce tracking detects and rejects replayed handshakes
- **Downgrade attacks**: Profile negotiation includes integrity checks
- **Impersonation**: Certificate/signature verification proves identity
- **Key compromise**: Forward secrecy limits damage from stolen long-term keys

#### Protocol Selection Criteria

TightBeam offers two handshake protocols optimized for different deployment scenarios:

**CMS-Based Handshake** (`transport-cms` feature):
- **Use when**: Full PKI infrastructure available, regulatory compliance requires 
  X.509 certificates, need non-repudiation through signed messages
- **Provides**: Strong mutual authentication, certificate validation chains, 
  revocation checking support, detailed audit trails
- **Security profile**: Fully integrated with Section 4.1 SecurityProfile system, 
  supports all profile types (Secp256k1Sha3, Ed25519Blake3, etc.)

**ECIES-Based Handshake** (`x509` feature, lightweight):
- **Use when**: Lightweight deployment, no PKI infrastructure, peer-to-peer 
  communication, embedded systems with resource constraints
- **Provides**: Efficient key exchange, optional certificate-based authentication, 
  minimal message overhead, faster handshake completion
- **Security profile**: Same cryptographic primitives as CMS but simpler message 
  structures

Both protocols provide equivalent security properties (authentication, forward 
secrecy, replay protection) but differ in message complexity and PKI integration depth.

#### Relationship to SecurityProfile System

The SecurityProfile system (Section 4.1) defines cryptographic algorithm suites 
as type-safe constants. Handshakes leverage this system in three ways:

1. **Algorithm Selection**: Clients offer supported profiles via `SecurityOffer`, 
   servers select the first mutually supported profile. This negotiation happens 
   during the initial handshake message exchange.

2. **Generic Implementation**: Handshake builders and processors are generic over 
   `P: CryptoProvider`, allowing compile-time polymorphism across different 
   cryptographic suites without runtime overhead or type erasure.

3. **Dealer's Choice Mode**: When client sends no offer, server selects its 
   preferred profile (first configured profile). This simplifies deployment in 
   controlled environments where all clients trust the server's cryptographic 
   decisions.

Example profile negotiation:

```rust
use tightbeam::crypto::profiles::{Secp256k1Sha3Profile, Ed25519Blake3Profile};
use tightbeam::crypto::negotiation::SecurityOffer;

// Client offers two profiles (ordered by preference)
let offer = SecurityOffer::new(vec![
    Secp256k1Sha3Profile::oid(),
    Ed25519Blake3Profile::oid(),
]);

// Server configured with three profiles
let server_profiles = vec![
    Ed25519Blake3Profile::descriptor(),    // Server's preference
    Secp256k1Sha3Profile::descriptor(),
    // ... other profiles
];

// Server selects first mutual profile: Secp256k1Sha3
// (Ed25519Blake3 not supported by client, Secp256k1Sha3 is mutual)
```

#### Security Properties Summary

All TightBeam handshakes provide:

- **Forward Secrecy**: Ephemeral ECDH keys mean session key compromise doesn't 
  affect past sessions
- **Replay Protection**: Nonce tracking prevents replaying captured handshakes
- **Transcript Integrity**: All handshake messages contribute to a cryptographic 
  transcript that is signed in the Finished message, detecting any tampering
- **Identity Verification**: Cryptographic proof that each party controls their 
  claimed private key
- **Downgrade Prevention**: Profile negotiation is included in transcript hash, 
  preventing attackers from forcing weaker algorithms

These properties align with modern protocol security standards (TLS 1.3, Noise 
Framework) while maintaining tightbeam's ASN.1 DER-based message encoding and 
type-safe Rust implementation.

#### 8.5.2 Specification: Handshake Flow and State Management

**Generic Handshake Flow:**

Both CMS and ECIES handshakes follow a three-phase message exchange pattern that 
establishes mutual authentication and session keys:

```text
┌──────────┐                                             ┌──────────┐
│  Client  │                                             │  Server  │
└────┬─────┘                                             └─────┬────┘
     │                                                         │
     │  Phase 1: Initiation                                    │
     │  ───────────────────────────────────────────────────►   │
     │  ClientHello:                                           │
     │    - client_nonce (32 bytes random)                     │
     │    - security_offer? (optional profile OIDs)            │
     │                                                         │
     │                                                         │
     │  Phase 2: Response                                      │
     │  ◄───────────────────────────────────────────────────   │
     │                      ServerHandshake:                   │
     │                        - server_certificate             │
     │                        - server_nonce (32 bytes)        │
     │                        - selected_profile? (if offered) │
     │                        - signature(transcript_hash)     │
     │                                                         │
     │                                                         │
     │  Phase 3: Key Exchange                                  │
     │  ───────────────────────────────────────────────────►   │
     │  ClientKeyExchange:                                     │
     │    - encrypted_session_key (KARI or ECIES)              │
     │    - client_certificate? (mutual auth)                  │
     │    - client_finished_sig? (mutual auth)                 │
     │                                                         │
     │                                                         │
     │  Phase 4: Application Data                              │
     │  ◄──────────────────────────────────────────────────►   │
     │  All messages encrypted with session AEAD key           │
     │                                                         │
```

**Phase 1 - ClientHello (Initiation)**:
- Client generates cryptographically random 32-byte nonce for replay protection
- Client optionally sends `SecurityOffer` listing supported profiles (negotiation mode)
- If no offer sent, server uses dealer's choice mode (selects first configured profile)
- Nonce immediately added to transcript hash accumulator

**Phase 2 - ServerHandshake (Response)**:
- Server validates client nonce (checks replay, adds to nonce tracking set)
- Server selects mutual profile or uses dealer's choice
- Server generates its own 32-byte nonce
- Server signs transcript hash (ClientHello || ServerHandshake) to prove possession 
  of private key and bind server to negotiated parameters
- Signature algorithm determined by selected SecurityProfile

**Phase 3 - ClientKeyExchange (Session Key Establishment)**:
- Client generates ephemeral session key (CEK) for AEAD cipher
- Client encrypts CEK using:
  - **CMS**: KeyAgreeRecipientInfo with ECDH + HKDF + AES Key Wrap
  - **ECIES**: Elliptic Curve Integrated Encryption Scheme
- For mutual authentication, client includes certificate and signs transcript
- Server decrypts CEK, derives session AEAD key via HKDF

**Phase 4 - Application Data**:
- Both parties now possess shared session key
- All subsequent messages encrypted/authenticated with AEAD cipher
- Transport layer (Section 8.2) handles WireEnvelope encryption automatically

#### State Machine Design

TightBeam uses role-specific state machines (`ClientHandshakeState`, 
`ServerHandshakeState`) with explicit terminal states and granular failure 
classification. This design enables:

1. **Type-safe transitions**: State machine ensures messages processed in correct order
2. **Replay detection**: Nonce tracking prevents accepting duplicate handshakes
3. **Failure attribution**: Distinguish protocol violations from network errors
4. **Audit trails**: Each state transition logged for security monitoring

**Client State Machine**:

```rust
pub enum ClientHandshakeState {
    #[default]
    Init,                    // Initial state, ready to send ClientHello
    WaitingServerHandshake,  // ClientHello sent, awaiting server response
    WaitingSessionKey,       // ServerHandshake received, sending ClientKeyExchange
    Completed,               // Handshake successful, session key established
    Failed(FailureKind),     // Terminal failure state
    Aborted(AbortReason),    // Intentional abort (policy decision)
}
```

State transitions:
1. `Init` → `WaitingServerHandshake`: Client sends ClientHello
2. `WaitingServerHandshake` → `WaitingSessionKey`: Receives valid ServerHandshake
3. `WaitingSessionKey` → `Completed`: ClientKeyExchange accepted by server
4. Any state → `Failed`: Protocol error, crypto failure, validation failure
5. Any state → `Aborted`: Policy rejection, explicit cancellation

**Server State Machine**:

```rust
pub enum ServerHandshakeState {
    #[default]
    Init,                    // Listening for ClientHello
    WaitingClientKeyExchange, // ClientHello processed, ServerHandshake sent
    Completed,               // ClientKeyExchange received, session established
    Failed(FailureKind),     // Terminal failure state
    Aborted(AbortReason),    // Policy-driven rejection
}
```

State transitions:
1. `Init` → `WaitingClientKeyExchange`: Valid ClientHello received
2. `WaitingClientKeyExchange` → `Completed`: Valid ClientKeyExchange received
3. Any state → `Failed`: Validation error, crypto error, replay detected
4. Any state → `Aborted`: Certificate validation failed, policy rejected

#### Failure Classification

The state machine distinguishes three failure categories for targeted error handling:

```rust
pub enum FailureKind {
    ProtocolViolation,       // Invalid message format, out-of-order message
    CryptographicFailure,    // Signature verification failed, decryption failed
    ValidationFailure,       // Certificate invalid, nonce replay detected
    NetworkError,            // Connection dropped, timeout
}
```

**ProtocolViolation**: Client sent message out of sequence, malformed ASN.1 DER 
encoding, missing required fields. Indicates potential implementation bug or 
malicious peer. Server SHOULD terminate connection immediately.

**CryptographicFailure**: Signature doesn't verify, HMAC mismatch, key derivation 
error. Indicates private key mismatch, corrupted certificate, or active attack. 
Server MUST terminate and MAY log for security audit.

**ValidationFailure**: Certificate expired, nonce already seen (replay), untrusted 
CA. Indicates configuration mismatch or policy violation. Server SHOULD send 
informative error before terminating.

**NetworkError**: TCP connection dropped, timeout waiting for message. Indicates 
transient network issue. Client MAY retry with backoff per restart policy.

#### Replay Protection with Nonce Tracking

Servers maintain a replay detection set that tracks recently seen nonces:

```rust
pub struct NonceReplaySet {
    seen: HashSet<[u8; 32]>,  // Nonces seen in recent time window
}

impl NonceReplaySet {
    pub fn check_and_insert(&mut self, nonce: &[u8; 32]) -> bool {
        if self.seen.contains(nonce) {
            return false;  // Replay detected
        }
        self.seen.insert(*nonce);
        true
    }
}
```

Properties:
- **Window-based tracking**: Nonces expire after configurable duration (default: 5 minutes)
- **Memory efficiency**: Bounded set size prevents memory exhaustion attacks
- **Constant-time lookup**: HashSet provides O(1) replay detection
- **Thread-safe**: Wrapped in `Arc<Mutex<>>` for concurrent server operation

Best practices:
- Servers MUST reject replayed nonces before processing any handshake logic
- Clients SHOULD use cryptographically strong random number generator (OsRng)
- Nonce size (32 bytes) provides 2^256 space, making collisions computationally infeasible
- Consider persisting nonce set across server restarts for long-lived deployments

#### Transcript Integrity

Both protocols maintain a transcript hash that accumulates all handshake messages. 
This prevents tampering and downgrade attacks:

```rust
// Transcript starts empty
let mut transcript = Vec::new();

// Phase 1: Accumulate ClientHello
transcript.extend_from_slice(&client_hello_der);

// Phase 2: Accumulate ServerHandshake
transcript.extend_from_slice(&server_handshake_der);

// Server signs transcript at this point
let transcript_hash = Sha3_256::digest(&transcript);
let server_signature = server_key.sign(&transcript_hash);

// Phase 3: Client verifies signature, then accumulates ClientKeyExchange
verify(server_pubkey, &transcript_hash, &server_signature)?;
transcript.extend_from_slice(&client_key_exchange_der);

// For mutual auth, client signs extended transcript
let final_hash = Sha3_256::digest(&transcript);
let client_signature = client_key.sign(&final_hash);
```

Security properties:
- **Immutability**: Once message added to transcript, cannot be removed or reordered
- **Binding**: Signature covers all prior messages, binding server to negotiated parameters
- **Downgrade prevention**: Profile negotiation included in transcript prevents 
  attacker from forcing weaker algorithms
- **Authenticated transcript**: Both parties sign portions of transcript, proving 
  they witnessed same message sequence

#### Error Handling and Alerts

Handshakes can fail at multiple points. TightBeam provides structured error 
reporting through alert messages:

```rust
pub enum HandshakeAlert {
    CertificateExpired,           // Server/client certificate not in validity period
    CertificateUntrusted,         // Certificate not signed by trusted CA
    ProfileMismatch,              // No mutual SecurityProfile available
    NonceReplay,                  // Nonce seen before (replay attack)
    SignatureVerificationFailed,  // Transcript signature invalid
    DecryptionFailed,             // Cannot decrypt session key
    InvalidMessage,               // Malformed ASN.1 DER
}
```

Alerts are encoded as CMS authenticated attributes in the handshake messages, 
allowing structured error communication without revealing sensitive information 
to attackers. See `transport/handshake/attributes.rs` for alert encoding.

#### Invariant Enforcement

The handshake state machine enforces critical invariants through runtime checks:

```rust
pub trait HandshakeInvariant {
    fn check_transcript_locked(&self) -> Result<(), HandshakeError>;
    fn check_aead_not_derived(&self) -> Result<(), HandshakeError>;
    fn check_finished_not_sent(&self) -> Result<(), HandshakeError>;
}
```

**Transcript Lock Invariant**: After ClientKeyExchange sent/received, transcript 
MUST be immutable. Prevents late tampering of handshake messages.

**AEAD Derivation Invariant**: Session key derived exactly once. Prevents 
accidentally deriving multiple keys from same material.

**Finished Invariant**: Finished message (transcript signature) sent exactly once. 
Ensures handshake completes atomically.

#### 8.5.3 Implementation: CMS-Based Handshake Protocol

The CMS-based handshake leverages Cryptographic Message Syntax (RFC 5652) to 
provide standards-compliant authenticated key exchange with full X.509 certificate 
support. This protocol is ideal for deployments requiring PKI integration, 
regulatory compliance, and non-repudiation.

**CMS Message Structures:**

TightBeam uses three primary CMS structures in the handshake:

**1. EnvelopedData (RFC 5652 §6)**: Encrypts content for one or more recipients

```asn1
EnvelopedData ::= SEQUENCE {
  version                  CMSVersion,
  recipientInfos           RecipientInfos,         -- How to decrypt
  encryptedContentInfo     EncryptedContentInfo    -- Encrypted payload
}

RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo

RecipientInfo ::= CHOICE {
  keyAgreeRecipientInfo [1] KeyAgreeRecipientInfo,  -- ECDH-based (used by TightBeam)
  -- ... other recipient types omitted ...
}
```

TightBeam uses `KeyAgreeRecipientInfo` (KARI) exclusively, which provides:
- **Key agreement**: ECDH between sender ephemeral key and recipient static key
- **Key derivation**: HKDF to derive key encryption key (KEK) from ECDH shared secret
- **Key wrapping**: AES Key Wrap (RFC 3394) to encrypt content encryption key (CEK)

**2. SignedData (RFC 5652 §5)**: Provides digital signatures over content

```asn1
SignedData ::= SEQUENCE {
  version           CMSVersion,
  digestAlgorithms  DigestAlgorithmIdentifiers,  -- Hash algorithms used
  encapContentInfo  EncapsulatedContentInfo,     -- Content to sign
  certificates  [0] IMPLICIT CertificateSet OPTIONAL,  -- Signer certificates
  signerInfos       SignerInfos                  -- Signatures
}
```

Used in TightBeam for:
- Server signs transcript hash in ServerHandshake (proves identity)
- Client signs transcript hash for mutual authentication (optional)

**3. ContentInfo (RFC 5652 §3)**: Top-level wrapper for all CMS messages

```asn1
ContentInfo ::= SEQUENCE {
  contentType     OBJECT IDENTIFIER,  -- id-signedData, id-envelopedData, etc.
  content     [0] EXPLICIT ANY DEFINED BY contentType
}
```

#### ClientKeyExchange: KARI-Based Session Key Encryption

The ClientKeyExchange message establishes the shared session key through a 
sophisticated multi-step process:

**Step 1: Client Generates Content Encryption Key (CEK)**

```rust
use tightbeam::crypto::secret::Secret;

// Generate random 32-byte key for AES-256-GCM
let cek = Secret::from(Box::new({
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}));
```

The CEK is the actual session key that will be used for AEAD encryption of 
application data. It's wrapped in `Secret<>` to ensure automatic zeroization 
when dropped.

**Step 2: Client Builds KeyAgreeRecipientInfo (KARI)**

KARI construction involves multiple cryptographic operations orchestrated by 
`TightBeamKariBuilder`:

```rust
use tightbeam::transport::handshake::builders::TightBeamKariBuilder;

let kari_builder = TightBeamKariBuilder::<Secp256k1Sha3Profile>::new()
    // Sender's ephemeral keys (generated fresh for this handshake)
    .with_sender_private_key(client_ephemeral_priv)
    .with_sender_public_key_spki(client_ephemeral_pub_spki)
    
    // Recipient's static public key (from server certificate)
    .with_recipient_public_key(server_static_pub)
    .with_recipient_identifier(server_cert_issuer_serial)
    
    // User Keying Material (random salt for HKDF)
    .with_ukm(UserKeyingMaterial::from(ukm_bytes))
    
    // Key wrap algorithm (AES-256 Key Wrap)
    .with_key_encryption_algorithm(AlgorithmIdentifierOwned {
        oid: KW_AES_256_WRAP_OID,
        parameters: None,
    });

// Build RecipientInfo, encrypting CEK for server
let recipient_info = kari_builder.build(&cek)?;
```

Internally, `TightBeamKariBuilder` performs:

1. **ECDH**: `shared_secret = ECDH(client_ephemeral_priv, server_static_pub)`
2. **HKDF**: `KEK = HKDF-Expand(HKDF-Extract(ukm, shared_secret), info, 32)`
3. **AES Key Wrap**: `wrapped_cek = AES-KW(KEK, cek)`

The wrapped CEK is embedded in the KARI structure along with:
- Sender's ephemeral public key (for server to perform ECDH)
- UKM (for server to derive same KEK)
- Key encryption algorithm OID

**Step 3: Client Builds EnvelopedData**

```rust
use tightbeam::transport::handshake::builders::TightBeamEnvelopedDataBuilder;

let enveloped_data_builder = TightBeamEnvelopedDataBuilder::<Secp256k1Sha3Profile>::new()
    .with_kari_builder(kari_builder)
    .with_plaintext_content(client_key_exchange_plaintext)
    .with_authenticated_attributes(vec![
        encode_client_nonce(&client_nonce)?,
        // ... other attributes
    ]);

let enveloped_data = enveloped_data_builder.build()?;
```

This produces a complete CMS EnvelopedData structure containing:
- `RecipientInfos` with the KARI (encrypted CEK)
- `EncryptedContentInfo` with AEAD-encrypted plaintext content

**Step 4: Server Decrypts Session Key**

Server uses `TightBeamKariRecipient` processor to reverse the operation:

```rust
use tightbeam::transport::handshake::processors::TightBeamKariRecipient;

let kari_recipient = TightBeamKariRecipient::<Secp256k1Sha3Profile>::new(
    server_static_priv,  // Server's long-term private key
);

// Extract CEK from RecipientInfo
let cek = kari_recipient.process_recipient(&recipient_info, 0)?;
```

Internally performs:
1. **Extract ephemeral key**: Parse sender's ephemeral public key from KARI
2. **ECDH**: `shared_secret = ECDH(server_static_priv, client_ephemeral_pub)`
3. **HKDF**: Derive same KEK using UKM from KARI
4. **AES Key Unwrap**: `cek = AES-KW-Unwrap(KEK, wrapped_cek)`
5. **Integrity check**: Re-wrap CEK and constant-time compare with original

The constant-time re-wrap check provides defense-in-depth against timing attacks, 
even though AES Key Wrap already includes an integrity check (RFC 3394).

#### ServerHandshake: Transcript Signature

The server proves possession of its private key by signing the handshake transcript:

```rust
use tightbeam::transport::handshake::builders::TightBeamSignedDataBuilder;

// Accumulate transcript
let mut transcript = Vec::new();
transcript.extend_from_slice(&client_hello_der);
transcript.extend_from_slice(&server_handshake_der);

// Hash transcript
let transcript_hash = Sha3_256::digest(&transcript);

// Build SignedData
let signed_data_builder = TightBeamSignedDataBuilder::<Secp256k1Sha3Profile, _>::new(
    &server_signing_key,
    AlgorithmIdentifierOwned::from(Sha3_256::OID),  // Digest algorithm
    AlgorithmIdentifierOwned::from(Secp256k1Sha3Profile::signature_oid()),
    compute_signer_identifier(&server_cert)?,
)?;

let signed_data = signed_data_builder.build(&transcript_hash)?;
```

The SignedData structure includes:
- `SignerInfo` with signature over transcript hash
- `DigestAlgorithm` identifying hash function (SHA3-256)
- `SignatureAlgorithm` identifying signature scheme (ECDSA-secp256k1)
- Optionally `certificates` field with server certificate chain

**Transcript Signature Verification (Client Side)**:

```rust
use tightbeam::transport::handshake::processors::TightBeamSignedDataProcessor;

// Extract verifying key from server certificate
let verifying_key = server_cert.tbs_certificate.subject_public_key_info
    .to_verifying_key::<Secp256k1>()?;

// Create signature verifier
let verifier = EcdsaSignatureVerifier::new(verifying_key);

// Process SignedData
let processor = TightBeamSignedDataProcessor::new(verifier);
let verified_content = processor.process(&signed_data, &Sha3_256::OID)?;

// Verify content matches transcript hash
assert_eq!(verified_content, transcript_hash);
```

This proves:
1. Server possesses private key corresponding to certificate public key
2. Server witnessed same transcript as client (binds server to ClientHello parameters)
3. Transcript hasn't been tampered with (signature would fail)

#### Mutual Authentication Flow

For mutual authentication, client includes its certificate and signs the extended 
transcript in ClientKeyExchange:

```rust
// Client extends transcript with ServerHandshake
transcript.extend_from_slice(&server_handshake_der);
transcript.extend_from_slice(&client_key_exchange_der);

// Client signs extended transcript
let final_hash = Sha3_256::digest(&transcript);
let client_signed_data = TightBeamSignedDataBuilder::<Secp256k1Sha3Profile, _>::new(
    &client_signing_key,
    // ... same parameters as server ...
)?.build(&final_hash)?;

// Include in ClientKeyExchange as authenticated attribute
let client_key_exchange = ClientKeyExchange {
    enveloped_data,  // Contains encrypted CEK
    client_certificate: Some(client_cert.clone()),
    client_signature: Some(client_signed_data.to_der()?),
};
```

Server verification flow:

```rust
// 1. Validate client certificate against trust anchors
validator.validate(&client_cert, &trust_anchors)?;

// 2. Verify certificate is within validity period
validate_certificate_expiry(&client_cert)?;

// 3. Extract client's public key and verify transcript signature
let client_verifying_key = client_cert.tbs_certificate
    .subject_public_key_info.to_verifying_key::<Secp256k1>()?;

let client_verifier = EcdsaSignatureVerifier::new(client_verifying_key);
let client_processor = TightBeamSignedDataProcessor::new(client_verifier);

let verified_hash = client_processor.process(&client_signed_data, &Sha3_256::OID)?;

// 4. Verify client witnessed same transcript
let expected_hash = Sha3_256::digest(&transcript);
if verified_hash != expected_hash.as_slice() {
    return Err(HandshakeError::TranscriptMismatch);
}
```

At this point, both parties have:
- Proven possession of their private keys through signatures
- Validated each other's certificates against trust anchors
- Established a shared CEK through ECDH + HKDF + Key Wrap
- Bound themselves cryptographically to the negotiated parameters

#### Integration with SecurityProfile System

CMS handshake is fully generic over `P: CryptoProvider`, allowing compile-time 
polymorphism across different profiles:

```rust
// Secp256k1 + SHA3-256 + AES-256-GCM + HKDF-SHA3-256
pub type CmsHandshakeClientSecp256k1 = 
    CmsHandshakeClient<Secp256k1Sha3Profile, Secp256k1SigningKey>;

// Ed25519 + BLAKE3 + ChaCha20Poly1305 + HKDF-BLAKE3  
pub type CmsHandshakeClientEd25519 = 
    CmsHandshakeClient<Ed25519Blake3Profile, Ed25519SigningKey>;
```

All cryptographic operations (ECDH, HKDF, signature, AEAD) are resolved at 
compile time through associated types on the `CryptoProvider` trait. This provides:

- **Zero-cost abstraction**: No runtime dispatch or type erasure
- **Type safety**: Mismatched profiles caught at compile time
- **Explicit semantics**: Profile choice visible in type signatures
- **Easy auditing**: Security-critical code paths determined statically

#### CMS Handshake Security Properties

The CMS-based handshake provides:

1. **Forward Secrecy**: Ephemeral ECDH keys ensure session key compromise doesn't 
   affect past sessions. Even if server's long-term private key is stolen later, 
   captured session traffic remains secure.

2. **Certificate Validation**: Full X.509 validation including:
   - Signature chain verification back to trusted root
   - Validity period checking (notBefore/notAfter)
   - Optional revocation checking (CRL, OCSP)
   - Custom policy enforcement through `CertificateValidation` trait

3. **Non-Repudiation**: SignedData structures provide cryptographic proof that 
   server/client generated specific messages. Useful for audit trails and 
   compliance requirements.

4. **Key Confirmation**: Both parties prove possession of private keys through 
   signatures before session established. Prevents key confusion attacks.

5. **Downgrade Protection**: Profile negotiation included in signed transcript 
   prevents attacker from forcing weaker algorithms even if they can modify 
   ClientHello in flight.

6. **Replay Protection**: Nonce tracking on server side prevents accepting 
   duplicate ClientHello messages.

## 9. Network Theory

### 9.1 Network Architecture

- Egress/Ingress policy management
- Retry and Egress client policy
- Service orchestration via Colony Monodomy/Polydomy patterns

### 9.2 Efficient Exchange-Compute Interconnect

The Efficient Exchange-Compute Interconnect or EECI is a software development 
paradigm inspired by the entomological world. As threads and tunnels underpin 
the basics of processing and communication, we can start at these base levels 
and develop from here. The goal of EECI is to operate on these base layers 
across any transmission protocol: 
- thread-thread.
- thread-port-thread.

### 9.3 Components

There are four main components to the EECI:
- **E** [Workers](#931-e-workers) - Efficient processing units
- **E** [Servlets](#932-e-servlets) - Exchange endpoints
- **C** [Clusters](#933-c-clusters) - Compute orchestration
- **I** [Drone/Hive](#934-i-drones--hives) - Interconnected infrastructure

Think of workers as ants, servlets as ant hills, and clusters as ant colonies.
Insects have specific functions for which they process organic matter 
using local information. These functions are often simple, but when combined 
in large numbers, they can perform complex tasks. The efficiency of each unit 
is attributed to  their fungible nature--how well it can accomplish its 
singular task. 

#### 9.3.1 E: Workers

Workers are the smallest unit of computation. They must be single-threaded and
handle a single message at a time. Workers are the "ants" of the EECI. Insects 
have a head, thorax, and abdomen. Workers have the following similarly 
inspired structure:

```rust
tightbeam::worker! {
	name: PingPongWorker<RequestMessage, PongMessage>,
	config: {
		response: &str,
	},
	policies: {
		with_receptor_gate: [PingGate]
	},
	handle: |_message, config| async move {
		PongMessage {
			result: config.response.to_string(),
		}
	}
}
```

Not unlike supraorganisms, we can name them, and their "head" may possess
a specific configuration (config). They may or may not have receptors which 
can be used to optionally gate messages. The "thorax" is itself the container
for which isolates the entity within its own scoped thread--locality. Finally, 
its "abdomen" is the handle which digests the message and produces a response.

The important thing to note is that workers operate on local information 
within their bounded scope. They are not aware of the larger system and only 
operate on the message they are given. This is a critical aspect of the EECI 
and allows for a high degree of parallelism and fault tolerance. As a result, 
they do not have access to the full Frame nor should they need it.

##### Testing
Testing workers is simple and a container is provided:

```rust
tightbeam::test_worker! {
	name: test_ping_pong_worker,
	setup: || {
		PingPongWorker::start()
	},
	assertions: |worker| async move {
		// Test accepted message
		let ping_msg = RequestMessage {
			content: "PING".to_string(),
			lucky_number: 42,
		};
		let response = worker.relay(ping_msg).await?;
		assert_eq!(response, Some(PongMessage { result: "PONG".to_string() }));

		// Test rejected message
		let pong_msg = RequestMessage {
			content: "PONG".to_string(),
			lucky_number: 42,
		};

		let result = worker.relay(pong_msg).await;
		assert!(matches!(result, Err(WorkerRelayError::Rejected(_))));

		Ok(())
	}
}
```

#### 9.3.2 E: Servlets

Servlets are "anthills" in the sense they operate on a specific protocol. From
a TCP/IP perspective, an anthill is a port in many ways. Servlets are 
multi-threaded and must handle messages asynchronously. A servlet may also
define as many different workers as it needs to accomplish its task as well
as a set of configurations. Servlets must be provided a relay which is used to
relay `Message` types to the worker without the entire Frame.

```rust
tightbeam::servlet! {
	name: PingPongServletWithWorker,
	protocol: Listener,
	config: {
		lotto_number: u32
	},
	workers: |config| {
		ping_pong: PingPongWorker = PingPongWorker::start(),
		lucky_number: LuckyNumberDeterminer = LuckyNumberDeterminer::start(LuckyNumberDeterminerConf {
			lotto_number: config.lotto_number,
		})
	},
	handle: |message, _config, workers| async move {
		let decoded = crate::decode::<RequestMessage, _>(&message.message).ok()?;
		let (ping_result, lucky_result) = tokio::join!(
			workers.ping_pong.relay(decoded.clone()),
			workers.lucky_number.relay(decoded.clone())
		);

		let reply = match ping_result {
			Ok(reply) => reply,
			Err(_) => return None,
		};

		let is_winner = match lucky_result {
			Ok(is_winner) => is_winner,
			Err(_) => return None,
		};

		crate::compose! {
			V0: id: message.metadata.id.clone(),
				message: ResponseMessage {
					result: reply.result,
					is_winner,
				}
		}.ok()
	}
}
```

Workers may process the message in parallel and have the results combined into 
a single response. 

##### Testing
Testing servlets is simple and a container is provided:

```rust
tightbeam::test_servlet! {
	name: test_servlet_with_workers,
	worker_threads: 2,
	protocol: Listener,
	setup: || {
		PingPongServletWithWorker::start(PingPongServletWithWorkerConf {
			lotto_number: 42,
			expected_message: "PING".to_string(),
		})
	},
	assertions: |client| async move {
		fn generate_message(
			lucky_number: u32,
			content: Option<String>
		) -> Result<crate::Frame, crate::TightBeamError> {
			let message = RequestMessage {
				content: content.unwrap_or_else(|| "PING".to_string()),
				lucky_number,
			};

			crate::compose! { V0: id: b"test-ping", message: message }
		}

		// Test winning case
		let ping_message = generate_message(42, None)?;
		let response = client.emit(ping_message, None).await?;
		let response_message = crate::decode::<ResponseMessage, _>(&response.unwrap().message)?;
		assert_eq!(response_message.result, "PONG");
		assert!(response_message.is_winner);

		Ok(())
	}
}
```

#### 9.3.3 C: Clusters

Clusters orchestrate multiple servlets and workers. They are the "ant colonies" 
of the EECI. Colonies are made up of multiple servlets which command different
workers. Clusters are multi-threaded and must handle messages asynchronously. 
Clusters may also define a configuration and as many different servlets as it 
needs to handle its purpose. While servlets are given a relay, clusters must be 
provided a router. Routers can emit messages to the servlets registered within 
the cluster. 

```rust
TODO
```

#### 9.3.4 I: Drones & Hives

Drones are containerized servlet runners that can dynamically morph between 
different servlet types based on command messages from a cluster. This 
allows you to seed your application over a specific protocol and then morph
into any known servlet type at runtime.

Hives are an extension of drones that can manage multiple servlets 
simultaneously. They are useful for managing a pool of servlets that can be 
activated on demand. Hives must only be available on 
[Mycelial](src/transport/mod.rs) protocols which support multiple ports 
per address. Hives should automatically maintain exactly the number of servlets 
required to efficiently process messages from the cluster.

##### "Mycelial" Protocols

Protocols such as TCP are considered "mycelial" as they operate over a single
address but can have multiple ports (SocketAddress). This allows the hive to 
establish a servlet on different ports and provide the protocol address to the 
cluster so it can register it under its hive.

```rust
TODO
```

##### Conclusion

How you wish to model your colonies is beyond the scope of this document. 
However, it is important to understand the basic building blocks and how they
can be combined to create complex systems. The swarm is yours to command.

## 10. Testing Framework

Full end-to-end containerized testing framework
- Asynchronous/synchronous containerized end-to-end testing
- Client/server "quantum tunneling" via MPSC channels

### 9.1 Quantum Entanglement Testing

These are our three "entangled particles" for our test.

```rust
// Server handler channel: tx for server, rx for container
let (tx, rx) = mpsc::channel();

// Status channels (container receives ok/reject)
let (ok_tx, ok_rx) = mpsc::channel();
let (reject_tx, reject_rx) = mpsc::channel();

// Exposed in test as single tuple
let channels = (rx, ok_rx, reject_rx);
```

####  Message Flow Sequence
1. Client emits a message
2. The server MAY receive the message
3. The gate MAY reject the message and MUST tell reject_tx
	- If so, the client SHOULD[^mpsc] hear from reject_rx
	- If not, the gate tells ok_tx and the client SHOULD hear from ok_rx
4. The server handles the message and MAY arbitrarily talk to tx
	- If so, the client SHOULD hear from rx
5. The server MAY respond with a message

[^mpsc]: MPSC ops MAY return Empty while polling; Disconnect occurs at teardown.

```rust
service: |message, tx| async move {
    tightbeam::relay!(ServiceAssertChecklist::ContainerMessageReceived, tx)?;

    let decoded = tightbeam::decode::<RequestMessage, _>(&message.clone().message).ok()?;
    if &decoded.content == "PING" {
        tightbeam::relay!(ServiceAssertChecklist::ContainerPingReceived, tx)?;

        let response = Some(tightbeam::compose! {
            V0: id: message.metadata.id.clone(),
                message: ResponseMessage {
                    result: "PONG".into()
                }
        }.ok()?);

        tightbeam::relay!(ServiceAssertChecklist::SentResponse, tx)?;
        response
    } else {
        None
    }
}
```
6. The client MAY receive a response or error or timeout
	- If no response, `None`
	- If response, `Some(Frame)`
	- If error, `Err(TransportError)`
7. The client MAY process the response and determine:
	- What the client sent
	- What the gate accepted or rejected
	- What the server wants to assert
	- What the server responded with
	- What the client received

The container is in a "Quantum State" before the client gets the response. The 
"wave function collapses" when await completes--causality intact. You can now 
observe the results of rx, ok_rx, and reject_rx: 
```rust
let decoded = if let Some(response) = client.emit(message.clone(), None).await? {
    // Collect checklist items
    assert_recv!(rx, ServiceAssertChecklist::ContainerMessageReceived);
    assert_recv!(rx, ServiceAssertChecklist::ContainerPingReceived);
    assert_recv!(rx, ServiceAssertChecklist::SentResponse);
    // Verify response metadata
    assert_eq!(response.metadata.id, message.metadata.id);
    // Ensure we received the message on the server side
    assert_recv!(ok_rx, message);
    // Ensure server did not reject
    assert_channels_quiet!(reject_rx);

    tightbeam::decode::<ResponseMessage, _>(&response.message).ok()
} else {
    panic!("Expected a response from the service");
};

```
This occurs while ensuring each client and server operate within their own 
scope in a single containerized test. Channels are automatically cleaned up.

**See:** [Container Integration Test](tests/container.rs)

## 11. Examples

### 11.1 Basic Test Container
```rust
/// Checklist for container assertions
#[derive(Enumerated, Beamable, Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
enum ServiceAssertChecklist {
	ContainerMessageReceived = 1,
	ContainerPingReceived = 2,
	SentResponse = 3,
}

test_container! {
	name: container_gates_basic,
	worker_threads: 2,
	protocol: Listener,
	service_policies: {
		with_collector_gate: [policy::AcceptAllGate]
	},
	client_policies: {
		with_emitter_gate: [policy::AcceptAllGate],
		with_restart: [RestartLinearBackoff::new(3, 1, 1, None)]
	},
	service: |message, tx| async move {
		tightbeam::relay!(ServiceAssertChecklist::ContainerMessageReceived, tx)?;

		let decoded = tightbeam::decode::<RequestMessage, _>(&message.clone().message).ok()?;
		if &decoded.content == "PING" {
			tightbeam::relay!(ServiceAssertChecklist::ContainerPingReceived, tx)?;

			let response = Some(tightbeam::compose! {
				V0: id: message.metadata.id.clone(),
					message: ResponseMessage {
						result: "PONG".into()
					}
			}.ok()?);

			tightbeam::relay!(ServiceAssertChecklist::SentResponse, tx)?;
			response
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
				message: RequestMessage {
					content: "PING".into()
				}
		}?;

		//# Test message transport

		// Send and expect acceptance + echo response
		let decoded = if let Some(response) = client.emit(message.clone(), None).await? {
			// Collect checklist items
			assert_recv!(rx, ServiceAssertChecklist::ContainerMessageReceived);
			assert_recv!(rx, ServiceAssertChecklist::ContainerPingReceived);
			assert_recv!(rx, ServiceAssertChecklist::SentResponse);
			// Verify response metadata
			assert_eq!(response.metadata.id, message.metadata.id);
			// Ensure we received the message on the server side
			assert_recv!(ok_rx, message);
			// Ensure server did not reject
			assert_channels_quiet!(reject_rx);

			tightbeam::decode::<ResponseMessage, _>(&response.message).ok()
		} else {
			panic!("Expected a response from the service");
		};

		//# Test message shape

		match decoded {
			Some(reply) => {
				assert_eq!(reply.result, "PONG");
			},
			None => panic!("Expected a PONG")
		};

		Ok(())
	}
}
```

## 12. References

### 12.1 Normative References

- [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119): Key words for use in RFCs to Indicate Requirement Levels
- [ITU-T X.690](https://www.itu.int/rec/T-REC-X.690): ASN.1 Distinguished Encoding Rules (DER)
- [RFC 3274](https://datatracker.ietf.org/doc/html/rfc3274): Compressed Data Content Type for Cryptographic Message Syntax (CMS)
- [RFC 3447](https://datatracker.ietf.org/doc/html/rfc3447): Public-Key Cryptography Standards (PKCS) #1: RSA Cryptography Specifications Version 2.1
- [RFC 5246](https://datatracker.ietf.org/doc/html/rfc5246): The Transport Layer Security (TLS) Protocol Version 1.2
- [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280): Internet X.509 Public Key Infrastructure Certificate and CRL Profile
- [RFC 5480](https://datatracker.ietf.org/doc/html/rfc5480): Elliptic Curve Cryptography Subject Public Key Information
- [RFC 5652](https://datatracker.ietf.org/doc/html/rfc5652): Cryptographic Message Syntax (CMS)
- [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869): HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- [RFC 6460](https://datatracker.ietf.org/doc/html/rfc6460): Suite B Profile for Transport Layer Security (TLS)
- [RFC 6960](https://datatracker.ietf.org/doc/html/rfc6960): X.509 Internet Public Key Infrastructure Online Certificate Status Protocol (OCSP)
- [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748): Elliptic Curves for Security
- [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032): Edwards-Curve Digital Signature Algorithm (EdDSA)
- [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439): ChaCha20 and Poly1305 for IETF Protocols
- [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446): The Transport Layer Security (TLS) Protocol Version 1.3

### 11.2 Standards References

- [FIPS 140-2](https://csrc.nist.gov/publications/detail/fips/140/2/final): Security Requirements for Cryptographic Modules
- [FIPS 140-3](https://csrc.nist.gov/publications/detail/fips/140/3/final): Security Requirements for Cryptographic Modules
- [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final): Secure Hash Standard (SHS)
- [FIPS 186-4](https://csrc.nist.gov/publications/detail/fips/186/4/final): Digital Signature Standard (DSS)
- [FIPS 197](https://csrc.nist.gov/publications/detail/fips/197/final): Advanced Encryption Standard (AES)
- [FIPS 202](https://csrc.nist.gov/publications/detail/fips/202/final): SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
- [NIST SP 800-56A](https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final): Recommendation for Pair-Wise Key Establishment Schemes Using Discrete Logarithm Cryptography
- [NIST SP 800-57](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final): Recommendation for Key Management: Part 1 - General
- [NIST SP 800-131A](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final): Transitioning the Use of Cryptographic Algorithms and Key Lengths

### 12.3 ASN.1 References

- [ITU-T X.680](https://www.itu.int/rec/T-REC-X.680): ASN.1 Specification of basic notation
- [ITU-T X.681](https://www.itu.int/rec/T-REC-X.681): ASN.1 Information object specification
- [ITU-T X.682](https://www.itu.int/rec/T-REC-X.682): ASN.1 Constraint specification
- [ITU-T X.683](https://www.itu.int/rec/T-REC-X.683): ASN.1 Parameterization of ASN.1 specifications
- [RFC 2474](https://datatracker.ietf.org/doc/html/rfc2474): Definition of the Differentiated Services Field (DS Field) in the IPv4 and IPv6 Headers
- [RFC 3246](https://datatracker.ietf.org/doc/html/rfc3246): An Expedited Forwarding PHB (Per-Hop Behavior)
- [ITU-T X.400](https://www.itu.int/rec/T-REC-X.400): Message Handling Systems (MHS): System and service overview
- [ITU-T X.420](https://www.itu.int/rec/T-REC-X.420): Message Handling Systems (MHS): Interpersonal messaging system

## 13. License

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

## 14. Implementation Notes

#### Project Structure

The workspace consists of the following components:

- **tightbeam/src/core.rs**: Shared library code and common utilities
- **tightbeam/src/lib.rs**: Library root
- **tightbeam/tests/**: Integration test suites

[crate-image]: https://img.shields.io/crates/v/tightbeam.svg
[crate-link]: https://crates.io/crates/tightbeam-rs

[docs-image]: https://img.shields.io/docsrs/tightbeam-rs
[docs-link]: https://docs.rs/tightbeam-rs

[build-image]: https://img.shields.io/github/actions/workflow/status/wahidgroup/tightbeam/ci.yaml?branch=main
[build-link]: https://github.com/wahidgroup/tightbeam/actions/workflows/ci.yaml

[license-image]: https://img.shields.io/badge/license-MIT%2FApache--2.0-blue
[rustc-image]: https://img.shields.io/badge/rustc-1.85.1%2B-orange?logo=rust

[chat-image]: https://img.shields.io/badge/chat-Discussions-blue?logo=github
[chat-link]: https://github.com/wahidgroup/tightbeam/discussions

#### Future 
- tightbeam-os