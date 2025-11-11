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

**Security Disclaimer:** A SECURITY AUDIT HAS NOT BEEN CONDUCTED. USE AT YOUR OWN RISK.

## Copyright Notice

   Copyright (C) Tanveer Wahid, WahidGroup, LLC (2025).  All Rights Reserved.

## Abstract

tightbeam is a Layer-5 messaging framework using ASN.1 DER encoding with 
versioned metadata structures for high-fidelity information transmission.

## Table of Contents

1. [Introduction](#1-introduction)
	- 1.1. [Information Fidelity Constraint](#11-information-fidelity-constraint)
	- 1.2. [Requirements Language](#12-requirements-language)
2. [Terminology](#2-terminology)
3. [Architecture](#3-architecture)
	- 3.1. [Information Theory Properties](#31-information-theory-properties)
4. [Protocol Specification](#4-protocol-specification)
	- 4.1. [Version Evolution](#41-version-evolution)
		- 4.1.1. [SecurityProfile Trait Architecture](#411-securityprofile-trait-architecture)
		- 4.1.2. [Security Profile Types](#412-security-profile-types)
		- 4.1.3. [Numeric Security Levels](#413-numeric-security-levels)
		- 4.1.4. [Message-Level Security Requirements](#414-message-level-security-requirements)
		- 4.1.5. [CryptoProvider System](#415-cryptoprovider-system)
	- 4.2. [Frame Structure](#42-frame-structure)
	- 4.3. [Metadata Specification](#43-metadata-specification)
	- 4.4. [Frame Encapsulation](#44-frame-encapsulation)
5. [ASN.1 Formal Specification](#5-asn1-formal-specification)
	- 5.1. [Core Types](#51-core-types)
	- 5.2. [Cryptographic Structures](#52-cryptographic-structures)
	- 5.3. [Message Structure](#53-message-structure)
	- 5.4. [External Dependencies](#54-external-dependencies)
	- 5.5. [Encoding Rules](#55-encoding-rules)
	- 5.6. [Version-Specific Constraints](#56-version-specific-constraints)
	- 5.7. [Semantic Constraints](#57-semantic-constraints)
		- 5.7.1. [Message Ordering](#571-message-ordering)
		- 5.7.2. [Compression Requirements](#572-compression-requirements)
		- 5.7.3. [Integrity Semantics: Order of Operations](#573-integrity-semantics-order-of-operations)
		- 5.7.4. [Previous Frame Chaining](#574-previous-frame-chaining)
		- 5.7.5. [Nonrepudiation Coverage and Binding](#575-nonrepudiation-coverage-and-binding)
		- 5.7.6. [Security Property Chain](#576-security-property-chain)
	- 5.9. [What is the Matrix?](#59-what-is-the-matrix)
		- 5.9.1. [Why Use the Matrix?](#591-why-use-the-matrix)
		- 5.9.2. [The Simple View](#592-the-simple-view)
		- 5.9.3. [Wire Format (Technical Details)](#593-wire-format-technical-details)
		- 5.9.4. [Usage Rules](#594-usage-rules)
		- 5.9.5. [Example: Flag System](#595-example-flag-system)
		- 5.9.6. [Advanced: Modeling with Matrix and Previous Frame](#596-advanced-modeling-with-matrix-and-previous-frame)
		- 5.9.7. [Summary](#597-summary)
	- 5.10. [Complete ASN.1 Module](#510-complete-asn1-module)
6. [Implementation](#6-implementation)
	- 6.1. [Requirements](#61-requirements)
		- 6.1.1. [Message Security Enforcement](#611-message-security-enforcement)
	- 6.2. [Transport Layer](#62-transport-layer)
	- 6.3. [Cryptographic Key Management](#63-cryptographic-key-management)
7. [Security Considerations](#7-security-considerations)
	- 7.1. [Cryptographic Requirements](#71-cryptographic-requirements)
	- 7.2. [Version Security](#72-version-security)
	- 7.3. [ASN.1 Security Considerations](#73-asn1-security-considerations)
	- 7.4. [Security Recommendations](#74-security-recommendations)
8. [Transport Layer & Handshake Protocols](#8-transport-layer--handshake-protocols)
	- 8.1. [Transport Architecture](#81-transport-architecture)
		- 8.1.1. [Design Principles](#811-design-principles)
		- 8.1.2. [Core Transport Traits](#812-core-transport-traits)
	- 8.2. [Wire Format](#82-wire-format)
	- 8.3. [TCP Transport](#83-tcp-transport)
	- 8.4. [Transport Policies](#84-transport-policies)
		- 8.4.1. [Concept](#841-concept)
		- 8.4.2. [Specification](#842-specification)
		- 8.4.3. [Implementation](#843-implementation)
	- 8.5. [Handshake Protocols](#85-handshake-protocols)
		- 8.5.1. [Concept: Security Goals and Protocol Selection](#851-concept-security-goals-and-protocol-selection)
		- 8.5.2. [Specification: Handshake Flow and State Management](#852-specification-handshake-flow-and-state-management)
		- 8.5.3. [Implementation: CMS-Based Handshake Protocol](#853-implementation-cms-based-handshake-protocol)
		- 8.5.4. [Implementation: ECIES-Based Handshake Protocol](#854-implementation-ecies-based-handshake-protocol)
		- 8.5.5. [Session Key Derivation & Rekey Strategy](#855-session-key-derivation--rekey-strategy)
		- 8.5.6. [Negotiation & Failure Modes](#856-negotiation--failure-modes)
		- 8.5.7. [Threat → Control Mapping](#857-threat--control-mapping)
		- 8.5.8. [Testing: Handshake Validation](#858-testing-handshake-validation)
		- 8.5.9. [Security Audit Checklist](#859-security-audit-checklist)
		- 8.5.10. [Security Disclaimer](#8510-security-disclaimer)
9. [Network Theory](#9-network-theory)
	- 9.1. [Network Architecture](#91-network-architecture)
	- 9.2. [Efficient Exchange-Compute Interconnect](#92-efficient-exchange-compute-interconnect)
	- 9.3. [Components](#93-components)
		- 9.3.1. [E: Workers](#931-e-workers)
		- 9.3.2. [E: Servlets](#932-e-servlets)
		- 9.3.3. [C: Clusters](#933-c-clusters)
		- 9.3.4. [I: Drones & Hives](#934-i-drones--hives)
10. [Testing Framework](#10-testing-framework)
	- 10.1. [Quantum Entanglement Testing](#101-quantum-entanglement-testing)
	- 10.2. [Test Container Example](#102-test-container-example)
11. [End-to-End Examples](#11-end-to-end-examples)
	- 11.1. [Complete Client-Server Application](#111-complete-client-server-application)
12. [References](#12-references)
	- 12.1. [Normative References](#121-normative-references)
	- 12.2. [Standards References](#122-standards-references)
	- 12.3. [ASN.1 References](#123-asn1-references)
13. [License](#13-license)
14. [Implementation Notes](#14-implementation-notes)

## 1. Introduction

tightbeam defines a structured, versioned messaging protocol with an 
information fidelity constraint: I(t) ∈ (0,1) for all t ∈ T. Sections follow 
a [concept → specification → implementation → testing] pattern.

### 1.1 Information Fidelity Constraint

tightbeam's design is based on the principle that information transmission 
maintains bounded fidelity: **I(t) ∈ (0,1)** for all time t.

This means:
- Information fidelity is never perfect (< 1) due to physical and encoding limits
- Information content is never absent (> 0) in valid frames
- All protocol decisions ensure frames carry bounded information content

The I(t) constraint informs all protocol design decisions.

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

## 3. Architecture

### 3.1 Information Theory Properties

tightbeam implements high-fidelity information transmission through the 
following bounds:

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

The `SecurityProfile` trait defines a pure metadata layer that declares 
algorithm identifiers (OIDs) for cryptographic operations:

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
the cryptographic capabilities they require rather than depending on the full 
provider.

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

Numeric security levels are a convenience shorthand:
- Level 1 or 2 → Sets `confidential + nonrepudiable + min_version = V1`
- Does NOT enable algorithm OID validation (use type-based profiles for that)

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
composed with compatible cryptographic algorithms.

#### Security Requirement Semantics
- When a message type specifies `MUST_BE_NON_REPUDIABLE = true`, the Frame MUST include a `nonrepudiation` field
- When a message type specifies `MUST_BE_CONFIDENTIAL = true`, the Frame's metadata MUST include a `confidentiality` field
- When a message type specifies `MUST_BE_COMPRESSED = true`, the Frame's metadata `compactness` field MUST NOT be `none`
- When a message type specifies `MUST_BE_PRIORITIZED = true`, the Frame's metadata MUST include a `priority` field (V2+ only)
- The Frame's `version` field MUST be >= the message type's `MIN_VERSION` requirement

#### Profile Validation in FrameBuilder

When composing frames with `FrameBuilder`, profile constraints are enforced at
compile time if the message type has `HAS_PROFILE = true`:

**Using the `compose!` Macro:**

```rust
// Example: Message with custom profile
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
#[beam(profile(MyAppProfile))]
struct SecureMessage { data: Vec<u8> }

// compose! macro validates algorithm OIDs match MyAppProfile
let frame = compose! {
	V1: id: b"msg-001",
		order: 1696521900,
		lifetime: 3600,
		message_integrity: type Sha3_256,
		confidentiality<Aes256GcmOid, _>: &cipher,
		nonrepudiation<Secp256k1Signature, _>: &signing_key,
		message: message
}?;
```

**Using FrameBuilder Directly:**

```rust
// FrameBuilder validates algorithm OIDs match MyAppProfile
let frame = compose::<SecureMessage>(Version::V1)
	.with_message(msg)
	.with_id(b"msg-001")
	.with_order(timestamp)
	.with_message_hasher::<Sha3_256>()              // ✓ Matches MyAppProfile::DigestOid
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

The `#[derive(Beamable)]` macro implements the `Message` trait with these attributes:

**Security attributes:**
- `#[beam(message_integrity)]`, `#[beam(frame_integrity)]`
- `#[beam(nonrepudiable)]`, `#[beam(confidential)]`
- `#[beam(compressed)]`, `#[beam(prioritized)]`
- `#[beam(min_version = "V1")]`

**Profile attributes:**
- `#[beam(profile = 1)]` or `#[beam(profile = 2)]` - Numeric levels (sets confidential + nonrepudiable, no OID validation)
- `#[beam(profile(TypeName))]` - Type-based profile (enables compile-time OID validation)

#### Example Message Types

```rust
// Numeric security level (convenience)
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
#[beam(profile = 1)]
struct PaymentInstruction { /* fields */ }

// Type-based profile with algorithm enforcement
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
#[beam(profile(MyAppProfile), confidential, nonrepudiable, min_version = "V1")]
struct HighSecurityTransfer { /* fields */ }
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

### 5.3 Message Structure

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

### 5.4 External Dependencies

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

### 5.5 Encoding Rules

- **Encoding**: Distinguished Encoding Rules (DER) as specified in [ITU-T X.690](https://www.itu.int/rec/T-REC-X.690)
- **Byte Order**: Network byte order (big-endian) for multi-byte integers
- **String Encoding**: UTF-8 for textual content, raw bytes for binary data
- **Optional Fields**: Absent optional fields MUST NOT be encoded (DER requirement)

### 5.6 Version-Specific Constraints

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

### 5.7 Semantic Constraints

#### 5.7.1 Message Ordering
- `order` field MUST be monotonically increasing within a message sequence
- `order` values SHOULD be based on reliable timestamp sources
- Duplicate `order` values within the same `id` namespace MUST be rejected

#### 5.7.2 Compression Requirements
- When `compactness` is present (not `None`), the `message` field MUST contain 
compressed data encoded as `CompressedData` per RFC 3274
- The `encapContentInfo` within `CompressedData` MUST use the `id-data` content 
type OID if the compressed data does not conform to any recognized content type
- Compression algorithm identifiers MUST be valid OIDs (e.g., 
`id-alg-zlibCompress` for zlib, custom OIDs for zstd -- tightbeam uses 
1.2.840.113549.1.9.16.3 pending formal assignment)
- Compression level parameters, when specified in 
`compressionAlgorithm.parameters`, MUST be within algorithm-specific valid ranges

#### 5.7.3 Integrity Semantics: Order of Operations

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

#### 5.7.4 Previous Frame Chaining
- The ``previous_frame`` field creates a cryptographic hash chain linking frames
- Each frame's hash commits to all previous history through transitive hashing
- This enables:
  - **Causal Ordering**: Frames carry proof of their position in the sequence
  - **Tamper Detection**: Any modification to a previous frame breaks all subsequent hashes
  - **Replay Protection**: Receivers can detect out-of-sequence or duplicate frames
  - **Fork Detection**: Multiple frames with the same ``previous_frame`` indicate reality branching
  - **Stateless Verification**: Frame ancestry can be verified without storing the entire chain
- Implementations MAY store any frames/message data to enable full chain reconstruction to their desired root

#### 5.7.5 Nonrepudiation Coverage and Binding

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

#### 5.7.6 Security Property Chain

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

### 6.2 Transport Layer

tightbeam MUST operate over ANY transport protocol:
- TCP (built-in async/sync support)
- Custom transports via trait implementation

### 6.3 Cryptographic Key Management

tightbeam accepts standard key formats (X.509 certificates, raw key material, CMS structures)
and delegates key lifecycle management to applications:

- **Key Formats**: X.509 certificates, raw keys, CMS structures
- **Handshake Protocols**: CMS-based and ECIES-based handshakes for session establishment
- **Application Responsibilities**: Key generation, storage, rotation, certificate validation, revocation checking

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

## 8. Transport Layer & Handshake Protocols

### 8.1 Transport Architecture

The tightbeam transport layer provides a pluggable framework for moving bytes
between endpoints while enforcing security policies. The transport layer is
responsible for the following:
- Establishing connections
- Sending and receiving messages
- Enforcing security policies
- Managing cryptographic state

#### 8.1.1 Design Principles

The transport layer uses trait-based architecture:
- **Protocol**: Bind/connect operations
- **MessageIO**: Frame serialization and wire protocol
- **MessageEmitter/MessageCollector**: Policy enforcement (gate, retry)
- **EncryptedProtocol/EncryptedMessageIO**: Encryption support

#### 8.1.2 Core Transport Traits

**Trait hierarchy:**
- `Protocol`: Bind/connect operations
- `MessageIO`: Read/write envelopes
- `MessageCollector`: Server-side with policies
- `MessageEmitter`: Client-side with policies and retry
- `EncryptedProtocol`: Adds certificate-based binding
- `EncryptedMessageIO`: Adds encryption/decryption

### 8.2 Wire Format

Messages use ASN.1 DER encoding with two-tier envelopes:
- **WireEnvelope**: Cleartext or encrypted outer layer
- **TransportEnvelope**: Request/Response/EnvelopedData/SignedData inner layer

DER tag-length-value encoding provides inherent framing. Default size limits:
- **128 KB** for cleartext envelopes (configurable via `TransportEncryptionConfig`)
- **256 KB** for encrypted envelopes (configurable via `TransportEncryptionConfig`)
- **16 KB** for handshake messages (hard limit to prevent DoS attacks)

### 8.3 TCP Transport

TCP transport bridges byte streams with message-oriented Frame API using DER 
length-prefixed envelopes. Supports both `std::net` (sync) and `tokio` (async).

**Example:**
```rust
use std::net::TcpListener;
use tightbeam::{server, compose};

let listener = TcpListener::bind("127.0.0.1:8080")?;
server! {
	protocol std::net::TcpListener: listener,
	|message: RequestMessage, tx| async move {
		tx.send(ResponseMessage { data: "response".to_string() }).await.ok();
	}
}
```

### 8.4 Transport Policies

#### 8.4.1 Concept

Policies control message flow without modifying transport logic:

- **GatePolicy**: Accept/reject messages (rate limiting, authentication)
- **RestartPolicy**: Retry behavior with backoff strategies (exponential, linear)
- **ReceptorPolicy**: Type-safe application-level filtering

#### 8.4.2 Specification

**GatePolicy Trait:**
```rust
pub trait GatePolicy: Send + Sync {
	fn evaluate(&self, frame: &Frame) -> TransitStatus;
}
```

**ReceptorPolicy Trait:**
```rust
pub trait ReceptorPolicy<T: Message>: Send + Sync {
	fn evaluate(&self, message: &T) -> TransitStatus;
}
```

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
```

**TransitStatus:**
```rust
pub enum TransitStatus {
	Request = 0,
	Accepted = 1,
	Busy = 2,
	Unauthorized = 3,
	Forbidden = 4,
	Timeout = 5,
}
```

**RetryAction:**
```rust
pub enum RetryAction {
	NoRetry,
	RetryWithSame,
	RetryAfter(Duration),
}
```

#### 8.4.3 Implementation

**GatePolicy - Frame-Level Filtering:**

```rust
use tightbeam::policy::{GatePolicy, TransitStatus};

// Accept only messages with specific ID patterns
#[derive(Default)]
struct IdPatternGate;

impl GatePolicy for IdPatternGate {
	fn evaluate(&self, frame: &Frame) -> TransitStatus {
		if frame.metadata.id.starts_with(b"api-") {
			TransitStatus::Accepted
		} else {
			TransitStatus::Forbidden
		}
	}
}
```

**ReceptorPolicy - Message-Level Filtering:**

```rust
use tightbeam::policy::ReceptorPolicy;

#[derive(Beamable, Sequence)]
struct RequestMessage {
	content: String,
	priority: u8,
}

// Only accept high-priority messages
#[derive(Default)]
struct PriorityGate;

impl ReceptorPolicy<RequestMessage> for PriorityGate {
	fn evaluate(&self, message: &RequestMessage) -> TransitStatus {
		if message.priority >= 5 {
			TransitStatus::Accepted
		} else {
			TransitStatus::Forbidden
		}
	}
}
```

**RestartPolicy - Retry Strategies:**

```rust
use tightbeam::transport::policy::{RestartLinearBackoff, RestartExponentialBackoff};

// Linear backoff: 1s, 2s, 3s delays
let restart = RestartLinearBackoff::new(3, 1000, 1, None);

// Exponential backoff: 1s, 2s, 4s, 8s delays
let restart = RestartExponentialBackoff::new(4, 1000, None);
```

**Policy Macro:**

```rust
tightbeam::policy! {
	GatePolicy: OnlyApiMessages |frame| {
		if frame.metadata.id.starts_with(b"api-") {
			TransitStatus::Accepted
		} else {
			TransitStatus::Forbidden
		}
	}

	ReceptorPolicy<RequestMessage>: OnlyPingMessages |message| {
		if message.content == "PING" {
			TransitStatus::Accepted
		} else {
			TransitStatus::Forbidden
		}
	}

	RestartPolicy: RetryThreeTimes |_message, result, attempt| {
		if attempt < 3 && result.is_err() {
			RetryAction::RetryAfter(Duration::from_secs(1))
		} else {
			RetryAction::NoRetry
		}
	}
}
```

**Composing Policies:**

```rust
// Server-side
let listener = TokioListener::bind_with_policies(
	addr,
	ServerPolicies::default()
		.with_collector_gate(vec![Box::new(IdPatternGate)])
)?;

// Client-side
let client = TcpTransport::connect_with_policies(
	addr,
	ClientPolicies::default()
		.with_emitter_gate(vec![Box::new(PriorityGate)])
		.with_restart(RestartLinearBackoff::new(3, 1000, 1, None))
)?;
```

### 8.5 Handshake Protocols

#### 8.5.1 Concept: Security Goals and Protocol Selection

TightBeam implements two handshake protocols for mutual authentication and
session key establishment:

- **CMS-Based**: Full PKI with X.509 certificates, certificate validation chains, RFC 5652 compliance
- **ECIES-Based**: Lightweight alternative with minimal overhead

**Security Goals:**
- **Mutual Authentication**: Both parties prove identity via certificates
- **Perfect Forward Secrecy**: Ephemeral ECDH keys ensure past sessions remain secure if long-term keys are compromised
- **Replay Protection**: Nonces prevent replay attacks
- **Downgrade Prevention**: Transcript hash covers all handshake messages including profile negotiation
- **Confidentiality**: Session keys derived via HKDF protect all subsequent messages

#### 8.5.2 Specification: Handshake Flow and State Management

**Three-Phase Exchange:**

```
Phase 1: Client → Server
┌─────────────────────────────────────────────────────────┐
│ ClientHello (ECIES) or KeyExchange (CMS)                │
│ - Client nonce (32 bytes)                               │
│ - Optional SecurityOffer (supported profiles)           │
│ - Ephemeral public key (CMS: in KARI structure)         │
└─────────────────────────────────────────────────────────┘

Phase 2: Server → Client
┌─────────────────────────────────────────────────────────┐
│ ServerHandshake (ECIES) or ServerFinished (CMS)         │
│ - Server certificate                                    │
│ - Server nonce (32 bytes)                               │
│ - Selected SecurityProfile (if negotiation occurred)    │
│ - Signature over transcript hash                        │
└─────────────────────────────────────────────────────────┘

Phase 3: Client → Server
┌─────────────────────────────────────────────────────────┐
│ ClientKeyExchange (ECIES) or ClientFinished (CMS)       │
│ - Encrypted session key                                 │
│ - Optional client certificate (mutual auth)             │
│ - Optional client signature (mutual auth)               │
└─────────────────────────────────────────────────────────┘
```

**State Machines:**

Client States:
```
Init → HelloSent → KeyExchangeSent → ServerFinishedReceived → ClientFinishedSent → Completed
```

Server States:
```
Init → KeyExchangeReceived → ServerFinishedSent → ClientFinishedReceived → Completed
```

**Transcript Hash:**
```
transcript = ClientHello || ServerHandshake || ClientKeyExchange
transcript_hash = SHA3-256(transcript)
```

The transcript hash binds all handshake messages together, preventing:
- Message reordering
- Profile downgrade attacks
- Man-in-the-middle modifications

#### 8.5.3 Implementation: CMS-Based Handshake Protocol

**Overview:**

Uses RFC 5652 Cryptographic Message Syntax with:
- **EnvelopedData**: ECDH + HKDF + AES Key Wrap for session key encryption
- **SignedData**: Transcript signatures for authentication
- **KeyAgreeRecipientInfo (KARI)**: Ephemeral-static ECDH key agreement

**Mutual Authentication Flow:**

For mutual authentication, client includes certificate and signs transcript in 
ClientKeyExchange:

```
Client Side - Building ClientKeyExchange:
┌─────────────────────────────────────────────────────────────────────┐
│ 1. Extend Transcript                                                │
│    transcript = ClientHello || ServerHandshake || ClientKeyExchange │
├─────────────────────────────────────────────────────────────────────┤
│ 2. Sign Extended Transcript                                         │
│    final_hash = SHA3-256(transcript)                                │
│    client_signed_data = Sign(final_hash, client_priv_key)           │
├─────────────────────────────────────────────────────────────────────┤
│ 3. Build ClientKeyExchange                                          │
│    ┌──────────────────────────────────────────────────────────┐     │
│    │ ClientKeyExchange {                                      │     │
│    │     enveloped_data: EnvelopedData,  // Encrypted CEK     │     │
│    │     client_certificate: Some(cert), // Client cert       │     │
│    │     client_signature: Some(sig),    // Transcript sig    │     │
│    │ }                                                        │     │
│    └──────────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────────┘
```

Server verification flow:

```
Server Side - Verifying Client Authentication:
┌─────────────────────────────────────────────────────────────┐
│ 1. Validate Client Certificate                              │
│    ✓ Check certificate chain against trust anchors          │
│    ✓ Verify certificate is within validity period           │
├─────────────────────────────────────────────────────────────┤
│ 2. Extract Client Public Key                                │
│    client_pub_key = cert.subject_public_key_info            │
├─────────────────────────────────────────────────────────────┤
│ 3. Verify Transcript Signature                              │
│    verified_hash = Verify(client_signature, client_pub_key) │
├─────────────────────────────────────────────────────────────┤
│ 4. Verify Transcript Match                                  │
│    expected_hash = SHA3-256(transcript)                     │
│    if verified_hash ≠ expected_hash:                        │
│       return TranscriptMismatch error                       │
│    ✓ Client witnessed same transcript                       │
└─────────────────────────────────────────────────────────────┘
```

#### 8.5.4 Implementation: ECIES-Based Handshake Protocol

**Overview:**

Lightweight alternative using ECIES (Elliptic Curve Integrated Encryption 
Scheme) for key encapsulation. Compact structures without ASN.1 
EnvelopedData/SignedData overhead, suitable for resource-constrained 
environments or applications requiring minimal wire format complexity.

**Key Differences from CMS:**
- **Simplified Structure**: Raw ECIES encryption instead of nested CMS EnvelopedData
- **Reduced Overhead**: Flat ASN.1 structures instead of multi-level CMS nesting
- **Same Security Goals**: Mutual authentication, forward secrecy, replay protection
- **Compatible Encoding**: Both use ASN.1 DER, but ECIES avoids RFC 5652 complexity

**Mutual Authentication Flow:**

For mutual authentication, client includes certificate and signs transcript in 
ClientKeyExchange:

```
Client Side - Building ClientKeyExchange:
┌─────────────────────────────────────────────────────────────────────┐
│ 1. Perform ECDH with Server's Public Key                            │
│    shared_secret = ECDH(client_ephemeral_priv, server_pub_key)      │
├─────────────────────────────────────────────────────────────────────┤
│ 2. Derive Session Key via HKDF                                      │
│    session_key = HKDF-SHA3-256(                                     │
│        ikm: shared_secret,                                          │
│        salt: client_nonce || server_nonce,                          │
│        info: "tightbeam-ecies-session-v1"                           │
│    )                                                                │
├─────────────────────────────────────────────────────────────────────┤
│ 3. Encrypt Session Key with ECIES                                   │
│    encrypted_key = ECIES-Encrypt(                                   │
│        plaintext: session_key,                                      │
│        recipient_pub_key: server_pub_key                            │
│    )                                                                │
├─────────────────────────────────────────────────────────────────────┤
│ 4. Sign Extended Transcript                                         │
│    transcript = ClientHello || ServerHandshake || ClientKeyExchange │
│    final_hash = SHA3-256(transcript)                                │
│    client_signature = Sign(final_hash, client_priv_key)             │
├─────────────────────────────────────────────────────────────────────┤
│ 5. Build ClientKeyExchange                                          │
│    ┌──────────────────────────────────────────────────────────┐     │
│    │ ClientKeyExchange {                                      │     │
│    │     encrypted_session_key: encrypted_key,                │     │
│    │     client_certificate: Some(cert),  // Client cert      │     │
│    │     client_signature: Some(sig),     // Transcript sig   │     │
│    │ }                                                        │     │
│    └──────────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────────┘
```

Server verification flow:

```
Server Side - Verifying Client Authentication:
┌─────────────────────────────────────────────────────────────┐
│ 1. Validate Client Certificate                              │
│    ✓ Check certificate chain against trust anchors          │
│    ✓ Verify certificate is within validity period           │
├─────────────────────────────────────────────────────────────┤
│ 2. Extract Client Public Key                                │
│    client_pub_key = cert.subject_public_key_info            │
├─────────────────────────────────────────────────────────────┤
│ 3. Verify Transcript Signature                              │
│    verified_hash = Verify(client_signature, client_pub_key) │
├─────────────────────────────────────────────────────────────┤
│ 4. Verify Transcript Match                                  │
│    expected_hash = SHA3-256(transcript)                     │
│    if verified_hash ≠ expected_hash:                        │
│       return TranscriptMismatch error                       │
│    ✓ Client witnessed same transcript                       │
├─────────────────────────────────────────────────────────────┤
│ 5. Decrypt Session Key                                      │
│    session_key = ECIES-Decrypt(                             │
│        ciphertext: encrypted_session_key,                   │
│        server_priv_key: server_private_key                  │
│    )                                                        │
│    ✓ Session established with forward secrecy               │
└─────────────────────────────────────────────────────────────┘
```

**ECIES Encryption Details:**

ECIES (Elliptic Curve Integrated Encryption Scheme) combines:
- **ECDH**: Ephemeral-static key agreement for shared secret derivation
- **KDF**: HKDF-SHA3-256 for deriving encryption and MAC keys from shared secret
- **AEAD**: AES-256-GCM for authenticated encryption of session key
- **Ephemeral Keys**: Fresh ephemeral key pair per encryption operation

```
ECIES-Encrypt(plaintext, recipient_pub_key):
┌─────────────────────────────────────────────────────────┐
│ 1. Generate ephemeral key pair                          │
│    (ephemeral_priv, ephemeral_pub) = GenerateKeyPair()  │
├─────────────────────────────────────────────────────────┤
│ 2. Perform ECDH                                         │
│    shared_secret = ECDH(ephemeral_priv, recipient_pub)  │
├─────────────────────────────────────────────────────────┤
│ 3. Derive encryption keys                               │
│    (enc_key, mac_key) = HKDF-SHA3-256(                  │
│        ikm: shared_secret,                              │
│        info: ephemeral_pub || "ecies-kdf"               │
│    )                                                    │
├─────────────────────────────────────────────────────────┤
│ 4. Encrypt with AEAD                                    │
│    ciphertext = AES-256-GCM.encrypt(                    │
│        key: enc_key,                                    │
│        plaintext: plaintext,                            │
│        aad: ephemeral_pub                               │
│    )                                                    │
├─────────────────────────────────────────────────────────┤
│ 5. Return ECIES message                                 │
│    return (ephemeral_pub || ciphertext)                 │
└─────────────────────────────────────────────────────────┘
```

**Wire Format Comparison:**

| Feature | CMS-Based | ECIES-Based |
|---------|-----------|-------------|
| Envelope Structure | RFC 5652 nested structures | Simplified ASN.1 structures |
| Key Agreement | KARI (KeyAgreeRecipientInfo) | Raw ECIES with DER encoding |
| Session Key Encryption | EnvelopedData + AES-KW | ECIES + AES-GCM |
| Signatures | SignedData structure | Raw signatures in ASN.1 |
| Size Overhead | ~400-600 bytes | ~200-300 bytes |
| Parsing Complexity | Multi-level ASN.1 nesting | Flat ASN.1 structures |
| Standards Compliance | RFC 5652, RFC 5753 | SECG SEC 1 + custom ASN.1 |

**Performance Characteristics:**

- **Handshake Time**: 20-30% faster than CMS (reduced parsing overhead)
- **Memory Usage**: 30-40% lower than CMS (no ASN.1 intermediate structures)
- **Wire Size**: 40-50% smaller than CMS (compact binary encoding)
- **CPU Usage**: Similar cryptographic operations (same curves and algorithms)

**Security Equivalence:**

Both protocols provide identical security properties:
- ✓ Mutual authentication via certificates
- ✓ Perfect forward secrecy via ephemeral ECDH
- ✓ Replay protection via nonces
- ✓ Transcript integrity via signatures
- ✓ Confidentiality via AEAD encryption

#### 8.5.5 Security Profile Negotiation

Both CMS and ECIES handshake protocols support cryptographic algorithm 
negotiation through `SecurityProfile` descriptors:

**Negotiation Process:**

```
Client                              Server
  │                                   │
  │─── SecurityOffer ───────────────► │
  │    supported_profiles: [          │
  │      Profile1: SHA3-256+          │  ◄─ Select first
  │               AES-256-GCM,        │     mutual profile
  │      Profile2: SHA-256+           │
  │               AES-128-GCM         │
  │    ]                              │
  │                                   │
  │ ◄── SecurityAccept ─────────────  │
  │     selected_profile:             │
  │       Profile1 (SHA3-256+         │
  │       AES-256-GCM+secp256k1)      │
  │                                   │
  ├═══════════════════════════════════┤
  │ All subsequent operations use     │
  │ selected profile algorithms       │
  └═══════════════════════════════════┘
```

**Profile Validation:**
- Server MUST select from client's offered profiles
- Server MUST NOT select unsupported algorithms
- Client MUST verify selected profile was in its offer
- Transcript signature covers the negotiation to prevent downgrade attacks

#### 8.5.6 Negotiation & Failure Modes

**Profile Negotiation:**

```rust
// Client offers supported profiles
let security_offer = SecurityOffer {
	supported_profiles: vec![
		ProfileDescriptor { /* SHA3-256 + AES-256-GCM + secp256k1 */ },
		ProfileDescriptor { /* SHA-256 + AES-128-GCM + P-256 */ },
	],
};

// Server selects first mutually supported profile
let security_accept = SecurityAccept {
	selected_profile: ProfileDescriptor { /* chosen profile */ },
};
```

**Failure Modes:**

| Error | Cause | Recovery |
|-------|-------|----------|
| `CertificateValidationFailed` | Invalid certificate chain | Reject connection |
| `TranscriptMismatch` | MITM or protocol error | Abort handshake |
| `NonceReplay` | Duplicate nonce detected | Reject message |
| `UnsupportedProfile` | No mutual profile | Negotiate or reject |
| `InvalidState` | Out-of-order message | Reset state machine |
| `DecryptionFailed` | Wrong key or corrupted data | Abort handshake |

#### 8.5.7 Threat → Control Mapping

| Threat | Control | Implementation |
|--------|---------|----------------|
| **Replay Attack** | 32-byte nonce + replay set | Server maintains set of seen nonces; rejects duplicates |
| **Downgrade Attack** | Profile list in signed transcript | Transcript hash covers SecurityOffer/SecurityAccept |
| **MITM** | Transcript signatures | Both parties sign transcript_hash; verified against certificates |
| **Confidentiality** | ECDH + HKDF derived AEAD key | Session key never transmitted; derived from ECDH shared secret |
| **Forward Secrecy** | Ephemeral client keys | New ephemeral key per handshake; compromise doesn't affect past sessions |
| **DoS** | 16 KiB handshake size cap | Reject oversized handshake messages before processing |
| **Certificate Forgery** | X.509 chain validation | Verify certificate chain against trust anchors |
| **Nonce Reuse** | Monotonic counter + XOR | Per-message nonce derived from seed XOR counter |

### 8.6 Audit

The tightbeam transport layer and handshake protocols have not yet been
independently audited. We welcome help in this area.

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
- [Workers](#931-e-workers) - Efficient processing units
- [Servlets](#932-e-servlets) - Exchange endpoints
- [Clusters](#933-c-clusters) - Compute orchestration
- [Drone/Hive](#934-i-drones--hives) - Interconnected infrastructure

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

tightbeam implements a novel testing approach called **Concurrent Behavior Verification 
with Observation Channels** (CBVOC), which enables deterministic testing of concurrent 
client-server interactions through non-intrusive observation points.

### 10.1 Testing Methodology Overview

Traditional integration testing of concurrent systems faces fundamental challenges:
- **Race Conditions**: Non-deterministic timing between client and server threads
- **State Inspection**: Difficulty observing internal state without disrupting execution
- **Causal Ordering**: Verifying event sequences across concurrent execution contexts
- **Test Isolation**: Ensuring tests don't interfere with the system under test

CBVOC solves these problems through side-channel observation: auxiliary communication 
channels that allow tests to observe system behavior without modifying the primary 
client-server communication path.

#### Why This Approach is Superior

**Compared to Traditional Mocking:**
- **Real Concurrency**: Tests actual multi-threaded behavior, not mock sequencing
- **No Stubs Required**: Uses actual transport implementations
- **Timing Verification**: Observes real async/await state transitions

**Compared to Deterministic Schedulers:**
- **Production-Like**: Tests run with real OS threading and scheduling
- **No Custom Runtime**: Works with standard Tokio/async-std executors
- **Performance Realistic**: Reveals actual timing-dependent bugs

**Compared to Black-Box Integration Tests:**
- **Internal Visibility**: Observes intermediate states during message processing
- **Assertion Granularity**: Can verify specific event orderings
- **Debugging Aid**: Observation channels provide execution traces

**Compared to Time-Based Synchronization:**
- **No Sleep/Wait**: Uses channel synchronization instead of arbitrary timeouts
- **Deterministic**: Events occur in predictable order relative to observations
- **Fast Execution**: No artificial delays bloating test suite runtime

### 10.2 Concurrent Behavior Verification with Observation Channels

The core mechanism uses three MPSC (multi-producer, single-consumer) channels 
that act as observation points into the concurrent system:

```rust
// Server handler channel: tx for server, rx for container
let (tx, rx) = mpsc::channel();

// Status channels (container receives ok/reject)
let (ok_tx, ok_rx) = mpsc::channel();
let (reject_tx, reject_rx) = mpsc::channel();

// Exposed in test as single tuple
let channels = (rx, ok_rx, reject_rx);
```

#### The Quantum Entanglement Analogy

While not literally quantum mechanics, the testing pattern exhibits analogous properties 
that help understand its behavior:

**Superposition**: Before observation (await completion), the system exists in a 
superposition of possible states—the message may be accepted, rejected, processed, 
or failed. The test doesn't know which until observation occurs.

**Wave Function Collapse**: When `client.emit(...).await` completes, the "wave function 
collapses"—the test can now deterministically observe what happened through the 
observation channels. Causality is preserved because channel receives are ordered.

**Entanglement**: The observation channels are "entangled" with the system under test. 
What happens in one channel (e.g., gate acceptance) is correlated with what you expect 
in others (e.g., server handler invocation). These correlations encode the system's 
causal structure.

**No Faster-Than-Light**: Just as quantum mechanics respects causality, so does 
CBVOC. Channel synchronization ensures that observations respect the 
happens-before relationship. A test cannot observe an event before it occurs.

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

The test container is in an indeterminate state before `client.emit().await` completes. 
When the await resolves, the system state "collapses" to a deterministic outcome—causality 
intact. The test can now observe the complete execution trace through the channels: 
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

#### Key Benefits

1. **Happens-Before Verification**: Channel ordering guarantees causal consistency
2. **No Race Conditions**: Synchronization points prevent non-deterministic failures
3. **Full Execution Trace**: Observe internal state transitions during message processing
4. **Minimal Overhead**: Channel operations are lightweight compared to alternatives
5. **Test Isolation**: Each test container has independent channel instances

### 10.3 Test Container Example

Complete example demonstrating Concurrent Behavior Verification with Observation Channels:
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

**See:** [Container Integration Test](tests/container.rs)

## 11. End-to-End Examples

This section contains complete, runnable examples demonstrating real-world usage patterns.

### 11.1 Complete Client-Server Application

Coming soon.

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

### 12.2 Standards References

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