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
	- 5.8. [What is the Matrix?](#58-what-is-the-matrix)
		- 5.8.1. [Why Use the Matrix?](#581-why-use-the-matrix)
		- 5.8.2. [The Simple View](#582-the-simple-view)
		- 5.8.3. [Wire Format (Technical Details)](#583-wire-format-technical-details)
		- 5.8.4. [Usage Rules](#584-usage-rules)
		- 5.8.5. [Example: Flag System](#585-example-flag-system)
		- 5.8.6. [Advanced: Modeling with Matrix and Previous Frame](#586-advanced-modeling-with-matrix-and-previous-frame)
		- 5.8.7. [Summary](#587-summary)
	- 5.9. [Complete ASN.1 Module](#59-complete-asn1-module)
6. [Implementation](#6-implementation)
	- 6.1. [Requirements](#61-requirements)
		- 6.1.1. [Message Security Enforcement](#611-message-security-enforcement)
	- 6.2. [Transport Layer](#62-transport-layer)
	- 6.3. [Cryptographic Key Management](#63-cryptographic-key-management)
7. [Security Considerations](#7-security-considerations)
	- 7.1. [Cryptographic Requirements](#71-cryptographic-requirements)
	- 7.2. [Version Security](#72-version-security)
	- 7.3. [ASN.1 Security Considerations](#73-asn1-security-considerations)
8. [Transport Layer](#8-transport-layer)
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
		- 8.5.5. [Security Profile Negotiation](#855-security-profile-negotiation)
		- 8.5.6. [Negotiation & Failure Modes](#856-negotiation--failure-modes)
		- 8.5.7. [Threat → Control Mapping](#857-threat--control-mapping)
	- 8.6. [Audit](#86-audit)
9. [Network Theory](#9-network-theory)
	- 9.1. [Network Architecture](#91-network-architecture)
	- 9.2. [Efficient Exchange-Compute Interconnect](#92-efficient-exchange-compute-interconnect)
	- 9.3. [Components](#93-components)
		- 9.3.1. [E: Workers](#931-e-workers)
		- 9.3.2. [E: Servlets](#932-e-servlets)
		- 9.3.3. [C: Clusters - WIP](#933-c-clusters-wip)
		- 9.3.4. [I: Drones & Hives - WIP](#934-i-drones-hives-wip)
10. [Testing Framework](#10-testing-framework)
	- 10.1. [Architecture and Concepts](#101-architecture-and-concepts)
		- 10.1.1. [Three-Layer Progressive Verification](#1011-three-layer-progressive-verification)
		- 10.1.2. [Unified Entry Point: tb_scenario!](#1012-unified-entry-point-tb_scenario)
		- 10.1.3. [Feature Flag Architecture](#1013-feature-flag-architecture)
	- 10.2. [Layer 1: Assertion Specifications](#102-layer-1-assertion-specifications)
		- 10.2.1. [Concept](#1021-concept)
		- 10.2.2. [Specification: tb_assert_spec! Syntax](#1022-specification-tb_assert_spec-syntax)
		- 10.2.3. [Implementation Examples](#1023-implementation-examples)
		- 10.2.4. [Generated API](#1024-generated-api)
		- 10.2.5. [Cardinality Helpers](#1025-cardinality-helpers)
		- 10.2.6. [Value Assertion Helpers](#1026-value-assertion-helpers)
		- 10.2.7. [Tag-Based Assertion Filtering](#1027-tag-based-assertion-filtering)
	- 10.3. [Layer 2: Process Specifications (CSP)](#103-layer-2-process-specifications-csp)
		- 10.3.1. [Concept](#1031-concept)
		- 10.3.2. [Specification: tb_process_spec! Syntax](#1032-specification-tb_process_spec-syntax)
		- 10.3.3. [Validation Rules](#1033-validation-rules)
		- 10.3.4. [Example: CSP Process Specification](#1034-example-csp-process-specification)
		- 10.3.5. [Generated API](#1035-generated-api)
	- 10.4. [Layer 3: Refinement Checking (FDR)](#104-layer-3-refinement-checking-fdr)
		- 10.4.1. [Concept](#1041-concept)
		- 10.4.2. [Specification: FdrConfig Syntax](#1042-specification-fdrconfig-syntax)
		- 10.4.3. [Implementation Examples](#1043-implementation-examples)
		- 10.4.4. [Multi-Seed Exploration](#1044-multi-seed-exploration)
		- 10.4.5. [FDR Verdict Structure](#1045-fdr-verdict-structure)
	- 10.5. [Formal CSP Theory](#105-formal-csp-theory)
		- 10.5.1. [Three Semantic Models](#1051-three-semantic-models)
		- 10.5.2. [Observable vs. Hidden Events](#1052-observable-vs-hidden-events)
		- 10.5.3. [Nondeterministic Choice and Refusal Sets](#1053-nondeterministic-choice-and-refusal-sets)
		- 10.5.4. [Multi-Seed Exploration and Scheduler Interleaving](#1054-multi-seed-exploration-and-scheduler-interleaving)
		- 10.5.5. [FDR Verification Verdict](#1055-fdr-verification-verdict)
		- 10.5.6. [CSPM Export for FDR4 Integration](#1056-cspm-export-for-fdr4-integration)
		- 10.5.7. [Trace Analysis Extensions](#1057-trace-analysis-extensions)
	- 10.6. [Unified Testing: tb_scenario! Macro](#106-unified-testing-tb_scenario-macro)
		- 10.6.1. [Syntax](#1061-syntax)
		- 10.6.2. [Examples](#1062-examples)
	- 10.7. [Coverage-Guided Fuzzing with AFL](#107-coverage-guided-fuzzing-with-afl)
		- 10.7.1. [Concept](#1071-concept)
		- 10.7.2. [Creating Fuzz Targets](#1072-creating-fuzz-targets)
		- 10.7.3. [Building and Running Fuzz Targets](#1073-building-and-running-fuzz-targets)
		- 10.7.4. [Advanced: CSP Oracle Integration](#1074-advanced-csp-oracle-integration)
		- 10.7.5. [IJON Integration: Input-to-State Correspondence](#1075-ijon-integration-input-to-state-correspondence)
	- 10.8. [Feature Matrix](#108-feature-matrix)
11. [Instrumentation](#11-instrumentation)
	- 11.1. [Objectives](#111-objectives)
	- 11.2. [Event Kind Taxonomy](#112-event-kind-taxonomy)
	- 11.3. [Event Structure](#113-event-structure)
	- 11.4. [Payload Representation](#114-payload-representation)
	- 11.5. [Configuration](#115-configuration)
	- 11.6. [Evidence Artifact Format](#116-evidence-artifact-format)
	- 11.7. [Failure Handling](#117-failure-handling)
12. [End-to-End Examples](#12-end-to-end-examples)
	- 12.1. [Complete Client-Server Application](#121-complete-client-server-application)
13. [References](#13-references)
	- 13.1. [Normative References](#131-normative-references)
	- 13.2. [Standards References](#132-standards-references)
	- 13.3. [ASN.1 References](#133-asn1-references)
14. [License](#14-license)
15. [Implementation Notes](#15-implementation-notes)

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

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC2119](https://datatracker.ietf.org/doc/html/rfc2119).

## 2. Terminology
The following project terms MUST be used consistently:
- [tightbeam](https://docs.rs/tightbeam-rs/latest): The project name. Lowercase as tightbeam.
- [Frame](#42-frame-structure): A versioned snapshot (state) at time t.
- [Message](#53-message-structure): A typed application payload serialized within a Frame.
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

- VERSION 3
  - Inherits: All V2 features
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
	type CurveOid: AssociatedOid;
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
	type CurveOid = Secp256k1Oid;
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
	type CurveOid = Secp256k1Oid;
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

	// V3+ fields
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
	v3(3)
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

	-- V3+ fields (context-specific tags)
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

> Note: TightBeam implementations SHOULD use SHA-256 or stronger hash algorithms
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
- OPTIONAL: `priority`, `lifetime`, ``previous_frame``
- FORBIDDEN: All V3+ specific fields

#### Version 3 (V3)
- INHERITS: All V2 requirements
- OPTIONAL: `matrix`

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
  - **Fork Detection**: Multiple frames with the same ``previous_frame`` indicate branching
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

### 5.8 What is the Matrix?

The Matrix is a compact, flexible structure for transmitting state information.
It uses a grid of cells, encoded with ASN.1 DER, to represent application-defined
states with perfect structure, aligning with tightbeam's core constraint: **I(t) ∈ (0,1)**.

#### 5.8.1 Why Use the Matrix?

The matrix enables applications to:
- **Pack Dense State**: Store up to 255×255 values (0-255) in ~63.5 KB.
- **Support Evolution**: Extensible design ensures backward compatibility.
- **Ensure Fidelity**: Deterministic encoding and validation constrain I(t) ∈ (0,1).
- **Enable Advanced Modeling**: Combine with `previous_frame` for causal state tracking.

#### 5.8.2 The Simple View

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

#### 5.8.3 Wire Format (Technical Details)

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

#### 5.8.4 Usage Rules

To constrain **I(t) ∈ (0,1)**:

- **Encoding**: Encoders MUST set data.len = n², filling cells with values 0-255.
- **Decoding**: Decoders MUST reject matrices where data.len != n² or values exceed 255.
- **Semantics**: Applications MUST define value meanings.
- **Unspecified Cells**: Receivers SHOULD ignore non-zero values in undefined cells to support evolvability.
- **Absent Matrix**: If the matrix field is omitted, applications MAY assume a default state.

#### 5.8.5 Example: Flag System

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

#### 5.8.6 Advanced: Modeling with Matrix and Previous Frame

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

#### 5.8.7 Summary

The matrix supports flexible state representation, from simple flags to
structured data encoding allowing for dynamic computation.

### 5.9 Complete ASN.1 Module

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
	v2(2),
	v3(3)
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
- V2: Enhanced with priority, lifetime, and state chaining
- V3: Enhanced with matrix controls

### 7.3 ASN.1 Security Considerations

- DER encoding prevents ambiguous parsing attacks
- Context-specific tags prevent field confusion
- Explicit versioning prevents downgrade attacks
- Optional field handling prevents injection attacks

## 8. Transport Layer

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
EnvelopedData/SignedData overhead requiring minimal wire format complexity.

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
  │      Profile1: SHA3-256           │  ◄─ Select first
  │                AES-128-GCM,       │     mutual profile
  |                secp256k1          │
  |                secp256k1          │
  │      Profile2: SHA3-512           │
  │                AES-256-GCM        │
  |                ed25519            │
  |                x25519             │
  │    ]                              │
  │                                   │
  │ ◄── SecurityAccept ─────────────  │
  │     selected_profile:             │
  │       Profile1 (SHA3-256+         │
  │       AES-128-GCM+secp256k1)      │
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
	handle: |_message, _trace, config| async move {
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
Testing workers uses the `tb_scenario!` macro with the Worker environment:

```rust
use tightbeam::testing::*;
use tightbeam::trace::TraceCollector;

// Define assertion spec for worker behavior
tb_assert_spec! {
	pub PingPongWorkerSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("relay_start", exactly!(2)),
			("relay_success", exactly!(1)),
			("response_result", exactly!(1), equals!("PONG")),
			("relay_rejected", exactly!(1))
		]
	},
}

// Define CSP process spec for worker state machine
tb_process_spec! {
	pub PingPongWorkerProcess,
	events {
		observable { "relay_start", "relay_success", "relay_rejected" }
		hidden { "validate_message", "process_message" }
	}
	states {
		Idle       => { "relay_start" => Processing }
		Processing => { "validate_message" => Validating }
		Validating => { "process_message" => Responding, "relay_rejected" => Idle }
		Responding => { "relay_success" => Idle }
	}
	terminal { Idle }
	choice { Validating }
}

tb_scenario! {
	name: test_ping_pong_worker,
	spec: PingPongWorkerSpec,
	csp: PingPongWorkerProcess,
	environment Worker {
		setup: PingPongWorker::new,
		stimulus: |trace, worker: &mut PingPongWorker| {
			// Test accepted message
			trace.assert("relay_start", &[]);
			let ping_msg = RequestMessage {
				content: "PING".to_string(),
				lucky_number: 42,
			};

			let response = worker.relay(trace.clone(), std::sync::Arc::new(ping_msg))?;
			if let Some(pong) = response {
				trace.assert_value("response_result", &[], pong.result);
			}

			trace.assert("relay_success", &[]);

			// Test rejected message
			trace.assert("relay_start", &[]);
			let pong_msg = RequestMessage {
				content: "PONG".to_string(),
				lucky_number: 42,
			};

			let result = worker.relay(trace.clone(), std::sync::Arc::new(pong_msg));
			if result.is_err() {
				trace.assert("relay_rejected", &[]);
			}

			Ok(())
		}
	}
}
```

The Worker environment:
- Calls `setup` constructor with TraceCollector to create worker instance
- Executes `stimulus` closure with trace and mutable worker reference
- Collects assertions from worker operations
- Verifies against spec and process after execution
- Does not involve transport layer (workers operate on local data)

#### 9.3.2 E: Servlets

Servlets are "anthills" in the sense they operate on a specific protocol. From
a protocol perspective, an anthill is a port in many ways. Servlets are
multi-threaded and must handle messages asynchronously. A servlet may also
define as many different workers as it needs to accomplish its task as well
as a set of configurations. Servlets must be provided a relay which is used to
relay `Message` types to the worker without the entire Frame. A servlet must
only be responsible for a single message type.

```rust
tightbeam::servlet! {
	pub PingPongServletWithWorker<RequestMessage>,
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
	handle: |message, _trace, _config, workers| async move {
		let decoded = crate::decode::<RequestMessage, _>(&message.message).ok()?;
		let decoded_arc = Arc::new(decoded);
			let (ping_result, lucky_result) = tokio::join!(
			workers.ping_pong.relay(trace.clone(), Arc::clone(&decoded_arc)),
			workers.lucky_number.relay(trace.clone(), Arc::clone(&decoded_arc))
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
			V0: id: std::sync::Arc::new(message.metadata.id.clone()),
				message: ResponseMessage {
					result: reply.result,
					is_winner,
				}
		}.ok()
	}
}
```

**Efficient Parallel Worker Processing**

Workers accept `Arc<Input>` instead of owned `Input` to enable efficient
parallel processing without cloning message data. When calling multiple workers
in parallel:

- `Arc::new(decoded)` creates a single shared reference-counted pointer to the message
- `Arc::clone(&decoded_arc)` increments the reference count (cheap operation, no data copying)
- Multiple workers can process the same message data concurrently
- `tokio::join!` executes all worker relays in parallel

**Example using `tokio::join!`:**
```rust
let decoded_arc = Arc::new(decoded);
let trace = TraceCollector::new();
let (result1, result2) = tokio::join!(
    workers.worker1.relay(trace.clone(), Arc::clone(&decoded_arc)),
    workers.worker2.relay(trace.clone(), Arc::clone(&decoded_arc))
);
```

##### Testing
Testing servlets uses the `tb_scenario!` macro with the Servlet environment:

```rust
use tightbeam::testing::*;
use tightbeam::trace::TraceCollector;

// Define assertion spec for servlet behavior
tb_assert_spec! {
	pub PingPongSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("request_received", exactly!(1)),
			("pong_sent", exactly!(1)),
			("response_result", exactly!(1), equals!("PONG")),
			("is_winner", exactly!(1), equals!(true))
		]
	},
}

// Define process spec for servlet state machine
tb_process_spec! {
	pub PingPongProcess,
	events {
		observable { "request_received", "pong_sent" }
		hidden { "validate_lucky_number", "format_response" }
	}
	states {
		Idle       => { "request_received" => Processing }
		Processing => { "validate_lucky_number" => Validating }
		Validating => { "format_response" => Responding }
		Responding => { "pong_sent" => Idle }
	}
	terminal { Idle }
	choice { Processing }
}

tb_scenario! {
	name: test_servlet_with_workers,
	spec: PingPongSpec,
	csp: PingPongProcess,
	environment Servlet {
		servlet: PingPongServletWithWorker,
		client: |trace, mut client| async move {
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

			// Client-side assertion before sending
			trace.assert("request_received", &[]);

			// Test winning case
			let ping_message = generate_message(42, None)?;
			let response = client.emit(ping_message, None).await?;
			let response_message: ResponseMessage = crate::decode(&response.unwrap().message)?;

			// Emit value assertions for spec verification
			trace.assert_value("response_result", &[], response_message.result);
			trace.assert_value("is_winner", &[], response_message.is_winner);

			// Client-side assertion after receiving
			trace.assert("pong_sent", &[]);

			Ok(())
		}
	}
}
```

The Servlet environment automatically:
- Starts the servlet with its configuration
- Manages the servlet lifecycle
- Provides a client connected to the servlet
- Collects assertions from both servlet handlers and client code
- Verifies against the spec and process model after execution

#### 9.3.3 C: Clusters - WIP

Clusters orchestrate multiple servlets and workers. They are the "ant colonies"
of the EECI. Colonies are made up of multiple servlets which command different
workers. Clusters are multi-threaded and must handle messages asynchronously.
Clusters may also define a configuration and as many different servlets as it
needs to handle its purpose. While servlets are given a relay, clusters must be
provided a router. Routers can emit messages to the servlets registered within
the cluster.

```rust
// TODO
```

#### 9.3.4 I: Drones & Hives - WIP

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

**Regular Drone Example** (morphs between servlets one at a time):

```rust
tightbeam::drone! {
	pub RegularDrone,
	protocol: Listener,
	servlets: {
		ping_pong: PingPongServletWithWorker<RequestMessage>,
		other_servlet: OtherServlet<RequestMessage>
	}
}

// Start the drone
let drone = RegularDrone::start(tightbeam::trace::TraceCollector::new(), None).await?;

// Register with cluster
let cluster_addr = "127.0.0.1:8888".parse()?;
let response = drone.register_with_cluster(cluster_addr).await?;
```

**Hive Example** (manages multiple servlets simultaneously on different ports):

```rust
tightbeam::drone! {
	pub MyHive,
	protocol: TokioListener,
	hive: true,
	servlets: {
		ping_pong: PingPongServletWithWorker<RequestMessage>,
		other_servlet: OtherServlet<RequestMessage>
	}
}

// Start the hive
let hive = MyHive::start(tightbeam::trace::TraceCollector::new(), None).await?;
```

**Drone with Policies**:

```rust
tightbeam::drone! {
	pub SecureDrone,
	protocol: Listener,
	policies: {
		with_collector_gate: [SignatureGate::new(verifying_key)]
	},
	servlets: {
		ping_pong: PingPongServletWithWorker<RequestMessage>
	}
}
```

##### Conclusion

How you wish to model your colonies is beyond the scope of this document.
However, it is important to understand the basic building blocks and how they
can be combined to create complex systems. The swarm is yours to command.

## 10. Testing Framework

The tightbeam testing framework provides three progressive verification layers
for rigorous behavioral testing of protocol implementations.

### 10.1 Architecture and Concepts

The tightbeam testing framework is built on two foundational concepts from
formal methods and statistical testing theory:

#### Communicating Sequential Processes (CSP)

CSP is a formal language for describing patterns of interaction in concurrent
systems, developed by Tony Hoare.[^hoare1978][^roscoe2010] In tightbeam, CSP
provides the mathematical foundation for modeling protocol behavior as labeled
transition systems (LTS). Each process specification defines:

- **Alphabet (Σ, τ)**: Observable events visible to the environment (Σ) and hidden internal events (τ)
- **State Space**: Named states representing protocol phases
- **Transitions**: Labeled edges defining valid state changes
- **Refinement**: Hierarchical relationship where implementation traces must be valid specification traces

CSP enables us to express protocol correctness as refinement relations:
`Implementation ⊑ Specification`, where ⊑ denotes trace refinement (⊑T) or
failures refinement (⊑F).

#### Failures-Divergences Refinement (FDR)

FDR is a model checking methodology that verifies CSP refinement relations
through exhaustive exploration.[^fdr4] The framework checks three key
properties:

1. **Trace Refinement (⊑T)**: Every observable trace of the implementation is a valid trace of the specification
2. **Failures Refinement (⊑F)**: The implementation cannot refuse events that the specification accepts at any state
3. **Divergence Freedom**: The system cannot enter infinite internal-only loops (livelock)

In tightbeam, FDR-style verification uses multi-seed exploration to account for
scheduler nondeterminism in cooperatively scheduled systems. This approach,
based on research by Pedersen & Chalmers,[^pedersen2024] recognizes that
refinement verification in systems with cooperative scheduling depends on
resource availability and execution interleaving.

#### Integration in tightbeam

The three-layer architecture progressively applies these concepts:
- **Layer 1 (Assertions)**: Basic event occurrence verification
- **Layer 2 (CSP)**: State machine modeling with observable/hidden event distinction
- **Layer 3 (FDR)**: Refinement checking via multi-seed exploration

This progressive approach allows developers to start with simple assertions and
incrementally add formal verification as protocol complexity grows.

#### 10.1.1 Three-Layer Progressive Verification

Tightbeam implements formal verification through three complementary layers,
each building upon the previous:

| Layer | Feature Flag | Purpose | Specification | Usage |
|-------|--------------|---------|---------------|-------|
| L1 AssertSpec | `testing` | Runtime assertion verification | `tb_assert_spec!` | Required: `spec:` field |
| L2 ProcessSpec | `testing-csp` | CSP state machine modeling | `tb_process_spec!` | Optional: `csp:` field |
| L3 Refinement | `testing-fdr` | Trace/failures refinement | Inline config | Optional: `fdr:` field |

**Layer 1 (Assertions)**: Verifies that expected events occur with correct
cardinality. This provides basic behavioral correctness through declarative
assertion specifications.

**Layer 2 (CSP Process Models)**: Adds formal state machine modeling using
Communicating Sequential Processes (CSP) theory. Validates that execution traces
follow valid state transitions and distinguishes between observable (external)
and hidden (internal) events.

**Layer 3 (FDR Refinement)**: Enables multi-seed exploration for exhaustive
verification of trace refinement, failures refinement, and divergence freedom.
Based on FDR (Failures-Divergences Refinement) model checking methodology.

#### 10.1.2 Unified Entry Point: tb_scenario!

All three layers are accessed through the `tb_scenario!` macro, which provides:
- Consistent syntax across all verification layers
- Progressive enhancement (L1 → L1+L2 → L1+L2+L3)
- Environment abstraction (ServiceClient, Servlet, Worker, Bare)
- Instrumentation integration
- Policy enforcement

#### 10.1.3 Feature Flag Architecture

The testing framework uses progressive feature flags:
- `testing`: Enables L1 assertion verification (foundation)
- `testing-csp`: Enables L1+L2 CSP process modeling
- `testing-fdr`: Enables L1+L2+L3 refinement checking (requires `testing-csp`)

Each layer builds on the previous, ensuring consistent semantics across
verification levels.

### 10.2 Layer 1: Assertion Specifications

#### 10.2.1 Concept

AssertSpec defines expected behavioral invariants through declarative assertion
specifications. Each specification version declares:
- Expected assertion labels (event identifiers)
- Cardinality constraints (exactly, at_least, at_most, between)
- Value assertions (equals) for verifying assertion payload values
- Execution mode (Accept, Reject)
- Gate policy (Accepted, Rejected, etc.)

Specifications are versioned using semantic versioning (major.minor.patch) and
produce deterministic SHA3-256 hashes over their canonical representation.

#### 10.2.2 Specification: tb_assert_spec! Syntax

```rust
tb_assert_spec! {
	pub MySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		tag_filter: ["v1"],
		assertions: [
			("Received", exactly!(1)),
			("Responded", exactly!(1), equals!("ok"))
		]
	},
	V(1,1,0): {
		mode: Accept,
		gate: Accepted,
		tag_filter: ["v1.1"],
		assertions: [
			("Received", exactly!(1)),
			("Responded", exactly!(2))
		]
	},
}
```

**Version Block Syntax**:
```
V(major, minor, patch): {
	mode: <ExecutionMode>,              // Accept or Reject
	gate: <TransitStatus>,              // Accepted, Rejected, etc.
	tag_filter: ["tag1", "tag2"],       // Optional: filter assertions by tags
	assertions: [                       // Array of (label, cardinality) or (label, cardinality, equals!(value))
		("label", cardinality),
		("label", cardinality, equals!(value)),
		...
	],
	events: [Kind, ...]                 // Optional: when instrumentation enabled
}
```

**Deterministic Hashing**: Each version produces a 32-byte SHA3-256 hash over:
- Domain tag `"TBSP"` (TightBeam Spec Protocol)
- Version triple (major, minor, patch)
- Spec identifier
- Mode code
- Gate presence and value
- Tag filter (if present)
- Normalized assertions (sorted by label)
- Optional event kinds

#### 10.2.3 Implementation Examples

**Basic Specification**:
```rust
tb_assert_spec! {
	pub DemoSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		tag_filter: ["v1"],
		assertions: [
			("A", exactly!(1)),
			("R", exactly!(1))
		]
	},
	V(1,1,0): {
		mode: Accept,
		gate: Accepted,
		tag_filter: ["v1.1"],
		assertions: [
			("A", exactly!(1)),
			("R", exactly!(2))
		]
	},
}
```

#### 10.2.4 Generated API

Each `tb_assert_spec!` generates a type with the following methods:

```rust
impl MySpec {
	// Retrieve all defined versions
	pub fn all() -> &'static [AssertionSpec];

	// Lookup specific version
	pub fn get(major: u16, minor: u16, patch: u16) -> Option<&'static AssertionSpec>;

	// Get highest semantic version
	pub fn latest() -> &'static AssertionSpec;
}
```

#### 10.2.5 Cardinality Helpers

The framework provides cardinality constraint macros:
- `exactly!(n)`: Exactly n occurrences
- `at_least!(n)`: Minimum n occurrences
- `at_most!(n)`: Maximum n occurrences
- `between!(min, max)`: Range [min, max] occurrences
- `present!()`: At least one occurrence
- `absent!()`: Zero occurrences

#### 10.2.6 Value Assertion Helpers

The framework provides value assertion helpers for verifying assertion payload values:
- `equals!(value)`: Verify assertion value equality

**Supported Types**:
- **Primitives**: `String`, `&str`, `bool`, `u8`, `u32`, `u64`, `i32`, `i64`, `f64`
- **Numeric literals**: `equals!(3_600)`, `equals!(42u32)`
- **Enums**: `MessagePriority`, `Version` (e.g., `equals!(MessagePriority::High)`, `equals!(Version::V2)`)
- **Options**: `equals!(Some(value))`, `equals!(None)`
- **Option presence**: `equals!(IsSome)` (matches any `Some(_)`), `equals!(IsNone)` (matches `None`)

**Examples**:
```rust
assertions: [
	("priority", exactly!(1), equals!(MessagePriority::High)),
	("lifetime", exactly!(1), equals!(3_600)),
	("version", exactly!(1), equals!(Version::V2)),
	("confidentiality", exactly!(1), equals!(IsSome)),
	("optional_field", exactly!(1), equals!(IsNone))
]
```

#### 10.2.7 Tag-Based Assertion Filtering

Assertions can be tagged with arbitrary string labels for flexible categorization and filtering. Tags enable version-scoped testing where a single scenario can validate multiple protocol versions.

**How Tags Work**:
- Assertions are emitted with tags: `trace.assert("label", &["tag1", "tag2"])`
- Specs filter assertions using `tag_filter: ["tag1"]` - only assertions with matching tags are validated
- A single assertion can satisfy multiple specs by including multiple tags

**Example: Version-Scoped Testing**:
```rust
tb_assert_spec! {
	pub VersionSpec,
	V(0,0,0): {
		mode: Accept,
		gate: Accepted,
		tag_filter: ["v0"],
		assertions: [
			("feature", exactly!(1), equals!(IsNone)),
		]
	},
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		tag_filter: ["v1"],
		assertions: [
			("feature", exactly!(1), equals!(IsNone)),
			("v1_specific", exactly!(1))
		]
	}
}

tb_scenario! {
	name: test_all_versions,
	specs: [VersionSpec::get(0, 0, 0), VersionSpec::get(1, 0, 0)],
	environment Bare {
		exec: |trace| {
			// Single assertion satisfies both version specs via tags
			trace.assert_option("feature", &["v0", "v1"], &some_option);
			trace.assert("v2_specific", &["v1"]);
			Ok(())
		}
	}
}
```

### 10.3 Layer 2: Process Specifications (CSP)

#### 10.3.1 Concept

ProcessSpec defines labeled transition systems (LTS) for formal process
modeling using Communicating Sequential Processes (CSP) theory. A process
specification declares:
- **Observable alphabet (Σ)**: External events visible to the environment
- **Hidden alphabet (τ)**: Internal events not visible externally
- **State space**: Named states and their transitions
- **Terminal states**: Valid end states
- **Nondeterministic states**: States with internal choice

Enabled with `testing-csp` feature flag.

#### 10.3.2 Specification: tb_process_spec! Syntax

```rust
tb_process_spec! {
	pub ProcessName,
	events {
		observable { "event1", "event2", ... }   // External alphabet (Σ)
		hidden { "internal1", "internal2", ... } // Internal alphabet (τ)
	}
	states {
		S0 => { "event1" => S1 }                 // State transitions
		S1 => { "event2" => S2, "event3" => S3 } // Nondeterministic branching
		S2 => {}                                 // Terminal state
		S3 => {}
	}
	terminal { S2, S3 }                         // Valid end states
	choice { S1 }                               // Nondeterministic states
	annotations { description: "..." }          // Optional metadata
}
```

#### 10.3.3 Validation Rules

When `csp:` is specified in `tb_scenario!`:

1. **Compile-Time**: Assert labels MUST be in CSP observable alphabet
2. **Runtime**: Observed events MUST form valid CSP trace (framework tracks state)
3. **Post-Execution**: Trace MUST terminate in valid terminal state

#### 10.3.4 Example: CSP Process Specification

```rust
use tightbeam::testing::*;

tb_process_spec! {
	pub SimpleProcess,
	events {
		observable { "Received", "Responded" }
		hidden { "internal_processing" }
	}
	states {
		Idle       => { "Received" => Processing }
		Processing => { "internal_processing" => Processing, "Responded" => Idle }
	}
	terminal { Idle }
	choice { Processing }
	annotations { description: "Simple request-response with internal processing" }
}
```

#### 10.3.5 Generated API

Each `tb_process_spec!` generates:
```rust
impl ProcessName {
	pub fn process() -> Process;  // Returns LTS structure
}
```

### 10.4 Layer 3: Refinement Checking (FDR)

#### 10.4.1 Concept

Refinement checking provides multi-seed exploration for trace and failures
refinement verification. Based on the Failures-Divergences Refinement (FDR)
methodology from CSP theory. Enabled with `testing-fdr` feature flag.

**Verification Properties**:
- **Trace Refinement (⊑T)**: All observed traces ∈ spec traces
- **Failures Refinement (⊑F)**: No invalid refusals at choice points
- **Divergence Freedom**: No internal-only loops exceeding threshold
- **Determinism**: Branching only at declared nondeterministic states

**Requirements**: Layer 3 requires `testing-fdr` feature flag. Refinement
checking requires the `specs` field in `FdrConfig` to be populated with
specification processes.

#### 10.4.2 Specification: FdrConfig Syntax

```rust
fdr: FdrConfig {
	seeds: 64,               // Number of exploration seeds
	max_depth: 128,          // Maximum trace depth
	max_internal_run: 32,    // Divergence detection threshold
	timeout_ms: 5000,        // Per-seed timeout
	specs: vec![],           // Processes for refinement checking (empty = exploration mode)
	fail_fast: true,         // Stop on first violation (default: true)
	expect_failure: false,   // Expect refinement to fail (default: false)
}
```

**Configuration Parameters**:
- `seeds`: Number of different scheduler strategies to explore
- `max_depth`: Maximum length of observable trace
- `max_internal_run`: Consecutive hidden events before divergence detection
- `timeout_ms`: Timeout for each seed exploration
- `specs`: Specification processes for refinement checking (empty vector = exploration mode)
- `fail_fast`: Stop on first refinement violation (default: true)
- `expect_failure`: Expect refinement to fail for negative tests (default: false)

**Operational Modes**:
- **Mode 1** (specs empty): Single-process exploration - verifies determinism, deadlock freedom, divergence freedom
- **Mode 2** (specs provided): Refinement checking - verifies Spec ⊑ Impl (trace/failures/divergence refinement)

#### 10.4.3 Implementation Examples

**Simple Working Example**:
```rust
// Define a simple two-state process
tb_process_spec! {
	pub SimpleProcess,
	events {
		observable { "start", "finish" }
		hidden { }
	}
	states {
		Idle => { "start" => Working },
		Working => { "finish" => Idle }
	}
	terminal { Idle }
}

// Define assertion spec
tb_assert_spec! {
	pub SimpleSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("start", exactly!(1)),
			("finish", exactly!(1))
		]
	},
}

// Test with refinement checking
tb_scenario! {
	name: test_simple_refinement,
	spec: SimpleSpec,
	fdr: FdrConfig {
		seeds: 4,
		max_depth: 10,
		max_internal_run: 8,
		timeout_ms: 500,
		specs: vec![SimpleProcess::process()],
		fail_fast: true,
		expect_failure: false,
	},
	environment Bare {
		exec: |trace| {
			trace.assert("start", &[]);
			trace.assert("finish", &[]);
			Ok(())
		}
	}
}
```

#### 10.4.4 Multi-Seed Exploration

The `seeds` parameter controls how many different execution paths are explored
during verification. Each seed produces a different scheduling of concurrent
operations, uncovering race conditions and nondeterministic behavior:

```rust
fdr: FdrConfig {
	seeds: 64,  // Try 64 different execution orderings
	// ...
}
```

Higher seed counts increase confidence but also test execution time. Typical values:
- **Development**: 16-32 seeds for quick feedback
- **CI Pipeline**: 64-128 seeds for thorough verification
- **Release**: 256+ seeds for critical protocols

Each seed explores different interleaving at nondeterministic choice points,
verifying trace refinement, failures refinement, and divergence freedom across
all executions.

#### 10.4.5 FDR Verdict Structure

After multi-seed exploration, tightbeam produces a comprehensive verdict:

```rust
pub struct FdrVerdict {
	// Overall status
	pub passed: bool,

	// Single-process properties
	pub divergence_free: bool,
	pub deadlock_free: bool,
	pub is_deterministic: bool,

	// Refinement properties (only when specs provided)
	pub trace_refines: bool,
	pub failures_refines: bool,
	pub divergence_refines: bool,

	// Witnesses to violations
	pub trace_refinement_witness: Option<Trace>,
	pub failures_refinement_witness: Option<Failure>,
	pub divergence_refinement_witness: Option<Trace>,
	pub determinism_witness: Option<(u64, Trace, Event)>,
	pub divergence_witness: Option<(u64, Vec<Event>)>,
	pub deadlock_witness: Option<(u64, Trace, State)>,

	// Statistics
	pub traces_explored: usize,
	pub states_visited: usize,
	pub seeds_completed: u32,
	pub failing_seed: Option<u64>,
}
```

**Verdict Fields**:
- **passed**: Overall pass/fail status
- **divergence_free**: No infinite τ-loops detected
- **deadlock_free**: No unexpected STOP states reached
- **is_deterministic**: No nondeterminism witnesses found
- **trace_refines**: traces(Impl) ⊆ traces(Spec) - only meaningful when specs provided
- **failures_refines**: failures(Impl) ⊆ failures(Spec) - only meaningful when specs provided
- **divergence_refines**: divergences(Impl) ⊆ divergences(Spec) - only meaningful when specs provided
- **trace_refinement_witness**: Trace in Impl but not in Spec (if found)
- **failures_refinement_witness**: (trace, refusal) in Impl but not in Spec (if found)
- **divergence_refinement_witness**: Divergent trace in Impl but not in Spec (if found)
- **determinism_witness**: (seed, trace, event) where different seeds diverge
- **divergence_witness**: (seed, τ-loop sequence) if found
- **deadlock_witness**: (seed, trace, state) if found
- **failing_seed**: Seed that caused failure, if any

**Note**: Refinement properties (trace_refines, failures_refines,
divergence_refines) are only meaningful when specs are provided in FdrConfig.

### 10.5 Formal CSP Theory

#### 10.5.1 Three Semantic Models

| CSP Model | Tightbeam Layer | Verification Property | Refinement Check |
|-----------|-----------------|----------------------|------------------|
| **Traces (T)** | L1 AssertSpec | Observable event sequences | traces(Impl) ⊆ traces(Spec) |
| **Stable Failures (F)** | L2 ProcessSpec | Valid refusals at choice points | failures(Impl) ⊆ failures(Spec) |
| **Failures-Divergences (FD)** | L3 FDR | Livelock freedom (no τ-loops) | divergences(Impl) = ∅ |

**Traces Model**: Verifies that all observable event sequences produced by the
implementation are allowed by the specification. This ensures basic behavioral
correctness—the system never produces an unexpected sequence of external events.

**Stable Failures Model**: Extends trace verification by checking what events a
process can *refuse* after each trace. A stable state is one where no internal
progress (τ-transitions) can occur. At choice points, the implementation must
not refuse events the specification accepts, preventing incorrect nondeterminism.

**Failures-Divergences Model**: Adds divergence detection to identify processes
that can make infinite internal progress without external interaction. A divergence
is a τ-loop where the process never becomes stable. The `max_internal_run`
parameter bounds consecutive hidden events to detect such livelocks.

#### 10.5.2 Observable vs. Hidden Events

CSP distinguishes between observable events (external alphabet Σ) and hidden
events (internal actions τ). This distinction is fundamental to process refinement:

```rust
tb_process_spec! {
	pub ClientServerProcess,
	events {
		// Observable alphabet (Σ): externally visible protocol events
		observable { "connect", "request", "response", "disconnect" }

		// Hidden alphabet (τ): internal implementation details
		hidden { "serialize", "encrypt", "decrypt", "deserialize" }
	}
	// ...
}
```

**Observable events** represent the process's contract with its environment.
These form the basis of trace refinement—implementations and specifications must
agree on observable behavior.

**Hidden events** model internal implementation details. They enable refinement
checking where implementations contain details absent from abstract specifications.
Hidden events are projected away when comparing traces: `trace \ {τ}`.

The instrumentation taxonomy (§11.2) maps tightbeam events to categories:
- **Observable**: `gate_accept`, `gate_reject`, `request_recv`, `response_send`, `assert_label`
- **Hidden (τ)**: `handler_enter`, `handler_exit`, `crypto_step`, `compress_step`, `route_step`, `policy_eval`, `process_hidden`

#### 10.5.3 Nondeterministic Choice and Refusal Sets

CSP provides two choice operators:
- **External choice (□)**: Environment selects which event occurs
- **Internal choice (⊓)**: Process selects non-deterministically

At choice points, a process has an *acceptance set* (events it can engage) and
*refusal set* (events it cannot engage in stable state). Failures refinement
ensures implementations don't introduce invalid refusals:

```rust
states {
	// External choice: environment determines next event
	Connected  => { "request" => Processing, "disconnect" => Idle }

	// Internal choice: process may non-deterministically choose path
	Processing => { "response" => Responded, "error" => ErrorState }
}
choice { Processing }  // Annotate nondeterministic states
```

The `choice` annotation declares states where internal nondeterminism may occur.
FDR exploration uses different seeds to explore all possible nondeterministic
branches, ensuring the specification covers all implementation behaviors.

#### 10.5.4 Multi-Seed Exploration and Scheduler Interleaving

Based on research by Pedersen & Chalmers,[^pedersen2024] refinement in cooperatively
scheduled systems depends on resource availability. With `n` concurrent processes
and `m` schedulers where `m < n`, some traces become impossible due to scheduling
constraints.

**Tightbeam addresses this through multi-seed exploration**: Each seed represents
a different scheduling strategy, exploring alternative interleaving of concurrent
events. This is analogous to testing with different numbers of schedulers to
verify behavior across resource constraints:

```rust
fdr: FdrConfig {
    seeds: 64,              // Explore 64 different scheduling
    max_depth: 128,         // Bound trace length
    max_internal_run: 32,   // Divergence detection threshold
    timeout_ms: 5000,       // Per-seed timeout
}
```

At nondeterministic choice points, the seed determines which branch to explore.
Across all seeds, the framework verifies that:
1. **Trace refinement**: All observable traces are valid
2. **Failures refinement**: No invalid refusals at choice points
3. **Divergence freedom**: No seed produces infinite τ-loops

#### 10.5.5 FDR Verification Verdict

After multi-seed exploration, tightbeam produces a comprehensive verdict:

```rust
pub struct FdrVerdict {
    // Refinement properties
    pub trace_refines: bool,           // Spec ⊑T Impl
    pub failures_refines: bool,        // Spec ⊑F Impl
    pub divergence_free: bool,         // No τ-loops detected

    // Determinism analysis
    pub is_deterministic: bool,        // No nondeterminism witnesses
    pub determinism_witness: Option<(Trace, Event)>,

    // Divergence witness
    pub divergence_witness: Option<Vec<Event>>,  // τ-loop if found

    // Statistics
    pub traces_explored: usize,
    pub states_visited: usize,
    pub seeds_completed: u32,
}
```

**Determinism checking**: FDR searches for witnesses to nondeterminism—a trace
and event where the process both accepts and refuses that event. If found, the
witness indicates unintended nondeterminism not declared via `choice`.

**Divergence witness**: If a τ-loop is detected (consecutive hidden events
exceeding `max_internal_run`), the witness provides the internal event sequence
causing livelock.

#### 10.5.6 CSPM Export for FDR4 Integration

Tightbeam can export process specifications as CSPM (CSP Machine-readable)
format for verification with external tools like FDR4:[^fdr4]

```rust
use tightbeam::testing::fdr::CspmExporter;

let process = ClientServerProcess::process();
let exporter = CspmExporter::new(&process);

let mut file = std::fs::File::create("target/tb_csp/client_server.csp")?;
exporter.export(&mut file)?;
```

Generated CSPM includes:
- Observable and hidden alphabet declarations
- State space enumeration
- Labeled transition system as CSP processes
- Main process with τ-hiding: `Process = InitialState \ {| hidden |}`

This enables:
1. **Independent verification** with FDR4's exhaustive model checker
2. **Algebraic proofs** using CSP laws and theorems
3. **Integration** with existing CSP toolchains and specifications

#### 10.5.7 Trace Analysis Extensions

The `FdrTraceExt` trait extends `ConsumedTrace` with CSP-specific analysis:

```rust
use tightbeam::testing::fdr::FdrTraceExt;

hooks {
    on_pass: |trace| {
        // Refinement properties
        assert!(trace.fdr_verdict.trace_refines);
        assert!(trace.fdr_verdict.failures_refines);
        assert!(trace.fdr_verdict.divergence_free);
        assert!(trace.fdr_verdict.is_deterministic);
    }
}
```

**Projection**: Extract observable or hidden event subsequences for analysis:
```rust
let observable = trace.project_to_observable();
// ["connect", "request", "response", "disconnect"]

let hidden = trace.project_to_hidden();
// ["serialize", "encrypt", "decrypt", "deserialize"]
```

**Acceptance/Refusal queries**: Inspect process behavior at specific states:
```rust
if let Some(acceptance) = trace.acceptance_at("Connected") {
    assert!(acceptance.contains(&Event("request")));
}

assert!(!trace.can_refuse_after("Connected", "request"));
```

### 10.6 Unified Testing: tb_scenario! Macro

The `tb_scenario!` macro is the unified entry point for all testing layers,
executing AssertSpec verifications under selectable environments with optional
CSP and FDR verification.

**Design Principles**:
- Single consistent syntax across all verification layers
- Progressive enhancement (L1 → L1+L2 → L1+L2+L3)
- Environment abstraction (ServiceClient, Servlet, Worker, Bare)
- Instrumentation integration
- Policy enforcement

#### 10.6.1 Syntax

```rust
tb_scenario! {
	name: test_function_name,        // OPTIONAL: creates standalone #[test] function NOTE: Do NOT use with `fuzz: afl`
	spec: AssertSpecType,            // REQUIRED: Layer 1 assertion spec
	csp: ProcessSpecType,            // OPTIONAL: Layer 2 CSP model (requires testing-csp)
	fuzz: afl,                       // OPTIONAL: AFL fuzzing mode (requires testing-csp)
	fdr: FdrConfig { ... },          // OPTIONAL: Layer 3 refinement (requires testing-fdr + csp)
	instrumentation: Config { ... }, // OPTIONAL: instrumentation config
	environment <Variant> { ... },   // REQUIRED: execution environment
	hooks { ... }                    // OPTIONAL: on_pass/on_fail callbacks
}
```

See sections 10.3.4 and 10.4 for detailed environment examples.

#### 10.6.2 Examples

**Bare Environment Example**: Pure logic/function invocation

```rust
use tightbeam::testing::*;

tb_assert_spec! {
	pub BareSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("Received", exactly!(1)),
			("Responded", exactly!(1))
		]
	},
}

tb_process_spec! {
	pub BareProcess,
	events {
		observable { "Received", "Responded" }
	}
	states {
		Idle       => { "Received" => Processing }
		Processing => { "Responded" => Idle }
	}
	terminal { Idle }
}

tb_scenario! {
	name: test_bare_environment,
	spec: BareSpec,
	csp: BareProcess,
	environment Bare {
		exec: |trace| {
			trace.assert("Received", &[]);
			trace.assert("Responded", &[]);
			Ok(())
		}
	}
}
```

**Full Example: All Three Layers with ServiceClient Environment**

This example demonstrates progressive verification from L1 through L3:

```rust
#![cfg(all(feature = "testing-fdr", feature = "tcp", feature = "tokio"))]
use tightbeam::testing::*;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::Protocol;

// Layer 1: Assert spec - defines expected assertions and cardinalities
tb_assert_spec! {
	pub ClientServerSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("connect", exactly!(1)),
			("request", exactly!(1)),
			("response", exactly!(2)),
			("disconnect", exactly!(1)),
			("message_content", exactly!(1), equals!("test"))
		]
	},
}

// Layer 2: CSP process spec - models state machine with internal events
tb_process_spec! {
	pub ClientServerProcess,
	events {
		observable { "connect", "request", "response", "disconnect" }
		hidden { "serialize", "encrypt", "decrypt", "deserialize" }
	}
	states {
		Idle        => { "connect" => Connected }
		Connected   => { "request" => Processing, "serialize" => Serializing }
		Serializing => { "encrypt" => Encrypting }
		Encrypting  => { "request" => Processing }
		Processing  => { "decrypt" => Decrypting, "response" => Responded }
		Decrypting  => { "deserialize" => Processing }
		Responded   => { "disconnect" => Idle }
	}
	terminal { Idle }
	choice { Connected, Processing }
	annotations { description: "Client-server with crypto and nondeterminism" }
}

tb_scenario! {
	name: test_client_server_all_layers,
	spec: ClientServerSpec,
	csp: ClientServerProcess,
	fdr: FdrConfig {
		seeds: 64,
		max_depth: 128,
		max_internal_run: 32,
		timeout_ms: 5000,
		specs: vec![ClientServerProcess::process()],
		fail_fast: true,
		expect_failure: false,
	},
	environment ServiceClient {
		worker_threads: 2,
		server: |trace: TraceCollector| async move {
			let bind_addr = "127.0.0.1:0".parse().unwrap();
			let (listener, addr) = <TokioListener as Protocol>::bind(bind_addr).await?;
			let handle = server! {
				protocol TokioListener: listener,
				assertions: trace,
				handle: |frame, trace| async move {
					trace.assert("connect", &[]);
					trace.assert("request", &[]);
					trace.assert("response", &[]);
					Some(frame)
				}
			};
			Ok((handle, addr))
		},
		client: |trace, mut client| async move {
			trace.assert("response", &[]);
			let frame = compose! {
				V0: id: "test",
				order: 1u64,
				message: TestMessage { content: "test".to_string() }
			}?;
			let response = client.emit(frame, None).await?;

			// Decode response and emit value assertion
			if let Some(resp_frame) = response {
				let decoded: TestMessage = crate::decode(&resp_frame.message)?;
				trace.assert_value("message_content", &[], decoded.content);
			}

			trace.assert("disconnect", &[]);
			Ok(())
		}
	},
	hooks {
		on_pass: |trace| {
			// Optional: custom logic on test pass
		},
		on_fail: |_trace, violations| {
			// Optional: custom logic on test fail
		}
	}
}
```

This test verifies:
- **L1**: Correct assertion labels and cardinalities
- **L2**: Valid state transitions with internal events
- **L3**: Trace refinement across multiple exploration seeds

### 10.7 Coverage-Guided Fuzzing with AFL

#### 10.7.1 Concept

TightBeam integrates [AFL.rs](https://github.com/rust-fuzz/afl.rs), a Rust port
of American Fuzzy Lop, for coverage-guided fuzzing of protocol implementations.
Unlike deterministic random testing, AFL uses evolutionary algorithms with
compile-time instrumentation to discover inputs that trigger new code paths.

**How AFL Works**:
1. **Instrumentation**: Code is compiled with coverage tracking (edge counters)
2. **Input Corpus**: Starts with seed inputs, mutates them intelligently
3. **Feedback Loop**: Monitors code coverage, keeps inputs that discover new paths
4. **Crash Detection**: Automatically detects crashes, hangs, and assertion failures

**Integration with tb_scenario!**: The `fuzz: afl` parameter generates
AFL-compatible fuzz targets that leverage the oracle for guided exploration:

```rust
tb_scenario! {
	fuzz: afl,              // ← AFL fuzzing mode
	spec: MySpec,
	csp: MyProcess,         // ← oracle for valid state navigation
	environment Bare {
		exec: |trace| {
			// AFL provides random bytes, oracle navigates state machine
			match trace.oracle().fuzz_from_bytes() {
				Ok(()) => {
					for event in trace.oracle().trace() {
						trace.assert(event.0, &[]);
					}
					Ok(())
				}
				Err(_) => Err(TestingError::FuzzInputExhausted.into())
			}
		}
	}
}
```

**Feature Requirements**:
- `testing-csp` feature flag (required for CSP oracle)
- `cargo-afl` installed: `cargo install cargo-afl`
- Fuzz targets gated by `#[cfg(fuzzing)]` to avoid compilation during normal tests
- `std` feature flag (required for most fuzz targets)

#### 10.7.2 Creating Fuzz Targets

**Example Fuzz Target**:

```rust
//! Simple 3-state workflow fuzz target for AFL

#![cfg(all(feature = "std", feature = "testing-csp"))]

use tightbeam::testing::error::TestingError;
use tightbeam::{at_least, exactly, tb_assert_spec, tb_process_spec, tb_scenario};

// Layer 1: Assertion spec
tb_assert_spec! {
	pub SimpleFuzzSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("start", exactly!(1)),
			("action_a", at_least!(0)),
			("action_b", at_least!(0)),
			("done", exactly!(1))
		]
	},
}

// Layer 2: CSP process with nondeterministic choices
tb_process_spec! {
	pub SimpleFuzzProc,
	events {
		observable { "start", "action_a", "action_b", "done" }
		hidden { }
	}
	states {
		S0 => { "start" => S1 },
		S1 => { "action_a" => S1, "action_b" => S1, "done" => S2 }
	}
	terminal { S2 }
}

// AFL fuzz target - compiled with `cargo afl build`
// Note: AFL fuzz targets generate `fn main()` - do NOT include `name:` parameter
#[cfg(fuzzing)]
tb_scenario! {
	fuzz: afl,
	spec: SimpleFuzzSpec,
	csp: SimpleFuzzProc,
	environment Bare {
		exec: |trace| {
			// AFL provides bytes, oracle interprets as state machine choices
			match trace.oracle().fuzz_from_bytes() {
				Ok(()) => {
					for event in trace.oracle().trace() {
						trace.assert(event.0, &[]);
					}
					Ok(())
				}
				Err(_) => Err(TestingError::FuzzInputExhausted.into())
			}
		}
	}
}
```

#### 10.7.3 Building and Running Fuzz Targets

**Prerequisites**:
```bash
cargo install cargo-afl
```

**Run AFL Fuzzer**:
```bash
# Build fuzz targets first
# Note: Some fuzz targets may require additional features
RUSTFLAGS="--cfg fuzzing" cargo afl build --test fuzzing --features "std,testing-csp"

# Create seed input directory
mkdir -p fuzz_in
echo "seed" > fuzz_in/seed.txt

# Run AFL fuzzer (find the actual binary name)
FUZZ_TARGET=$(ls target/debug/deps/fuzzing-* 2>/dev/null | grep -v '\.d$' | head -1)
cargo afl fuzz -i fuzz_in -o fuzz_out "$FUZZ_TARGET"
```

#### 10.7.4 Advanced: CSP Oracle Integration

The `CspOracle` interprets AFL's random bytes as state machine navigation choices,
ensuring fuzz inputs trigger valid protocol behavior:

**How It Works**:
```
AFL Random Bytes          CspOracle                State Machine
─────────────────  ───►  ───────────────  ───►  ─────────────────
[0x7A, 0x3F, ...]        byte % events.len()     S0 → S1 → S2 → ...
                         selects valid event      (valid trace)
```

**Benefits**:
1. **Valid Traces Only**: Oracle ensures all fuzz inputs produce valid traces
2. **Nondeterminism Exploration**: AFL discovers which byte patterns lead to different branches
3. **Coverage Feedback**: AFL learns which choices uncover new code paths
4. **Crash Attribution**: Crashes map to specific state sequences

**Example Trace** (from crash analysis):
```
Input: [0x00, 0x01, 0x00, 0x02]
Trace: "start" → "action_a" → "action_b" → "done"
State: S0 → S1 → S1 → S2
Result: Crash at state S1 after "action_b"
```

#### 10.7.5 IJON Integration: Input-to-State Correspondence

TightBeam optionally integrates with AFL's IJON extension[^ijon2020] for
state-aware fuzzing. IJON enables "input-to-state correspondence" - bridging
the semantic gap between fuzzer input mutations and program state exploration.

**IJON Core Concepts**:
- **Annotation-Based Guidance**: Developers annotate interesting state variables
- **Maximization**: `ijon_max(label, value)` - fuzzer tries to maximize value
- **Set Tracking**: `ijon_set(label, value)` - fuzzer discovers unique values
- **Hash Tracking**: `ijon_hashint(label, value)` - track integer distributions

**TightBeam's CSP-Based Approach**:

TightBeam automatically derives IJON annotations from CSP process specifications,
eliminating manual annotation while providing formal state coverage guarantees:

| Aspect | Standard IJON | TightBeam CSP Oracle |
|--------|---------------|---------------------|
| **State Definition** | Manual annotations of raw variables | Formal CSP process states (automatic) |
| **Annotation Burden** | Developer must identify & annotate | Derived from `tb_process_spec!` |
| **Coverage Metric** | Arbitrary program values | State + transition coverage (provable) |
| **State Abstraction** | Low-level (memory, counters, etc.) | High-level (protocol semantics) |
| **Validation** | None (annotations may be incorrect) | Trace validation (runtime checking) |
| **Integration** | Explicit `IJON_MAX`/`IJON_SET` calls | Automatic when `testing-fuzz-ijon` enabled |

**Automatic IJON Integration**:

When built with `--features testing-fuzz-ijon`, tightbeam's `tb_scenario!` macro
automatically inserts IJON calls after each successful fuzz execution

**Comparison with Pure AFL**:

Without IJON, AFL relies solely on code coverage (edge hit counts). With
tightbeam's oracle + IJON:

- **AFL alone**: Discovers `branch_A`, `branch_B`, `branch_C` (syntax)
- **AFL + CSP oracle**: Discovers `State_Init → State_Processing → State_Done` (semantics)
- **AFL + CSP + IJON**: Prioritizes inputs that maximize unique states visited

**Example: Magic Value Discovery**:

Traditional IJON use case - finding magic values in parsers:

```c
// Standard IJON annotation
if (input[0] == 0xDEADBEEF) {
    IJON_MAX("magic_value", input[0]);  // Manual annotation
    enter_special_state();
}
```

TightBeam equivalent - no manual annotation needed:

```rust
tb_process_spec! {
    pub ParserProcess,
    events { observable { "magic_detected", "parse_continue" } }
    states {
        Init   => { "magic_detected" => SpecialState, "parse_continue" => Parsing }
        SpecialState => { /* ... */ }
    }
    // IJON automatically reports when SpecialState is reached
}
```

### 10.8 Feature Matrix

The following table summarizes capabilities available across the testing layers:

| Capability | `testing` | `testing-csp` | `testing-fdr` | `testing-fuzz` |
|------------|-----------|---------------|---------------|----------------|
| **Basic Verification** | | | | |
| Single trace verification | ✓ | ✓ | ✓ | ✓ |
| Assertion cardinality checks | ✓ | ✓ | ✓ | ✓ |
| Crash/panic detection | ✓ | ✓ | ✓ | ✓ |
| **CSP Modeling** | | | | |
| CSP process modeling | – | ✓ | ✓ | – |
| Compile-time label validation | – | ✓ | ✓ | – |
| Runtime trace validation | – | ✓ | ✓ | – |
| Terminal state verification | – | ✓ | ✓ | – |
| **FDR Refinement** | | | | |
| Multi-seed exploration | – | – | ✓ | – |
| Trace refinement (⊑T) | – | – | ✓ | – |
| Failures refinement (⊑F) | – | – | ✓ | – |
| Divergence detection (τ-loops) | – | – | ✓ | – |
| Determinism checking | – | – | ✓ | – |
| Refusal set analysis | – | – | ✓ | – |
| Acceptance set queries | – | – | ✓ | – |
| CSPM export (FDR4) | – | – | ✓ | – |
| **AFL Fuzzing** | | | | |
| Coverage-guided fuzzing | – | – | – | ✓ |
| Edge coverage tracking | – | – | – | ✓ |
| Input corpus evolution | – | – | – | ✓ |
| **Combined Capabilities** | | | | |
| CSP oracle for fuzzing | – | – | – | `csp` + `fuzz` |
| IJON state annotations | – | – | – | `csp` + `fuzz-ijon` |

## 11. Instrumentation

This section normatively specifies the TightBeam instrumentation subsystem.
Instrumentation produces a semantic event sequence consumed by verification
logic. It is an observation facility, NOT an application logging API. Tests
MUST NOT depend on instrumentation events imperatively; verification MUST treat
the event stream as authoritative ground truth for one execution.

Feature Gating:
- Instrumentation can be enabled only by the standalone crate feature `instrument`.

### 11.1 Objectives
- Emission MUST be amortized O(1) per event.
- Ordering MUST be strictly increasing by sequence number per trace.
- Evidence artifacts MUST be deterministic and hash‑stable given identical executions.
- Detail level MUST be feature‑gated to avoid unnecessary overhead.
- Payload handling MUST preserve privacy (hash or summarize; never emit secret raw bytes).

### 11.2 Event Kind Taxonomy
Each event MUST have one kind from a closed, feature‑gated set:
- External: `gate_accept`, `gate_reject`, `request_recv`, `response_send`
- Assertion: `assert_label`, `assert_payload`
- Internal (hidden): `handler_enter`, `handler_exit`, `crypto_step`, `compress_step`, `route_step`, `policy_eval`
- Process (requires `testing-csp`): `process_transition`, `process_hidden`
- Exploration (requires `testing-fdr`): `seed_start`, `seed_end`, `state_expand`, `state_prune`, `divergence_detect`, `refusal_snapshot`, `enabled_set_sample`
- Meta: `start`, `end`, `warn`, `error`

Hidden/internal events MUST use the internal category.

### 11.3 Event Structure
Conceptual fixed layout (names illustrative):
```
trace_id | seq | kind | label? | payload? | phase? | dur_ns? | flags | extras
```
Requirements:
- `trace_id` MUST uniquely identify the execution instance.
- `seq` MUST start at 0 and increment by 1 for each emitted event.
- `kind` MUST be a valid taxonomy member.
- `label` MUST be present for assertion and labeled process events; otherwise absent.
- `payload` MAY be present only if the label is declared payload‑capable.
- `phase` SHOULD map to one of: Gate, Handler, Assertion, Response, Crypto, Compression, Routing, Policy, Process, Exploration.
- `dur_ns` MAY appear on exit or boundary events and MUST represent a monotonic duration in nanoseconds.
- `flags` MUST represent a bitset (e.g. ASSERT_FAIL, HIDDEN, DIVERGENCE, OVERFLOW).
- `extras` MAY supply fixed numeric slots and a bounded byte sketch for extended metrics (e.g. enabled set cardinality).

### 11.4 Payload Representation
Runtime values captured under `assert_payload` MUST be transformed before emission:
- Algorithm: SHA3‑256 digest over canonical byte representation.
- Representation: First 32 bytes (full SHA3‑256 output) MUST be stored; NO truncation below 32 bytes.
- Literal integers MAY be emitted directly as 64‑bit unsigned values IF NOT sensitive.
- Structured values SHOULD emit a static schema tag plus digest.
Secret or potentially sensitive raw data MUST NOT be emitted verbatim.

### 11.5 Configuration
Instrumentation behavior MUST be controlled by a configuration object (conceptual fields). Configuration existence itself is gated by `instrument`:
```rust
TbInstrumentationConfig {
	enable_payloads: bool,
	enable_internal_detail: bool,
	sample_enabled_sets: bool,
	sample_refusals: bool,
	divergence_heuristics: bool,
	max_events: u32,
	record_durations: bool,
}
```
Defaults (instrument only):
- `enable_payloads = false`
- `enable_internal_detail = false`
- `sample_enabled_sets = false`
- `sample_refusals = false`
- `divergence_heuristics = false`
- `record_durations = false`
- `max_events = 1024`

Layer Interaction (informative): Enabling testing layers does NOT alter these defaults; tests MAY explicitly override fields per scenario.

If `max_events` is exceeded, the implementation MUST set an OVERFLOW flag, emit a single `warn` event, and drop subsequent events.

### 11.6 Evidence Artifact Format
For every finalized trace an artifact MUST be producible in a canonical binary form (DER).

Canonical DER Schema (conceptual):
```
EvidenceArtifact ::= SEQUENCE {
	specHash   OCTET STRING,               -- SHA3-256(spec definition)
	traceId    INTEGER,                    -- Unique per execution
	seed       INTEGER OPTIONAL,           -- Exploration seed (testing-fdr only)
	outcome    ENUMERATED { acceptResponse(0), acceptNoResponse(1), reject(2), error(3) },
	metrics    SEQUENCE {
		countEvents   INTEGER,
		durationNs    INTEGER OPTIONAL,
		overflow      BOOLEAN OPTIONAL
	},
	events     SEQUENCE OF Event
}

Event ::= SEQUENCE {
	i           INTEGER,                   -- sequence number
	k           ENUMERATED { start(0), end(1), warn(2), error(3), gate_accept(4), gate_reject(5), request_recv(6), response_send(7), assert_label(8), assert_payload(9), handler_enter(10), handler_exit(11), crypto_step(12), compress_step(13), route_step(14), policy_eval(15), process_transition(16), process_hidden(17), seed_start(18), seed_end(19), state_expand(20), state_prune(21), divergence_detect(22), refusal_snapshot(23), enabled_set_sample(24) },
	l           UTF8String OPTIONAL,       -- label
	payloadHash OCTET STRING OPTIONAL,     -- SHA3-256(payload canonical bytes) if captured
	durationNs  INTEGER OPTIONAL,          -- monotonic duration for boundary/exit events
	flags       BIT STRING OPTIONAL,       -- ASSERT_FAIL | HIDDEN | DIVERGENCE | OVERFLOW ...
	extras      OCTET STRING OPTIONAL      -- bounded auxiliary metrics sketch
}
```

Binary Serialization Requirements:
- DER MUST omit absent OPTIONAL fields.
- Field ordering MUST follow the schema strictly.
- BIT STRING unused bits MUST be zero.
- `payloadHash` MUST be 32 bytes when present (SHA3-256).

Artifact Integrity:
- `trace_hash` MUST be SHA3-256 over the DER encoding of the Events sequence ONLY (excluding surrounding fields).
- `evidence_hash` SHOULD be SHA3-256(specHash || trace_hash) where `||` denotes raw byte concatenation.

Privacy:
- Raw payload bytes MUST NOT appear; only hashed representation or numeric scalar (non-sensitive) values MAY be represented.

### 11.7 Failure Handling
- Emission errors MUST NOT panic; they MUST degrade gracefully (e.g. drop event + OVERFLOW flag).
- Verification MUST treat missing expected instrumentation events as spec violations (e.g. absent assertion label).

## 12. End-to-End Examples

This section contains complete, runnable examples demonstrating real-world usage patterns.

### 12.1 Complete Client-Server Application

```rust
// TODO
```

## 13. References

[^hoare1978]: C.A.R. Hoare, "Communicating sequential processes," *Communications of the ACM*, vol. 21, no. 8, pp. 666-677, August 1978. DOI: [10.1145/359576.359585](https://doi.org/10.1145/359576.359585)

[^roscoe2010]: A.W. Roscoe, *Understanding Concurrent Systems*. Springer-Verlag, 2010. ISBN: 978-1-84882-257-3. DOI: [10.1007/978-1-84882-258-0](https://doi.org/10.1007/978-1-84882-258-0)

[^fdr4]: University of Oxford, *FDR4 User Manual*, Version 4.2.7, 2020. Available: [https://www.cs.ox.ac.uk/projects/fdr/](https://www.cs.ox.ac.uk/projects/fdr/)

[^pedersen2024]: M. Pedersen and K. Chalmers, "Refinement Checking of Cooperatively Scheduled Concurrent Systems," in *Formal Methods: Foundations and Applications (SBMF 2024)*, pp. 3-21, 2024. DOI: [10.1007/978-3-031-78561-1_1](https://doi.org/10.48550/arXiv.2510.11751)

[^ijon2020]: C. Aschermann, S. Schumilo, A. Abbasi, and T. Holz, "IJON: Exploring Deep State Spaces via Fuzzing," in *2020 IEEE Symposium on Security and Privacy (SP)*, San Francisco, CA, USA, 2020, pp. 1597-1612. DOI: [10.1109/SP40000.2020.00117](https://doi.org/10.1109/SP40000.2020.00117)

### 13.1 Normative References

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

### 13.2 Standards References

- [FIPS 140-2](https://csrc.nist.gov/publications/detail/fips/140/2/final): Security Requirements for Cryptographic Modules
- [FIPS 140-3](https://csrc.nist.gov/publications/detail/fips/140/3/final): Security Requirements for Cryptographic Modules
- [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final): Secure Hash Standard (SHS)
- [FIPS 186-4](https://csrc.nist.gov/publications/detail/fips/186/4/final): Digital Signature Standard (DSS)
- [FIPS 197](https://csrc.nist.gov/publications/detail/fips/197/final): Advanced Encryption Standard (AES)
- [FIPS 202](https://csrc.nist.gov/publications/detail/fips/202/final): SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
- [NIST SP 800-56A](https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final): Recommendation for Pair-Wise Key Establishment Schemes Using Discrete Logarithm Cryptography
- [NIST SP 800-57](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final): Recommendation for Key Management: Part 1 - General
- [NIST SP 800-131A](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final): Transitioning the Use of Cryptographic Algorithms and Key Lengths

### 13.3 ASN.1 References

- [ITU-T X.680](https://www.itu.int/rec/T-REC-X.680): ASN.1 Specification of basic notation
- [ITU-T X.681](https://www.itu.int/rec/T-REC-X.681): ASN.1 Information object specification
- [ITU-T X.682](https://www.itu.int/rec/T-REC-X.682): ASN.1 Constraint specification
- [ITU-T X.683](https://www.itu.int/rec/T-REC-X.683): ASN.1 Parameterization of ASN.1 specifications
- [RFC 2474](https://datatracker.ietf.org/doc/html/rfc2474): Definition of the Differentiated Services Field (DS Field) in the IPv4 and IPv6 Headers
- [RFC 3246](https://datatracker.ietf.org/doc/html/rfc3246): An Expedited Forwarding PHB (Per-Hop Behavior)
- [ITU-T X.400](https://www.itu.int/rec/T-REC-X.400): Message Handling Systems (MHS): System and service overview
- [ITU-T X.420](https://www.itu.int/rec/T-REC-X.420): Message Handling Systems (MHS): Interpersonal messaging system

## 14. License

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

## 15. Implementation Notes

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
