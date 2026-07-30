# tightbeam

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

## Status

This project is under active development. Public APIs and file formats MAY change without notice. Not all feature combinations are supported. `no_std` and WASM support is limited. No security audit has been conducted. Use this software at your own risk.

## Copyright Notice

Copyright (C) Tanveer Wahid, WahidGroup, LLC (2025). All Rights Reserved.

## Abstract

tightbeam is a Layer-5 messaging framework. Frames use Abstract Syntax Notation One (ASN.1) with Distinguished Encoding Rules (DER). Versioned metadata carries protocol control data beside the application message.

Hot paths aim for zero-copy operation where the design allows it. Production paths avoid panic for ordinary error cases. Core protocol types target `no_std` environments; see Status for current limits.

## Table of Contents

1. [Introduction](#1-introduction)
   - 1.1. [Information Fidelity Constraint](#11-information-fidelity-constraint)
   - 1.2. [Requirements Language](#12-requirements-language)
   - 1.3. [Document Conventions](#13-document-conventions)
2. [Terminology](#2-terminology)
3. [Architecture](#3-architecture)
   - 3.1. [Information Theory Properties](#31-information-theory-properties)
4. [Protocol Specification](#4-protocol-specification)
   - 4.1. [Version Evolution](#41-version-evolution)
   - 4.2. [Frame Structure](#42-frame-structure)
   - 4.3. [Metadata Specification](#43-metadata-specification)
   - 4.4. [Frame Encapsulation](#44-frame-encapsulation)
5. [ASN.1 Formal Specification](#5-asn1-formal-specification)
   - 5.1. [Enumerated Types](#51-enumerated-types)
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
6. [Security Model](#6-security-model)
   - 6.1. [SecurityProfile Trait Architecture](#61-securityprofile-trait-architecture)
   - 6.2. [Security Profile Types](#62-security-profile-types)
   - 6.3. [Numeric Security Levels](#63-numeric-security-levels)
   - 6.4. [Message-Level Security Requirements](#64-message-level-security-requirements)
   - 6.5. [CryptoProvider System](#65-cryptoprovider-system)
   - 6.6. [Cryptographic Requirements](#66-cryptographic-requirements)
   - 6.7. [Version Security](#67-version-security)
   - 6.8. [ASN.1 Security Considerations](#68-asn1-security-considerations)
7. [Implementation](#7-implementation)
   - 7.1. [Requirements](#71-requirements)
     - 7.1.1. [Message Security Enforcement](#711-message-security-enforcement)
   - 7.2. [Transport Layer](#72-transport-layer)
   - 7.3. [Cryptographic Key Management](#73-cryptographic-key-management)
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
     - 8.5.6. [Negotiation and Failure Modes](#856-negotiation-and-failure-modes)
     - 8.5.7. [Threat-to-Control Mapping](#857-threat-to-control-mapping)
   - 8.6. [Multiplexing](#86-multiplexing)
     - 8.6.1. [Concept: Concurrent Streams Over One Connection](#861-concept-concurrent-streams-over-one-connection)
     - 8.6.2. [Specification: Stream Rules, Envelopes, and Runtime](#862-specification-stream-rules-envelopes-and-runtime)
     - 8.6.3. [Implementation: Assembling MuxTransport](#863-implementation-assembling-muxtransport)
     - 8.6.4. [Testing](#864-testing)
     - 8.6.5. [Serving and Pooling](#865-serving-and-pooling)
   - 8.7. [Connection Pooling](#87-connection-pooling)
   - 8.8. [Audit](#88-audit)

9. [Network Theory](#9-network-theory)
   - 9.1. [Network Architecture](#91-network-architecture)
   - 9.2. [Efficient Exchange-Interconnect-Compute](#92-efficient-exchange-interconnect-compute)
   - 9.3. [Components](#93-components)
     - 9.3.1. [E: Workers](#931-e-workers)
     - 9.3.2. [E: Servlets](#932-e-servlets)
     - 9.3.3. [I: Hives](#933-i-hives)
     - 9.3.4. [C: Clusters](#934-c-clusters)
10. [Instrumentation](#10-instrumentation)
    - 10.1. [Objectives](#101-objectives)
    - 10.2. [Event Kind Taxonomy](#102-event-kind-taxonomy)
    - 10.3. [Event Structure](#103-event-structure)
    - 10.4. [Payload Representation](#104-payload-representation)
    - 10.5. [Configuration](#105-configuration)
    - 10.6. [Evidence Artifact Format](#106-evidence-artifact-format)
    - 10.7. [Failure Handling](#107-failure-handling)
    - 10.8. [Logging Subsystem](#108-logging-subsystem)
11. [Misc](#11-misc)
    - 11.1. [Utilities](#111-utilities)
      - 11.1.1. [URNs](#1111-urns)
      - 11.1.2. [Jobs](#1112-jobs)
      - 11.1.3. [Job Pipelines](#1113-job-pipelines)
12. [Testing Framework](#12-testing-framework)
    - 12.1. [Architecture and Concepts](#121-architecture-and-concepts)
      - 12.1.1. [Three-Layer Progressive Verification](#1211-three-layer-progressive-verification)
      - 12.1.2. [Unified Entry Point: tb_scenario!](#1212-unified-entry-point-tb_scenario)
      - 12.1.3. [Feature Flag Architecture](#1213-feature-flag-architecture)
    - 12.2. [Layer 1: Assertion Specifications](#122-layer-1-assertion-specifications)
      - 12.2.1. [Concept](#1221-concept)
      - 12.2.2. [Specification: tb_assert_spec! Syntax](#1222-specification-tb_assert_spec-syntax)
      - 12.2.3. [Implementation Examples](#1223-implementation-examples)
      - 12.2.4. [Generated API](#1224-generated-api)
      - 12.2.5. [Cardinality Helpers](#1225-cardinality-helpers)
      - 12.2.6. [Value Assertion Helpers](#1226-value-assertion-helpers)
      - 12.2.7. [Tag-Based Assertion Filtering](#1227-tag-based-assertion-filtering)
      - 12.2.8. [Recording Trace Events](#1228-recording-trace-events)
      - 12.2.9. [Schedulability Analysis](#1229-schedulability-analysis)
    - 12.3. [Layer 2: Process Specifications (CSP)](#123-layer-2-process-specifications-csp)
      - 12.3.1. [Concept](#1231-concept)
      - 12.3.2. [Specification: tb_process_spec! Syntax](#1232-specification-tb_process_spec-syntax)
      - 12.3.3. [Validation Rules](#1233-validation-rules)
      - 12.3.4. [Example: CSP Process Specification](#1234-example-csp-process-specification)
      - 12.3.5. [Timing and Schedulability Verification](#1235-timing-and-schedulability-verification)
      - 12.3.6. [Process Composition: tb_compose_spec!](#1236-process-composition-tb_compose_spec)
    - 12.4. [Layer 3: Refinement Checking (FDR)](#124-layer-3-refinement-checking-fdr)
      - 12.4.1. [Concept](#1241-concept)
      - 12.4.2. [Specification: FdrConfig Syntax](#1242-specification-fdrconfig-syntax)
      - 12.4.3. [Implementation Examples](#1243-implementation-examples)
      - 12.4.4. [Multi-Seed Exploration](#1244-multi-seed-exploration)
      - 12.4.5. [FDR Verdict Structure](#1245-fdr-verdict-structure)
    - 12.5. [Formal CSP Theory](#125-formal-csp-theory)
      - 12.5.1. [Three Semantic Models](#1251-three-semantic-models)
      - 12.5.2. [Observable vs. Hidden Events](#1252-observable-vs-hidden-events)
      - 12.5.3. [Nondeterministic Choice and Refusal Sets](#1253-nondeterministic-choice-and-refusal-sets)
      - 12.5.4. [Multi-Seed Exploration and Scheduler Interleaving](#1254-multi-seed-exploration-and-scheduler-interleaving)
      - 12.5.5. [CSPM Export for FDR4 Integration](#1255-cspm-export-for-fdr4-integration)
      - 12.5.6. [Trace Analysis Extensions](#1256-trace-analysis-extensions)
    - 12.6. [Fault Injection](#126-fault-injection)
      - 12.6.1. [FaultModel Configuration](#1261-faultmodel-configuration)
      - 12.6.2. [Injection Strategies](#1262-injection-strategies)
      - 12.6.3. [Type-Safe State and Event Identifiers](#1263-type-safe-state-and-event-identifiers)
      - 12.6.4. [Integration with FDR](#1264-integration-with-fdr)
    - 12.7. [Unified Testing: tb_scenario! Macro](#127-unified-testing-tb_scenario-macro)
      - 12.7.1. [Syntax](#1271-syntax)
      - 12.7.2. [Examples](#1272-examples)
      - 12.7.3. [Hook Semantics](#1273-hook-semantics)
    - 12.8. [Coverage-Guided Fuzzing with AFL](#128-coverage-guided-fuzzing-with-afl)
      - 12.8.1. [Concept](#1281-concept)
      - 12.8.2. [Creating Fuzz Targets](#1282-creating-fuzz-targets)
      - 12.8.3. [Building and Running Fuzz Targets](#1283-building-and-running-fuzz-targets)
      - 12.8.4. [Advanced: CSP Oracle Integration](#1284-advanced-csp-oracle-integration)
      - 12.8.5. [IJON Integration: Input-to-State Correspondence](#1285-ijon-integration-input-to-state-correspondence)
    - 12.9. [Feature Matrix](#129-feature-matrix)
    - 12.10. [Standards Compliance Mapping](#1210-standards-compliance-mapping)
      - 12.10.1. [DO-178C DAL A / ISO 26262 ASIL-D](#12101-do-178c-dal-a--iso-26262-asil-d)
      - 12.10.2. [IEC 61508 SIL 4](#12102-iec-61508-sil-4)
      - 12.10.3. [NASA/ESA ECSS-E-HB-40A](#12103-nasaesa-ecss-e-hb-40a)
      - 12.10.4. [Common Criteria EAL7](#12104-common-criteria-eal7)
      - 12.10.5. [FMEA/FMECA (MIL-STD-1629, ISO 26262)](#12105-fmeafmeca-mil-std-1629-iso-26262)
      - 12.10.6. [Standards Compliance Summary](#12106-standards-compliance-summary)
13. [End-to-End Examples](#13-end-to-end-examples)
    - 13.1. [Complete Client-Server Application](#131-complete-client-server-application)
14. [References](#14-references)
    - 14.1. [Normative References](#141-normative-references)
    - 14.2. [Informative References](#142-informative-references)
15. [License](#15-license)
16. [Implementation Notes](#16-implementation-notes)

## 1. Introduction

tightbeam defines a structured, versioned messaging protocol. Information fidelity stays in the open interval **I(t) ∈ (0,1)** for all time t in the operating lifetime T. Protocol choices keep Frames inside that bound.

### 1.1 Information Fidelity Constraint

tightbeam treats information transmission as bounded for every time t:

**I(t) ∈ (0,1)**

- I(t) is never 1. Fidelity is never perfect because physical and encoding limits remain.
- I(t) is never 0 for a valid Frame. A valid Frame always carries information content.
- Protocol decisions MUST keep Frames inside these bounds.

Later sections apply this constraint to framing, integrity, and state structures such as `Matrix`.

### 1.2 Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119][rfc2119] and [RFC 8174][rfc8174].

### 1.3 Document Conventions

This document follows the [RFC Editor Style Guide][rfc-style-guide] and [RFC 7322][rfc7322] for structure and editorial style. Prose uses short full sentences and active voice. Prefer bullets or short paragraphs by default. Use a table only when readers must compare parallel rows. Project terms and software names override generic wording.

- **Section pattern**: Normative sections progress through concept, specification, implementation, then testing.
- **Requirements language**: Key words follow [§1.2 Requirements Language](#12-requirements-language).
- **Terminology**: Project terms are defined once in [§2 Terminology](#2-terminology) and used consistently after that.
- **Citations**: External standards are cited by name and linked on first mention in a section. Full entries live in [§14 References](#14-references). Every reference entry is cited at least once. Every in-text citation resolves to an entry there.

## 2. Terminology

The following project terms MUST be used consistently. This list holds identity nouns only. Design properties are indexed in [§3.1 Information Theory Properties](#31-information-theory-properties). Security and state terms such as Message Integrity (MI), Frame Integrity (FI), Matrix, `previous_frame`, and Nonrepudiation are defined in [§5.7](#57-semantic-constraints) and [§5.8](#58-what-is-the-matrix).

- [tightbeam](https://docs.rs/tightbeam-rs/latest): The project name. Write it in lowercase as tightbeam.
- [Frame](#42-frame-structure): A versioned snapshot at time t.
- [Message](#53-message-structure): A typed application payload carried inside a Frame.
- [Metadata](#43-metadata-specification): Protocol control fields carried with a Frame.
- [Version](#41-version-evolution): The protocol generation identifier (`V0` through `V3`).
- [TIP](tips/tip-0001.md): tightbeam Improvement Proposal.

## 3. Architecture

### 3.1 Information Theory Properties

tightbeam keeps Frames inside the fidelity bound **I(t) ∈ (0,1)** through the following design properties. The list is a property index, not a second glossary. Nouns stay in [§2 Terminology](#2-terminology). Each entry links to the normative rules.

- **STRUCTURE**: ASN.1 DER gives a single canonical encoding for equal values ([§5.5 Encoding Rules](#55-encoding-rules)).
- **IDEMPOTENCE**: Each Frame carries a unique `id` for message identification ([§4.1 Version Evolution](#41-version-evolution)).
- **ORDER**: Each Frame carries a monotonic `order` value ([§5.7.1 Message Ordering](#571-message-ordering)).
- **COMPACTNESS**: A Frame MAY carry enforceable compression via `compactness` ([§5.7.2 Compression Requirements](#572-compression-requirements)).
- **INTEGRITY**: Message Integrity (MI) and Frame Integrity (FI) bind body and envelope ([§5.7.3 Integrity Semantics](#573-integrity-semantics-order-of-operations)).
- **CONFIDENTIALITY**: A Frame MAY protect the body with AEAD encryption ([§5.7.3](#573-integrity-semantics-order-of-operations)).
- **PRIORITY**: A Frame MAY carry one of six `MessagePriority` levels ([§5.1 Enumerated Types](#51-enumerated-types)).
- **LIFETIME**: A Frame MAY carry a 64-bit TTL in `lifetime` ([§4.3 Metadata Specification](#43-metadata-specification)).
- **STATE**: Previous Frame chaining links snapshots across time ([§5.7.4 Previous Frame Chaining](#574-previous-frame-chaining)).
- **MATRIX**: Matrix carries dense application control state ([§5.8 What is the Matrix?](#58-what-is-the-matrix)).
- **NONREPUDIATION**: A signature MAY bind the signed Frame fields ([§5.7.5 Nonrepudiation Coverage and Binding](#575-nonrepudiation-coverage-and-binding)).

## 4. Protocol Specification

### 4.1 Version Evolution

Each protocol version inherits the required features of the prior version. A higher version MAY add optional features. Receivers that implement version N MUST accept Frames that use only features defined for version N or earlier, when those features remain valid for the negotiated version.

| Version | Required features                                          | Optional features                                                             |
| ------- | ---------------------------------------------------------- | ----------------------------------------------------------------------------- |
| V0      | Message identification (`id`); temporal ordering (`order`) | Compression (`compactness`)                                                   |
| V1      | All V0 required features                                   | Message Integrity (MI); Frame Integrity (FI); confidentiality; Nonrepudiation |
| V2      | All V1 required features                                   | Priority (`MessagePriority`); lifetime (TTL); Previous Frame chaining         |
| V3      | All V2 required features                                   | Matrix control                                                                |

Concrete field requirements and forbidden fields are stated in [§5.6 Version-Specific Constraints](#56-version-specific-constraints). Semantic rules for integrity, chaining, and signatures are stated in [§5.7 Semantic Constraints](#57-semantic-constraints).

### 4.2 Frame Structure

Every Frame MUST carry these elements:

- Frame `Version`
- Identifier (`Metadata.id`)
- Order (`Metadata.order`)
- Message payload (`Frame.message`)

A Frame MAY also carry:

- Message Integrity (MI) in `Metadata.integrity` ([§5.7.3](#573-integrity-semantics-order-of-operations))
- Frame Integrity (FI) in `Frame.integrity`: digest over `version` and `metadata`; MUST exclude `message` ([§5.7.3](#573-integrity-semantics-order-of-operations))
- Nonrepudiation in `Frame.nonrepudiation` ([§5.7.5](#575-nonrepudiation-coverage-and-binding))

Which optional fields a version MAY emit is stated in [§5.6](#56-version-specific-constraints). The Rust shapes follow in [§4.3](#43-metadata-specification) and [§4.4](#44-frame-encapsulation).

### 4.3 Metadata Specification

`Metadata` holds identity, order, and optional control fields. Version gates for each field are in [§5.6](#56-version-specific-constraints).

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

> Note: `Metadata.integrity` is Message Integrity (MI). `Frame.integrity` is Frame Integrity (FI). Both MAY appear from V1 onward. Same type name, different coverage. See [§5.7.3](#573-integrity-semantics-order-of-operations).

### 4.4 Frame Encapsulation

`Frame` is the top-level envelope. It carries `version`, `metadata`, `message`, and optional FI and Nonrepudiation fields.

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

ASN.1 types for the tightbeam wire format use [ITU-T X.680][itu-x680] notation and Distinguished Encoding Rules (DER) per [ITU-T X.690][itu-x690]. Semantic constraints are in [§5.6](#56-version-specific-constraints) through [§5.8](#58-what-is-the-matrix). The assembled module is in [§5.9](#59-complete-asn1-module).

### 5.1 Enumerated Types

#### Version Enumeration (tightbeam-specific)

```asn1
Version ::= ENUMERATED {
	v0(0),
	v1(1),
	v2(2),
	v3(3)
}
```

`Version` names the protocol generation on every Frame. Feature and field rules per value are in [§4.1](#41-version-evolution) and [§5.6](#56-version-specific-constraints).

The named, zero-based form follows the ASN.1 idiom used by X.509 ([RFC 5280][rfc5280], `Version ::= INTEGER { v1(0), v2(1), v3(2) }`) and CMS ([RFC 5652][rfc5652], `CMSVersion`). tightbeam numbers `vN` as integer `N`, matching CMS.

#### Message Priority Levels ([RFC 2474][rfc2474] DiffServ)

```asn1
MessagePriority ::= ENUMERATED {
	lowEffort(0),       -- LE PHB: background, non-urgent traffic, logs
	standard(1),        -- DF/CS0: best-effort default
	highThroughput(2),  -- AF1: batch processing, large data transfers
	lowLatency(3),      -- CS4: time-sensitive interactive data
	expedited(4),       -- EF: real-time interactive responses
	networkControl(5)   -- CS6/CS7: control plane, security/emergency alerts, keep-alive
}
```

There are six priority levels. Each level maps to a DiffServ Per-Hop Behavior (PHB) or service class in [RFC 2474][rfc2474], [RFC 4594][rfc4594], [RFC 3246][rfc3246], and [RFC 8622][rfc8622]. A higher numeric value means higher priority.

A secondary mapping to ITU-T X.400/X.420 message importance (low, normal, high) remains available for message-handling interoperability ([ITU-T X.400][itu-x400], [ITU-T X.420][itu-x420]).

### 5.2 Cryptographic Structures

tightbeam reuses CMS and PKCS structures for digests, encryption, signatures, and compression ([RFC 5652][rfc5652], [RFC 3447][rfc3447], [RFC 3274][rfc3274]).

#### Digest Information ([RFC 3447][rfc3447] PKCS #1)

From RFC 3447 Section 9.2:

```asn1
DigestInfo ::= SEQUENCE {
	digestAlgorithm  AlgorithmIdentifier,
	digest           OCTET STRING
}
```

> Note: `DigestInfo` is reused in three roles: Message Integrity (`Metadata.integrity`), Frame Integrity (`Frame.integrity`), and Previous Frame chaining (`previous_frame`). The type is the same. The covered bytes differ. The `previous_frame` digest is not FI.

#### Encrypted Content Information ([RFC 5652][rfc5652] CMS)

From RFC 5652 Section 6.1:

```asn1
EncryptedContentInfo ::= SEQUENCE {
	contentType                 ContentType,
	contentEncryptionAlgorithm  ContentEncryptionAlgorithmIdentifier,
	encryptedContent            [0] IMPLICIT OCTET STRING OPTIONAL
}
```

> Note: Used in `Metadata.confidentiality` for body encryption.

#### Signer Information ([RFC 5652][rfc5652] CMS)

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

> Note: Used in `Frame.nonrepudiation` for Nonrepudiation signatures.

#### Compressed Data ([RFC 3274][rfc3274] CMS)

From RFC 3274 Section 2:

```asn1
CompressedData ::= SEQUENCE {
	version                    CMSVersion,
	compressionAlgorithm       CompressionAlgorithmIdentifier,
	encapContentInfo           EncapsulatedContentInfo
}
```

> Note: Used in `Metadata.compactness` for compression. Compression rules are in [§5.7.2](#572-compression-requirements).

#### Matrix (tightbeam-specific)

```asn1
Matrix ::= SEQUENCE {
	n     INTEGER (1..255),
	data  OCTET STRING (SIZE(1..(255*255)))  -- MUST be exactly n*n octets. Row-major.
}
```

> Note: Used in `Metadata.matrix`. Full Matrix rules are in [§5.8 What is the Matrix?](#58-what-is-the-matrix).

### 5.3 Message Structure

These ASN.1 shapes match the Rust types in [§4.3](#43-metadata-specification) and [§4.4](#44-frame-encapsulation).

#### Metadata Structure

```asn1
Metadata ::= SEQUENCE {
	-- Core fields (V0+)
	id               OCTET STRING,
	order            INTEGER,
	compactness      CompressedData OPTIONAL,

	-- V1+ fields (context-specific tags)
	integrity        [0] DigestInfo OPTIONAL,           -- Message Integrity (MI)
	confidentiality  [1] EncryptedContentInfo OPTIONAL,

	-- V2+ fields (context-specific tags)
	priority         [2] MessagePriority OPTIONAL,
	lifetime         [3] INTEGER OPTIONAL,
	previous_frame   [4] DigestInfo OPTIONAL,           -- prior Frame digest; not FI

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
	integrity       [0] DigestInfo OPTIONAL,            -- Frame Integrity (FI)
	nonrepudiation  [1] SignerInfo OPTIONAL
}
```

### 5.4 External Dependencies

The protocol imports standard algorithm and identifier types from CMS and related RFCs.

#### Algorithm Identifier ([RFC 5652][rfc5652] CMS)

From RFC 5652 Section 10.1.2:

```asn1
AlgorithmIdentifier ::= SEQUENCE {
	algorithm   OBJECT IDENTIFIER,
	parameters  ANY DEFINED BY algorithm OPTIONAL
}
```

> Note: The Rust implementation uses the [spki](https://crates.io/crates/spki) crate for this type.

#### Compression Algorithm Identifiers ([RFC 3274][rfc3274] CMS)

From RFC 3274 Section 2:

```asn1
CompressionAlgorithmIdentifier ::= AlgorithmIdentifier

-- Standard compression algorithm OID
id-alg-zlibCompress OBJECT IDENTIFIER ::= { iso(1) member-body(2)
	us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 8 }

-- tightbeam zstd compression (Wahid Group PEN; no S/MIME registry OID yet)
id-alg-zstdCompress OBJECT IDENTIFIER ::= { iso(1) org(3) dod(6) internet(1)
	private(4) enterprise(1) wahidGroup(64586) algorithms(2) zstd(1) }
```

> Note: The numeric form is `1.3.6.1.4.1.64586.2.1`. The Rust implementation uses the [cms](https://crates.io/crates/cms) crate for CMS compression containers.

#### Hash and Signature Algorithms ([RFC 5246][rfc5246] TLS)

From RFC 5246 Section 7.4.1.4.1 (informative):

```asn1
enum {
	none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
	sha512(6), (255)
} HashAlgorithm;

enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
	SignatureAlgorithm;
```

> Note: Implementations SHOULD use SHA-256 or a stronger hash. Implementations SHOULD NOT use MD5 or SHA-1 for new deployments.

### 5.5 Encoding Rules

- Encoders MUST use DER as specified in [ITU-T X.690][itu-x690].
- Multi-byte integers use network byte order (big-endian).
- Textual content uses UTF-8. Binary fields use raw octets.
- Absent optional fields MUST NOT be encoded.

### 5.6 Version-Specific Constraints

Each protocol version has required, optional, and forbidden Frame and Metadata fields. Feature intent is summarized in [§4.1 Version Evolution](#41-version-evolution).

| Version | Required fields          | Optional fields                                                                              | Forbidden                        |
| ------- | ------------------------ | -------------------------------------------------------------------------------------------- | -------------------------------- |
| V0      | `id`, `order`, `message` | `compactness`                                                                                | Fields introduced in V1 or later |
| V1      | All V0 required fields   | `Metadata.integrity` (MI); `confidentiality`; `Frame.nonrepudiation`; `Frame.integrity` (FI) | Fields introduced in V2 or later |
| V2      | All V1 required fields   | `priority`; `lifetime`; `previous_frame`                                                     | Fields introduced in V3 or later |
| V3      | All V2 required fields   | `matrix`                                                                                     | None beyond the ASN.1 schema     |

A version that inherits prior requirements MUST satisfy every required field of those prior versions. Absent optional fields MUST NOT be encoded (DER). Encoders MUST NOT emit a field that is forbidden for the Frame version in use. Decoders MUST reject Frames that carry forbidden fields for the declared version.

### 5.7 Semantic Constraints

The following rules cover ordering, compression, integrity, chaining, and Nonrepudiation. They fix validation semantics and data-retention choices.

#### 5.7.1 Message Ordering

- The `order` field MUST increase monotonically within a message sequence.
- When ordering is time-based, `order` values SHOULD come from a reliable clock or counter source.
- Receivers MUST reject duplicate `order` values inside the same message namespace.

#### 5.7.2 Compression Requirements

- When `compactness` is present, `message` MUST hold `CompressedData` per [RFC 3274][rfc3274].
- If the compressed bytes do not match a recognized content type, `encapContentInfo` MUST use the `id-data` content type OID.
- Compression algorithm identifiers MUST be valid OIDs. zlib uses `id-alg-zlibCompress`. zstd uses Wahid Group PEN `1.3.6.1.4.1.64586.2.1` until an S/MIME registry OID exists.
- When `compressionAlgorithm.parameters` carries a level, that level MUST stay inside the algorithm-specific valid range.

#### 5.7.3 Integrity Semantics: Order of Operations

Message Integrity (MI) and Frame Integrity (FI) bind different byte ranges. Receivers MUST apply each check to the correct coverage.

| Term                   | Coverage                             | Binding rule                                                                |
| ---------------------- | ------------------------------------ | --------------------------------------------------------------------------- |
| Message Integrity (MI) | Message payload bytes                | When `Metadata.integrity` is present, MI MUST bind the message body.        |
| Frame Integrity (FI)   | DER-canonical `version` + `metadata` | FI MUST exclude `message`. FI MUST bind the frame envelope around the body. |

- FI alone MUST NOT prove message-content correctness. FI proves only that `version` and `metadata` are intact.
- MI MUST prove message-content correctness.
- MI lives in metadata. FI commits to the frame that contains that metadata, so FI witnesses MI.
- When FI is authenticated (for example by nonrepudiation or consensus), tampering with MI MUST fail authenticated FI validation.
- Receivers SHOULD treat the pair (valid MI, authenticated FI) as enough evidence that both frame and message are intact.
- An in-band, unsigned FI MUST NOT be trusted against an active attacker who changes both MI and FI.

##### Optional Hiding Commitment (Salt)

By default, MI is the bare digest `H(message)`. That digest is binding. It is not hiding. The digest travels in cleartext metadata. If the body has low entropy, an attacker who sees the digest MAY brute-force candidate preimages. Encrypting the body does not remove that risk by itself.

An application MAY store a hiding commitment in the same `Metadata.integrity` field. The commitment salts the body with a secret, high-entropy blinding value.

**Commitment formula**

`H(len(salt) || salt || DER(message))`

- `len(salt)` is an 8-byte big-endian integer.
- Distinct `(salt, message)` pairs cannot collide under concatenation ambiguity.
- An empty salt is treated as the plain digest `H(message)`.
- Callers use `Opening::prove` and `Opening::verify`.
- Disclosing `(salt, message)` proves the committed content in constant time.
- The pattern matches the salted-hash disclose-then-verify construction in SD-JWT ([RFC 9901][rfc9901]) and ISO mdoc ([ISO/IEC 18013-5][iso-18013-5]).

**Salt ownership**

The salt is not a tightbeam responsibility. tightbeam does not generate, encrypt, store, or transmit the salt.

| Concern                 | Owner                              |
| ----------------------- | ---------------------------------- |
| Salt entropy            | Caller MUST provide it.            |
| Opening retention       | Caller MUST decide where it lives. |
| Disclosure              | Caller MUST control it.            |
| Self-contained envelope | Caller MUST define it when needed. |

One example of a caller-defined envelope is a credential that carries an encrypted salt beside the body for later selective disclosure.

**Recommended pattern (confidentiality enabled)**

Carry the salt inside the sealed body. The opening is then recoverable by decryption alone, with no out-of-band state.

1. Wrap the payload with its blinding salt.
2. Commit to the payload with `Opening::prove`.
3. Encrypt the wrapper to the recipient.
4. Store the ciphertext as `Frame.message`.

```asn1
SealedBody ::= SEQUENCE {
	salt   OCTET STRING,   -- random, fixed-length blinding value
	value  Payload         -- the application message type
}
```

A recipient decrypts the body and recovers the opening `(salt, DER(value))`. The recipient MAY later disclose that opening to a third party. Disclosure proves the committed `value` in constant time and does not reveal the content key.

##### Message Integrity with AEAD

When confidentiality is enabled, implementations MUST use Authenticated Encryption with Associated Data (AEAD). The type system enforces this requirement through trait bounds:

```rust
pub fn with_aead<C, Cipher>(mut self, cipher: Cipher) -> Self
where
	C: AssociatedOid,
	Cipher: Aead + Encryptor<C> + 'static, // AEAD + canonical OID binding required
	T: CheckAeadOid<C>;
```

- Non-AEAD ciphers cannot be selected. The compiler rejects them.
- `Encryptor<C>` exists only for canonically matched cipher and OID pairs. The wire algorithm identifier cannot diverge from the cipher, even when the message type has no security profile.
- AEAD tags prove that ciphertext was not modified. Examples include AES-GCM ([FIPS 197][fips197]) and ChaCha20-Poly1305 ([RFC 8439][rfc8439]).
- MI proves that decrypted plaintext matches the original message content.
- AEAD protects ciphertext. MI proves plaintext. FI witnesses MI in metadata. Signatures cover the frame.

When AEAD is enforced, the construction is cryptographically equivalent to Encrypt-then-MAC for ciphertext authenticity. An attacker cannot modify the ciphertext without failing AEAD authentication. An attacker cannot modify MI without breaking authenticated FI when signing is present. An attacker cannot decrypt without the key.

#### 5.7.4 Previous Frame Chaining

The `previous_frame` field links Frames through a cryptographic hash chain. Each digest commits to prior history by transitive hashing.

- **Causal ordering**: A Frame carries proof of its position in the sequence.
- **Tamper detection**: A change to an earlier Frame breaks every later digest that depends on it.
- **Replay protection**: Receivers can detect out-of-sequence or duplicate Frames.
- **Fork detection**: Two Frames that share one `previous_frame` digest indicate a branch.
- **Stateless verification**: Ancestry can be checked without storing the entire chain.

Implementations MAY retain Frame or message bytes so they can reconstruct the chain back to a chosen root.

#### 5.7.5 Nonrepudiation Coverage and Binding

When `nonrepudiation` is present, the signature MUST cover the canonical DER encoding of the Frame fields except the `nonrepudiation` field itself. The covered fields are `version`, `metadata` (including MI when present), `message`, and `integrity` (FI) when FI is present.

Any change to those fields invalidates the signature. The resulting binding is transitive: the signature binds the frame envelope (including FI when present), FI binds the metadata envelope (including MI when present), and MI binds the message body.

**Figure: nonrepudiation binding**

```
Signature
	|
	v
FI (envelope: version + metadata)
	|
	v
MI (in metadata)
	|
	v
Message body
```

#### 5.7.6 Security Property Chain

When MI, FI, AEAD encryption, and signatures are all enabled, senders and receivers MUST apply the following order.

**Sender operations (in order):**

1. Compute MI over the plaintext message. Store `DigestInfo` in `Metadata`.
2. Optionally compress the plaintext message. Store `CompressedData` in `Metadata`.
3. Encrypt with an AEAD cipher to produce authenticated ciphertext. Store `EncryptedContentInfo` in `Metadata` and the ciphertext in `Frame.message`.
4. Compute FI over the envelope (`Version` + `Metadata` that contains MI). Store `DigestInfo` in `Frame`.
5. Sign the complete frame (`Version` + `Metadata` + ciphertext + FI). Store `SignerInfo` in `Frame`.

**Receiver verification (in order):**

1. Verify the signature over the complete Frame and message bytes in scope.
2. Verify FI over the envelope (`Version` + `Metadata`).
3. Verify the AEAD authentication tag on the ciphertext.
4. Decrypt the ciphertext to recover plaintext.
5. Verify that MI matches the decrypted plaintext.

AEAD protects ciphertext authenticity. FI protects envelope integrity, including MI in metadata. MI proves plaintext correctness after decryption. The signature provides nonrepudiation over the signed frame. Tampering at any layer MUST cause verification to fail.

### 5.8 What is the Matrix?

The `Matrix` type carries compact application state inside a Frame. It is an **n x n** grid of octets. ASN.1 DER encodes the grid so that equal values always produce the same bytes. The application assigns meaning to each cell. The optional `Metadata.matrix` field is available in protocol version V3 and later. These bounds support the information-fidelity constraint **I(t) ∈ (0,1)**.

#### 5.8.1 Why Use the Matrix?

Applications use the matrix when they need dense, version-tolerant control state on the wire.

- A matrix holds up to 255x255 cell values in the range 0-255. The maximum encoded size is about 63.5 KB.
- Newer senders MAY set cells that older receivers do not understand. Receivers SHOULD ignore those cells.
- Deterministic DER encoding and length checks keep invalid grids off the wire.
- Applications MAY combine the matrix with `previous_frame` to bind successive state snapshots.

The matrix does not replace the message payload. It carries structured control or status data that benefits from a fixed grid layout.

#### 5.8.2 The Simple View

The matrix is a two-dimensional array **M** of size **n x n**, where **n ≤ 255**. Each element satisfies **M[r,c] ∈ {0, ..., 255}**. The application defines what each value means. Common uses include flags, counters, state codes, and function selectors.

Under a uniform distribution, the maximum entropy of a full matrix is:

**H = n² log₂ 256 = 8n²** bits.

A sparse application that uses only **k** cells has lower entropy. In that case the used set contributes about **8k** bits when the unused cells are treated as fixed.

| Symbol     | Meaning                                | Range    |
| ---------- | -------------------------------------- | -------- |
| **n**      | Grid size (number of rows and columns) | 1-255    |
| **r**      | Row index                              | 0 .. n-1 |
| **c**      | Column index                           | 0 .. n-1 |
| **M[r,c]** | Cell value defined by the application  | 0-255    |

**Figure: 2x2 game-state example**

```
        c=0  c=1
      +----+----+
  r=0 | 1  | 0  |   M[0,0] = 1  Player 1 at (0,0)
      +----+----+   M[1,1] = 2  Player 2 at (1,1)
  r=1 | 0  | 2  |   M[0,1] = 0 and M[1,0] = 0 (empty)
      +----+----+
```

Matrix coordinates MAY also encode structured data. For example, an application MAY map regions of the grid to public-key material or other fixed-layout fields.

#### 5.8.3 Wire Format (Technical Details)

Encoders MUST serialize the matrix with ASN.1 DER. DER gives a single canonical byte encoding for each matrix value.

```asn1
Matrix ::= SEQUENCE {
    n INTEGER (1..255),                 -- Grid size (n x n)
    data OCTET STRING (SIZE(1..65025))  -- Row-major cell values
}
```

- Cells are stored in row-major order. The octet index of cell (r,c) is **r \* n + c**.
- The length of `data` MUST equal **n²**.
- When **n = 255**, `data` contains 65,025 bytes (about 63.5 KB).
- There are **256^(n²)** distinct matrices of size n.
- For a uniform full matrix, **H = 8n²** bits.
- Encoding and decoding take O(n²) time. Length validation takes O(1) time.

#### 5.8.4 Usage Rules

The following rules constrain matrix handling so that frames remain within **I(t) ∈ (0,1)**.

- Encoders MUST set `data.len = n²`.
- Encoders MUST write each cell as an octet in the range 0-255.
- Decoders MUST reject a matrix when `data.len != n²`.
- Decoders MUST reject a matrix when a decoded cell value falls outside 0-255.
- Applications MUST define the meaning of every cell they use.
- Receivers SHOULD ignore non-zero values in cells that the local application has not defined.
- If `Metadata.matrix` is omitted, the application MAY assume a default matrix state.

#### 5.8.5 Example: Flag System

The following example sets diagonal feature flags in a 3x3 matrix and embeds the matrix in a Frame:

```rust
use tightbeam::Matrix;

// Full 3x3 matrix
let mut matrix = Matrix::<3>::default();
matrix.set(0, 0, 1); // Feature A: enabled
matrix.set(1, 1, 1); // Feature B: enabled
matrix.set(2, 2, 0); // Feature C: disabled

// Embed in a frame
let frame = compose! {
    V1: id: "config-001",
        order: 1000,
        message: my_message,
        matrix: Some(matrix)
}?;
```

**Figure: resulting 3x3 flag matrix**

```
[1, 0, 0]
[0, 1, 0]
[0, 0, 0]
```

A diagonal layout supports up to 255 distinct flags. Applications MAY extend the flag set by defining additional diagonal entries. For structured data that is not a flag, applications SHOULD use non-diagonal cells. For example, **M[0,1] = 10** MAY represent a count, and a block of cells MAY hold a public key or similar fixed-layout value.

#### 5.8.6 Advanced: Modeling with Matrix and Previous Frame

Applications MAY combine the matrix with the `previous_frame` field to track state across Frames. In this model, each Frame is a snapshot. The `previous_frame` digest binds the current Frame to an earlier Frame. When verification succeeds, the linked snapshots form a directed acyclic graph (DAG) of state.

A useful mathematical view treats the sequence as a Markov chain. The matrix **M_t** at time t depends on **M\_{t-1}**. The cryptographic digest in `previous_frame` supplies the causal link between those snapshots.

- **Snapshot**: The matrix **M_t** carried by the Frame at time t. Its entropy is at most **8n²** bits.
- **Causal link**: A verified `previous_frame` digest that binds Frame t to Frame t-1.
- **Transition**: A change in one or more cells from **M\_{t-1}** to **M_t**.
- **Branch**: Two or more Frames that share the same `previous_frame` digest but carry different matrices **M_t**.

**Figure: causal chain of matrix snapshots**

```
Frame t-1 (M_{t-1})
        |
        |  previous_frame digest verifies against prior Frame
        v
Frame t   (M_t)
        |
        |  previous_frame digest verifies against prior Frame
        v
Frame t+1 (M_{t+1})
```

Applications MAY define a transition model **P(M*t | M*{t-1})**. The model may capture deterministic application logic, noise, or both. Application-level fidelity MAY be expressed with mutual information, for example:

**I(t) = I(M*t; M*{t-1}) / H(M_t) ∈ (0,1)**.

That ratio is application-defined. Protocol integrity still depends on digest verification and on the matrix encoding rules in [§5.8.4](#584-usage-rules). Partial recovery of earlier state remains an application concern when some cells are unused or unknown.

#### 5.8.7 Summary

The matrix provides a bounded **n x n** octet grid for application state. DER encoding and the rules in [§5.8.4](#584-usage-rules) keep the wire form deterministic and checkable. Simple deployments MAY use diagonal flags or small game-style grids. Advanced deployments MAY chain matrices through `previous_frame` to model causal state over time.

### 5.9 Complete ASN.1 Module

The following module collects the types from this section into one ASN.1 module for reference.

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

-- Message priority enumeration (DiffServ; see §5.1)
MessagePriority ::= ENUMERATED {
	lowEffort(0),
	standard(1),
	highThroughput(2),
	lowLatency(3),
	expedited(4),
	networkControl(5)
}

-- tightbeam-specific matrix structure
Matrix ::= SEQUENCE {
	n     INTEGER (1..255),
	data  OCTET STRING (SIZE(1..(255*255)))  -- MUST be exactly n*n octets; row-major
}

-- Core message structures
Metadata ::= SEQUENCE {
	id               OCTET STRING,
	order            INTEGER,
	compactness      CompressedData OPTIONAL,
	integrity        [0] DigestInfo OPTIONAL,           -- Message Integrity (MI)
	confidentiality  [1] EncryptedContentInfo OPTIONAL,
	priority         [2] MessagePriority OPTIONAL,
	lifetime         [3] INTEGER OPTIONAL,
	previous_frame   [4] DigestInfo OPTIONAL,           -- prior Frame digest; not FI
	matrix           [5] Matrix OPTIONAL
}

Frame ::= SEQUENCE {
	version         Version,
	metadata        Metadata,
	message         OCTET STRING,
	integrity       [0] DigestInfo OPTIONAL,            -- Frame Integrity (FI)
	nonrepudiation  [1] SignerInfo OPTIONAL
}

END
```

## 6. Security Model

A `SecurityProfile` declares algorithm OIDs at compile time. Provider traits supply the operations that realize those algorithms at run time. Message-level requirements are specified in [§6.4](#64-message-level-security-requirements).

### 6.1 SecurityProfile Trait Architecture

A `SecurityProfile` is a compile-time metadata type. It declares which algorithm identifiers (OIDs) a message type or component MAY use. It does not perform cryptographic operations by itself. Runtime work is supplied through provider traits that compose into `CryptoProvider` ([§6.5](#65-cryptoprovider-system)).

#### Design Principles

The `SecurityProfile` trait associates OID types with digest, AEAD, signature, curve, and KEM roles. An optional key-wrap OID MAY be set as a constant:

```rust
pub trait SecurityProfile {
	type DigestOid: AssociatedOid;
	type AeadOid: AssociatedOid + AeadKeySize;
	type SignatureAlg: SignatureAlgorithmIdentifier;
	type CurveOid: AssociatedOid;
	type KemOid: AssociatedOid;

	const KEY_WRAP_OID: Option<ObjectIdentifier> = None;
}
```

#### Role-Based Provider Traits

tightbeam splits cryptographic work across specialized provider traits. A component depends only on the providers it needs.

- **`DigestProvider`**: Hash and digest operations. Examples include SHA-256 ([FIPS 180-4][fips180-4]) and SHA3-256 ([FIPS 202][fips202]).
- **`AeadProvider`**: Authenticated encryption. Examples include AES-GCM variants.
- **`SigningProvider`**: Signature generation and verification. Examples include ECDSA ([FIPS 186-5][fips186-5]) and Ed25519 ([RFC 8032][rfc8032]).
- **`KdfProvider`**: Key derivation. Examples include HKDF ([RFC 5869][rfc5869]).
- **`CurveProvider`**: Elliptic-curve operations. Examples include secp256k1, P-384 ([RFC 5480][rfc5480]), and X25519 ([RFC 7748][rfc7748]).

These traits compose into `CryptoProvider`. Full composition rules are in [§6.5 CryptoProvider System](#65-cryptoprovider-system).

### 6.2 Security Profile Types

An application implements `SecurityProfile` to fix the algorithm set for a security context. Different message types MAY use different profile types.

#### Implementing Custom Profiles

```rust
// Example: Custom application profile
pub struct MyAppProfile;

impl SecurityProfile for MyAppProfile {
	type DigestOid = Sha3_256;
	type AeadOid = Aes256GcmOid;
	type SignatureAlg = Secp256k1Signature;
	type CurveOid = Secp256k1Oid;
	type KemOid = Kyber1024Oid;

	const KEY_WRAP_OID: Option<ObjectIdentifier> = Some(AES_256_WRAP);
}
```

#### Built-in Default Profile

`TightbeamProfile` is the built-in default and reference profile:

```rust
pub struct TightbeamProfile;

impl SecurityProfile for TightbeamProfile {
	type DigestOid = Sha3_256;
	type AeadOid = Aes256GcmOid;
	type SignatureAlg = Secp256k1Signature;
	type CurveOid = Secp256k1Oid;
	type KemOid = Kyber1024Oid;

	const KEY_WRAP_OID: Option<ObjectIdentifier> = Some(AES_256_WRAP);
}
```

> Note: Applications MAY define additional profiles for other contexts. Examples include a high-assurance profile, a legacy-interop profile, or a post-quantum profile. Bind each profile to the message types that require it ([§6.4](#64-message-level-security-requirements)).

### 6.3 Numeric Security Levels

Numeric security levels are a shorthand for common `Message` requirement flags. They do not replace a typed `SecurityProfile`.

- Level 1 or level 2 sets confidential and nonrepudiable requirements and sets `min_version` to `V1`.
- Numeric levels do **not** enable algorithm OID validation. Use a type-based `SecurityProfile` for OID checks ([§6.4](#64-message-level-security-requirements)).

### 6.4 Message-Level Security Requirements

The `Message` trait attaches security requirements to a message type. Composition paths enforce those requirements at compile time when a typed profile is active. Frame validation checks the resulting shape at run time.

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

`HAS_PROFILE` selects whether the message type enforces algorithm OID matching.

- When `HAS_PROFILE` is `false` (default), the associated `Profile` defaults to `TightbeamProfile`. Composition does not require OID matching against that profile.
- When `HAS_PROFILE` is `true`, `FrameBuilder` and `compose!` require cryptographic operations to use algorithms from `Message::Profile`.

The associated `Profile` type MAY be any type that implements `SecurityProfile`. It defaults to `TightbeamProfile` when the application does not set another type. OID validation runs at compile time only when `HAS_PROFILE` is `true`.

When `HAS_PROFILE` is `true`, the following matches are required at compile time:

- Digest algorithms MUST match `<Profile::DigestOid as AssociatedOid>::OID`.
- AEAD ciphers MUST match `<Profile::AeadOid as AssociatedOid>::OID`.
- Signature algorithms MUST match `<Profile::SignatureAlg as SignatureAlgorithmIdentifier>::ALGORITHM_OID`.

A message type with a typed profile therefore composes only with compatible algorithms.

#### Security Requirement Semantics

- When `MUST_BE_NON_REPUDIABLE` is `true`, the Frame MUST include `nonrepudiation`.
- When `MUST_BE_CONFIDENTIAL` is `true`, `Metadata` MUST include `confidentiality`.
- When `MUST_BE_COMPRESSED` is `true`, `Metadata.compactness` MUST be present (not absent).
- When `MUST_BE_PRIORITIZED` is `true`, `Metadata` MUST include `priority`. This requirement applies only for V2 and later.
- When `MUST_HAVE_MESSAGE_INTEGRITY` is `true`, `Metadata.integrity` (MI) MUST be present.
- When `MUST_HAVE_FRAME_INTEGRITY` is `true`, `Frame.integrity` (FI) MUST be present.
- `Frame.version` MUST be greater than or equal to `Message::MIN_VERSION`.

#### Profile Validation in FrameBuilder

When `HAS_PROFILE` is `true`, `FrameBuilder` and `compose!` enforce profile constraints at compile time.

**Using the `compose!` macro:**

```rust
// Example: Message with custom profile
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
#[beam(profile(MyAppProfile))]
struct SecureMessage { data: Vec<u8> }

// compose! macro validates algorithm OIDs match MyAppProfile
let frame = compose! {
	V1: id: b"msg-001",
		order: 1696521900,
		message_integrity<Sha3_256>: salt,
		confidentiality<Aes256GcmOid, _>: &cipher,
		nonrepudiation<Secp256k1Signature, _>: &signing_key,
		message: message
}?;
```

**Using FrameBuilder directly:**

```rust
// FrameBuilder validates algorithm OIDs match MyAppProfile
let frame = compose::<SecureMessage>(Version::V1)
	.with_message(msg)
	.with_id(b"msg-001")
	.with_order(timestamp)
	.with_message_hasher::<Sha3_256>(salt)          // ✓ Matches MyAppProfile::DigestOid
	.with_aead::<Aes256GcmOid, _>(&cipher)          // ✓ Matches MyAppProfile::AeadOid
	.with_signer::<Secp256k1Signature, _>(&signer)  // ✓ Matches MyAppProfile::SignatureAlg
	.build()?;
```

> Note: tightbeam macros are optional. The same behavior is available through the underlying builders and traits for direct use.

**Validation rules** (when `HAS_PROFILE` is `true`):

- `with_message_hasher::<D>(salt)` requires `D::OID == Profile::DigestOid::OID`.
- `with_witness_hasher::<D>()` requires `D::OID == Profile::DigestOid::OID`.
- `with_aead::<C, _>()` requires `C::OID == Profile::AeadOid::OID`. The `Encryptor<C>` bound also ties the cipher type to its canonical OID, even when no typed profile is active.
- `with_signer::<S, _>()` requires `S::ALGORITHM_OID == Profile::SignatureAlg::ALGORITHM_OID`.

An algorithm mismatch returns `TightBeamError::UnexpectedAlgorithmForProfile`. The error carries the expected OID and the received OID.

#### Implementation Enforcement

- **Compile time**: The type system rejects compositions that violate the active profile or requirement flags.
- **Run time**: Frame validation checks that the Frame shape matches the message requirements.
- **Profile binding**: A `SecurityProfile` type is attached through `Message::Profile` and the `#[beam(profile(...))]` attributes below.

#### Derive Macro Usage

`#[derive(Beamable)]` implements `Message`. Security and profile attributes set the trait constants and associated type.

**Security attributes:**

- `#[beam(message_integrity)]`, `#[beam(frame_integrity)]`
- `#[beam(nonrepudiable)]`, `#[beam(confidential)]`
- `#[beam(compressed)]`, `#[beam(prioritized)]`
- `#[beam(min_version = "V1")]`

**Profile attributes:**

- `#[beam(profile = 1)]` or `#[beam(profile = 2)]`: numeric levels. These set confidential and nonrepudiable requirements. They do not enable OID validation ([§6.3](#63-numeric-security-levels)).
- `#[beam(profile(TypeName))]`: typed profile. This sets `HAS_PROFILE` and enables compile-time OID validation.

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

### 6.5 CryptoProvider System

`CryptoProvider` composes the role-based provider traits from [§6.1](#61-securityprofile-trait-architecture). It binds concrete cryptographic implementations to a `SecurityProfile`. A provider type is a zero-sized `Copy + Default` value.

```rust
pub trait CryptoProvider:
	Default +
	Copy + // zero-sized type (ZST),
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

`DefaultCryptoProvider` is the reference provider. It uses:

- **Digest**: SHA3-256
- **AEAD**: AES-256-GCM
- **Signature**: secp256k1 ECDSA
- **KDF**: HKDF-SHA3-256
- **Curve**: secp256k1

Its associated profile is `TightbeamProfile` ([§6.2](#62-security-profile-types)).

### 6.6 Cryptographic Requirements

- Integrity digests MUST use a cryptographically secure hash function ([§5.7.3](#573-integrity-semantics-order-of-operations)).
- Confidentiality MUST use authenticated encryption (AEAD) ([§5.7.3](#573-integrity-semantics-order-of-operations)).
- Nonrepudiation MUST use digital signatures with securely generated key pairs ([§5.7.5](#575-nonrepudiation-coverage-and-binding)).

### 6.7 Version Security

Security-related Frame features are version-gated. Full field rules are in [§4.1](#41-version-evolution) and [§5.6](#56-version-specific-constraints).

- **V0**: No optional security fields. Identification and ordering only.
- **V1**: MAY include MI, FI, confidentiality, and Nonrepudiation.
- **V2**: Adds optional priority, lifetime, and `previous_frame` chaining.
- **V3**: Adds optional Matrix control state.

A receiver MUST reject security fields that are forbidden for the declared Frame version ([§5.6](#56-version-specific-constraints)).

### 6.8 ASN.1 Security Considerations

ASN.1 DER encoding supports several security properties of the wire format:

- DER is canonical. Equal values produce one encoding, which reduces ambiguous-parsing attacks ([ITU-T X.690][itu-x690]).
- Context-specific tags distinguish optional fields and reduce field-confusion risk.
- Explicit `Version` values support refusal of unsupported or downgraded Frames.
- Absent optional fields MUST NOT be encoded. That rule reduces injection of unexpected OPTIONAL elements ([§5.5](#55-encoding-rules)).

## 7. Implementation

Minimum implementation requirements follow. Protocol field rules live in [§4](#4-protocol-specification) and [§5](#5-asn1-formal-specification). Security enforcement details live in [§6](#6-security-model). Transport mechanics live in [§8](#8-transport-layer).

### 7.1 Requirements

An implementation MUST provide at least the following:

- Memory safety and ownership guarantees (Rust)
- ASN.1 DER encoding and decoding ([ITU-T X.690][itu-x690])
- `Frame` and `Metadata` shapes that match the ASN.1 module ([§5.9](#59-complete-asn1-module))
- Enforcement of message-level security requirements ([§6.4](#64-message-level-security-requirements))
- Frame composition and verification ([§5.7](#57-semantic-constraints))
- Cryptographic abstraction for confidentiality, integrity, and Nonrepudiation ([§6.5](#65-cryptoprovider-system))
- A transport abstraction that can run over more than one byte-moving protocol ([§7.2](#72-transport-layer), [§8](#8-transport-layer))

### 7.1.1 Message Security Enforcement

Implementations MUST enforce `Message` security requirements at compile time and at run time ([§6.4](#64-message-level-security-requirements)).

#### Compile-Time Validation

- The type system MUST reject unsafe message composition when requirement flags or a typed `SecurityProfile` are active.
- Trait bounds MUST enforce security requirements at build time.
- Message type definitions MUST check version compatibility against `MIN_VERSION`.

#### Runtime Validation

- Frame encode and decode paths MUST validate the Frame shape against the message type requirements.
- Requirement violations MUST surface as errors. Implementations MUST NOT panic for ordinary validation failures.

### 7.2 Transport Layer

tightbeam MUST be usable over any transport that can carry opaque byte frames. The crate includes a TCP transport with synchronous and asynchronous APIs. Full transport architecture, policies, handshakes, multiplexing, and pooling are specified in [§8 Transport Layer](#8-transport-layer).

### 7.3 Cryptographic Key Management

tightbeam accepts standard key material and delegates key lifecycle management to the application ([NIST SP 800-57][nist-800-57]).

- **Accepted formats**: X.509 certificates, raw key material, and CMS structures.
- **Session establishment**: CMS-based and ECIES-based handshakes ([§8.5](#85-handshake-protocols)).
- **Application duties**: key generation, storage, rotation, certificate validation, and revocation checking ([RFC 6960][rfc6960]).

#### Trust Stores

The `CertificateTrust` trait verifies certificate chains and manages trust anchors. Implementations use a trust store to:

- Verify peer certificates during connection establishment
- Validate a chain from trust anchor through intermediates to the leaf
- Look up signer certificates when verifying Frame Nonrepudiation

**Building a trust store:**

```rust
let cert = Certificate::try_from(CERT_PEM)?;
let trust_store = CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
    .with_certificate(cert)?
    .build();
```

**Adding a certificate chain:**

```rust
let trust_store = CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
    .with_chain(vec![root_cert, intermediate_cert, leaf_cert])?
    .build();
```

## 8. Transport Layer

The transport layer moves Frame bytes between endpoints. It establishes connections, applies security policies, and manages session cryptographic state. Policy details are in [§8.4](#84-transport-policies). Handshakes are in [§8.5](#85-handshake-protocols). Multiplexing and pooling are in [§8.6](#86-multiplexing) and [§8.7](#87-connection-pooling).

### 8.1 Transport Architecture

Transport behavior is split across traits so applications can plug in a byte protocol without rewriting policy or crypto code.

#### 8.1.1 Design Principles

- Bind and connect live on protocol traits. Frame read and write live on I/O traits.
- Gate and retry policies attach to emitter and collector wrappers. They do not rewrite the byte protocol.
- Encryption extends the same trait family. Cleartext and encrypted paths share the Frame API.

#### 8.1.2 Core Transport Traits

- `Protocol`: bind and connect operations
- `MessageIO`: read and write wire envelopes
- `MessageCollector`: server-side receive path with policies
- `MessageEmitter`: client-side send path with policies and retry
- `EncryptedProtocol`: certificate-based bind and connect
- `EncryptedMessageIO`: encrypt and decrypt envelopes on the wire

### 8.2 Wire Format

Frames use ASN.1 DER with two envelope layers:

- **`WireEnvelope`**: Outer cleartext or encrypted container
- **`TransportEnvelope`**: Inner request, response, CMS, or mux payload

With the `transport-multiplex` feature, `TransportEnvelope` includes a `Mux` arm (ASN.1 context tag 4). That arm nests a `MuxEnvelope` CHOICE with Open, Data, End, Credit, Cancel, GoAway, and Ping (inner context tags 0 through 6). Multiplex stream correlation metadata travels inside the `TransportEnvelope` payload. When `WireEnvelope` is encrypted, that metadata is not cleartext on the wire.

DER tag-length-value encoding supplies framing. Default size limits:

- Cleartext envelopes: 128 KB (configurable through `TransportEncryptionConfig`)
- Encrypted envelopes: 256 KB (configurable through `TransportEncryptionConfig`)
- Handshake messages: 16 KB hard limit (DoS bound)

### 8.3 TCP Transport

The TCP transport maps a byte stream to the Frame API with DER length-prefixed envelopes. It supports `std::net` (synchronous) and `tokio` (asynchronous).

```rust
use std::net::TcpListener;
use tightbeam::{server, compose, Frame};

let listener = TcpListener::bind("127.0.0.1:8080")?;
server! {
	protocol std::net::TcpListener: listener,
	handle: |message: Frame| async move {
		// Echo the frame back
		Ok(Some(message))
	}
}
```

### 8.4 Transport Policies

#### 8.4.1 Concept

Policies control message flow. They do not rewrite the byte transport.

- **`GatePolicy`**: Accept or reject a Frame (rate limits, authentication, session checks)
- **`RestartPolicy`**: Decide retry after failure (linear or exponential backoff)
- **`ReceptorPolicy`**: Filter a decoded application `Message` by type

#### 8.4.2 Specification

**GatePolicy trait:**

```rust
pub trait GatePolicy: Send + Sync {
	fn evaluate(&self, frame: Option<&Frame>, session: &SessionContext) -> TransitStatus;
}
```

Every evaluation receives the connection `SessionContext`. Identity-blind gates ignore it. Identity gates key on it. Cleartext connections, client emit paths, and in-process evaluation pass the default empty context. Accessors on that context all return `None`.

`frame` is `None` for mux streaming and duplex opens that have no request Frame at dispatch. Session and capacity gates still run. Optional integrity gates that need a Frame SHOULD return `Ok` when `frame` is `None`. Auth that needs a signed or intact Frame MUST fail closed. Stream authorization SHOULD use session facts (mutual TLS, peer lists), not Frame-content rules alone.

**ReceptorPolicy trait:**

```rust
pub trait ReceptorPolicy<T: Message>: Send + Sync {
	fn evaluate(&self, message: &T) -> TransitStatus;
}
```

**RestartPolicy trait:**

```rust
pub trait RestartPolicy: Send + Sync {
	/// Evaluate whether to restart after a transport operation.
	///
	/// # Arguments
	/// * `frame` - Boxed frame from the failed operation
	/// * `failure` - The failure reason
	/// * `attempt` - The current attempt number (0-indexed)
	///
	/// # Returns
	/// * `RetryAction` - What action to take (retry with frame, or no retry)
	fn evaluate(
		&self, frame: Box<Frame>,
		failure: &TransportFailure,
		attempt: usize
	) -> RetryAction;
}
```

**TransitStatus** (gRPC `google.rpc.Code` registry):

```rust
// The gRPC canonical status registry (google.rpc.Code)
pub enum TransitStatus {
	Ok = 0,
	Cancelled = 1,
	#[default]
	Unknown = 2,
	InvalidArgument = 3,
	DeadlineExceeded = 4,
	NotFound = 5,
	AlreadyExists = 6,
	PermissionDenied = 7,
	ResourceExhausted = 8,
	FailedPrecondition = 9,
	Aborted = 10,
	OutOfRange = 11,
	Unimplemented = 12,
	Internal = 13,
	Unavailable = 14,
	DataLoss = 15,
	Unauthenticated = 16,
}
```

**RetryAction:**

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum RetryAction {
	/// Retry with the provided frame (same or modified from input)
	Retry(Box<Frame>),
	/// Do not retry, propagate the error
	NoRetry,
}
```

#### 8.4.3 Implementation

**GatePolicy (Frame-level filtering):**

```rust
use tightbeam::policy::{GatePolicy, SessionContext, TransitStatus};

// Accept only messages with specific ID patterns
#[derive(Default)]
struct IdPatternGate;

impl GatePolicy for IdPatternGate {
	fn evaluate(&self, frame: Option<&Frame>, _session: &SessionContext) -> TransitStatus {
		let Some(frame) = frame else {
			return TransitStatus::PermissionDenied;
		};
		if frame.metadata.id.starts_with(b"api-") {
			TransitStatus::Ok
		} else {
			TransitStatus::PermissionDenied
		}
	}
}
```

**GatePolicy (session-identity filtering):**

```rust
use tightbeam::colony::hive::PeerListGate;

// Bar these public keys (SPKI DER) at the door; the gate matches the
// session's mutually-authenticated peer certificate, not frame signers.
let doorman = PeerListGate::deny([banned_spki_der]);

// Or admit only listed keys; sessions without an authenticated peer
// fail closed (Unauthenticated).
let doorman = PeerListGate::allow([member_spki_der]);
```

**ReceptorPolicy (message-level filtering):**

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
			TransitStatus::Ok
		} else {
			TransitStatus::PermissionDenied
		}
	}
}
```

**RestartPolicy (retry strategies):**

```rust
use tightbeam::transport::policy::{RestartLinearBackoff, RestartExponentialBackoff};

// Linear backoff: 1s, 2s, 3s delays
let restart = RestartLinearBackoff::new(3, 1000, 1, None);

// Exponential backoff: 1s, 2s, 4s, 8s delays
let restart = RestartExponentialBackoff::new(4, 1000, None);
```

**`policy!` macro:**

```rust
tightbeam::policy! {
	// Frame-content gate: fail closed when no request frame exists
	// (mux streaming / duplex). Pair with a session gate for stream opens.
	GatePolicy: OnlyApiMessages |frame| {
		let Some(frame) = frame else {
			return TransitStatus::PermissionDenied;
		};
		if frame.metadata.id.starts_with(b"api-") {
			TransitStatus::Ok
		} else {
			TransitStatus::PermissionDenied
		}
	}

	// Session-aware arm: streaming and duplex opens key on peer identity.
	GatePolicy: MutualAuthOnly |_frame, session| {
		if session.peer_certificate().is_some() {
			TransitStatus::Ok
		} else {
			TransitStatus::Unauthenticated
		}
	}

	ReceptorPolicy<RequestMessage>: OnlyPingMessages |message| {
		if message.content == "PING" {
			TransitStatus::Ok
		} else {
			TransitStatus::PermissionDenied
		}
	}

	RestartPolicy: RetryThreeTimes |frame, _failure, attempt| {
		if attempt < 3 {
			RetryAction::Retry(frame)
		} else {
			RetryAction::NoRetry
		}
	}
}
```

**Composing policies:**

```rust
// Client-side with policies
let builder = ClientBuilder::<TokioListener>::builder()
	.with_emitter_gate(IdPatternGate)
	.with_collector_gate(PriorityGate)
	.with_restart(RestartLinearBackoff::new(3, 1000, 1, None))
	.build();

let mut client = builder.connect(addr).await?;
```

### 8.5 Handshake Protocols

#### 8.5.1 Concept: Security Goals and Protocol Selection

Two handshake protocols establish mutual authentication and a session key:

- **CMS-based**: Full PKI with X.509 certificates and [RFC 5652][rfc5652] CMS structures
- **ECIES-based**: Lighter wire form with less CMS nesting

Security goals for both:

- **Mutual authentication**: Each party proves identity with certificates
- **Perfect forward secrecy**: Ephemeral ECDH ([NIST SP 800-56A][nist-800-56a]) protects past sessions if long-term keys leak later
- **Replay protection**: Nonces block replayed handshake messages
- **Downgrade prevention**: The transcript hash covers handshake messages, including profile negotiation ([RFC 9846 §4.1.3][rfc9846-4.1.3])
- **Confidentiality**: HKDF-derived session keys protect later messages

#### 8.5.2 Specification: Handshake Flow and State Management

**Three-phase exchange:**

```
Phase 1: Client -> Server
┌─────────────────────────────────────────────────────────┐
│ ClientHello (ECIES) or KeyExchange (CMS)                │
│ - Client nonce (32 bytes)                               │
│ - Optional SecurityOffer (supported profiles)           │
│ - Ephemeral public key (CMS: in KARI structure)         │
└─────────────────────────────────────────────────────────┘

Phase 2: Server -> Client
┌─────────────────────────────────────────────────────────┐
│ ServerHandshake (ECIES) or ServerFinished (CMS)         │
│ - Server certificate                                    │
│ - Server nonce (32 bytes)                               │
│ - Selected SecurityProfile (if negotiation occurred)    │
│ - Signature over transcript hash                        │
└─────────────────────────────────────────────────────────┘

Phase 3: Client -> Server
┌─────────────────────────────────────────────────────────┐
│ ClientKeyExchange (ECIES) or ClientFinished (CMS)       │
│ - Encrypted session key                                 │
│ - Optional client certificate (mutual auth)             │
│ - Optional client signature (mutual auth)               │
└─────────────────────────────────────────────────────────┘
```

**State machines** (diagram form):

Client:

```
Init -> HelloSent -> KeyExchangeSent -> ServerFinishedReceived -> ClientFinishedSent -> Completed
```

Server:

```
Init -> KeyExchangeReceived -> ServerFinishedSent -> ClientFinishedReceived -> Completed
```

**Transcript hash:**

```
transcript = ClientHello || ServerHandshake || ClientKeyExchange
transcript_hash = SHA3-256(transcript)
```

The transcript hash binds the handshake messages. It blocks reordering, profile downgrade, and undetected man-in-the-middle edits of the transcript.

#### 8.5.3 Implementation: CMS-Based Handshake Protocol

CMS handshake uses [RFC 5652][rfc5652] Cryptographic Message Syntax:

- **`EnvelopedData`**: ECDH, HKDF, and AES key wrap for the session key
- **`SignedData`**: Transcript signatures for authentication
- **`KeyAgreeRecipientInfo` (KARI)**: Ephemeral-static ECDH key agreement

**Mutual authentication flow:**

For mutual authentication, the client includes a certificate and signs the transcript in `ClientKeyExchange`:

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

ECIES (Elliptic Curve Integrated Encryption Scheme) is the lighter handshake path. It encapsulates the session key without nested CMS `EnvelopedData` / `SignedData` containers.

Differences from CMS:

- Raw ECIES encryption instead of nested CMS `EnvelopedData`
- Flatter ASN.1 structures instead of multi-level CMS nesting
- Same security goals: mutual authentication, forward secrecy, replay protection
- Both paths use ASN.1 DER. ECIES avoids [RFC 5652][rfc5652] container complexity

**Mutual authentication flow:**

For mutual authentication, the client includes a certificate and signs the transcript in `ClientKeyExchange`:

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

**ECIES encryption details:**

ECIES combines:

- **ECDH**: Ephemeral-static key agreement for the shared secret
- **KDF**: HKDF-SHA3-256 for encryption and MAC keys from that secret
- **AEAD**: AES-256-GCM for authenticated encryption of the session key
- **Ephemeral keys**: A fresh ephemeral key pair per encryption

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

**Wire format comparison:**

| Feature                | CMS-based                      | ECIES-based                            |
| ---------------------- | ------------------------------ | -------------------------------------- |
| Envelope structure     | RFC 5652 nested structures     | Simplified ASN.1 structures            |
| Key agreement          | KARI (`KeyAgreeRecipientInfo`) | Raw ECIES with DER encoding            |
| Session key encryption | `EnvelopedData` + AES-KW       | ECIES + AES-GCM                        |
| Signatures             | `SignedData` structure         | Raw signatures in ASN.1                |
| Size overhead          | about 400-600 bytes            | about 200-300 bytes                    |
| Parsing complexity     | Multi-level ASN.1 nesting      | Flat ASN.1 structures                  |
| Standards              | RFC 5652, [RFC 5753][rfc5753]  | [SECG SEC 1][secg-sec1] + custom ASN.1 |

**Performance characteristics** (relative to CMS on the same curves and algorithms):

- Handshake time: about 20-30% faster (less parsing)
- Memory use: about 30-40% lower (fewer ASN.1 intermediate structures)
- Wire size: about 40-50% smaller
- CPU for crypto primitives: similar

**Security equivalence:**

Both protocols target the same properties: mutual authentication, forward secrecy via ephemeral ECDH, replay protection via nonces, transcript integrity via signatures, and confidentiality via AEAD.

#### 8.5.5 Security Profile Negotiation

CMS and ECIES handshakes both negotiate algorithms through `SecurityProfile` descriptors.

**Negotiation process:**

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

**Profile validation:**

- The server MUST select a profile from the client's offer.
- The server MUST NOT select unsupported algorithms.
- The client MUST verify that the selected profile was in its offer.
- The transcript signature MUST cover the negotiation so a peer cannot downgrade algorithms unnoticed.

**Transport capability negotiation:**

CMS and ECIES handshakes MAY also negotiate multiplexing with `TransportOffer` / `TransportAccept`. Those structures travel in the opening handshake messages. They bind into the same transcript as security-profile negotiation. A peer cannot silently enable or disable multiplexing after authentication.

**Transport negotiation process:**

```
Client                              Server
  │                                   │
  │─── TransportOffer ──────────────► │
  │    mux: true                      │
  │    max_peer_initiated_streams: N  │  ◄─ Server may Accept only if
  │                                   │     it also offered mux locally
  │                                   │
  │ ◄── TransportAccept ────────────  │
  │     mux: true                     │
  │     max_peer_initiated_streams: M │
  │                                   │
  ├═══════════════════════════════════┤
  │ MuxSettings (directional):        │
  │   client local_initiated_cap = M  │
  │   client peer_initiated_cap  = N  │
  │   (server view is the reverse)    │
  └═══════════════════════════════════┘
```

**Transport validation:**

- Each side advertises how many streams its peer MAY initiate at once (`max_peer_initiated_streams`), matching [RFC 9113 §5.1.2][rfc9113-5.1.2] directional semantics.
- Multiplexing MUST activate only when both sides offered it. If either side omits the offer, the connection stays single-flight.
- Caps are directional. There is no symmetric min-collapse of the two advertisements.
- Both endpoints MUST clamp each advertised cap to `MAX_MUX_STREAM_CAP` (1024) when deriving `MuxSettings`.
- A peer that accepts multiplexing without a matching local offer MUST fail closed (`UnsolicitedTransportAccept`).
- Offer and accept also carry flow-control values (`chunk_payload_size`, `credit_unit`, `initial_stream_credit`) with the same directional rule: the sender advertises what it will receive. Accept fixes `credit_unit` for both directions.
- The offer MAY request per-direction session budgets (`requested_budgets`) and MAY attach an opaque `authorization` token. Accept answers with `granted_budgets`. Grants are opt-in on the server. Without a local budget ceiling or an authorizer verdict, nothing is granted. A server-side `TransportAuthorizer` MAY refuse the session (`AuthorizationRefused`). See [§8.6.2](#862-specification-stream-rules-envelopes-and-runtime).
- The client MUST fail closed on every grant that diverges from its request: a grant without a request (`UnsolicitedTransportAccept`), a grant beyond `MAX_MUX_SESSION_BUDGET` (`BudgetBeyondCap`), a grant beyond the request (`BudgetBeyondRequest`), or a grant withheld against a request (`BudgetGrantWithheld`). Grants at or below the request activate metering and the receipt exchange.

Stream identifier rules, envelope types, and runtime assembly are in [§8.6 Multiplexing](#86-multiplexing).

#### 8.5.6 Negotiation and Failure Modes

**Profile negotiation:**

```rust
// Client offers supported profiles
let security_offer = SecurityOffer {
	profiles: vec![
		SecurityProfileDesc { /* SHA3-256 + AES-256-GCM + secp256k1 */ },
		SecurityProfileDesc { /* SHA-256 + AES-128-GCM + P-256 */ },
	],
};

// Server selects first mutually supported profile
let security_accept = SecurityAccept {
	profile: SecurityProfileDesc { /* chosen profile */ },
};
```

**Failure modes:**

| Error                         | Cause                                              | Recovery            |
| ----------------------------- | -------------------------------------------------- | ------------------- |
| `CertificateValidationFailed` | Invalid certificate chain                          | Reject connection   |
| `TranscriptMismatch`          | MITM or protocol error                             | Abort handshake     |
| `NonceReplay`                 | Duplicate nonce detected                           | Reject message      |
| `UnsupportedProfile`          | No mutual profile                                  | Negotiate or reject |
| `UnsolicitedTransportAccept`  | Peer accepted a transport capability never offered | Abort handshake     |
| `AuthorizationRefused`        | Server's `TransportAuthorizer` refused the session | Abort handshake     |
| `InvalidState`                | Out-of-order message                               | Reset state machine |
| `DecryptionFailed`            | Wrong key or corrupted data                        | Abort handshake     |

#### 8.5.7 Threat-to-Control Mapping

| Threat                     | Control                                     | Implementation                                                                                                                                                                                                    |
| -------------------------- | ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Replay Attack**          | 32-byte nonce + replay set                  | Server maintains set of seen nonces. Rejects duplicates                                                                                                                                                           |
| **Downgrade Attack**       | Profile list in signed transcript           | Transcript hash covers SecurityOffer/SecurityAccept                                                                                                                                                               |
| **Multiplexing Downgrade** | Transport offer/accept in signed transcript | Transcript hash covers TransportOffer/TransportAccept. Unsolicited accept fails closed                                                                                                                            |
| **MITM**                   | Transcript signatures                       | Both parties sign transcript_hash. Verified against certificates                                                                                                                                                  |
| **Confidentiality**        | ECDH + HKDF derived AEAD key                | Session key never transmitted. Derived from ECDH shared secret                                                                                                                                                    |
| **Forward Secrecy**        | Ephemeral client keys                       | New ephemeral key per handshake. Compromise does not affect past sessions                                                                                                                                         |
| **DoS**                    | 16 KiB handshake size cap                   | Reject oversized handshake messages before processing                                                                                                                                                             |
| **Stream Cap Inflation**   | Clamp + ResourceExhausted                   | Caps clamped to `MAX_MUX_STREAM_CAP`. Local exhaustion returns `ResourceExhausted`                                                                                                                                |
| **Reassembly Exhaustion**  | Chunk + credit + cap clamps                 | Chunk size clamped to `MIN..=MAX_MUX_CHUNK_SIZE`, stream credit to `MAX_MUX_STREAM_CREDIT`. Per-stream reassembly memory bounded by granted credit and concurrent partial streams by the advertised cap (CWE-770) |
| **Flow-Control Overrun**   | Receiver-side duplicate accounting          | Oversize chunks, credit overruns, and session-budget overspends each answered with GoAway(`ProtocolError`)                                                                                                        |
| **Rapid Reset**            | Cancel budget + GoAway                      | Peer cancels that abort in-flight handlers draw on `DEFAULT_MUX_CANCEL_BUDGET`. Exhaustion sends GoAway(`EnhanceYourCalm`) (CVE-2023-44487 / [RFC 9113 §7][rfc9113-7])                                            |
| **Certificate Forgery**    | X.509 chain validation                      | Verify against a configured root of trust (application responsibility)                                                                                                                                            |
| **Nonce Reuse**            | Monotonic counter + XOR                     | Per-message nonce derived from seed XOR counter                                                                                                                                                                   |

### 8.6 Multiplexing

#### 8.6.1 Concept: Concurrent Streams Over One Connection

A multiplexer (mux) runs concurrent request/response streams on one connection. The model follows [RFC 9113][rfc9113] HTTP/2 streams. Without mux, each `emit`/`collect` pair is single-flight. A slow peer response then stalls later requests on that connection. With mux, independent streams interleave on the wire. One delayed response does not block siblings.

Mux is an application-layer stream router over the envelope transport. It does not replace TCP or the handshake. It sits above split envelope halves after session establishment.

> Requires the `transport-multiplex` feature.

**Design goals:**

- **Concurrency**: Many outstanding request/response pairs per connection without head-of-line blocking
- **Correlation**: Stream identifiers travel inside the `TransportEnvelope` payload
- **Fair limits**: Directional concurrency caps are negotiated per connection and clamped
- **Fair sharing**: Mandatory chunking bounds record size. Per-stream credit windows bound reassembly memory. One stream cannot monopolize the shared writer
- **Metered sessions**: Optional handshake-granted per-direction budgets bound encrypted-session volume before renewal
- **Accountable sessions**: Budget-bearing sessions produce a dual-signed `SessionReceipt`. The receipt binds transcript, budgets, and settlement terms under both identities. A third party verifies it from the certificates alone
- **Epoch renewal**: Budget-bearing sessions renew keys, counters, budgets, and receipts in band before the cipher record limit ([RFC 9846 §5.5][rfc9846-5.5])
- **Graceful drain**: `GoAway` completes in-flight streams at or below a threshold and rejects newer ones
- **Abuse resistance**: Rapid reset (CVE-2023-44487) exhausts a cancel budget and draws GoAway(`EnhanceYourCalm`)

**Assembly modes:**

| Mode      | Session                                                | Settings source                                                 | Split API                | Security properties                                                 |
| --------- | ------------------------------------------------------ | --------------------------------------------------------------- | ------------------------ | ------------------------------------------------------------------- |
| Encrypted | CMS or ECIES handshake with matching `TransportOffer`s | `negotiated_mux()`                                              | `into_split()`           | Handshake authentication + AEAD as configured for the session       |
| Cleartext | None (handshake MUST NOT have started)                 | Out-of-band `MuxSettings::symmetric(cap)`. Both ends MUST agree | `into_split_cleartext()` | NONE: no confidentiality, integrity, replay, or deletion protection |

Cleartext mux is for controlled environments and tests. It MUST NOT replace an encrypted session on a hostile network.

#### 8.6.2 Specification: Stream Rules, Envelopes, and Runtime

**Stream identifiers** ([RFC 9113 §5.1.1][rfc9113-5.1.1]/[§5.1.2][rfc9113-5.1.2]):

Stream IDs identify one logical stream on one physical connection:

- Client-initiated streams use odd IDs. Server-initiated streams use even IDs.
- Stream ID 0 is reserved and MUST NOT be allocated.
- Each endpoint MUST allocate locally-initiated IDs strictly monotonically.
- `MuxRole::Client` is the handshake initiator (odd IDs). `MuxRole::Server` is the responder (even IDs). The role passed to `MuxTransport::new` MUST match the endpoint's connection role.

**Stream states:**

```
Idle -> Open -> HalfClosedLocal / HalfClosedRemote -> Closed
```

Streams in `Open`, `HalfClosedLocal`, or `HalfClosedRemote` count toward the peer-advertised concurrency cap. `Idle` and `Closed` do not ([RFC 9113 §5.1.2][rfc9113-5.1.2]).

**Concurrency caps:**

`MuxSettings` carries two directional values:

- `local_initiated_cap`: how many streams this endpoint may initiate (the value the peer advertised)
- `peer_initiated_cap`: how many streams the peer may initiate (the value this endpoint advertised)

Each endpoint MUST enforce the cap it advertised against peer-initiated streams. It MUST respect the peer-advertised cap when allocating locally. Exhausting the local-initiated cap MUST return `ResourceExhausted` without allocating a stream. Advertised caps MUST be clamped to `MAX_MUX_STREAM_CAP` (1024) when deriving settings. An absurd wire advertisement MUST NOT inflate bookkeeping bounds (CWE-770).

**Envelope types** (`TransportEnvelope` context tag 4 nests the `MuxEnvelope` CHOICE, inner context tags 0-10):

| Variant         | Role                                                                                                    |
| --------------- | ------------------------------------------------------------------------------------------------------- |
| `Open`          | Open a stream and carry its first payload chunk inline (`stream_id`, `last`, `payload`)                 |
| `Data`          | Continuation chunk on an open stream, either direction (`stream_id`, `last`, `payload`)                 |
| `End`           | Responder trailer: `status` plus the final payload chunk inline                                         |
| `Credit`        | Grant absolute cumulative chunk credit on a stream (QUIC MAX_STREAM_DATA, [RFC 9000 §4.1][rfc9000-4.1]) |
| `Cancel`        | Abort a single in-flight stream without tearing down the connection                                     |
| `GoAway`        | Connection-level drain: streams at or below `last_stream_id` complete. Newer streams are rejected       |
| `Ping`          | Liveness probe and ack (`opaque`, `ack`), answered without touching the handler                         |
| `RekeyRequest`  | Client opens an epoch renewal: fresh nonce ([RFC 9846 §4.7.3][rfc9846-4.7.3] update-request)            |
| `RekeyResponse` | Server answers: its nonce plus the server-signed epoch receipt                                          |
| `RekeyAck`      | Client accepts: its countersignature. Marks the client-to-server key switch                             |
| `RekeyDone`     | Server confirms settlement. Marks the server-to-client key switch                                       |

**Stream grammar** (unified: a unary request is a degenerate stream, [RFC 9113 §8.1][rfc9113-8.1]):

```
initiator:  Open(last?)   Data(...)*  Data(last)
responder:  Data(...)*    End(status, payload?)
either:     Cancel(code)  Credit(limit)
```

**Chunking** (mandatory, no opt-out): Every message segments at the peer-advertised `chunk_payload_size` (1-64 KiB, default 16 KiB, [RFC 9113 §4.2][rfc9113-4.2]). Reassembly follows arrival order. The ordered AEAD channel already proves order and completeness. Chunks carry no sequence numbers. An oversize chunk is a protocol violation: GoAway(`ProtocolError`). A unary message still travels in one record.

**Stream credit** (per-stream flow control, QUIC MAX_STREAM_DATA-like, [RFC 9000 §4.1][rfc9000-4.1]): Receivers grant inbound streams a chunk allowance (default 64). They replenish it with `Credit` grants. A sender out of credit parks. Control envelopes bypass the gate. The reader never blocks on the writer, so saturated endpoints cannot deadlock ([RFC 9113 §5.2.2][rfc9113-5.2.2]). Credit and concurrency-cap overruns are protocol violations. Those rules bound reassembly memory (CWE-770). Grant policy is pluggable via `CreditGrantor`.

**Session budgets** (optional metering, encrypted sessions only): The handshake MAY grant each direction a spendable volume. The grant is transcript-bound so peers cannot forge it. Data chunks debit `ceil(payload_len / credit_unit)`. Control is free. Budgets never grow within an epoch. Exhaustion fails the emit fast (`BudgetExhausted`) and drains the connection gracefully. Both sides run the accounting. An inbound overspend is a protocol violation. No budgets, and always under cleartext mux, means unmetered.

**Session authorization** (server hook between offer and accept): The offer MAY carry an opaque `authorization` token. tightbeam never parses that token. A `TransportAuthorizer` decides the budgets to grant. It MAY attach a settlement challenge. It MAY refuse the session (`AuthorizationRefused { code }`). The hook fires before authentication. Keep it cheap and rate-limit it upstream.

**Session receipts** (budget-bearing sessions only): Every metered session produces a CMS `SignedData` artifact ([RFC 5652 §5][rfc5652-5]). Its `eContent` is the `SessionReceipt` body. That body binds the handshake transcript (as a self-describing `DigestInfo`, [RFC 8017 §9.2][rfc8017-9.2]), budgets, and settlement terms. Each peer contributes one role-tagged `SignerInfo`. A third party that holds the two certificates verifies the agreement from the stored artifact alone.

- The server signs first. The client validates against the negotiated session. The client answers the challenge via its `ReceiptApprover` and countersigns. Its `SignerInfo` signed attributes ([RFC 5652 §11][rfc5652-11]) bind the answer and the role. Neither answer nor role can be swapped or spliced (CWE-347).
- The client's `SignerInfo` travels only encrypted to the server (inside the ECIES key-exchange payload, or an `EnvelopedData` [RFC 5652 §6][rfc5652-6] attribute on the CMS Finished). The settlement answer is a bearer secret. It MUST NOT travel on the cleartext wire.
- The server's `TransportAuthorizer::settle` accepts or refuses the answer. The session MUST NOT activate before it accepts. Every step fails closed. Budgets REQUIRE mutual authentication.
- A server-side `SessionObserver` records every concluded outcome, including refused and forged acknowledgements. It never vetoes.
- Both endpoints retain the completed artifact (`session_receipt()`). The settlement answer is application truth: never parsed, never price-checked, never persisted. The receipt makes the agreement non-repudiable. It does not prove the answer is correct.

**Epoch renewal (rekey)** (budget-bearing sessions only): Renew the AEAD epoch in band instead of draining at a watermark. The client opens `RekeyRequest` / `RekeyResponse` / `RekeyAck`. The server finishes with `RekeyDone`. Renewal starts when send budget hits the drain reserve, or when send records approach the rekey limit. Endpoints MUST rekey before that limit ([RFC 9846 §5.5][rfc9846-5.5]), with `DEFAULT_REKEY_RENEWAL_ALLOWANCE` slack.

- Fresh keys derive via `kdf_chain` from the retained epoch secret and both exchanged nonces. The prior secret is zeroized once its successor exists ([RFC 9846 §7.2][rfc9846-7.2]).
- Each direction switches keys at its marker on the ordered AEAD channel ([RFC 9846 §4.7.3][rfc9846-4.7.3] per-direction precedent). Client-to-server switches at the `RekeyAck` record. Server-to-client switches at the `RekeyDone` record. Record counters reset only with the fresh keys ([NIST SP 800-38D][nist-800-38d] §8.2.1).
- Budgets reset to the negotiated terms at `RekeyDone`. The epoch receipt MUST carry the same credit terms as the initial one (credit-match invariant, absolute-limits [RFC 9000 §4.1][rfc9000-4.1]-like). A renewal never renegotiates.
- Every epoch produces a fresh dual-signed receipt chained to its predecessor by transcript hash. A third party verifies it from the original certificates. `session_receipt()` rotates to the current epoch's artifact.
- The authorizer MAY attach a settlement challenge to the renewal (`TransportAuthorizer::challenge_renewal`). The client's `ReceiptApprover` answers inside the encrypted `RekeyAck`. `settle` accepts or refuses, as at the handshake.
- Failures fail closed into a graceful drain. Settlement or approval refusal drains with the refusal's code. A stalled exchange drains at the renewal deadline (default `DEFAULT_REKEY_DEADLINE_SECS`, override via `MuxTransport::with_renewal_deadline`). A premature (below the minimum-spend floor) or duplicate `RekeyRequest` is a protocol violation: GoAway(`ProtocolError`).
- A renewal still in flight at the drain threshold parks data chunks on the hard floor. Control and the exchange legs keep the remaining records. Parked chunks resume on the fresh cipher.
- Sessions without rekey materials (receiptless or cleartext) drain via GoAway near the watermark. The caller re-establishes.

**Reason code space** (open u32, HTTP/2 error-code and QUIC application-close precedent: [RFC 9113 §7][rfc9113-7], [RFC 9000 §20.2][rfc9000-20.2]): Codes below `MUX_APPLICATION_CODE_FLOOR` (0x1000) are reserved for the tightbeam protocol. Applications own the rest. Unknown codes decode to `Application(code)` and MUST NOT kill the connection.

**Cancel reasons:**

| Reason              | Code    | Meaning                                               |
| ------------------- | ------- | ----------------------------------------------------- |
| `Cancelled`         | 0       | Requester is no longer interested                     |
| `Timeout`           | 1       | Per-stream deadline elapsed before a response arrived |
| `Rejected`          | 2       | Responder refused to process the stream               |
| `Application(code)` | 0x1000+ | Application-defined                                   |

**GoAway reasons:**

| Reason              | Code    | Meaning                                                                  |
| ------------------- | ------- | ------------------------------------------------------------------------ |
| `Shutdown`          | 0       | Orderly shutdown initiated by the sender                                 |
| `ProtocolError`     | 1       | Peer violated multiplexing rules                                         |
| `EnhanceYourCalm`   | 2       | Peer exceeded the cancel budget (RFC 9113 §7 / CVE-2023-44487 hardening) |
| `BudgetExhausted`   | 3       | Sender's outbound session budget reached the drain reserve               |
| `SettlementFailed`  | 4       | Settlement instrument revoked or failed (reserved for session receipts)  |
| `Application(code)` | 0x1000+ | Application-defined                                                      |

**Request/response flow:**

```
Client (MuxHandle)                         Server (MuxResponder)
  │                                              │
  │── Open { stream_id=1, last, payload } ─────► │
  │                                              │── dispatch handler
  │◄─ End { stream_id=1, status, payload } ───── │
  │                                              │
  │── Open { stream_id=3, last, payload } ─────► │  ◄─ may interleave
  │── Open { stream_id=5, last, payload } ─────► │
  │◄─ End { stream_id=5, ... } ───────────────── │
  │◄─ End { stream_id=3, ... } ───────────────── │
```

**Lifecycle rules:**

- Dropping an in-flight `emit_on_stream` future MUST cancel the stream: remove the pending entry, free the cap slot, and best-effort send `MuxCancel`.
- Per-stream timeouts compose externally. Wrap the emit future in the caller's timer. Expiry cancels via the drop guard.
- A non-mux peer MUST reject muxed envelopes as invalid.
- A mux peer that receives a non-mux application envelope (plain `Request`/`Response` where muxed traffic is required) MUST send GoAway(`ProtocolError`) and fail pending streams.
- Cancels that abort in-flight handlers draw on a per-connection budget (`DEFAULT_MUX_CANCEL_BUDGET` = 1024). Exhaustion MUST end the connection with GoAway(`EnhanceYourCalm`). Override via `MuxTransport::with_cancel_budget`.
- Near the AEAD send-record limit ([RFC 9846 §5.5][rfc9846-5.5]), a rekey-capable session opens an in-band epoch renewal (see Epoch renewal above). Otherwise the writer MUST begin a graceful drain via GoAway while `2 * (local_cap + peer_cap) + 1` records plus every registered-but-unsent chunk remain. Queued chunked responses, cancels, and the GoAway itself must still fit under the cipher limit.

**Runtime architecture:**

```
┌─────────────────────────────────────────────────────────────┐
│ Application                                                 │
│   MuxHandle.emit_on_stream / close_stream / shutdown        │
│   MuxResponder.serve(handler)                               │
└───────────────┬─────────────────────────────┬───────────────┘
                │                             │
                ▼                             ▼
        ┌───────────────┐             ┌───────────────┐
        │ Outbound queue│◄────────────│ Inbound queue │
        └───────┬───────┘             └───────▲───────┘
                │                             │
                ▼                             │
        ┌───────────────┐             ┌───────┴───────┐
        │MuxWriterDriver│             │MuxReaderDriver│
        │ (serialize)   │             │ (route)       │
        └───────┬───────┘             └───────▲───────┘
                │                             │
                ▼                             │
        EnvelopeSink                  EnvelopeSource
        (encrypt or cleartext write)  (decrypt or cleartext read)
```

- **MuxWriterDriver**: Single serialization point for the connection. It drains the outbound queue and writes each envelope through the send half. Spawn `drive()` on the caller's executor.
- **MuxReaderDriver**: Reads envelopes from the receive half. It routes responses to pending stream slots and forwards peer-initiated requests to the responder. Unknown response IDs are discarded. Cancel/response races are benign.
- **MuxHandle**: Cloneable client handle. It allocates stream IDs, registers pending slots, and awaits correlated responses.
- **MuxResponder**: Serves peer-initiated streams with a caller-supplied handler. Handlers for distinct streams run concurrently. Cap exhaustion answers with `TransitStatus::ResourceExhausted`.

**MultiplexedProtocol trait:**

```rust
pub trait MultiplexedProtocol {
	/// Negotiated cap on concurrent locally-initiated streams
	fn max_concurrent_streams(&self) -> u32;

	/// Allocate a stream, send `frame`, await the correlated response
	fn emit_on_stream(
		&self,
		frame: &Frame,
	) -> impl Future<Output = TransportResult<Option<Frame>>> + MaybeSend;

	/// Best-effort cancel of a locally-initiated in-flight stream
	fn close_stream(&self, stream_id: StreamId);
}
```

#### 8.6.3 Implementation: Assembling MuxTransport

After the transport is ready (handshake complete for encrypted mux, or a never-handshaken socket for cleartext), split it into exclusive read/write halves. Build `MuxTransport` with the endpoint role and settings. Decompose into four parts the application MUST keep running: handle, reader driver, writer driver, and responder.

**Encrypted path:**

Both sides MUST configure multiplexing before the handshake so the offer is transcript-bound:

```
Client Side - Offering Mux:
┌──────────────────────────────────────────────────────────┐
│ 1. transport = transport.with_mux_offer(Some(            │
│        TransportOffer::mux(max_peer_initiated_streams)   │
│    ))                                                    │
│ 2. Perform CMS or ECIES handshake                        │
│ 3. settings = transport.negotiated_mux()  // Some(...)   │
│ 4. (reader, writer) = transport.into_split()             │
│ 5. MuxTransport::new(reader, writer, MuxRole::Client,    │
│                      settings)                           │
└──────────────────────────────────────────────────────────┘
```

```rust
use tightbeam::policy::TransitStatus;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::multiplex::{MuxRole, MuxTransport};
use tightbeam::transport::ResponsePackage;
use tightbeam::Frame;

transport = transport.with_mux_offer(Some(TransportOffer::mux(32)));
// ... perform CMS or ECIES handshake ...

let settings = transport.negotiated_mux().expect("mux negotiated");
let (reader, writer) = transport.into_split()?;
let mux = MuxTransport::new(reader, writer, MuxRole::Client, settings);
let (handle, reader_drv, writer_drv, responder) = mux.into_parts();

tokio::spawn(reader_drv.drive());
tokio::spawn(writer_drv.drive());
tokio::spawn(async move {
	responder
		.serve(|frame| async move {
			ResponsePackage::new(TransitStatus::Ok, Some(Frame::clone(&frame)))
		})
		.await
});

let response = handle.emit_on_stream(&frame).await?;
handle.shutdown().await?;
```

`MuxHandle::shutdown` sends GoAway(`Shutdown`). It halts new stream allocation, waits for the pending table to drain, then closes the writer driver. A drain deadline composes by wrapping `shutdown()` in the caller's timer. Per-stream timeouts compose the same way around `emit_on_stream`. Override the cancel budget with `MuxTransport::with_cancel_budget` when the default (`DEFAULT_MUX_CANCEL_BUDGET`) is wrong for the deployment.

**Cleartext path:**

Use cleartext only when both endpoints intentionally forgo the handshake. Settings are not negotiated. Divergent caps cause asymmetric refuse/accept behavior. `into_split_cleartext` requires a never-handshaken transport with no server identity or key manager configured.

```rust
use tightbeam::transport::handshake::negotiation::MuxSettings;
use tightbeam::transport::multiplex::{MuxRole, MuxTransport};

// Both ends MUST share this value. Cleartext mux has no negotiation.
let settings = MuxSettings::symmetric(32);
let (reader, writer) = transport.into_split_cleartext()?;
let mux = MuxTransport::new(reader, writer, MuxRole::Client, settings);
let (handle, reader_drv, writer_drv, responder) = mux.into_parts();
```

**Server role:**

The accepting endpoint uses `MuxRole::Server` with the same assembly sequence. Either role may call `emit_on_stream` (server-initiated streams use even IDs). Either role may `serve` peer-initiated requests.

#### 8.6.4 Testing

Test multiplexed services with `environment ServiceClient`. The `server:` closure starts a `server!` accept loop advertising `with_mux_offer`. The `client:` closure drives a mux-offering `ConnectionPool` against the bound address. Peers that decline the offer fall back to single-flight. The same scenario shape covers both paths.

```rust
tb_assert_spec! {
	pub EchoOverMuxSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(echo_over_mux, exactly!(1), equals!(true))
		]
	}
}

tb_scenario! {
	name: echo_over_mux,
	spec: EchoOverMuxSpec,
	environment ServiceClient {
		context: ServerMaterials::generate(),
		server: |env| async move {
			let (listener, addr) = bind_listener(&env.context).await?;
			let handle = server! {
				protocol TokioListener: listener,
				policies: { with_mux_offer: [Some(TransportOffer::mux(8))] },
				handle: move |frame: Frame| async move { Ok(Some(frame)) }
			};

			Ok((handle, addr))
		},
		client: |ClientEnv { trace, context: materials, addr }| async move {
			let pool = mux_pool(&materials, Some(TransportOffer::mux(8)))?;
			let mut lease = pool.connect(addr).await?;

			let frame = create_v0_tightbeam(Some("ping"), None);
			let reply = lease.emit(frame.clone(), None).await?;

			trace.event_with(EchoOverMuxSpec::echo_over_mux, &[], reply == Some(frame))?;

			Ok(())
		}
	}
}
```

#### 8.6.5 Serving and Pooling

`server!` and `ConnectionPool` assemble and drive the mux plane internally. One handler and one `emit` call serve both multiplexed and single-flight peers. Manual assembly remains available for custom setups.

**Serving with `server!`:**

The async accept loop branches per connection after the handshake. A peer that negotiated multiplexing is served through the mux plane (split halves, drivers, concurrent handlers behind the collector gate). The server advertises multiplexing per accepted transport through the policy list:

```rust
let server_handle = server! {
	protocol TokioListener: listener,
	policies: { with_mux_offer: [Some(TransportOffer::mux(32))] },
	handle: move |frame: Frame| async move { Ok(Some(frame)) }
};
```

- `with_mux_offer` takes an `Option<TransportOffer>`. `None` advertises nothing.
- `servlet!`, `hive!`, and `cluster!` servers inherit the branch through their `server!` delegation. `HiveConfig::mux_offer` and `ClusterConfig::pool_config.mux_offer` carry the advertisement to their listeners and pools.
- The sync (`std`-thread) serving path never multiplexes. Mux drivers need an async executor.
- Serving mux requires `transport-multiplex` (plus `x509`, `tokio`, `transport-policy`). A server built without it never advertises and keeps serving single-flight peers.

```rust
let server_handle = server! {
	protocol TokioListener: listener,
	policies: { with_mux_offer: [Some(offer)], with_transport_authorizer: [authorizer] },
	handle: move |frame: Frame, session: SessionContext| async move {
		let certificate = session.peer_certificate();  // mutual-auth client identity
		let receipt = session.session_receipt();       // dual-signed budget receipt
		Ok(Some(frame))
	}
};
```

**Pooling with `PoolConfig::mux_offer`:**

```rust
let pool = Arc::new(ConnectionPool::<TokioListener>::builder()
	.with_config(PoolConfig { mux_offer: Some(TransportOffer::mux(32)), ..Default::default() })
	.with_trust_store(trust_store)
	.build());

let mut client = pool.connect(server_addr).await?;
let response = client.emit(frame, None).await?;
```

With an offer configured, `connect` shares one multiplexed connection per destination. Every caller leases a clone of the same `MuxHandle`. `emit` opens a fresh stream. `PooledClient::conn()` (the exclusive-connection accessor) answers `ResourceExhausted` on a mux lease. `emit` is the transport-agnostic call.

**Metered pooled sessions** (budgets on the offer, settlement hooks on the pool):

```rust
let pool = Arc::new(ConnectionPool::<TokioListener>::builder()
	.with_config(PoolConfig { mux_offer: Some(offer.with_budgets(budgets)), ..Default::default() })
	.with_trust_store(trust_store)
	.with_client_identity(client_cert, client_key)?  // budgets REQUIRE mutual auth
	.with_receipt_approver(approver)                 // answers settlement challenges
	.build());

let lease = pool.connect(server_addr).await?;
let receipt = lease.session_receipt();  // Option<Arc<StoredReceipt>>
```

- `ConnectionPoolBuilder::with_receipt_approver` forwards the approver to every dialed transport (handshake and epoch renewal). Without one, pooled clients fail closed on challenge-bearing receipts.
- `PooledClient::session_receipt()` exposes the connection dual-signed receipt shared across leases. Epoch renewal rotates that receipt in place. Exclusive leases and receiptless sessions return `None`.
- Size invoices with the public watermark math on `MuxSettings`. `usable_send_budget()` returns credits spendable on application data before the budget watermark opens an in-band renewal. That value is `send_budget` minus `send_budget_reserve()` (credits reserved so owed traffic can flush during a drain).

**Fallback semantics** (automatic, per connection):

| Client pool     | Server      | Result                                        |
| --------------- | ----------- | --------------------------------------------- |
| `mux_offer` set | mux-serving | One shared mux connection, concurrent streams |
| `mux_offer` set | no offer    | Exclusive lease, unchanged behavior           |
| No offer        | mux-serving | Exclusive lease, unchanged behavior           |
| No offer        | no offer    | Exclusive lease, unchanged behavior           |

**Mux connection lifecycle in the pool:**

- Stream-cap exhaustion (`ResourceExhausted`): `emit` opens an additional mux connection to the same destination (bounded by `max_connections`) and retries there once.
- `ConnectionClosed`, or `Draining` from a rekey GoAway: the entry is evicted and the failure is reported. The next `connect` re-establishes with fresh keys.
- Dead entries (driver ended) are pruned on the next `connect`. Multiple live entries round-robin.

### 8.7 Connection Pooling

`ConnectionPool` reuses connections across requests. Configure the pool once with `.builder()`. Call `.connect()` to retrieve a connection.

**Example:**

```rust
// Create shared pool with configuration (once per application)
let pool = Arc::new(ConnectionPool::<TokioListener>::builder()
	.with_config(PoolConfig { max_connections: 3, ..Default::default() })
	.with_trust_store(trust_store)
	.with_client_identity(CLIENT_CERT, CLIENT_KEY.to_provider::<Secp256k1>()?)?
	.with_timeout(Duration::from_millis(5000))
	.build());

// Get connection from pool
let mut client = pool.connect(server_addr).await?;

client.emit(frame, None).await?;
// Connection automatically returned to pool on drop
```

**Configuration:**

- `PoolConfig::max_connections`: Max connections per destination (default: 64)
- `PoolConfig::idle_timeout`: Optional connection expiration (default: None)
- `PoolConfig::mux_offer`: Optional multiplexing advertisement. See [§8.6.5](#865-serving-and-pooling) (default: None)

### 8.8 Audit

The tightbeam transport layer and handshake protocols have not yet been independently audited. Help in this area is welcome.

#### 8.8.1 Audit Trail Deployment Requirements

Access and session verdicts (`GATE_ACCEPT`/`GATE_REJECT` with the refusing status and the peer SPKI hash, `SESSION_CERT_REJECTED`, receipt events) are recorded only when the deployment opts in. Deployments with audit obligations (for example ISO 27001 A.8.15, NIST 800-53 AU-2) MUST:

1. Enable the `instrument` feature and attach a `TraceCollector` to every transport that terminates connections (`with_trace`).
2. Enable `enable_payloads` in the instrumentation configuration if peer identity (SPKI SHA3-256) must appear on gate verdicts.
3. Provide a durable `EventSink`. The default sink is a bounded in-memory buffer. It drops the oldest events under pressure. Sequence-number gaps in exported evidence reveal where truncation occurred.

Event timestamps are nanoseconds since collector construction. Once per collector, `TRACE_CLOCK_ORIGIN` records that construction time as Unix-epoch nanoseconds. Offline tools can map relative timestamps to absolute times.

## 9. Network Theory

### 9.1 Network Architecture

Colony networks combine:

- Egress and ingress policy management
- Retry and egress client policy
- Service orchestration via Colony Monodomy and Polydomy patterns
- Peer federation and colony gossip between gateways (see [§9.3.4](#934-c-clusters))

### 9.2 Efficient Exchange-Interconnect-Compute

Efficient Exchange-Interconnect-Compute (EEIC) is a software paradigm inspired by the entomological world. Threads and tunnels are the base of processing and communication. EEIC builds from those layers across any transmission protocol:

- thread-thread
- thread-protocol-thread

### 9.3 Components

EEIC has four main components:

- [Workers](#931-e-workers) - Efficient processing units
- [Servlets](#932-e-servlets) - Exchange endpoints
- [Hives](#933-i-hives) - Interconnected infrastructure
- [Clusters](#934-c-clusters) - Compute orchestration

Think of workers as ants, servlets as ant hills, and clusters as ant colonies. Insects have specific functions with which they process organic matter using local information. These functions are often simple, but when combined in large numbers, they can perform complex tasks. The efficiency of each unit is attributed to their fungible nature--how well it can accomplish its singular task.

#### 9.3.1 E: Workers

Workers are the smallest unit of computation in the EEIC--the "ants" that do the actual work. Most business logic does not need network context. A function that doubles a number does not care whether the input came from TCP, UDP, or an in-memory channel. Isolating that logic into workers gives:

- **Parallelism**: Multiple workers can process messages concurrently
- **Fault Isolation**: A failing worker does not crash the servlet
- **Testability**: Workers can be tested without network setup
- **Reusability**: The same worker can serve multiple servlets

##### Design Constraints

Workers are intentionally constrained:

1. **Single-threaded**: Each worker processes one message at a time
2. **Message-only**: Workers receive decoded messages, not raw Frames
3. **Stateless between messages**: Configuration is fixed at creation time

These constraints enable the parallelism and fault isolation that make EEIC effective. Workers do not coordinate with each other--they just transform input to output.

> Note: Do not work around the Frame limitation by stuffing a Frame into a message parameter. Handle Frame concerns at the servlet boundary instead.

##### The `worker!` Macro

Workers follow an insect-inspired structure: a "head" (configuration), optional "receptors" (gates), a "thorax" (isolation container), and an "abdomen" (handler).

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

The handler receives the message, a trace collector for instrumentation, and the worker's configuration. It returns the output message type.

##### Testing

Workers can be tested using the `tb_scenario!` macro with `environment Worker`:

```rust
use tightbeam::{tb_scenario, tb_assert_spec, exactly, worker};

tb_assert_spec! {
	pub PingPongSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(worker_called, exactly!(1)),
			(response_received, exactly!(1), equals!("pong"))
		]
	}
}

tb_scenario! {
	name: test_ping_pong_worker,
	spec: PingPongSpec,
	environment Worker {
		setup: |_env| {
			PingPongWorker::new(PingPongWorkerConfig {
				response: "pong",
			})
		},
		stimulus: |WorkerEnv { trace, worker, .. }| async move {
			trace.event_with(PingPongSpec::worker_called, &[], ())?;

			let request = RequestMessage { content: "ping".to_string() };
			let response = worker.relay(Arc::new(request)).await?;

			trace.event_with(PingPongSpec::response_received, &[], response.result)?;
			Ok(())
		}
	}
}
```

The `environment Worker` syntax provides:

- `setup`: Creates the worker builder from a `SetupEnv` (sync)
- `stimulus`: Drives the started worker through `WorkerEnv` via `relay()` and records trace events

Ident assertion keys generate constants on the spec type (`PingPongSpec::worker_called`). Event sites and assertions share that definition. The `spec:` key is shorthand for a `ScenarioConfig` with that spec's latest version.

#### 9.3.2 E: Servlets

Servlets are the network endpoints of the EEIC--the "anthills" where messages arrive and are processed. Workers own pure business logic. Servlets own the protocol layer: accept connections, decode frames, dispatch to workers, and send responses.

##### Architecture

Servlets sit between the network and workers:

1. **Listen** on a protocol-specific endpoint (e.g., TCP port)
2. **Receive** raw Frames from clients
3. **Decode** and validate incoming messages
4. **Dispatch** to one or more workers for processing
5. **Compose** the response Frame and send it back

This separation means servlets handle concerns like connection management, frame validation, and response composition--things workers should not know about.

##### Single Message Type Rule

Each servlet is responsible for exactly one message type. This keeps servlets focused and predictable. When you need to handle multiple related message types, use an ASN.1 Choice type to group them:

```rust
// A Choice type groups related messages
#[derive(Beamable, Choice)]
pub enum CalcRequest {
	Add(AddParams),
	Multiply(MultiplyParams),
	Divide(DivideParams),
}
```

> Note: It is preferrable to implement a strict separation of concerns between servlets. Each servlet should handle only one message type. Abusing Choice types to group unrelated message types is poor form.

##### Gate Policies

Servlets can apply gate policies to filter or validate incoming messages before processing:

```rust
servlet! {
	pub SecureServlet<Request, EnvConfig = ()>,
	protocol: TokioListener,
	policies: {
		with_collector_gate: [RateLimitGate::new(100), AuthGate::new(key)]
	},
	handle: |frame, ctx| async move {
		// Only reached if all gates pass
		// Access trace, config, workers via ctx
		let _trace = ctx.trace();
		// ...
	}
}
```

##### Defining a Servlet

**Step 1**: Define configuration struct outside the macro:

```rust
#[derive(Clone)]
pub struct PingPongServletConfig {
	pub service_name: String,
}
```

**Step 2**: Define the servlet using `EnvConfig`:

```rust
tightbeam::servlet! {
	pub PingPongServletWithWorker<RequestMessage, EnvConfig = PingPongServletConfig>,
	protocol: TokioListener,
	handle: |frame, ctx| async move {
		// Access context members
		let trace = ctx.trace();
		let config: &PingPongServletConfig = ctx.env_config()?;
		trace.event_with("request_received", &[], config.service_name.clone())?;

		// Handler receives Frame, not decoded message
		let decoded = decode::<RequestMessage, _>(&frame.message)?;
		let decoded_arc = Arc::new(decoded);

		// Workers are accessed via ctx.relay
		let (ping_result, lucky_result) = tokio::join!(
			ctx.relay::<PingPongWorker>(Arc::clone(&decoded_arc)),
			ctx.relay::<LuckyNumberDeterminer>(Arc::clone(&decoded_arc))
		);

		let reply = match ping_result {
			Ok(Some(reply)) => reply,
			_ => return Ok(None),
		};

		let is_winner = match lucky_result {
			Ok(Some(is_winner)) => is_winner,
			_ => return Ok(None),
		};

		Ok(Some(compose! {
			V0: id: b"response-id",
				message: ResponseMessage {
					result: reply.result,
					is_winner,
				}
		}?))
	}
}
```

**Step 3**: Configure workers via `ServletConfig` when starting the servlet:

```rust
// Create workers (use ::new, not .start - servlet auto-starts them)
let ping_pong_worker = PingPongWorker::new(());
let lucky_number_worker = LuckyNumberDeterminer::new(LuckyNumberDeterminerConfig {
	lotto_number: 42,
});

// Build servlet configuration
let servlet_conf = ServletConfig::<TokioListener, RequestMessage>::builder()
	.with_config(Arc::new(PingPongServletConfig { service_name: "ping-pong".to_string() }))
	.with_worker(ping_pong_worker)
	.with_worker(lucky_number_worker)
	.build();

// Start the servlet (workers are auto-started with servlet's trace)
PingPongServletWithWorker::start(trace, Some(servlet_conf)).await?
```

**Worker Lifecycle**

Workers follow a two-phase lifecycle:

1. **Creation** (`::new(config)` or `::default()`) - Creates the worker in an unstarted state
2. **Starting** (`.start(trace)`) - Spawns the worker's async task loop with a trace collector

When workers are added to a servlet via `ServletConfig::builder().with_worker(worker)`:

- The servlet automatically calls `.start(trace)` on each worker during servlet startup
- Workers inherit the servlet's trace collector for instrumentation
- All worker events are captured in the servlet's trace

For standalone worker testing (outside servlets), use the `Worker` trait's `start()` method explicitly:

```rust
let worker = MyWorker::new(config);
let trace = Arc::new(TraceCollector::new());
let started_worker = worker.start(trace).await?;
```

**Efficient Parallel Worker Processing**

Workers accept `Arc<Input>` instead of owned `Input` to enable efficient parallel processing. When calling multiple workers in parallel:

**Example using `tokio::join!`:**

```rust
let decoded_arc = Arc::new(decoded);
let (result1, result2) = tokio::join!(
    workers.worker1.relay(Arc::clone(&decoded_arc)),
    workers.worker2.relay(Arc::clone(&decoded_arc))
);
```

##### Testing

Servlets with workers can be tested using `environment Servlet`:

```rust
use tightbeam::{tb_scenario, tb_assert_spec, exactly, servlet, worker};

tb_assert_spec! {
	pub CalcServletSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(servlet_receive, exactly!(1)),
			(worker_process, exactly!(1)),
			(servlet_respond, exactly!(1)),
			(result_verified, exactly!(1), equals!(10u32))
		]
	}
}

tb_scenario! {
	name: test_calc_servlet,
	spec: CalcServletSpec,
	environment Servlet {
		context: CalcServletConfig { multiplier: 2 },
		start: |env| async move {
			let worker = DoublerWorker::new(());

			let servlet_conf = ServletConfig::<TokioListener, CalcRequest>::builder()
				.with_config(env.context)
				.with_worker(worker)
				.build();

			CalcServlet::start(Arc::new(env.trace), Some(servlet_conf)).await
		},
		setup: |env| async move {
			let builder = ClientBuilder::<TokioListener>::builder().build();
			let client = builder.connect(env.addr).await?;
			Ok(client)
		},
		client: |env| async move {
			let (trace, mut client) = (env.trace, env.client);
			let request = compose! {
				V0: id: b"calc-req",
					message: CalcRequest { value: 5 }
			}?;

			let response_frame = client.emit(request, None).await?
				.ok_or(TightBeamError::MissingResponse)?;
			let response: CalcResponse = decode(&response_frame.message)?;

			trace.event_with(CalcServletSpec::result_verified, &[], response.result)?;
			Ok(())
		}
	}
}
```

The `environment Servlet` syntax provides:

- `context`: Scenario fixture shared as `Arc<C>` with every closure (unit when omitted)
- `start`: Configures and starts the servlet with workers from a `SetupEnv`
- `setup`: Builds the client connection from a `ClientEnv` (optional). Default connects a plain `TokioListener` client
- `client`: Sends requests through `ServletEnv` and validates responses via trace events

#### 9.3.3 I: Hives

Hives sit between clusters and servlets. A servlet handles one message type on one listener. A hive can manage multiple servlets and coordinate with a cluster for work distribution. Think of hives as "ant nests" that house specialized workers (servlets).

##### Operating Modes

Hives support two operating modes:

**Single-Servlet Mode** lets a hive "morph" between servlet types. The cluster sends an `ActivateServletRequest`. The hive stops its current servlet and starts the requested one. That supports dynamic workload reallocation--for example switching from "analysis" to "calculation" based on cluster demand.

**Multi-Servlet Mode** runs all registered servlets at once, each on a different port. That requires a "mycelial" protocol (like TCP) which supports multiple endpoints. Call `establish_hive()` to spawn all servlets, then register with a cluster to advertise capabilities.

The protocol's capabilities select the mode. On mycelial protocols, multi-servlet mode usually gives the best throughput.

##### Mycelial Protocols

"Mycelial" means a protocol can spawn multiple endpoints from one base address--like fungal mycelium branching from a central point. TCP is mycelial: one host address (for example `192.168.1.100`) can bind multiple ports (`SocketAddress`). A hive can then spawn servlets on ports 8001, 8002, 8003, and so on, each handling a different message type.

Non-mycelial protocols (like in-memory channels) stay in single-servlet mode.

##### The `hive!` Macro

Define a hive type with its available servlets:

```rust
hive! {
	pub MyHive,
	protocol: TokioListener,
	servlets: {
		ping: PingServlet<PingRequest>,
		calc: CalculatorServlet<CalcRequest>
	}
}
```

Add security policies to gate incoming messages:

```rust
hive! {
	pub SecureHive,
	protocol: TokioListener,
	policies: {
		with_collector_gate: [SignatureGate::new(verifying_key)]
	},
	servlets: {
		ping: PingServlet<PingRequest>
	}
}
```

##### Hive Lifecycle

A typical hive lifecycle with cluster integration:

```rust
// 1. Start the hive
let mut hive = MyHive::start(trace, Some(HiveConfig::default())).await?;

// 2. Establish multi-servlet mode (spawns all servlets on separate ports)
hive.establish_hive().await?;

// 3. Register with cluster (announces available servlet types)
let response = hive.register_with_cluster(cluster_addr).await?;

// 4. Hive now receives work routed by the cluster

// 5. Clean shutdown
hive.stop();
```

##### Cluster Trust

For hives to accept commands from a cluster (heartbeats, management requests), they must trust the cluster's certificate. Configure this via `HiveConfig.trust_store`:

```rust
let hive_conf = HiveConfig {
	trust_store: Some(Arc::new(cluster_trust_store)),
	..Default::default()
};
```

Without a trust store, all cluster commands are rejected. See [Trust Stores](#trust-stores) for building trust stores from cluster certificates.

Signed commands are additionally checked for freshness: each `ClusterCommand` carries an `issued_at_ms` timestamp, and the hive rejects commands outside `command_freshness_window_ms` of its clock or whose signature was already seen inside that window (replay protection).

##### Resilience Features

Hives include built-in resilience mechanisms:

**Backpressure**: When utilization exceeds the threshold (default: 90%), the hive signals to the cluster that it is overloaded. The cluster can then route new work to less-loaded hives.

**Circuit Breaker**: After consecutive failures (default: 3), the circuit opens and the hive temporarily stops accepting work, allowing time for recovery before resuming.

These are configured via `HiveConfig`:

```rust
let hive_conf = HiveConfig {
	backpressure_threshold: BasisPoints::new(8000),  // 80%
	circuit_breaker_threshold: 5,                    // Open after 5 failures
	circuit_breaker_cooldown_ms: 60_000,             // 1 minute cooldown
	..Default::default()
};
```

##### Load Balancing

A hive resolves each servlet type to a single instance address, so it carries no balancer. Selecting among a type's replicas is the cluster gateway's job: see [Cluster load balancing](#load-balancing-1). Within a hive, message-to-type dispatch is derived directly from the message type.

##### TLS Configuration

For secure communication, configure TLS on the hive:

```rust
let tls_config = Arc::new(HiveTlsConfig {
	certificate: CertificateSpec::Built(Box::new(cert)),
	key: Arc::new(Secp256k1KeyProvider::from(signing_key)),
	validators: vec![],  // Optional: validate client certificates
});

let hive_conf = HiveConfig {
	hive_tls: Some(tls_config),
	..Default::default()
};
```

When `hive_tls` is set, the hive control server binds with TLS and outbound control frames (registration, scaling updates) are signed with the hive key. Cluster gateways reject control frames they cannot verify against `hive_trust`, so hives participating in a cluster require a signing identity.

##### HiveConfig Reference

```rust
pub struct HiveConfig {
	/// Naming scope for resource URNs (foreign authority/realm refused at register)
	pub namespace: ColonyNamespace,
	pub default_scale: ServletScaleConfig,
	/// Per-type overrides keyed by servlet type URN
	pub servlet_overrides: HashMap<Urn<'static>, ServletScaleConfig>,
	pub cooldown: Duration,                         // Default: 5s
	pub queue_capacity: u32,                        // Default: 100
	pub backpressure_threshold: BasisPoints,        // Default: 9000 (90%)
	pub circuit_breaker_threshold: u8,              // Default: 3
	pub circuit_breaker_cooldown_ms: u64,           // Default: 30_000
	pub servlet_pool_size: usize,                   // Default: 8
	pub servlet_pool_idle_timeout: Option<Duration>,// Default: 30s
	pub drain_timeout: Duration,                    // Default: 30s
	pub command_freshness_window_ms: u64,           // Default: 30_000 (replay window)
	pub cluster_notify_retry: Arc<dyn CoreRetryPolicy + Send + Sync>,
	pub trust_store: Option<Arc<dyn CertificateTrust>>,
	pub hive_tls: Option<Arc<HiveTlsConfig>>,
	/// Multiplexing offer for servlet pool + control server (default: None = single-flight)
	pub mux_offer: Option<TransportOffer>,
	/// Anti-entropy re-registration beat (default: 5s; None disables)
	pub reregister_interval: Option<Duration>,
}
```

##### Testing

Standalone hive behavior (control plane gates, circuit breaker, backpressure, drain) is tested with `environment Hive`:

```rust
tb_scenario! {
	name: hive_backpressure_reply_shape,
	spec: HiveBackpressureShapeSpec,
	environment Hive {
		// Signer pinned by the hive trust store
		context: trusted_signer("CN=Hive Backpressure Cluster"),
		// Returns the established hive
		start: |SetupEnv { context: signer, .. }| async move {
			start_trusted_hive(&signer, HiveConfig {
				backpressure_threshold: BasisPoints::default(),
				..Default::default()
			}).await
		},
		// Owns the hive for drain, registry checks, and stop
		client: |HiveEnv { trace, context: signer, hive }| async move {
			let mut client = connect_hive(&hive).await?;

			let signed_stop = signed_stop_frame(&signer.provider, b"manage-bp").await?;
			let response = emit_command(&mut client, signed_stop).await?;
			assert_manage_stop_shape(&response, TransitStatus::ResourceExhausted);

			trace.event(HiveBackpressureShapeSpec::backpressure_manage_manage_shape)?;

			hive.stop();
			Ok(())
		}
	}
}
```

The `environment Hive` syntax provides:

- `context`: Scenario fixture shared as `Arc<C>` with every closure (unit when omitted)
- `start`: Configures and starts the hive from a `SetupEnv`, returns the established hive
- `client`: Owns the hive through `HiveEnv`, asserts behavior, and stops it

Cluster-hive communication (registration, heartbeats, routing) is covered under [Cluster Testing](#cluster-testing).

#### 9.3.4 C: Clusters

Clusters are the "ant colonies" of the EEIC--centralized gateways that coordinate distributed hives. Hives manage individual servlets. Clusters own higher-level orchestration: route work, monitor hive health, balance load, federate with peer gateways, and flood colony gossip across the swarm.

##### Architecture

A cluster operates as a gateway server with five primary responsibilities:

1. **Hive Registry**: Maintains a dynamic registry of connected hives and their available servlet types. Hives register on startup and announce which servlet types they can handle.

2. **Work Routing**: Receives `ClusterWorkRequest` messages from external clients (or peer gateways), looks up Local and Peer routes for the servlet type, selects one via load balancing, and forwards the request.

3. **Health Monitoring**: Periodically sends heartbeats to registered hives. Unresponsive hives are evicted after consecutive failures so clients are not routed to dead endpoints.

4. **Peer Federation**: Optionally advertises local servlet types to peer gateways and installs soft-state Peer routes from their advertisements. Work can then hop one step to a peer colony that exports the type.

5. **Colony Gossip**: Optionally floods origin-signed rumors across colony member gateways, with journal deduplication and anti-entropy repair.

##### The `cluster!` Macro

Define a cluster type using the `cluster!` macro:

```rust
cluster! {
	pub MyCluster,
	protocol: TokioListener
}
```

The macro accepts an optional `digest` parameter for custom hash algorithms used in frame integrity verification:

```rust
cluster! {
	pub MyCluster,
	protocol: TokioListener,
	digest: Blake3
}
```

Runtime configuration is supplied to `Cluster::start`:

```rust
let cluster = MyCluster::start(trace, ClusterConfig::new(tls)).await?;
```

##### Mutual TLS

Clusters require TLS configuration for secure communication with hives and, when federating, with peer gateways. The cluster acts as a TLS client when connecting outbound, presenting its certificate for mutual authentication.

```rust
let tls = ClusterTlsConfig {
	certificate: CertificateSpec::Built(Box::new(cert)),
	key: Arc::new(Secp256k1KeyProvider::from(key)),
	validators: vec![],         // Optional: validators for hive certificates
	client_validators: vec![],  // Non-empty: gateway requires client certs (mTLS)
	hive_trust: Some(hive_trust),  // Hive-plane: registration, address updates, PublishGossip
	peer_trust: Some(peer_trust),  // Peer-plane: AdvertisePeer, relayed Gossip, ReconcileGossip
};
```

The two trust stores are separate planes and MUST NOT cross:

- **`hive_trust`**: Validates hive-origin control frames (registration, servlet address updates) and origin gossip publish (`PublishGossip`). Missing signatures reply `TransitStatus::Unauthenticated`. Failed verification replies `TransitStatus::PermissionDenied`. `None` fails closed for those frames.
- **`peer_trust`**: Validates peer advertisements and relayed gossip. `None` disables inbound federation (peer ads and relayed gossip are refused). Hive certificates cannot forge peer ads; peer certificates cannot publish origin gossip.

For hives to trust cluster commands (like heartbeats), they must have the cluster's certificate in their trust store. See [Trust Stores](#trust-stores) for details.

##### Colony Membership

Federation and gossip are colony operations. Membership is the colony URN in the gateway certificate's URI Subject Alternative Name, validated against `ClusterConfig::namespace` and exposed read-only as `ClusterConfig::colony_urn()`. Ambiguous or missing SAN entries leave the gateway a non-member.

- Non-members still register hives and route work.
- Non-members refuse peer advertisements, gossip publish, gossip relay, and gossip reconciliation.
- The advertise beat skips gossip repair when the local gateway is not a member.

Flood scope is that certificate binding. Rumor bytes never carry a destination colony.

##### Peer Federation

Peer federation lets gateways learn which servlet types neighboring colonies export and forward work one hop. Think of it as trail-sharing between nests: each gateway re-advertises what its local hives currently serve.

Configure outbound advertisement with a dial list and beat cadence:

```rust
let conf = ClusterConfig::builder(tls)
	.with_peers([peer_addr.to_string()])
	.with_advertise_interval(Duration::from_secs(5))
	// Optional: only accept peer ads that claim dial addresses in this list
	.with_peer_dial_allowlist([peer_addr.to_string()])
	.build();
```

Behavior:

1. Each advertise beat snapshots the **local hive registry** (never a static configured slate) and dials peers with a signed `AdvertisePeer` (`PeerAdvertisement`).
2. The receiver admits on the peer trust plane: signature, freshness, colony membership on both sides, parseable dial address, optional allowlist, and namespace-scoped servlet types.
3. Installed routes are soft-state and keyed by the peer's signer certificate fingerprint. The claimed `gateway_addr` is the dial target. An empty advertisement clears that peer's routes.
4. The load balancer selects among Local and Peer trails together. Locality emerges from pheromone strength rather than a hard preference flag.
5. A peer hop re-emits `ClusterWorkRequest` with `forwarded: true`. An inbound forwarded request is local-only--a one-hop loop guard so peer graphs cannot bounce work forever.
6. Peer dials prefer the peer connection pool when `peer_trust` is set. Peer failures weaken trails and can abandon a grey-hole peer while local routes keep serving.

`peers` is a dial list, not an identity mesh. Partial or asymmetric peer graphs are expected.

##### Heartbeat Mechanism

Clusters continuously monitor hive health through heartbeats. Each heartbeat is a signed frame sent to the hive, which responds with its current utilization. This serves two purposes:

- **Liveness Detection**: Hives that fail to respond are marked unhealthy and eventually evicted from the registry.
- **Load Metrics**: Utilization data informs the load balancer, enabling smarter routing decisions.

Configure heartbeat behavior via `HeartbeatConfig`:

```rust
let heartbeat_conf = HeartbeatConfig::builder()
	.with_interval(Duration::from_secs(5))   // Check every 5 seconds
	.with_timeout(Duration::from_secs(15))   // Response deadline
	.with_max_failures(3)                    // Evict after 3 failures
	.with_max_concurrent(10)                 // Parallel heartbeat limit
	.build();
```

The `on_heartbeat` callback enables monitoring and metrics collection:

```rust
.with_callback(Arc::new(|event| {
	metrics::counter!("heartbeat", "success" => event.success.to_string()).increment(1);
}))
```

##### Load Balancing

When multiple instances support the same servlet type, the cluster uses a `LoadBalancer` to select one among Local hive routes and Peer gateway routes. The default `StochasticForager` is a pheromone-based swarm strategy: it draws each instance with probability proportional to its trail strength, keeps an exploration floor so no instance is starved, and applies termite-style repellency so no instance is monopolized. Alternative strategies (`RoundRobin`, `PowerOfTwoChoices`) and any custom `LoadBalancer` are pluggable via `ClusterConfig::builder(..).with_load_balancer(..)`.

##### Colony Gossip

Colony gossip floods origin-signed rumors across member gateways--the pheromone broadcast of the swarm. A publisher asks the local gateway to mint a rumor; peers relay and repair until hop budget or freshness expires.

```rust
let conf = ClusterConfig::builder(tls)
	.with_peers([peer_addr.to_string()])
	.with_advertise_interval(Duration::from_secs(5))
	.with_gossip_ingress(servlet_type_urn) // optional local delivery target
	.with_gossip_config(GossipConfig {
		ttl: 4, // hop radius cap (clamped to MAX_GOSSIP_TTL)
		..GossipConfig::default()
	})
	.build();
```

Flow:

1. **Publish**: A hive-plane signed `PublishGossip` carries `GossipRumor { payload }`. The accepting origin gateway must be a colony member. It mints an origin-signed rumor Frame (id and issue time from the publish frame) and starts the flood.
2. **Relay**: Peers carry `ClusterRequest::Gossip` with an outer relay Frame. Hop radius lives only in the outer `metadata.lifetime`. The inner rumor stays byte-identical under the origin signature. Relays verify on the peer trust plane; the origin colony URN MUST equal the local gateway's colony URN.
3. **Admit and journal**: Payload size, freshness (`seen_ttl`), hop TTL, per-signer rate admission, and content-digest dedup run before delivery. Duplicates are acknowledged without spending rate tokens twice.
4. **Local ingress**: `GossipConfig.ingress` names a servlet type on the receiving gateway. `None` means journal and reflood only (immediate local ack).
5. **Reflood**: Remaining hop TTL and a non-empty `peers` list continue the flood.
6. **Reconcile**: `ReconcileGossip` exchanges held digests; the peer answers with `GossipWant`. The advertise beat also runs anti-entropy repair and pending-local retry.

Misbehavior on tampered or lifetime-missing relays weakens peer trails. A foreign-colony refuse does not.

##### Work Request Flow

Clients interact with clusters through work request messages:

1. Client sends `ClusterWorkRequest` with `servlet_type` and encoded `payload`
2. Cluster looks up Local and Peer routes for that servlet type
3. Load balancer selects an instance (hive or peer gateway)
4. Cluster forwards the payload--directly to a local hive, or one hop to a peer with `forwarded: true`
5. The serving hive processes and returns a response
6. Cluster wraps the response in `ClusterWorkResponse` and returns it to the client

```rust
// Client sends (forwarded defaults to false):
let request = ClusterWorkRequest::new(
	servlet_type_urn, // e.g. urn:tightbeam::servlet:calculator
	encode(&CalcRequest { value: 42 })?,
);

// Client receives:
let response: ClusterWorkResponse = decode(&frame.message)?;
match response.status {
	TransitStatus::Ok => { /* process response.payload */ }
	TransitStatus::Unavailable => { /* no hive available */ }
	_ => { /* handle other statuses */ }
}
```

##### ClusterConfig Reference

```rust
pub struct PeerConfig {
	/// Peer dial list for advertise/gossip reflood (empty = no outbound federation)
	pub peers: Vec<String>,
	/// Re-advertise beat cadence (`None` disables the beat)
	pub advertise_interval: Option<Duration>,
	/// Optional exact-match allowlist for claimed peer dial addresses
	pub peer_dial_allowlist: Option<Vec<String>>,
}

pub struct ClusterConfig {
	// --- Identity and local gateway ---
	/// Naming scope for inbound resource URNs (authority/realm gate)
	pub namespace: ColonyNamespace,
	/// Optional stable gateway bind address
	pub bind_addr: Option<String>,
	/// Freshness/replay window for signed hive control frames (ms)
	pub control_freshness_window_ms: u64,
	/// TLS configuration, including `hive_trust` and `peer_trust`
	pub tls: ClusterTlsConfig,

	// --- Work routing ---
	/// Load balancing strategy (defaults to `StochasticForager`)
	pub load_balancer: Arc<dyn LoadBalancer>,
	pub heartbeat: HeartbeatConfig,
	pub pheromone: PheromoneConfig,
	/// Gate policies evaluated on every gateway frame before decoding
	pub policies: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	/// Connection pool configuration for hive (and peer) connections
	pub pool_config: PoolConfig,

	// --- Peer federation ---
	pub peer: PeerConfig,

	// --- Colony gossip ---
	/// Gossip freshness, hop TTL, ingress URN, journal, and admission
	pub gossip: GossipConfig,
}

// Colony URN is derived from the gateway cert URI SAN at build time.
// Read it with ClusterConfig::colony_urn(); it is not a settable field.
```

##### Cluster Testing

Clusters can be tested using `environment Cluster`:

```rust
use tightbeam::{tb_scenario, tb_assert_spec, exactly, cluster, hive};

tb_assert_spec! {
	pub ClusterRoutingSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(work_sent, exactly!(1)),
			(routing_accepted, exactly!(1))
		]
	}
}

tb_scenario! {
	name: cluster_work_routing,
	spec: ClusterRoutingSpec,
	environment Cluster {
		// Shared as Arc<C> with every closure
		context: ClusterTestCerts::generate(),
		start: |SetupEnv { context: certs, .. }| async move {
			let mut conf = ClusterConfig::new(cluster_tls_config(&certs));
			// Both offers set: client -> cluster and cluster -> hive run multiplexed
			conf.pool_config.mux_offer = Some(TransportOffer::mux(8));
			ClusterGateway::start(Arc::new(TraceCollector::new()), conf).await
		},
		// Optional: awaited and registered with the cluster.
		// Omit when driving registration from the client.
		hives: |SetupEnv { context: certs, .. }| vec![async move {
			let servlet = PingServlet::start(Arc::new(TraceCollector::new()), None).await?;
			let mut hive = TestHive::new(Some(HiveConfig {
				mux_offer: Some(TransportOffer::mux(8)),
				..hive_tls_config(&certs)
			}))?;
			hive.register("ping", servlet, |t| PingServlet::start(t, None))?;
			hive.establish(Arc::new(TraceCollector::new())).await?;
			Ok(hive)
		}],
		// Owns the cluster for registry checks and stop
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			trace.event(ClusterRoutingSpec::work_sent)?;

			let request = ClusterWorkRequest::new(
				ping_type(), // urn:tightbeam::servlet:ping
				encode(&PingRequest { value: 21 })?,
			);

			let mut client = connect_cluster(&certs, cluster.addr()).await?;
			let response_frame = client.emit(compose! {
				V0: id: b"work-001", message: ClusterRequest::Work(request)
			}?, None).await?.ok_or(TightBeamError::MissingResponse)?;

			let work_response: ClusterWorkResponse = decode(&response_frame.message)?;
			assert_eq!(work_response.status, TransitStatus::Ok);

			trace.event(ClusterRoutingSpec::routing_accepted)?;

			cluster.stop();
			Ok(())
		}
	}
}
```

The `environment Cluster` syntax provides:

- `context`: Scenario fixture (certificates, flags) shared as `Arc<C>` with every closure
- `start`: Configures and starts the cluster from a `SetupEnv`, returns the cluster instance
- `hives` (OPTIONAL): Returns hive futures from a `SetupEnv`. Each is awaited and registered with the cluster
- `client`: Owns the cluster through `ClusterEnv`, builds connections from the context, asserts registry state, and stops the cluster

Adversarial registration scenarios (unsigned, replayed, stale, hijacked) omit `hives:` and drive registration from the client, asserting the rejection and the registry count on the owned instance.

Peer federation and gossip use the same `environment Cluster` shape with peer trust, dial lists, and signed `AdvertisePeer` / `PublishGossip` frames from the client. See `tests/colony/cluster/` (`registration.rs`, `routing.rs`, `topology.rs`, `peering.rs`, `gossip.rs`).

##### Conclusion

How you wish to model your colonies is beyond the scope of this document. However, it is important to understand the basic building blocks and how they can be combined to create complex systems. The swarm is yours to command.

## 10. Instrumentation

Instrumentation produces a semantic event sequence for verification and audit. Tests MUST NOT assert against instrumentation events by inspecting or branching on individual events at runtime. Tests MUST declare expectations as a spec. Verification MUST treat the finalized event stream as the authoritative truth for a single execution.

Feature gating:

- Instrumentation is enabled only by the crate feature `instrument`.
- `TraceCollector` (`tightbeam::trace`) requires `std` and MUST NOT require the `testing` feature.

### 10.1 Objectives

- Emission MUST be amortized O(1) per event.
- Ordering MUST be strictly increasing by sequence number per trace.
- Evidence artifacts MUST be deterministic and hash-stable for identical executions.
- Detail level MUST be feature-gated to avoid unnecessary overhead.
- Payload handling MUST preserve privacy (hash or summarize).

### 10.2 Event Kind Taxonomy

Each emitted event carries a kind URN from the closed inventory in `tightbeam::instrumentation::events`. Format:

```
urn:tightbeam:event:<domain>/<event-name>
```

Domains (illustrative; full constants live in that module):

- **Core / meta**: `core/start`, `core/end`, `core/warn`, `core/error`, `trace/clock-origin`
- **External**: `gate/accept`, `gate/reject`, `transport/request-recv`, `transport/response-send`
- **Connection**: `connection/accepted`, `connection/closed`, `connection/stale`, `connection/reconnected`
- **Assertion**: `assert/label`, `assert/payload`
- **Internal** (detail-gated): `handler/enter`, `handler/exit`, `crypto/step`, `compress/step`, `route/step`, `policy/eval`
- **Process** (requires `testing-csp`): `process/transition`, `process/hidden`
- **Exploration** (requires `testing-fdr`): `fdr/seed-start`, `fdr/seed-end`, `fdr/state-expand`, `fdr/state-prune`, `fdr/divergence-detect`, `fdr/refusal-snapshot`, `fdr/enabled-set-sample`
- **Mux / pool / session**: `mux/*`, `pool/*`, `session/*` (handshake, receipts, rekey, drain)
- **Colony**: `hive/reregistered`, `cluster/hive-registered`, `cluster/work-routed`, `cluster/work-forwarded`, `cluster/peer-advertised`, `cluster/gossip-accepted`, `cluster/gossip-refused`, and related accept/refuse pairs

Hidden/internal detail MUST stay behind `enable_internal_detail` (and related sampling flags). Control-plane accept/refuse events (gates, cluster, gossip) fire when the subsystem decides, independent of that detail flag.

> Note: `TightbeamUrnSpec` (`urn:tightbeam:instrumentation:<resource_type>/<resource_id>`) is a separate helper for application/test labeling. Production control-plane events use the `event:<domain>/<name>` inventory above. See [§11.1.1](#1111-urns).

Assertion matching compares full URN strings for equality. Specs and emit sites MUST share the same rendered URN (or the same `events::*` constant).

### 10.3 Event Structure

Runtime shape is `TbEvent`:

```
seq | urn | label? | payload_hash? | duration_ns? | timestamp_ns? | flags | extras?
```

Requirements:

- `seq` MUST start at 0 and increment by 1 for each emitted event on a collector.
- `urn` MUST be a member of the event inventory (or an application URN the deployment treats as first-class).
- `label` MAY carry a human-readable or numeric annotation (for example the Unix-epoch nanoseconds on `TRACE_CLOCK_ORIGIN`).
- `payload_hash` MAY be present only when payloads are enabled and the emit site captures one.
- `duration_ns` MAY appear on exit or boundary events and MUST be a monotonic span length in nanoseconds.
- `timestamp_ns` MAY appear as nanoseconds since collector construction. `TRACE_CLOCK_ORIGIN` records the construction time once as Unix-epoch nanoseconds so absolute times are reconstructible offline (see [§8.8.1](#881-audit-trail-deployment-requirements)).
- `flags` MUST be a bitset (for example ASSERT_FAIL, HIDDEN, DIVERGENCE, OVERFLOW).
- `extras` MAY carry a bounded byte sketch for extended metrics.

### 10.4 Payload Representation

Runtime values captured under `assert_payload` MUST be transformed before emission:

- Algorithm: SHA3-256 digest over the canonical byte representation.
- Representation: The full 32-byte SHA3-256 output MUST be stored. Truncation below 32 bytes is forbidden.
- Literal integers MAY be emitted directly as 64-bit unsigned values if they are not sensitive.
- Structured values SHOULD emit a static schema tag plus digest.

> Warning: Secret or potentially sensitive raw data MUST NOT be emitted verbatim.

### 10.5 Configuration

Instrumentation behavior MUST be controlled by `TbInstrumentationConfig` (gated by `instrument`):

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

Defaults (`instrument` only):

- `enable_payloads = false`
- `enable_internal_detail = false`
- `sample_enabled_sets = false`
- `sample_refusals = false`
- `divergence_heuristics = false`
- `record_durations = false`
- `max_events = 1024`

Enabling testing layers does not change these defaults. Tests MAY override fields per scenario.

Every emitted `TbEvent` goes to exactly one `EventSink`. When no sink is configured, the collector uses `BoundedMemorySink` sized by `max_events`. If that bound is exceeded, the implementation MUST set an OVERFLOW condition, emit a single `core/warn` event, and drop subsequent events. Sequence gaps in exported evidence reveal truncation (see [§8.8.1](#881-audit-trail-deployment-requirements)).

### 10.6 Evidence Artifact Format

For every finalized trace an artifact MUST be producible as ASN.1 DER (`EvidenceArtifact`).

Wire shape:

```
EvidenceArtifact ::= SEQUENCE {
	specHash      OCTET STRING,           -- SHA3-256(spec definition)
	traceHash     OCTET STRING,           -- SHA3-256 over canonical event bytes
	evidenceHash  OCTET STRING,           -- SHA3-256(specHash || traceHash)
	events        SEQUENCE OF TbEvent,
	overflow      BOOLEAN                 -- true if the collector dropped events
}

TbEvent ::= SEQUENCE {
	seq           INTEGER,
	urn           URN,                    -- event kind
	label         [0] UTF8String OPTIONAL,
	payloadHash   [1] OCTET STRING OPTIONAL,  -- 32 bytes when present
	durationNs    [2] INTEGER OPTIONAL,
	timestampNs   [3] INTEGER OPTIONAL,
	flags         INTEGER,
	extras        [4] OCTET STRING OPTIONAL
}
```

Binary serialization requirements:

- DER MUST omit absent OPTIONAL fields.
- Field ordering MUST follow the schema strictly.
- Optional fields use explicit context tags so adjacent optionals of the same universal type stay unambiguous.
- `payloadHash` MUST be 32 bytes when present (SHA3-256).

Artifact integrity:

- `trace_hash` MUST be SHA3-256 over a canonical byte encoding of the event list (sequence numbers, URN strings, labels, payload hashes, flags, durations, timestamps, and extras)--not a free-form dump of surrounding artifact fields.
- `evidence_hash` MUST be SHA3-256(`specHash` || `traceHash`) where `||` is raw byte concatenation.

Privacy:

- Raw payload bytes MUST NOT appear. Only hashed representation or non-sensitive numeric scalars MAY be represented.

### 10.7 Failure Handling

- Emission errors MUST NOT panic. They MUST degrade gracefully (for example drop the event and set OVERFLOW).
- Verification MUST treat missing expected instrumentation events as spec violations (for example an absent assertion label).

### 10.8 Logging Subsystem

The logging subsystem implements [RFC 5424][rfc5424]-compliant logging with trait-based backends.

#### RFC 5424 Severity Levels

```rust
pub enum LogLevel {
	Emergency = 0,
	Alert = 1,
	Critical = 2,
	Error = 3,
	Warning = 4,
	Notice = 5,
	Info = 6,
	Debug = 7,
}
```

#### LogBackend Trait

```rust
pub trait LogBackend: Send + Sync {
	fn emit(&self, record: &LogRecord) -> Result<(), LogError>;
	fn accepts(&self, level: LogLevel) -> bool;
	fn flush(&self) -> Result<(), LogError> { Ok(()) }
}
```

Built-in backends: `StdoutBackend` (std only), `MultiplexBackend` (fan-out).

#### Log Filtering

```rust
let filter = LogFilter::new(LogLevel::Warning)
	.with_component("security", LogLevel::Debug);
```

#### Integration

```rust
use tightbeam::instrumentation::events;
use tightbeam::trace::{TraceConfig, logging::*};

let backend = Box::new(StdoutBackend);
let filter = LogFilter::new(LogLevel::Warning);
let config = LoggerConfig::new(backend, filter)
	.with_default_level(LogLevel::Info);

let trace: TraceCollector = TraceConfig::builder()
	.with_logger(config)
	.build();

trace.event(events::ERROR)?.with_log_level(LogLevel::Error).emit();
```

> Note: The event emit may be elided; events are emitted on drop.

## 11. Misc

### 11.1 Utilities

The `utils` module family covers cross-cutting concerns.

#### 11.1.1 URNs

**Module**: `tightbeam::utils::urn`

The URN subsystem provides:

- `Urn<'a>`: [RFC 8141][rfc8141]-compliant `urn:<nid>:<nss>` representation.
- `UrnBuilder`: a fluent builder for constructing and validating URNs from either a raw NID/NSS or structured components.
- `UrnSpec` / `UrnValidationError`: traits and error types for namespace-specific validation logic.
- `tightbeam::utils::urn::specs::TightbeamUrnSpec`: a built-in spec for application/test instrumentation labels of the form `urn:tightbeam:instrumentation:<resource_type>/<resource_id>`.
- Control-plane event URNs (`urn:tightbeam:event:<domain>/<name>`) live in `tightbeam::instrumentation::events` (see [§10.2](#102-event-kind-taxonomy)).

`TightbeamUrnSpec` constrains:

- **`resource_type`**: one of `trace`, `event`, `seed`, `verdict` (case-insensitive, normalized to lowercase)
- **`resource_id`**: an application-defined identifier that must match an alphanumeric-with-hyphen pattern

Applications MAY use these URNs to name resources in a stable, parseable way. They are distinct from the control-plane event inventory in [§10.2](#102-event-kind-taxonomy).

**Example: Building a custom application URN**

```rust
use tightbeam::utils::urn::{UrnBuilder, UrnValidationError};

fn build_customer_urn() -> Result<(), UrnValidationError> {
	let urn = UrnBuilder::default()
		.with_nid("example")
		.with_nss("customer:1234")
		.build()?;

	assert_eq!(urn.to_string(), "urn:example:customer:1234");

	Ok(())
}
```

#### 11.1.2 Jobs

**Module**: `tightbeam::utils::task`

The `job!` macro wraps a unit of work as a zero-sized type (ZST) with a static `run` method. Sync jobs implement `Job`. Async jobs implement `AsyncJob`.

```rust
use tightbeam::job;
use tightbeam::utils::task::{Job, AsyncJob, Pipeline, join};
```

Properties:

- Zero-cost ZST with one static `run`
- Named type for composition and tests
- Sync or async, protocol-independent

**Syntax:**

```rust
// Async job with tuple input (implements AsyncJob)
job! {
	name: JobName,
	async fn run((param1, param2): (Type1, Type2)) -> ReturnType {
		// Implementation
	}
}

// Sync job with tuple input (implements Job)
job! {
	name: JobName,
	fn run((param1, param2): (Type1, Type2)) -> ReturnType {
		// Implementation
	}
}

// No-parameter job (Input = ())
job! {
	name: NoParamJob,
	fn run() -> ReturnType {
		// Implementation
	}
}
```

**Traits** (implemented by `job!`):

```rust
pub trait Job {
	type Input;
	type Output;
	fn run(input: Self::Input) -> Self::Output;
}

pub trait AsyncJob {
	type Input;
	type Output;
	fn run(input: Self::Input) -> impl Future<Output = Self::Output> + Send;
}
```

Call sites pass a single `Input` value (often a tuple): `AddNumbers::run((1, 2))`.

#### 11.1.3 Job Pipelines

**Module**: `tightbeam::utils::task`

`Result<T, E>` implements `Pipeline`. Jobs that return `Result` chain with familiar `and_then`, `map`, and `or_else`. Closures that return `Result` are pipelines too.

```rust
use tightbeam::job;
use tightbeam::utils::task::{Pipeline, PipelineBuilder, join};
```

**Basic usage:**

```rust
let frame = CreateHandshakeRequest::run((client_id, nonce))
	.map(|req| req.with_timestamp(now()))
	.and_then(|req| ValidateRequest::run(req))
	.map_err(|e| TightBeamError::ValidationFailed(e))
	.and_then(|req| SendRequest::run(req))
	.run()?;
```

**Mixed composition** (start from any `Result`):

```rust
let config: Result<Config, Error> = parse_config_file(path);

config
	.and_then(|cfg| ValidateConfig::run(cfg))
	.and_then(|cfg| SaveConfig::run(cfg))
	.map(|_| "Configuration saved successfully")
	.and_then(|msg| NotifyUser::run(msg))
	.run()?;
```

**Parallel execution with `join()`:**

```rust
let (encrypted, signed) = join(
	EncryptPayload::run(payload),
	SignPayload::run(payload)
).run()?;

SendRequest::run((encrypted, signed))?;
```

**Error recovery** (`Pipeline` exposes `or_else`, not `or`):

```rust
let frame = SendRequest::run(request)
	.or_else(|_| UseCachedResponse::run())
	.or_else(|e| HandleError::run(e))
	.run()?;
```

**Automatic trace with `PipelineBuilder`:**

`PipelineBuilder` (feature `testing`) attaches a `TraceCollector`. Each traced `and_then` emits job lifecycle URNs:

```
urn:tightbeam:event:job/<job-name>-<start|success|error>
```

Job names are derived from the closure type (`Type::run` path), converted to snake_case, then hyphenated in the NSS (for example `CreateHandshakeRequest` becomes `create-handshake-request`).

```rust
PipelineBuilder::new(trace)
	.start((client_id, nonce))
	// Auto-emits: urn:tightbeam:event:job/create-handshake-request-start
	//             urn:tightbeam:event:job/create-handshake-request-success
	.and_then(|(id, n)| CreateHandshakeRequest::run((id, n)))
	.map(|req| req.validate()) // no job URN (plain map)
	.and_then(|req| ValidateRequest::run(req))
	.and_then(|req| SendRequest::run(req))
	.run()?;
```

**Testing integration:**

Assert the full job URNs (exact string match; see [§10.2](#102-event-kind-taxonomy)):

```rust
tb_assert_spec! {
	pub PipelineSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			("urn:tightbeam:event:job/create-handshake-request-start", exactly!(1)),
			("urn:tightbeam:event:job/create-handshake-request-success", exactly!(1)),
			("urn:tightbeam:event:job/validate-request-start", exactly!(1)),
			("urn:tightbeam:event:job/validate-request-success", exactly!(1))
		]
	}
}

tb_process_spec! {
	pub PipelineProcess,
	events {
		observable {
			"urn:tightbeam:event:job/create-handshake-request-start",
			"urn:tightbeam:event:job/create-handshake-request-success",
			"urn:tightbeam:event:job/validate-request-start",
			"urn:tightbeam:event:job/validate-request-success"
		}
		hidden {}
	}
	states {
		Idle => { "urn:tightbeam:event:job/create-handshake-request-start" => Creating },
		Creating => { "urn:tightbeam:event:job/create-handshake-request-success" => Validating },
		Validating => { "urn:tightbeam:event:job/validate-request-start" => ValidatingRun },
		ValidatingRun => { "urn:tightbeam:event:job/validate-request-success" => Done },
		Done => {}
	}
	terminal { Done }
}

tb_scenario! {
	name: test_pipeline_workflow,
	config: ScenarioConfig::builder()
		.with_spec(PipelineSpec::latest())
		.with_csp(PipelineProcess)
		.build(),
	environment Pipeline {
		exec: |pipeline| {
			pipeline
				.start(("test-001".to_string(), "nonce".to_string()))
				.and_then(|input| CreateHandshakeRequest::run(input))
				.map(|req| req.with_metadata())
				.and_then(|req| ValidateRequest::run(req))
				.run()
		}
	}
}
```

**Complete example:**

```rust
use tightbeam::utils::task::{Pipeline, PipelineBuilder, join};

let session_id = PipelineBuilder::new(trace)
	.start(client_id)
	.and_then(|id| CreateHandshakeRequest::run((id, nonce)))
	.map(|req| req.add_timestamp(now()))
	.and_then(|req| {
		let encrypted = EncryptPayload::run(payload);
		let signed = SignPayload::run(payload);
		join(encrypted, signed).map(|(e, s)| (req, e, s))
	})
	.and_then(|(req, enc, sig)| SendRequest::run((req, enc, sig)))
	.or_else(|_| UseCachedResponse::run())
	.or_else(|e| HandleError::run(e))
	.and_then(|resp| ExtractSessionId::run(resp))
	.run()?;
```

## 12. Testing Framework

The tightbeam testing framework provides three progressive verification layers for rigorous behavioral testing of protocol implementations.

### 12.1 Architecture and Concepts

The tightbeam testing framework is built on two foundational concepts from formal methods and statistical testing theory:

#### Communicating Sequential Processes (CSP)

CSP is a formal language for describing patterns of interaction in concurrent systems, developed by Tony Hoare.[^hoare1978][^roscoe2010] In tightbeam, CSP provides the mathematical foundation for modeling protocol behavior as labeled transition systems (LTS). Each process specification defines:

- **Alphabet (Σ, τ)**: Observable events visible to the environment (Σ) and hidden internal events (τ)
- **State Space**: Named states representing protocol phases
- **Transitions**: Labeled edges defining valid state changes
- **Refinement**: Hierarchical relationship where implementation traces must be valid specification traces

CSP enables us to express protocol correctness as refinement relations: `Implementation ⊑ Specification`, where ⊑ denotes trace refinement (⊑T) or failures refinement (⊑F).

#### Failures-Divergences Refinement (FDR)

FDR is a model checking methodology that verifies CSP refinement relations through exhaustive exploration.[^fdr4] The framework checks three key properties:

1. **Trace Refinement (⊑T)**: Every observable trace of the implementation is a valid trace of the specification
2. **Failures Refinement (⊑F)**: The implementation cannot refuse events that the specification accepts at any state
3. **Divergence Freedom**: The system cannot enter infinite internal-only loops (livelock)

In tightbeam, FDR-style verification uses multi-seed exploration to account for scheduler nondeterminism in cooperatively scheduled systems. This approach, based on research by Pedersen & Chalmers,[^pedersen2024] recognizes that refinement verification in systems with cooperative scheduling depends on resource availability and execution interleaving.

#### Integration in tightbeam

The three-layer architecture progressively applies these concepts:

- **Layer 1 (Assertions)**: Basic event occurrence verification
- **Layer 2 (CSP)**: State machine modeling with observable/hidden event distinction
- **Layer 3 (FDR)**: Refinement checking via multi-seed exploration

This progressive approach allows developers to start with simple assertions and incrementally add formal verification as protocol complexity grows.

#### 12.1.1 Three-Layer Progressive Verification

tightbeam implements formal verification through three complementary layers, each building upon the previous:

| Layer          | Feature Flag  | Purpose                        | Specification      | Usage                                       |
| -------------- | ------------- | ------------------------------ | ------------------ | ------------------------------------------- |
| L1 AssertSpec  | `testing`     | Runtime assertion verification | `tb_assert_spec!`  | Required: `.with_spec()` or `.with_specs()` |
| L2 ProcessSpec | `testing-csp` | CSP state machine modeling     | `tb_process_spec!` | Optional: `.with_csp()`                     |
| L3 Refinement  | `testing-fdr` | Trace/failures refinement      | Inline config      | Optional: `.with_fdr()`                     |

**Layer 1 (Assertions)**: Verifies that expected events occur with correct cardinality. This provides basic behavioral correctness through declarative assertion specifications.

**Layer 2 (CSP Process Models)**: Adds formal state machine modeling using Communicating Sequential Processes (CSP) theory. Validates that execution traces follow valid state transitions and distinguishes between observable (external) and hidden (internal) events.

**Layer 3 (FDR Refinement)**: Enables multi-seed exploration for exhaustive verification of trace refinement, failures refinement, and divergence freedom. Based on FDR (Failures-Divergences Refinement) model checking methodology.

#### 12.1.2 Unified Entry Point: tb_scenario!

All three layers are accessed through the `tb_scenario!` macro, which provides:

- Consistent syntax across all verification layers
- Progressive enhancement (L1 -> L1+L2 -> L1+L2+L3)
- Environment abstraction (ServiceClient, Servlet, Worker, Bare, Cluster, Hive)
- Instrumentation integration
- Policy enforcement

#### 12.1.3 Feature Flag Architecture

The testing framework uses progressive feature flags:

- `testing`: Enables L1 assertion verification (foundation)
- `testing-csp`: Enables L1+L2 CSP process modeling
- `testing-fdr`: Enables L1+L2+L3 refinement checking (requires `testing-csp`)
- `testing-timing`: Enables timing verification (WCET, deadline, jitter, slack) - requires `testing`
- `testing-schedulability`: Enables schedulability analysis (RMA/EDF) - requires `testing-timing`

Each layer builds on the previous, ensuring consistent semantics across verification levels.

### 12.2 Layer 1: Assertion Specifications

#### 12.2.1 Concept

AssertSpec defines expected behavioral invariants through declarative assertion specifications. Each specification version declares:

- Expected assertion labels (event identifiers)
- Cardinality constraints (exactly, at_least, at_most, between)
- Value assertions (equals) for verifying assertion payload values
- Execution mode (Accept, Reject)
- Gate policy (Ok, rejection statuses, etc.)

Specifications are versioned using semantic versioning (major.minor.patch) and produce deterministic SHA3-256 hashes over their canonical representation.

#### 12.2.2 Specification: tb_assert_spec! Syntax

```rust
tb_assert_spec! {
	pub MySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		tag_filter: ["v1"],
		assertions: [
			(Received, exactly!(1)),
			(Responded, exactly!(1), equals!("ok"))
		]
	},
	V(1,1,0): {
		mode: Accept,
		gate: Ok,
		tag_filter: ["v1.1"],
		assertions: [
			(Received, exactly!(1)),
			(Responded, exactly!(2))
		]
	},
}
```

**Version Block Syntax**:

```
V(major, minor, patch): {
	mode: <ExecutionMode>,              // Accept or Reject
	gate: <TransitStatus>,              // Ok, rejection statuses, etc.
	tag_filter: ["tag1", "tag2"],       // Optional: filter assertions by tags
	assertions: [                       // Array of (label, cardinality) or (label, cardinality, equals!(value))
		("label", cardinality),
		("label", cardinality, equals!(value)),
		...
	],
	events: [Kind, ...]                 // Optional: when instrumentation enabled
	schedulability: {                   // Optional: when testing-schedulability enabled
		task_set: <TaskSet>,
		scheduler: RateMonotonic | EarliestDeadlineFirst,
		must_be_schedulable: <bool>
	}
}
```

**Deterministic Hashing**: Each version produces a 32-byte SHA3-256 hash over:

- Domain tag `"TBSP"` (tightbeam Spec Protocol)
- Version triple (major, minor, patch)
- Spec identifier
- Mode code
- Gate presence and value
- Tag filter (if present)
- Normalized assertions (sorted by label)
- Optional event kinds
- Optional schedulability parameters (when `testing-schedulability` enabled)

#### 12.2.3 Implementation Examples

**Basic Specification**:

```rust
tb_assert_spec! {
	pub DemoSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		tag_filter: ["v1"],
		assertions: [
			(A, exactly!(1)),
			(R, exactly!(1))
		]
	},
	V(1,1,0): {
		mode: Accept,
		gate: Ok,
		tag_filter: ["v1.1"],
		assertions: [
			(A, exactly!(1)),
			(R, exactly!(2))
		]
	},
}
```

#### 12.2.4 Generated API

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

#### 12.2.5 Cardinality Helpers

The framework provides cardinality constraint macros:

- `exactly!(n)`: Exactly n occurrences
- `at_least!(n)`: Minimum n occurrences
- `at_most!(n)`: Maximum n occurrences
- `between!(min, max)`: Range [min, max] occurrences
- `present!()`: At least one occurrence
- `absent!()`: Zero occurrences

#### 12.2.6 Value Assertion Helpers

The framework provides value assertion helpers for verifying assertion payload values:

- `equals!(value)`: Verify assertion value equality

**Supported Types**:

- **Primitives**: `String`, `&str`, `bool`, `u8`, `u32`, `u64`, `i32`, `i64`, `f64`
- **Numeric literals**: `equals!(3_600)`, `equals!(42u32)`
- **Enums**: `MessagePriority`, `Version` (e.g., `equals!(MessagePriority::LowLatency)`, `equals!(Version::V2)`)
- **Options**: `equals!(Some(value))`, `equals!(None)`
- **Option presence**: `equals!(IsSome)` (matches any `Some(_)`), `equals!(IsNone)` (matches `None`)

**Examples**:

```rust
assertions: [
	(priority, exactly!(1), equals!(MessagePriority::LowLatency)),
	(lifetime, exactly!(1), equals!(3_600)),
	(version, exactly!(1), equals!(Version::V2)),
	(confidentiality, exactly!(1), equals!(IsSome)),
	(optional_field, exactly!(1), equals!(IsNone))
]
```

#### 12.2.7 Tag-Based Assertion Filtering

Assertions can be tagged with arbitrary string labels for flexible categorization and filtering. Tags enable version-scoped testing where a single scenario can validate multiple protocol versions.

#### 12.2.8 Recording Trace Events

`TraceCollector` exposes two entry points:

- `trace.event("label")` records a label-only event (no tags/value) and advances the CSP oracle.
- `trace.event_with("label", &["tag"], value)` records the label with tags plus an optional value (anything implementing `Into<AssertionValue>`, e.g. `bool`, `u64`, `Version`, etc.).:

```rust
trace.event("relay_start")?;
trace.event_with("response_ok", &["tag_a"], true)?;
```

**How Tags Work**:

- Assertions are emitted with tags: `trace.event_with("label", &["tag1", "tag2"], ())`
- Specs filter assertions using `tag_filter: ["tag1"]` - only assertions with matching tags are validated
- A single assertion can satisfy multiple specs by including multiple tags

**Example: Version-Scoped Testing**:

```rust
tb_assert_spec! {
	pub VersionSpec,
	V(0,0,0): {
		mode: Accept,
		gate: Ok,
		tag_filter: ["v0"],
		assertions: [
			(feature, exactly!(1), equals!(IsNone)),
		]
	},
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		tag_filter: ["v1"],
		assertions: [
			(feature, exactly!(1), equals!(IsNone)),
			(v1_specific, exactly!(1))
		]
	}
}

tb_scenario! {
	name: test_all_versions,
	config: ScenarioConfig::builder()
		.with_specs(vec![VersionSpec::get(0, 0, 0), VersionSpec::get(1, 0, 0)])
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// Single assertion satisfies both version specs via tags
			trace.event_with("feature", &["v0", "v1"], Presence::of_option(&some_option))?;
			trace.event_with("v2_specific", &["v1"], ())?;
			Ok(())
		}
	}
}
```

All such events are emitted via the instrumentation subsystem described in §10. Layer 1-3 verification operates over this event stream as the authoritative trace for a single execution.

#### 12.2.9 Schedulability Analysis

Assertion specs support schedulability verification via the `schedulability: { }` block when `testing-schedulability` is enabled:

```rust
schedulability: {
	task_set: my_task_set,
	scheduler: RateMonotonic | EarliestDeadlineFirst,
	must_be_schedulable: true
}
```

Supported schedulers:

- **Rate Monotonic Analysis (RMA)**: Fixed-priority scheduling. The Liu & Layland utilization bound is a sufficient-only fast path (implicit deadlines), with RTA arbitrating above the bound or for constrained deadlines
- **Earliest Deadline First (EDF)**: Dynamic priority scheduling with utilization bound ≤ 1.0 (exact for implicit deadlines)
- **Response Time Analysis (RTA)**: Exact schedulability test for fixed-priority task sets (D ≤ T). EDF task sets are rejected since the fixed-priority recurrence does not model dynamic priorities

Additional features include percentile-based WCET analysis (P50-P99.99), confidence intervals, and fixed-point arithmetic for deterministic calculations. See §12.3.5 for timing constraints in process specifications

### 12.3 Layer 2: Process Specifications (CSP)

#### 12.3.1 Concept

ProcessSpec defines labeled transition systems (LTS) for formal process modeling using Communicating Sequential Processes (CSP) theory. A process specification declares:

- **Observable alphabet (Σ)**: External events visible to the environment
- **Hidden alphabet (τ)**: Internal events not visible externally
- **State space**: Named states and their transitions
- **Terminal states**: Valid end states
- **Nondeterministic states**: States with internal choice

Enabled with `testing-csp` feature flag.

#### 12.3.2 Specification: tb_process_spec! Syntax

```rust
tb_process_spec! {
	pub ProcessName,
	events {
		observable { "event1", "event2", ... }    // External alphabet (Σ)
		hidden { "internal1", "internal2", ... }  // Internal alphabet (τ)
	}
	states {
		S0 => { "event1" => S1 }                  // State transitions
		S1 => { "event2" => S2, "event3" => S3 }  // Nondeterministic branching
		S2 => { "event4" [ guard!(clock1 < 10ms) ] => S3 }  // Timed transition with guard
		S3 => { "event5" [ guard!(clock2 >= 5ms), reset: ["clock1"] ] => S4 }  // Guard with clock reset
		S4 => {}                                  // Terminal state
	}
	terminal { S4 }                               // Valid end states
	choice { S1 }                                 // Nondeterministic states
	clocks: { "clock1", "clock2" }                // Optional: when testing-timing enabled
	timing {                                      // Optional: when testing-timing enabled
		wcet:     { "event1" => wcet!(10ms) },
		jitter:   { "event2" => jitter!(5ms) },
		deadline: { "start" => "end", deadline!(duration: 100ms) },
		slack:    { "start" => "end", slack!(min: 5ms) }
	}
	schedulability {                              // Optional: when testing-schedulability enabled
		scheduler: RateMonotonic,                 // or EarliestDeadlineFirst
		periods: {
			"event1" => 50ms,
			"event2" => 100ms
		}
	}
	annotations { description: "..." }            // Optional metadata
}
```

#### 12.3.3 Validation Rules

When CSP is configured via `.with_csp()` in `tb_scenario!`:

1. **Compile-Time**: Assert labels MUST be in CSP observable alphabet
2. **Runtime**: Observed events MUST form valid CSP trace (framework tracks state)
3. **Post-Execution**: Trace MUST terminate in valid terminal state

#### 12.3.4 Example: CSP Process Specification

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

#### 12.3.5 Timing and Schedulability Verification

When `testing-timing` is enabled, process specifications support timing constraints and timed automata semantics.

**Timing Constraints:**

Process specs support four types of timing constraints via the `timing: { }` block:

- **WCET (Worst-Case Execution Time)**: `wcet: { "event" => wcet!(10ms) }` - Maximum allowed execution time per event
- **Deadline**: `deadline: { "start" => "end", deadline!(duration: 100ms) }` - Maximum latency between start and end events
- **Jitter**: `jitter: { "event" => jitter!(5ms) }` - Maximum timing variation for an event
- **Slack**: Specified via `deadline!(duration: 100ms, slack: 5ms)` - Minimum safety margin

**Timed CSP Semantics:**

Process specs support timed automata semantics with clock variables and timing guards:

- **Clock Variables**: `clocks: { "clock1", "clock2" }` - Named clocks that advance during execution
- **Timing Guards**: `"event" [ guard!(clock1 < 10ms) ] => State` - Transitions enabled only when guard conditions are satisfied
- **Clock Resets**: `"event" [ guard!(clock2 >= 5ms), reset: ["clock1"] ] => State` - Reset clocks when transition is taken

Guard expressions support: `<`, `<=`, `>`, `>=`, `==`, and ranges (`5ms <= x <= 10ms`).

**Early Pruning and FDR Integration:**

Timing violations automatically prune traces during FDR exploration:

- Per-event WCET violations prune immediately
- Deadline violations prune when detected
- Path-based WCET violations prune compositional violations
- Timed transitions filter based on guard satisfaction

When `testing-schedulability` is also enabled, timing constraints and task periods are combined into task sets for Rate Monotonic or EDF analysis. See §12.2.9 for schedulability configuration in assertion specs.

#### 12.3.6 Process Composition: tb_compose_spec!

In addition to individual `ProcessSpec` models, tightbeam supports **composed processes** via the `CompositionSpec` trait and the `tb_compose_spec!` macro. Compositions allow you to build larger CSP models from smaller ones using standard parallel composition operators:

- **Synchronized**: All shared events synchronize (`P || Q`)
- **Interleaved**: No synchronization, pure interleaving (`P ||| Q`)
- **Interface**: Synchronize on an explicit event set (`P [| A |] Q`)
- **Alphabetized**: Per-process alphabets with synchronization on intersection (`P [| αP | αQ |] Q`)

The `tb_compose_spec!` macro generates a type that implements `CompositionSpec` and, via a blanket impl, `ProcessSpec`, so it can be used anywhere a process spec is expected (including with `.with_csp()` in `tb_scenario!`).

**Example: Interleaved request/response and retry flows**

```rust
use tightbeam::testing::*;

// Two simple processes
tb_process_spec! {
	pub RequestFlow,
	events { observable { "request", "response" } }
	states {
		Idle => { "request" => Waiting },
		Waiting => { "response" => Idle }
	}
	terminal { Idle }
}

tb_process_spec! {
	pub RetryFlow,
	events { observable { "retry" } }
	states {
		RetryIdle => { "retry" => RetryIdle }
	}
	terminal { RetryIdle }
}

// Compose them with interleaved parallelism
tb_compose_spec! {
	pub RequestWithRetry,
	processes: {
		RequestFlow,
		RetryFlow
	},
	composition: Interleaved,
	properties: {
		deadlock_free: true,
		livelock_free: true,
		deterministic: false
	}
}

// Use the composed process in a scenario
tb_scenario! {
	name: test_request_with_retry,
	config: ScenarioConfig::builder()
		.with_spec(ClientServerSpec::latest())
		.with_csp(RequestWithRetry)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			trace.event("request")?;
			trace.event("retry")?;
			trace.event("response")?;
			Ok(())
		}
	}
}
```

Composition properties (`deadlock_free`, `livelock_free`, `deterministic`) are checked by the composition verification layer (§12.4, §12.5) and provide an early sanity check before enabling full FDR refinement.

### 12.4 Layer 3: Refinement Checking (FDR)

#### 12.4.1 Concept

Refinement checking provides multi-seed exploration for trace and failures refinement verification. Formal definitions of traces, failures, and divergences are in §12.1.1 and §12.5. Configuration and verdict structure follow. The method is Failures-Divergences Refinement (FDR) from CSP theory. Enable it with the `testing-fdr` feature flag.

**Verification Properties**:

- **Trace Refinement (⊑T)**: All observed traces ∈ spec traces
- **Failures Refinement (⊑F)**: No invalid refusals at choice points
- **Divergence Freedom**: No internal-only loops exceeding threshold
- **Determinism**: Branching only at declared nondeterministic states

**Requirements**: Layer 3 requires `testing-fdr` feature flag. Refinement checking requires the `specs` field in `FdrConfig` to be populated with specification processes.

#### 12.4.2 Specification: FdrConfig Syntax

```rust
fdr: FdrConfig {
	seeds: 64,               // Number of exploration seeds
	max_depth: 128,          // Maximum trace depth
	max_internal_run: 32,    // Divergence detection threshold
	timeout_ms: 5000,        // Per-seed timeout
	specs: vec![],           // Processes for refinement checking (empty = exploration mode)
	fail_fast: true,         // Stop on first violation (default: true)
	expect_failure: false,   // Expect refinement to fail (default: false)

	// Optional scheduler/resource modeling (feature `testing-fault`)
	scheduler_count: None,   // Number of schedulers (m)
	process_count: None,     // Number of concurrent processes (n)
	scheduler_model: None,   // Cooperative / Preemptive model, when enabled

	// Optional fault/FMEA configuration (features `testing-fault`, `testing-fmea`)
	fault_model: None,
	fmea_config: None,
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
- `scheduler_count` / `process_count` (feature `testing-fault`): Optional resource-modeling parameters where `scheduler_count ≤ process_count`. When set, refinement explores traces under constrained scheduler availability (§12.5.4).
- `scheduler_model` (feature `testing-fault`): Chooses between cooperative and preemptive scheduler models for refinement.
- `fault_model` (feature `testing-fault`): Enables CSP state-driven fault injection during FDR exploration (e.g., link drops, node failures).
- `fmea_config` (feature `testing-fmea`): Configures Failure Modes and Effects Analysis integrated with refinement runs.

**Operational Modes**:

- **Mode 1** (specs empty): Single-process exploration - verifies determinism, deadlock freedom, divergence freedom
- **Mode 2** (specs provided): Refinement checking - verifies Spec ⊑ Impl (trace/failures/divergence refinement)

#### 12.4.3 Implementation Examples

**Simple Example**:

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
		gate: Ok,
		assertions: [
			(start, exactly!(1)),
			(finish, exactly!(1))
		]
	},
}

// Test with refinement checking
tb_scenario! {
	name: test_simple_refinement,
	config: ScenarioConfig::builder()
		.with_spec(SimpleSpec::latest())
		.with_fdr(FdrConfig {
			seeds: 4,
			max_depth: 10,
			max_internal_run: 8,
			timeout_ms: 500,
			specs: vec![SimpleProcess::process()],
			fail_fast: true,
			expect_failure: false,
		})
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			trace.event("start")?;
			trace.event("finish")?;
			Ok(())
		}
	}
}
```

#### 12.4.4 Multi-Seed Exploration

The `seeds` parameter controls how many different execution paths are explored during verification. Each seed produces a different scheduling of concurrent operations, uncovering race conditions and nondeterministic behavior:

```rust
fdr: FdrConfig {
	seeds: 64,  // Try 64 different execution orderings
	// ...
}
```

Each seed explores different interleaving at nondeterministic choice points, verifying trace refinement, failures refinement, and divergence freedom across all executions.

#### 12.4.5 FDR Verdict Structure

After multi-seed exploration, tightbeam produces a verdict:

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

> Note: Refinement properties (trace_refines, failures_refines, divergence_refines) are only meaningful when specs are provided in FdrConfig.

### 12.5 Formal CSP Theory

#### 12.5.1 Three Semantic Models

| CSP Model                     | tightbeam Layer | Verification Property           | Refinement Check                |
| ----------------------------- | --------------- | ------------------------------- | ------------------------------- |
| **Traces (T)**                | L1 AssertSpec   | Observable event sequences      | traces(Impl) ⊆ traces(Spec)     |
| **Stable Failures (F)**       | L2 ProcessSpec  | Valid refusals at choice points | failures(Impl) ⊆ failures(Spec) |
| **Failures-Divergences (FD)** | L3 FDR          | Livelock freedom (no τ-loops)   | divergences(Impl) = ∅           |

**Traces Model**: Verifies that all observable event sequences produced by the implementation are allowed by the specification. This ensures basic behavioral correctness - the system never produces an unexpected sequence of external events.

**Stable Failures Model**: Extends trace verification by checking what events a process can _refuse_ after each trace. A stable state is one where no internal progress (τ-transitions) can occur. At choice points, the implementation must not refuse events the specification accepts, preventing incorrect nondeterminism.

**Failures-Divergences Model**: Adds divergence detection to identify processes that can make infinite internal progress without external interaction. A divergence is a τ-loop where the process never becomes stable. The `max_internal_run` parameter bounds consecutive hidden events to detect such livelocks.

#### 12.5.2 Observable vs. Hidden Events

CSP distinguishes between observable events (external alphabet Σ) and hidden events (internal actions τ). This distinction is fundamental to process refinement:

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

**Observable events** represent the process's contract with its environment. These form the basis of trace refinement - implementations and specifications must agree on observable behavior.

**Hidden events** model internal implementation details. They enable refinement checking where implementations contain details absent from abstract specifications. Hidden events are projected away when comparing traces: `trace \ {τ}`.

The instrumentation taxonomy (§10.2) maps tightbeam events to categories:

- **Observable**: `gate_accept`, `gate_reject`, `request_recv`, `response_send`, `assert_label`
- **Hidden (τ)**: `handler_enter`, `handler_exit`, `crypto_step`, `compress_step`, `route_step`, `policy_eval`, `process_hidden`

#### 12.5.3 Nondeterministic Choice and Refusal Sets

CSP provides two choice operators:

- **External choice (□)**: Environment selects which event occurs
- **Internal choice (⊓)**: Process selects non-deterministically

At choice points, a process has an _acceptance set_ (events it can engage) and _refusal set_ (events it cannot engage in stable state). Failures refinement ensures implementations do not introduce invalid refusals:

```rust
states {
	// External choice: environment determines next event
	Connected  => { "request" => Processing, "disconnect" => Idle }

	// Internal choice: process may non-deterministically choose path
	Processing => { "response" => Responded, "error" => ErrorState }
}
choice { Processing }  // Annotate nondeterministic states
```

The `choice` annotation declares states where internal nondeterminism may occur. FDR exploration uses different seeds to explore all possible nondeterministic branches, ensuring the specification covers all implementation behaviors.

#### 12.5.4 Multi-Seed Exploration and Scheduler Interleaving

Based on research by Pedersen & Chalmers,[^pedersen2024] refinement in cooperatively scheduled systems depends on resource availability. With `n` concurrent processes and `m` schedulers where `m < n`, some traces become impossible due to scheduling constraints.

**tightbeam addresses this through multi-seed exploration**: Each seed represents a different scheduling strategy, exploring alternative interleaving of concurrent events. This is analogous to testing with different numbers of schedulers to verify behavior across resource constraints:

```rust
fdr: FdrConfig {
    seeds: 64,              // Explore 64 different scheduling
    max_depth: 128,         // Bound trace length
    max_internal_run: 32,   // Divergence detection threshold
    timeout_ms: 5000,       // Per-seed timeout
}
```

At nondeterministic choice points, the seed determines which branch to explore. Across all seeds, the framework verifies that:

1. **Trace refinement**: All observable traces are valid
2. **Failures refinement**: No invalid refusals at choice points
3. **Divergence freedom**: No seed produces infinite τ-loops

#### 12.5.5 CSPM Export for FDR4 Integration

tightbeam can export process specifications as CSPM (CSP Machine-readable) format for verification with external tools like FDR4:[^fdr4]

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

#### 12.5.6 Trace Analysis Extensions

The `FdrTraceExt` trait extends `ConsumedTrace` with CSP-specific analysis:

```rust
use tightbeam::testing::fdr::FdrTraceExt;

.with_hooks(TestHooks {
	on_pass: Some(Arc::new(|context| {
		// Refinement properties
		if let Some(ref fdr_verdict) = context.fdr_verdict {
			assert!(fdr_verdict.trace_refines);
			assert!(fdr_verdict.failures_refines);
			assert!(fdr_verdict.divergence_free);
			assert!(fdr_verdict.is_deterministic);
		}
		Ok(())
	})),
	on_fail: None,
})
```

**Trace Analysis in Hooks**: Query process behavior and event sequences:

```rust
use tightbeam::testing::fdr::FdrTraceExt;

hooks {
	on_pass: |context| {
		// Acceptance queries: Check what events are accepted at specific states
		if let Some(acceptance) = context.trace.acceptance_at("Connected") {
			// At Connected state, process accepts "serialize"
			assert!(acceptance.iter().any(|e| e.0 == "serialize"));
		}

		// Refusal queries: Verify process can refuse events not in acceptance set
		// At Connected, process must do "serialize" before "request"
		assert!(context.trace.can_refuse_after("Connected", "request"));
		assert!(context.trace.can_refuse_after("Connected", "disconnect"));

		Ok(())
	}
}
```

These queries enable CSP-style reasoning about process behavior at specific states, validating that the implementation matches the formal specification.

### 12.6 Fault Injection

Fault injection enables systematic error testing through CSP state-driven fault injection during refinement checking. Requires `testing-fault` feature flag.

#### 12.6.1 FaultModel Configuration

```rust
use tightbeam::testing::{FaultModel, InjectionStrategy};
use tightbeam::utils::BasisPoints;

let fault_model = FaultModel::from(InjectionStrategy::Deterministic)
	.with_fault(
		States::Sending,              // Type-safe state enum
		Event("response"),            // Event label
		|| NetworkTimeoutError {...}, // Error factory
		BasisPoints::new(3000),       // 30% probability
	)
	.with_seed(0xDEADBEEF);           // Reproducibility
```

#### 12.6.2 Injection Strategies

**Deterministic (Counter-Based):**

```rust
InjectionStrategy::Deterministic
```

- Call counters per event label
- Predictable fault sequences
- Ideal for [DO-178C][do-178c] DAL A, [IEC 61508][iec-61508] SIL 4

**Random (Seeded RNG):**

```rust
InjectionStrategy::Random
```

- Linear Congruential Generator (LCG) with seed
- Statistical coverage analysis
- Same seed produces same fault sequence

#### 12.6.3 Type-Safe State and Event Identifiers

Generate type-safe enums via `tb_gen_process_types!`:

```rust
tb_gen_process_types!(FaultTolerantProcess, Idle, Sending, Retrying, Success, Fallback);

// Generates:
// - fault_tolerant_process::States enum (implements ProcessState)
// - fault_tolerant_process::Event struct (implements ProcessEvent)
```

Manual implementation:

```rust
pub trait ProcessState: Copy + Debug {
	fn process_name(&self) -> &'static str;
	fn state_name(&self) -> &'static str;
	fn full_key(&self) -> Cow<'static, str>;
}

pub trait ProcessEvent: Copy + Debug {
	fn event_label(&self) -> &'static str;
}
```

#### 12.6.4 Integration with FDR

```rust
fdr: FdrConfig {
	seeds: 64,
	fault_model: Some(fault_model),
	specs: vec![MyProcess::process()],
	..Default::default()
}
```

Faults are injected during CSP exploration before state transitions. Injected faults are recorded in `FdrVerdict::faults_injected` with full traceability (state, event, error message, probability).

**Example:** See `tightbeam/tests/fault/basic.rs` for a full fault injection demonstration.

### 12.7 Unified Testing: tb_scenario! Macro

The `tb_scenario!` macro is the unified entry point for all testing layers, executing AssertSpec verifications under selectable environments with optional CSP and FDR verification.

**Design Principles**:

- Single consistent syntax across all verification layers
- Progressive enhancement (L1 -> L1+L2 -> L1+L2+L3)
- Environment abstraction (ServiceClient, Servlet, Worker, Bare, Cluster, Hive)
- Instrumentation integration
- Policy enforcement

#### 12.7.1 Syntax

```rust
tb_scenario! {
	name: test_function_name,        // OPTIONAL: creates standalone #[test] function NOTE: Do NOT use with `fuzz: afl`
	spec: AssertSpecType,            // Layer 1 assertion spec (latest version). Use config: for anything more
	config: ScenarioConfig::builder()  // Full configuration (alternative to spec:)
		.with_spec(AssertSpecType::latest())          // Layer 1 assertion spec
		.with_csp(ProcessSpecType)                    // OPTIONAL: Layer 2 CSP model (requires testing-csp)
		.with_fdr(FdrConfig { ... })                  // OPTIONAL: Layer 3 refinement (requires testing-fdr + csp)
		.with_trace(TraceConfig::builder()            // OPTIONAL: unified trace config (§10)
			.with_instrumentation(TbInstrumentationConfig { ... })
			.with_logger(LoggerConfig::new(...))
			.build())
		.with_hooks(TestHooks { ... })                // OPTIONAL: on_pass/on_fail callbacks
		.build(),
	fuzz: afl,                       // OPTIONAL: AFL fuzzing mode (requires testing-csp)
	environment <Variant> { ... },   // REQUIRED: execution environment (Bare, Worker, ServiceClient, Servlet, Cluster, Hive)
}
```

Exactly one of `spec:` or `config:` configures the scenario. `spec:` expands to a `ScenarioConfig` with that AssertSpec's latest version. `config:` accepts a full `ScenarioConfig` expression.

Every closure receives one environment struct from `tightbeam::testing::env`. Setup-phase closures take `SetupEnv { trace, context }`. Later phases extend that shape: `ClientEnv` adds `addr`, and `ClusterEnv` / `HiveEnv` / `ServletEnv` / `WorkerEnv` add the owned instance. The conventional parameter name is `env`. Destructure the struct in the closure pattern when field aliases read better.

The `context:` key inside the environment block is evaluated once per test and shared as `Arc<C>` with every closure (unit when omitted).

See sections 10.3.4 and 10.4 for detailed environment examples.

#### 12.7.2 Examples

**Bare Environment Example**: Pure logic/function invocation

```rust
use tightbeam::testing::*;

tb_assert_spec! {
	pub BareSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(Received, exactly!(1)),
			(Responded, exactly!(1))
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
	config: ScenarioConfig::builder()
		.with_spec(BareSpec::latest())
		.with_csp(BareProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			trace.event(BareSpec::Received)?;
			trace.event(BareSpec::Responded)?;
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
		gate: Ok,
		assertions: [
			(connect, exactly!(1)),
			(request, exactly!(1)),
			(response, exactly!(2)),
			(disconnect, exactly!(1)),
			(message_content, exactly!(1), equals!("test"))
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
	config: ScenarioConfig::builder()
		.with_spec(ClientServerSpec::latest())
		.with_csp(ClientServerProcess)
		.with_fdr(FdrConfig {
			seeds: 64,
			max_depth: 128,
			max_internal_run: 32,
			timeout_ms: 5000,
			specs: vec![ClientServerProcess::process()],
			fail_fast: true,
			expect_failure: false,
		})
		.with_hooks(TestHooks {
			on_pass: Some(Arc::new(|_context| {
				// Optional: custom logic on test pass
				Ok(())
			})),
			on_fail: Some(Arc::new(|_context, _violation| {
				// Optional: custom logic on test fail
				Err(TightBeamError::MissingResponse)
			})),
		})
		.build(),
	environment ServiceClient {
		worker_threads: 2,
		server: |SetupEnv { trace, .. }| async move {
			let bind_addr = "127.0.0.1:0".parse().expect("invalid bind address");
			let (listener, addr) = <TokioListener as Protocol>::bind(bind_addr).await?;
			let handle = server! {
				protocol TokioListener: listener,
				assertions: trace.share(),
				handle: |frame, trace| async move {
					trace.event("connect")?;
					trace.event("request")?;
					trace.event("response")?;
					Some(frame)
				}
			};
			Ok((handle, addr))
		},
		client: |ClientEnv { trace, addr, .. }| async move {
			let stream = <TokioListener as Protocol>::connect(addr).await?;
			let mut client = <TokioListener as Protocol>::create_transport(stream);

			trace.event("response")?;
			let frame = compose! {
				V0: id: "test",
				order: 1u64,
				message: TestMessage { content: "test".to_string() }
			}?;
			let response = client.emit(frame, None).await?;

			// Decode response and emit value assertion
			if let Some(resp_frame) = response {
				let decoded: TestMessage = crate::decode(&resp_frame.message)?;
				trace.event_with("message_content", &[], decoded.content)?;
			}

			trace.event("disconnect")?;
			Ok(())
		}
	}
}
```

This test verifies:

- **L1**: Correct assertion labels and cardinalities
- **L2**: Valid state transitions with internal events
- **L3**: Trace refinement across multiple exploration seeds

`environment ServiceClient` accepts a `context:` key for state both sides need (certificates, synchronization primitives, observation flags). The expression is evaluated once and shared as `Arc<C>`. The server closure receives a `SetupEnv`. The client closure receives a `ClientEnv` with the bound server address and builds its own connection:

```rust
	environment ServiceClient {
		context: ServerMaterials::generate(),
		server: |env| async move {
			let (listener, addr) = bind_encrypted_listener(&env.context).await?;
			Ok((spawn_server(listener), TightBeamSocketAddr(addr)))
		},
		client: |ClientEnv { trace, context: materials, addr }| async move {
			let pool = build_pool(&materials, mux_offer(), 1)?;
			let mut client = pool.connect(addr).await?;
			// ... emits and trace events ...
			Ok(())
		}
	}
```

#### 12.7.3 Hook Semantics

Hooks provide optional callbacks that can observe and override test outcomes:

- Configured via `.with_hooks(TestHooks { on_pass: Some(...), on_fail: Some(...) })` in the `ScenarioConfig` builder.
- Each hook is a closure wrapped in `Arc`, of type `Arc<dyn Fn(&HookContext) -> Result<(), TightBeamError> + Send + Sync>` for `on_pass` and `Arc<dyn Fn(&HookContext, &SpecViolation) -> Result<(), TightBeamError> + Send + Sync>` for `on_fail`.
- `Ok(())` means the hook accepts the outcome and the test passes.
- `Err(e)` means the hook rejects the outcome and the test fails
- Hooks receive `HookContext` containing the consumed trace, FDR verdict (if enabled), process spec, timing constraints, and assertion spec, allowing inspection of all verification results.

### 12.8 Coverage-Guided Fuzzing with AFL

#### 12.8.1 Concept

tightbeam integrates [AFL.rs](https://github.com/rust-fuzz/afl.rs), a Rust port of American Fuzzy Lop, for coverage-guided fuzzing of protocol implementations. Unlike deterministic random testing, AFL uses evolutionary algorithms with compile-time instrumentation to discover inputs that trigger new code paths.

**How AFL Works**:

1. **Instrumentation**: Code is compiled with coverage tracking (edge counters)
2. **Input Corpus**: Starts with seed inputs, mutates them intelligently
3. **Feedback Loop**: Monitors code coverage, keeps inputs that discover new paths
4. **Crash Detection**: Automatically detects crashes, hangs, and assertion failures

**Integration with tb_scenario!**: The `fuzz: afl` parameter generates AFL-compatible fuzz targets that use the oracle for guided exploration:

```rust
tb_scenario! {
	fuzz: afl,                        // ← AFL fuzzing mode
	config: ScenarioConfig::builder()
		.with_spec(MySpec::latest())
		.with_csp(MyProcess)          // ← oracle for valid state navigation
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// AFL provides random bytes, oracle navigates state machine
			match trace.oracle().fuzz_from_bytes() {
				Ok(()) => {
					for event in trace.oracle().trace() {
						trace.event(event.0)?;
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
- `std` feature flag (required for most fuzz targets)

#### 12.8.2 Creating Fuzz Targets

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
		gate: Ok,
		assertions: [
			(start, exactly!(1)),
			(action_a, at_least!(0)),
			(action_b, at_least!(0)),
			(done, exactly!(1))
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
tb_scenario! {
	fuzz: afl,
	config: ScenarioConfig::builder()
		.with_spec(SimpleFuzzSpec::latest())
		.with_csp(SimpleFuzzProc)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// AFL provides bytes, oracle interprets as state machine choices
			match trace.oracle().fuzz_from_bytes() {
				Ok(()) => {
					for event in trace.oracle().trace() {
						trace.event(event.0)?;
					}
					Ok(())
				}
				Err(_) => Err(TestingError::FuzzInputExhausted.into())
			}
		}
	}
}
```

#### 12.8.3 Building and Running Fuzz Targets

**Prerequisites**:

```bash
cargo install cargo-afl
```

**Run AFL Fuzzer**:

```bash
# Build fuzz targets first
# Note: Some fuzz targets may require additional features
RUSTFLAGS="--cfg fuzzing" cargo afl build --test fuzzing --features "std,testing-csp,testing-fuzz"

# Create seed input directory
mkdir -p fuzz_in
echo "seed" > fuzz_in/seed.txt

# Run AFL fuzzer (find the actual binary name)
FUZZ_TARGET=$(ls target/debug/deps/fuzzing-* 2>/dev/null | grep -v '\.d$' | head -1)
cargo afl fuzz -i fuzz_in -o fuzz_out "$FUZZ_TARGET"
```

#### 12.8.4 Advanced: CSP Oracle Integration

The `CspOracle` interprets AFL's random bytes as state machine navigation choices, ensuring fuzz inputs trigger valid protocol behavior:

**How It Works**:

```
AFL Random Bytes          CspOracle                State Machine
─────────────────  ───►  ───────────────  ───►  ─────────────────
[0x7A, 0x3F, ...]        byte % events.len()     S0 -> S1 -> S2 -> ...
                         selects valid event      (valid trace)
```

Valid events are sorted by label, so the byte-to-event mapping is deterministic across runs (AFL crash inputs replay). When a chosen event has multiple target states (nondeterministic transition), the oracle consumes one additional byte to select the target (`byte % targets.len()` over name-sorted targets), so every branch is reachable under mutation.

**Benefits**:

1. **Valid Traces Only**: Oracle ensures all fuzz inputs produce valid traces
2. **Nondeterminism Exploration**: AFL discovers which byte patterns lead to different branches
3. **Coverage Feedback**: AFL learns which choices uncover new code paths
4. **Crash Attribution**: Crashes map to specific state sequences

**Example Trace** (from crash analysis):

```
Input: [0x00, 0x01, 0x00, 0x02]
Trace: "start" -> "action_a" -> "action_b" -> "done"
State: S0 -> S1 -> S1 -> S2
Result: Crash at state S1 after "action_b"
```

#### 12.8.5 IJON Integration: Input-to-State Correspondence

tightbeam optionally integrates with AFL's IJON extension[^ijon2020] for state-aware fuzzing. IJON enables "input-to-state correspondence" - bridging the semantic gap between fuzzer input mutations and program state exploration.

**IJON Core Concepts**:

- **Annotation-Based Guidance**: Developers annotate interesting state variables
- **Maximization**: `ijon_max(label, value)` - fuzzer tries to maximize value
- **Set Tracking**: `ijon_set(label, value)` - fuzzer discovers unique values
- **Hash Tracking**: `ijon_hashint(label, value)` - track integer distributions

**tightbeam's CSP-Based Approach**:

tightbeam automatically derives IJON annotations from CSP process specifications, eliminating manual annotation while providing formal state coverage guarantees:

| Aspect                | Standard IJON                        | tightbeam CSP Oracle                       |
| --------------------- | ------------------------------------ | ------------------------------------------ |
| **State Definition**  | Manual annotations of raw variables  | Formal CSP process states (automatic)      |
| **Annotation Burden** | Developer must identify & annotate   | Derived from `tb_process_spec!`            |
| **Coverage Metric**   | Arbitrary program values             | State + transition coverage (provable)     |
| **State Abstraction** | Low-level (memory, counters, etc.)   | High-level (protocol semantics)            |
| **Validation**        | None (annotations may be incorrect)  | Trace validation (runtime checking)        |
| **Integration**       | Explicit `IJON_MAX`/`IJON_SET` calls | Automatic when `testing-fuzz-ijon` enabled |

**Automatic IJON Integration**:

When built with `--features testing-fuzz-ijon`, tightbeam's `tb_scenario!` macro automatically inserts IJON calls after each successful fuzz execution

**Comparison with Pure AFL**:

Without IJON, AFL relies solely on code coverage (edge hit counts). With tightbeam's oracle + IJON:

- **AFL alone**: Discovers `branch_A`, `branch_B`, `branch_C` (syntax)
- **AFL + CSP oracle**: Discovers `State_Init -> State_Processing -> State_Done` (semantics)
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

tightbeam equivalent - no manual annotation needed:

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

### 12.9 Feature Matrix

The following table summarizes capabilities available across the testing layers:

| Capability                                      | `testing`        | `testing-csp`            | `testing-fdr`                    | `testing-fuzz`      |
| ----------------------------------------------- | ---------------- | ------------------------ | -------------------------------- | ------------------- |
| **Basic Verification**                          |                  |                          |                                  |                     |
| Single trace verification                       | ✓                | ✓                        | ✓                                | ✓                   |
| Assertion cardinality checks                    | ✓                | ✓                        | ✓                                | ✓                   |
| Crash/panic detection                           | ✓                | ✓                        | ✓                                | ✓                   |
| **CSP Modeling**                                |                  |                          |                                  |                     |
| CSP process modeling                            | –                | ✓                        | ✓                                | –                   |
| Compile-time label validation                   | –                | ✓                        | ✓                                | –                   |
| Runtime trace validation                        | –                | ✓                        | ✓                                | –                   |
| Terminal state verification                     | –                | ✓                        | ✓                                | –                   |
| **FDR Refinement**                              |                  |                          |                                  |                     |
| Multi-seed exploration                          | –                | –                        | ✓                                | –                   |
| Trace refinement (⊑T)                           | –                | –                        | ✓                                | –                   |
| Failures refinement (⊑F)                        | –                | –                        | ✓                                | –                   |
| Divergence detection (τ-loops)                  | –                | –                        | ✓                                | –                   |
| Determinism checking                            | –                | –                        | ✓                                | –                   |
| Refusal set analysis                            | –                | –                        | ✓                                | –                   |
| Acceptance set queries                          | –                | –                        | ✓                                | –                   |
| CSPM export (FDR4)                              | –                | –                        | ✓                                | –                   |
| **AFL Fuzzing**                                 |                  |                          |                                  |                     |
| Coverage-guided fuzzing                         | –                | –                        | –                                | ✓                   |
| Edge coverage tracking                          | –                | –                        | –                                | ✓                   |
| Input corpus evolution                          | –                | –                        | –                                | ✓                   |
| **Timing Verification**                         |                  |                          |                                  |                     |
| Timing constraints (WCET/Deadline/Jitter/Slack) | `testing-timing` | `testing-timing`         | `testing-timing`                 | –                   |
| Timed CSP (clocks, guards)                      | –                | `testing-timing`         | `testing-timing`                 | –                   |
| Schedulability analysis (RMA/EDF)               | –                | `testing-schedulability` | `testing-schedulability`         | –                   |
| Early pruning (timing violations)               | –                | –                        | `testing-fdr` + `testing-timing` | –                   |
| **Combined Capabilities**                       |                  |                          |                                  |                     |
| CSP oracle for fuzzing                          | –                | –                        | –                                | `csp` + `fuzz`      |
| IJON state annotations                          | –                | –                        | –                                | `csp` + `fuzz-ijon` |

### 12.10 Standards Compliance Mapping

The following mapping relates tightbeam verification features to common high-assurance standards and regulations. The framework supports many certification requirements. Final certification evidence and process compliance remain the integrator's responsibility.

#### 12.10.1 DO-178C DAL A / ISO 26262 ASIL-D

**Requirements**: 100% MC/DC coverage, systematic fault injection, and complete traceability from requirements to test evidence.

**tightbeam Support**:

- Deterministic fault injection tied to CSP states/events via `FaultModel` (§12.4.2), configured with `with_fault()` for specific state-event pairs
- Probabilistic fault coverage with `BasisPoints` (0-10000) for precise injection rates
- `InjectedFaultRecord` tracking in `FdrVerdict::faults_injected` provides complete fault campaign traceability
- URN-based evidence artifacts (§10, §11.1.1) link instrumentation events to test assertions
- CSP process specifications (§12.3) model state machines for formal trace verification

#### 12.10.2 IEC 61508 SIL 4

**Requirements**: Systematic fault injection with proof that all error paths are exercised and tested.

**tightbeam Support**:

- `FaultModel` with `InjectionStrategy::Deterministic` ensures reproducible fault campaigns (§12.4.2)
- FDR refinement checking (§12.4) explores all modeled error paths across multiple seeds
- `FdrVerdict` tracks error recovery success/failure counts via `error_recovery_successful` and `error_recovery_failed` fields
- Multi-seed exploration (default 64 seeds) verifies behavior under different scheduling interleavings

#### 12.10.3 NASA/ESA ECSS-E-HB-40A

**Requirements**: Fault tree analysis with coverage of all single-event upsets (SEUs) and failure propagation paths.

**tightbeam Support**:

- Per-transition fault injection models SEUs at the CSP state machine level
- FDR exploration traces fault propagation through the state space
- `CompositionSpec` (§12.3.6) enables hierarchical fault tree modeling via CSP parallel composition
- Instrumentation events (§10) capture fault propagation sequences for post-hoc analysis

#### 12.10.4 Common Criteria EAL7

**Requirements**: Formal verification methods with machine-checkable evidence and complete attack/failure tree coverage.

**tightbeam Support**:

- CSP formal semantics with trace/failures/divergence refinement checking (§12.4)
- Instrumentation evidence artifacts tagged with [RFC 8141][rfc8141]-compliant URNs (§11.1.1)
- `FdrVerdict` provides machine-readable witnesses to violations (trace/failure/divergence witnesses)
- Process specifications export to standard CSP notations for external tool verification

#### 12.10.5 FMEA/FMECA (MIL-STD-1629, ISO 26262)

**Requirements**: Enumerate all failure modes, inject each mode, observe effects, and calculate Risk Priority Numbers (RPN) based on Severity × Occurrence × Detection ratings.

**tightbeam Support**:

- `FmeaConfig` with configurable severity scales (`MilStd1629`, `Iso26262`) and RPN thresholds (default: 100)
- Auto-generated `FmeaReport` from FDR verdicts via `fmea_config` field, containing:
  - `failure_modes`: enumerated failure modes with severity/occurrence/detection
  - `total_rpn`: aggregate risk priority
  - `critical_failures`: indices of failures exceeding RPN threshold
- `FaultModel::with_fault()` allows precise failure mode specification with error factories and injection probabilities
- `FdrVerdict::faults_injected` records all injected faults with CSP context for traceability

**Automatic FMEA Calculation**:

tightbeam automatically calculates Severity, Occurrence, and Detection ratings from FDR exploration results using CSP-based criticality analysis:

1. **Severity** (calculated via CSP reachability analysis):
   - **[MIL-STD-1629][mil-std-1629] scale (1-10)**:
     - 10: Deadlock (system completely stops)
     - 9: Cannot reach terminal states (cannot complete normal operation)
     - 7: Severe restriction (<50% of states reachable)
     - 5: Moderate restriction (50-80% states reachable)
     - 3: Minor impact (>80% states reachable)
   - **[ISO 26262][iso-26262] scale (1-4)**:
     - 4: Catastrophic (deadlock or cannot reach terminal)
     - 3: Hazardous (<50% states reachable)
     - 2: Major (50-80% states reachable)
     - 1: Minor (>80% states reachable)

2. **Occurrence** (converted from `BasisPoints` injection probability):
   - MIL-STD-1629: `probability_bps / 1000` (0-10000 -> 1-10)
   - ISO 26262: `probability_bps / 2500` (0-10000 -> 1-4)

3. **Detection** (calculated from error recovery statistics):
   - Based on `FdrVerdict::error_recovery_successful` vs `error_recovery_failed` counts
   - Inverted success rate: high recovery = low detection number (easily detected)
   - 100% recovery success -> Detection = 1 (easily detected/recoverable)
   - 0% recovery success -> Detection = max scale (undetectable/unrecoverable)

**FMEA Report Structure**:

```rust
pub struct FmeaReport {
	pub failure_modes: Vec<FailureMode>,
	pub severity_scale: SeverityScale,
	pub total_rpn: u32,
	pub critical_failures: Vec<usize>,
}

pub struct FailureMode {
	pub component: String,
	pub failure: String,
	pub effects: Vec<String>,
	pub severity: u8,        // Auto-calculated from CSP reachability
	pub occurrence: u16,     // Auto-converted from BasisPoints
	pub detection: u8,       // Auto-calculated from recovery stats
	pub rpn: u32,            // severity × occurrence × detection
}
```

**Example Configuration**:

```rust
fdr: FdrConfig {
	fault_model: Some(FaultModel::default()
		.with_fault(
			State::Active,
			Event::Send,
			|| TightBeamError::Unavailable,
			BasisPoints::new(2500)  // 25% occurrence
		)
	),
	fmea_config: Some(FmeaConfig {
		severity_scale: SeverityScale::MilStd1629,
		rpn_critical_threshold: 100,
		auto_generate: true,
	}),
	// ... other FDR config
}
```

#### 12.10.6 Standards Compliance Summary

The following table summarizes tightbeam's native support for high-assurance standards requirements:

| Standard        | Level  | Key Requirements                           | tightbeam Features                         | Feature Flags                  |
| --------------- | ------ | ------------------------------------------ | ------------------------------------------ | ------------------------------ |
| DO-178C         | DAL A  | 100% MC/DC, fault injection, traceability  | `FaultModel`, CSP specs, URN evidence      | `testing-fdr`, `testing-fault` |
| ISO 26262       | ASIL-D | Systematic fault injection, FMEA/FMECA     | Auto-FMEA (ISO scale), fault campaigns     | `testing-fdr`, `testing-fmea`  |
| IEC 61508       | SIL 4  | Error path coverage, reproducibility       | Deterministic injection, multi-seed FDR    | `testing-fdr`, `testing-fault` |
| ECSS-E-HB-40A   | –      | SEU coverage, fault tree analysis          | Per-transition injection, CSP composition  | `testing-fdr`, `testing-fault` |
| Common Criteria | EAL7   | Formal methods, machine-checkable evidence | CSP refinement, URN artifacts, CSPM export | `testing-fdr`                  |
| MIL-STD-1629    | –      | FMEA with RPN calculation                  | Auto-severity (1-10), auto-RPN             | `testing-fmea`                 |

**Legend**:

- All features require base `testing` feature
- `testing-fdr` enables FDR refinement checking and multi-seed exploration
- `testing-fault` enables `FaultModel` and deterministic fault injection
- `testing-fmea` enables automatic FMEA report generation
- `instrument` enables URN-based evidence artifacts (independent of testing)

## 13. End-to-End Examples

The following examples are complete and runnable.

### 13.1 Complete Client-Server Application

This example demonstrates an end-to-end worker and servlet setup tested with `tb_scenario!`, covering assertion specs, CSP process specs, and environment integration.

#### Worker Integration Example

```rust
use tightbeam::testing::*;

// Define assertion spec for worker behavior
tb_assert_spec! {
	pub PingPongWorkerSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(relay_start, exactly!(2)),
			(relay_success, exactly!(1)),
			(response_result, exactly!(1), equals!("PONG")),
			(relay_rejected, exactly!(1))
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
	config: ScenarioConfig::builder()
		.with_spec(PingPongWorkerSpec::latest())
		.with_csp(PingPongWorkerProcess)
		.build(),
	environment Worker {
		setup: |_env| {
			PingPongWorker::default()
		},
		stimulus: |WorkerEnv { trace, worker, .. }| async move {
			// Test accepted message
			trace.event("relay_start")?;

			let ping_msg = RequestMessage {
				content: "PING".to_string(),
				lucky_number: 42,
			};

			let response = worker.relay(Arc::new(ping_msg)).await?;
			if let Some(pong) = response {
				trace.event("relay_success")?;
				trace.event_with("response_result", &[], pong.result)?;
			}

			// Test rejected message
			trace.event("relay_start")?;

			let pong_msg = RequestMessage {
				content: "PONG".to_string(),
				lucky_number: 42,
			};

			let result = worker.relay(Arc::new(pong_msg)).await;
			if result.is_err() {
				trace.event("relay_rejected")?;
			}

			Ok(())
		}
	}
}
```

#### Servlet Integration Example

```rust
use tightbeam::testing::*;

// Define assertion spec for servlet behavior
tb_assert_spec! {
	pub PingPongSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(request_received, exactly!(1)),
			(pong_sent, exactly!(1)),
			(response_result, exactly!(1), equals!("PONG")),
			(is_winner, exactly!(1), equals!(true))
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
	config: ScenarioConfig::builder()
		.with_spec(PingPongSpec::latest())
		.with_csp(PingPongProcess)
		.build(),
	environment Servlet {
		start: |env| async move {
			PingPongServletWithWorker::start(Arc::new(env.trace), None).await
		},
		client: |env| async move {
			let (trace, mut client) = (env.trace, env.client);
			fn generate_message(
				lucky_number: u32,
				content: Option<String>
			) -> Result<Frame, TightBeamError> {
				let message = RequestMessage {
					content: content.unwrap_or_else(|| "PING".to_string()),
					lucky_number,
				};

				compose! {
					V0: id: b"test-ping",
						message: message
				}
			}

			// Client-side assertion before sending
			trace.event("request_received")?;

			// Test winning case
			let ping_message = generate_message(42, None)?;
			let Some(response) = client.emit(ping_message, None).await? else {
				return Err(TightBeamError::MissingResponse);
			};
			let response_message: ResponseMessage = decode(&response.message)?;

			// Emit value assertions for spec verification
			trace.event_with("response_result", &[], response_message.result)?;
			trace.event_with("is_winner", &[], response_message.is_winner)?;

			// Client-side assertion after receiving
			trace.event("pong_sent")?;

			Ok(())
		}
	}
}
```

## 14. References

[^hoare1978]: C.A.R. Hoare, "Communicating sequential processes," _Communications of the ACM_, vol. 21, no. 8, pp. 666-677, August 1978. DOI: [10.1145/359576.359585](https://doi.org/10.1145/359576.359585)

[^roscoe2010]: A.W. Roscoe, _Understanding Concurrent Systems_. Springer-Verlag, 2010. ISBN: 978-1-84882-257-3. DOI: [10.1007/978-1-84882-258-0](https://doi.org/10.1007/978-1-84882-258-0)

[^fdr4]: University of Oxford, _FDR4 User Manual_, Version 4.2.7, 2020. Available: [https://www.cs.ox.ac.uk/projects/fdr/](https://www.cs.ox.ac.uk/projects/fdr/)

[^pedersen2024]: M. Pedersen and K. Chalmers, "Refinement Checking of Cooperatively Scheduled Concurrent Systems," in _Formal Methods: Foundations and Applications (SBMF 2024)_, pp. 3-21, 2024. DOI: [10.1007/978-3-031-78561-1_1](https://doi.org/10.48550/arXiv.2510.11751)

[^ijon2020]: C. Aschermann, S. Schumilo, A. Abbasi, and T. Holz, "IJON: Exploring Deep State Spaces via Fuzzing," in _2020 IEEE Symposium on Security and Privacy (SP)_, San Francisco, CA, USA, 2020, pp. 1597-1612. DOI: [10.1109/SP40000.2020.00117](https://doi.org/10.1109/SP40000.2020.00117)

### 14.1 Normative References

- [FIPS 180-4][fips180-4]: Secure Hash Standard (SHS)
- [FIPS 186-5][fips186-5]: Digital Signature Standard (DSS)
- [FIPS 197][fips197]: Advanced Encryption Standard (AES)
- [FIPS 202][fips202]: SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
- [ITU-T X.680][itu-x680]: ASN.1 Specification of basic notation
- [ITU-T X.690][itu-x690]: ASN.1 Distinguished Encoding Rules (DER)
- [NIST SP 800-56A][nist-800-56a]: Recommendation for Pair-Wise Key Establishment Schemes Using Discrete Logarithm Cryptography
- [RFC 2119][rfc2119]: Key words for use in RFCs to Indicate Requirement Levels
- [RFC 3274][rfc3274]: Compressed Data Content Type for Cryptographic Message Syntax (CMS)
- [RFC 3447][rfc3447]: Public-Key Cryptography Standards (PKCS) #1: RSA Cryptography Specifications Version 2.1
- [RFC 5246][rfc5246]: The Transport Layer Security (TLS) Protocol Version 1.2
- [RFC 5280][rfc5280]: Internet X.509 Public Key Infrastructure Certificate and CRL Profile
- [RFC 5480][rfc5480]: Elliptic Curve Cryptography Subject Public Key Information
- [RFC 5652][rfc5652]: Cryptographic Message Syntax (CMS)
- [RFC 5753][rfc5753]: Use of Elliptic Curve Cryptography (ECC) Algorithms in Cryptographic Message Syntax (CMS)
- [RFC 5869][rfc5869]: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- [RFC 8032][rfc8032]: Edwards-Curve Digital Signature Algorithm (EdDSA)
- [RFC 8141][rfc8141]: Uniform Resource Names (URNs)
- [RFC 8174][rfc8174]: Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words
- [RFC 8439][rfc8439]: ChaCha20 and Poly1305 for IETF Protocols
- [SECG SEC 1][secg-sec1]: Elliptic Curve Cryptography (Standards for Efficient Cryptography)

### 14.2 Informative References

- [DO-178C][do-178c]: Software Considerations in Airborne Systems and Equipment Certification
- [FIPS 140-3][fips140-3]: Security Requirements for Cryptographic Modules
- [IEC 61508-1:2010][iec-61508]: Functional safety of electrical/electronic/programmable electronic safety-related systems -- Part 1: General requirements
- [ISO 26262-1:2018][iso-26262]: Road vehicles -- Functional safety -- Part 1: Vocabulary
- [ISO/IEC 18013-5][iso-18013-5]: Personal identification -- ISO-compliant driving licence -- Part 5: Mobile driving licence (mDL) application
- [ITU-T X.400][itu-x400]: Message Handling Systems (MHS): System and service overview
- [ITU-T X.420][itu-x420]: Message Handling Systems (MHS): Interpersonal messaging system
- [MIL-STD-1629A][mil-std-1629]: Procedures for Performing a Failure Mode, Effects and Criticality Analysis (FMECA)
- [NIST SP 800-57][nist-800-57]: Recommendation for Key Management: Part 1 - General
- [RFC 2474][rfc2474]: Definition of the Differentiated Services Field (DS Field) in the IPv4 and IPv6 Headers
- [RFC 3246][rfc3246]: An Expedited Forwarding PHB (Per-Hop Behavior)
- [RFC 4594][rfc4594]: Configuration Guidelines for DiffServ Service Classes
- [RFC 5424][rfc5424]: The Syslog Protocol
- [RFC 6960][rfc6960]: X.509 Internet Public Key Infrastructure Online Certificate Status Protocol (OCSP)
- [RFC 7322][rfc7322]: RFC Style Guide
- [RFC 7748][rfc7748]: Elliptic Curves for Security
- [RFC 8622][rfc8622]: A Lower-Effort Per-Hop Behavior (LE PHB) for Differentiated Services
- [RFC 9113][rfc9113]: HTTP/2
- [RFC 9846][rfc9846]: The Transport Layer Security (TLS) Protocol Version 1.3 (obsoletes RFC 8446)
- [RFC 9901][rfc9901]: Selective Disclosure for JSON Web Tokens (SD-JWT)
- [RFC Editor Style Guide][rfc-style-guide]: Web Portion of the Style Guide

## 15. License

### For Users (Outbound Licensing)

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](../LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](../LICENSE-MIT) or http://opensource.org/licenses/MIT)

**at your option**. You may choose whichever license best fits your needs:

- **Choose MIT** if you prefer simplicity and broad compatibility
- **Choose Apache-2.0** if you want explicit patent protection and retaliation clauses

### For Contributors (Inbound Licensing)

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

**This means contributors grant rights under BOTH licenses**, providing:

- MIT's simplicity for users who prefer it
- Apache-2.0's patent grants for enhanced protection

## 16. Implementation Notes

#### Project Structure

The workspace consists of the following components:

- **tightbeam/src/core.rs**: Shared library code and common utilities
- **tightbeam/src/lib.rs**: Library root
- **tightbeam/tests/**: Integration test suites

[crate-image]: https://img.shields.io/crates/v/tightbeam-rs.svg
[crate-link]: https://crates.io/crates/tightbeam-rs
[docs-image]: https://img.shields.io/docsrs/tightbeam-rs
[docs-link]: https://docs.rs/tightbeam-rs
[build-image]: https://img.shields.io/github/actions/workflow/status/wahidgroup/tightbeam/ci.yaml?branch=master
[build-link]: https://github.com/wahidgroup/tightbeam/actions/workflows/ci.yaml
[license-image]: https://img.shields.io/badge/license-MIT%2FApache--2.0-blue
[rustc-image]: https://img.shields.io/badge/rustc-1.88.0%2B-orange?logo=rust
[chat-image]: https://img.shields.io/badge/chat-Discussions-blue?logo=github
[chat-link]: https://github.com/wahidgroup/tightbeam/discussions

#### Future

- tightbeam-os

[rfc-style-guide]: https://www.rfc-editor.org/styleguide/part2/
[rfc2119]: https://datatracker.ietf.org/doc/html/rfc2119
[rfc2474]: https://datatracker.ietf.org/doc/html/rfc2474
[rfc3246]: https://datatracker.ietf.org/doc/html/rfc3246
[rfc3274]: https://datatracker.ietf.org/doc/html/rfc3274
[rfc3447]: https://datatracker.ietf.org/doc/html/rfc3447
[rfc4594]: https://datatracker.ietf.org/doc/html/rfc4594
[rfc5246]: https://datatracker.ietf.org/doc/html/rfc5246
[rfc5280]: https://datatracker.ietf.org/doc/html/rfc5280
[rfc5424]: https://datatracker.ietf.org/doc/html/rfc5424
[rfc5480]: https://datatracker.ietf.org/doc/html/rfc5480
[rfc5652]: https://datatracker.ietf.org/doc/html/rfc5652
[rfc5652-5]: https://datatracker.ietf.org/doc/html/rfc5652#section-5
[rfc5652-6]: https://datatracker.ietf.org/doc/html/rfc5652#section-6
[rfc5652-11]: https://datatracker.ietf.org/doc/html/rfc5652#section-11
[rfc5753]: https://datatracker.ietf.org/doc/html/rfc5753
[rfc5869]: https://datatracker.ietf.org/doc/html/rfc5869
[rfc6960]: https://datatracker.ietf.org/doc/html/rfc6960
[rfc7322]: https://datatracker.ietf.org/doc/html/rfc7322
[rfc7748]: https://datatracker.ietf.org/doc/html/rfc7748
[rfc8017-9.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-9.2
[rfc8032]: https://datatracker.ietf.org/doc/html/rfc8032
[rfc8141]: https://datatracker.ietf.org/doc/html/rfc8141
[rfc8174]: https://datatracker.ietf.org/doc/html/rfc8174
[rfc8439]: https://datatracker.ietf.org/doc/html/rfc8439
[rfc8622]: https://datatracker.ietf.org/doc/html/rfc8622
[rfc9000]: https://datatracker.ietf.org/doc/html/rfc9000
[rfc9000-4.1]: https://datatracker.ietf.org/doc/html/rfc9000#section-4.1
[rfc9000-20.2]: https://datatracker.ietf.org/doc/html/rfc9000#section-20.2
[rfc9113]: https://datatracker.ietf.org/doc/html/rfc9113
[rfc9113-4.2]: https://datatracker.ietf.org/doc/html/rfc9113#section-4.2
[rfc9113-5.1.1]: https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.1
[rfc9113-5.1.2]: https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.2
[rfc9113-5.2.2]: https://datatracker.ietf.org/doc/html/rfc9113#section-5.2.2
[rfc9113-7]: https://datatracker.ietf.org/doc/html/rfc9113#section-7
[rfc9113-8.1]: https://datatracker.ietf.org/doc/html/rfc9113#section-8.1
[rfc9846]: https://datatracker.ietf.org/doc/html/rfc9846
[rfc9846-4.1.3]: https://datatracker.ietf.org/doc/html/rfc9846#section-4.1.3
[rfc9846-4.7.3]: https://datatracker.ietf.org/doc/html/rfc9846#section-4.7.3
[rfc9846-5.5]: https://datatracker.ietf.org/doc/html/rfc9846#section-5.5
[rfc9846-7.2]: https://datatracker.ietf.org/doc/html/rfc9846#section-7.2
[rfc9901]: https://datatracker.ietf.org/doc/html/rfc9901
[itu-x680]: https://www.itu.int/rec/T-REC-X.680
[itu-x690]: https://www.itu.int/rec/T-REC-X.690
[itu-x400]: https://www.itu.int/rec/T-REC-X.400
[itu-x420]: https://www.itu.int/rec/T-REC-X.420
[fips140-3]: https://csrc.nist.gov/publications/detail/fips/140/3/final
[fips180-4]: https://csrc.nist.gov/publications/detail/fips/180/4/final
[fips186-5]: https://csrc.nist.gov/pubs/fips/186-5/final
[fips197]: https://csrc.nist.gov/publications/detail/fips/197/final
[fips202]: https://csrc.nist.gov/publications/detail/fips/202/final
[nist-800-38d]: https://csrc.nist.gov/publications/detail/sp/800-38d/final
[nist-800-56a]: https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final
[nist-800-57]: https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final
[iso-18013-5]: https://www.iso.org/standard/69084.html
[iso-26262]: https://www.iso.org/standard/68383.html
[iec-61508]: https://webstore.iec.ch/publication/5515
[do-178c]: https://www.rtca.org/do-178/
[mil-std-1629]: https://everyspec.com/MIL-STD/MIL-STD-1600-1699/MIL_STD_1629A_1556/
[secg-sec1]: https://www.secg.org/sec1-v2.pdf
