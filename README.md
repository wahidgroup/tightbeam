# tightbeam

[![Crate][crate-image]][crate-link] [![Docs][docs-image]][docs-link] [![Build Status][build-image]][build-link] ![Apache2/MIT licensed][license-image] ![Rust Version][rustc-image] [![Project Chat][chat-image]][chat-link]

## Status

This project is under active development. Public APIs and file formats MAY change without notice. Not all feature combinations are supported. `no_std` and WASM support is limited. No security audit has been conducted. Use this software at your own risk.

## Copyright Notice

Copyright (C) Tanveer Wahid, WahidGroup, LLC (2025). All Rights Reserved.

## Abstract

tightbeam is a Layer-5 messaging framework. Frames use Abstract Syntax Notation One (ASN.1) with Distinguished Encoding Rules (DER). Versioned metadata carries protocol control data beside the application message.

> Zero-Copy, Zero-Panic, no_std-Ready

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
- 6.5. [Crypto Provider System](#65-crypto-provider-system)
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
  - 8.5.4. [Implementation: HPKE-Based Handshake Protocol](#854-implementation-hpke-based-handshake-protocol)
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

tightbeam defines a structured, versioned messaging protocol with an information fidelity constraint: I(t) ∈ (0,1) for all t ∈ T. Its philosophy is predicated upon a return to first order principles.

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

This document adheres to the [RFC Editor Style Guide][rfc-style-guide] and [RFC 7322][rfc7322] for structure and editorial style:

- **Section pattern**: Normative sections progress through concept, then specification, then implementation, then testing.
- **Requirements language**: Key words are interpreted per [RFC 2119][rfc2119] (see [§1.2 Requirements Language](#12-requirements-language)).
- **Terminology**: Project terms are defined once in [§2 Terminology](#2-terminology) and used consistently thereafter.
- **Citations**: External standards are cited by name and linked on their first mention within a section. Full references are recorded in [§14 References](#14-references). Every entry there is cited at least once in the text, and every in-text citation resolves to an entry there.

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

tightbeam implements high-fidelity information transmission through the following bounds:

- **STRUCTURE**: ASN.1 DER gives a single canonical encoding for equal values ([§5.5 Encoding Rules](#55-encoding-rules)).
- **IDEMPOTENCE**: Each Frame carries a unique `id` for message identification ([§4.1 Version Evolution](#41-version-evolution)).
- **ORDER**: Each Frame carries a monotonic `order` value ([§5.7.1 Message Ordering](#571-message-ordering)).
- **COMPACTNESS**: A Frame MAY carry enforceable compression ([§5.7.2 Compression Requirements](#572-compression-requirements)).
- **INTEGRITY**: Message Integrity (MI) and Frame Integrity (FI) ([§5.7.3 Integrity Semantics](#573-integrity-semantics-order-of-operations)).
- **CONFIDENTIALITY**: A Frame MAY protect the body with AEAD encryption ([§5.7.3](#573-integrity-semantics-order-of-operations)).
- **PRIORITY**: A Frame MAY carry one of six `MessagePriority` levels ([§5.1 Enumerated Types](#51-enumerated-types)).
- **LIFETIME**: A Frame MAY carry a 64-bit TTL in `lifetime` ([§4.3 Metadata Specification](#43-metadata-specification)).
- **STATE**: Previous Frame chaining links snapshots across time ([§5.7.4 Previous Frame Chaining](#574-previous-frame-chaining)).
- **MATRIX**: Matrix carries dense application control state ([§5.8 What is the Matrix?](#58-what-is-the-matrix)).
- **NONREPUDIATION**: A signature MAY bind a signed Frame ([§5.7.5 Nonrepudiation Coverage and Binding](#575-nonrepudiation-coverage-and-binding)).

## 4. Protocol Specification

### 4.1 Version Evolution

Protocol versions evolve under three rules. Implementation: [docs/frame.md](docs/frame.md#versions-and-gated-fields).

- Each protocol version inherits the required features of the prior version.
- A higher version MAY add optional features.
- Receivers that implement version N MUST accept Frames that use only features defined for version N or earlier, when those features remain valid for the negotiated version.

| Version | Required features                                          | Optional features                                                             |
| ------- | ---------------------------------------------------------- | ----------------------------------------------------------------------------- |
| V0      | Message identification (`id`), temporal ordering (`order`) | Compression (`compactness`)                                                   |
| V1      | All V0 required features                                   | Message Integrity (MI), Frame Integrity (FI), confidentiality, Nonrepudiation |
| V2      | All V1 required features                                   | Priority (`MessagePriority`), lifetime (TTL), Previous Frame chaining         |
| V3      | All V2 required features                                   | Matrix control                                                                |

> Note: Concrete field requirements and forbidden fields are stated in [§5.6 Version-Specific Constraints](#56-version-specific-constraints). Semantic rules for integrity, chaining, and signatures are stated in [§5.7 Semantic Constraints](#57-semantic-constraints).

### 4.2 Frame Structure

Every Frame MUST carry these elements:

- Frame `Version`
- Identifier (`Metadata.id`)
- Order (`Metadata.order`)
- Message payload (`Frame.message`)

A Frame MAY also carry:

- Message Integrity (MI) in `Metadata.integrity` ([§5.7.3](#573-integrity-semantics-order-of-operations))
- Frame Integrity (FI) in `Frame.integrity`: digest over `version` and `metadata`. It MUST exclude `message` ([§5.7.3](#573-integrity-semantics-order-of-operations))
- Nonrepudiation in `Frame.nonrepudiation` ([§5.7.5](#575-nonrepudiation-coverage-and-binding))

Which optional fields a version MAY emit is stated in [§5.6](#56-version-specific-constraints). The metadata follows in [§4.3](#43-metadata-specification), and the envelope in [§4.4](#44-frame-encapsulation). Implementation: [docs/frame.md](docs/frame.md#frame-and-metadata).

### 4.3 Metadata Specification

`Metadata` holds identity, order, and optional control fields. Version gates for each field are in [§5.6](#56-version-specific-constraints). The ASN.1 type and its tags are in [§5.3](#metadata-structure). Implementation: [docs/frame.md](docs/frame.md#frame-and-metadata).

> Note: `Metadata.integrity` is Message Integrity (MI). `Frame.integrity` is Frame Integrity (FI). Both MAY appear from V1 onward. The two share a type name and differ in coverage. See [§5.7.3](#573-integrity-semantics-order-of-operations).

### 4.4 Frame Encapsulation

A Frame is the top-level envelope. It carries the version, the metadata, the message, and optionally FI and Nonrepudiation. Implementation: [docs/frame.md](docs/frame.md#framebuilder-and-compose).

No Frame in memory carries a field its version forbids ([§5.6](#56-version-specific-constraints)). Building a Frame and decoding one both refuse such a field, and so does every step that changes a Frame in place.

Nonrepudiation is a CMS `SignerInfo` ([RFC 5652][rfc5652] §5.3). A signature read from the wire is trusted only after it verifies under a certificate the receiver admits for signing ([§5.7.5](#575-nonrepudiation-coverage-and-binding)).

## 5. ASN.1 Formal Specification

ASN.1 types for the tightbeam wire format use [ITU-T X.680][itu-x680] notation and Distinguished Encoding Rules (DER) per [ITU-T X.690][itu-x690]. Semantic constraints are in [§5.6](#56-version-specific-constraints) through [§5.8](#58-what-is-the-matrix). The assembled module is in [§5.9](#59-complete-asn1-module).

### 5.1 Enumerated Types

The protocol defines two enumerations, `Version` and `MessagePriority`. Implementation: [docs/frame.md](docs/frame.md#enumerated-types).

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

tightbeam reuses CMS and PKCS structures for digests, encryption, signatures, and compression ([RFC 5652][rfc5652], [RFC 3447][rfc3447], [RFC 3274][rfc3274]). Implementation: [docs/frame.md](docs/frame.md#cryptographic-structures).

#### Digest Information ([RFC 3447][rfc3447] PKCS #1)

From RFC 3447 Section 9.2:

```asn1
DigestInfo ::= SEQUENCE {
	digestAlgorithm  AlgorithmIdentifier,
	digest           OCTET STRING
}
```

> Note: `DigestInfo` is reused in three roles: Message Integrity (`Metadata.integrity`), Frame Integrity (`Frame.integrity`), and Previous Frame chaining (`previousFrame`). The type is the same in each role, and the covered bytes differ.

#### Authenticated-Enveloped Data ([RFC 5083][rfc5083] CMS)

From RFC 5083 Section 2.1:

```asn1
AuthEnvelopedData ::= SEQUENCE {
	version                    CMSVersion,
	originatorInfo             [0] IMPLICIT OriginatorInfo OPTIONAL,
	recipientInfos             RecipientInfos,
	authEncryptedContentInfo   EncryptedContentInfo,
	authAttrs                  [1] IMPLICIT AuthAttributes OPTIONAL,
	mac                        MessageAuthenticationCode,
	unauthAttrs                [2] IMPLICIT UnauthAttributes OPTIONAL
}
```

`Metadata.confidentiality` holds this type for body encryption:

- The ciphertext travels in `Frame.message`, detached from the envelope as [RFC 5652][rfc5652] §6.1 permits.
- The content cipher is the provider's AEAD, AES-256-GCM with `GCMParameters` ([RFC 5084][rfc5084]) in the reference provider, under a fresh content key for each frame.
- The content type is among the `authAttrs`, and a receiver refuses `authAttrs` that did not arrive as DER ([RFC 5083][rfc5083] §2.1).
- The one recipient is a `KEKRecipientInfo` named by the key identifier of its key-encryption key, or a `KEMRecipientInfo` ([RFC 9629][rfc9629]) to the recipient's public key.

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

> Note: `Frame.nonrepudiation` holds this type for Nonrepudiation signatures.

#### Compressed Data ([RFC 3274][rfc3274] CMS)

From RFC 3274 Section 2:

```asn1
CompressedData ::= SEQUENCE {
	version                    CMSVersion,
	compressionAlgorithm       CompressionAlgorithmIdentifier,
	encapContentInfo           EncapsulatedContentInfo
}
```

> Note: `Metadata.compactness` holds this type for compression. Compression rules are in [§5.7.2](#572-compression-requirements).

#### Matrix (tightbeam-specific)

```asn1
Matrix ::= SEQUENCE {
	n     INTEGER (1..255),
	data  OCTET STRING (SIZE(1..65025))  -- MUST be exactly n*n octets. Row-major.
}
```

> Note: `Metadata.matrix` holds this type. Full Matrix rules are in [§5.8 What is the Matrix?](#58-what-is-the-matrix).

### 5.3 Message Structure

These ASN.1 types define the metadata of [§4.3](#43-metadata-specification) and the envelope of [§4.4](#44-frame-encapsulation). Implementation: [docs/frame.md](docs/frame.md#frame-and-metadata).

#### Metadata Structure

```asn1
Metadata ::= SEQUENCE {
	-- Core fields (V0+)
	id               OCTET STRING,
	order            INTEGER,
	compactness      CompressedData OPTIONAL,

	-- V1+ fields (context-specific tags)
	integrity        [0] DigestInfo OPTIONAL,           -- Message Integrity (MI)
	confidentiality  [1] AuthEnvelopedData OPTIONAL,

	-- V2+ fields (context-specific tags)
	priority         [2] MessagePriority OPTIONAL,
	lifetime         [3] INTEGER OPTIONAL,
	previousFrame    [4] DigestInfo OPTIONAL,           -- prior Frame digest; not FI

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

The protocol imports standard algorithm and identifier types from CMS and related RFCs. Implementation: [docs/frame.md](docs/frame.md#cryptographic-structures).

#### Algorithm Identifier ([RFC 5652][rfc5652] CMS)

From RFC 5652 Section 10.1.2:

```asn1
AlgorithmIdentifier ::= SEQUENCE {
	algorithm   OBJECT IDENTIFIER,
	parameters  ANY DEFINED BY algorithm OPTIONAL
}
```

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

> Note: The numeric form is `1.3.6.1.4.1.64586.2.1`.

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

The wire form follows six rules. Implementation: [docs/frame.md](docs/frame.md#encoding).

- Encoders MUST use DER as specified in [ITU-T X.690][itu-x690].
- Multi-byte integers use network byte order (big-endian).
- Textual content uses UTF-8. Binary fields use raw octets.
- Absent optional fields MUST NOT be encoded.
- Decoders MUST refuse a `SET OF` under its universal tag whose elements are not in ascending DER order ([ITU-T X.690][itu-x690] § 11.6).
- Decoders MUST refuse a `Frame` or a `Metadata` that repeats a context-tagged field or carries one out of schema order ([ITU-T X.690][itu-x690] § 8.9.2).

### 5.6 Version-Specific Constraints

Each protocol version has required, optional, and forbidden Frame and Metadata fields. Feature intent is summarized in [§4.1 Version Evolution](#41-version-evolution). Implementation: [docs/frame.md](docs/frame.md#versions-and-gated-fields).

| Version | Required fields          | Optional fields                                                                              | Forbidden                        |
| ------- | ------------------------ | -------------------------------------------------------------------------------------------- | -------------------------------- |
| V0      | `id`, `order`, `message` | `compactness`                                                                                | Fields introduced in V1 or later |
| V1      | All V0 required fields   | `Metadata.integrity` (MI), `confidentiality`, `Frame.nonrepudiation`, `Frame.integrity` (FI) | Fields introduced in V2 or later |
| V2      | All V1 required fields   | `priority`, `lifetime`, `previousFrame`                                                      | Fields introduced in V3 or later |
| V3      | All V2 required fields   | `matrix`                                                                                     | None beyond the ASN.1 schema     |

Every version follows these rules:

- A version that inherits prior requirements MUST satisfy every required field of those prior versions.
- Absent optional fields MUST NOT be encoded (DER).
- Encoders MUST NOT emit a field that is forbidden for the Frame version in use.
- Decoders MUST reject Frames that carry forbidden fields for the declared version.

### 5.7 Semantic Constraints

The following rules cover ordering, compression, integrity, chaining, and Nonrepudiation. They fix validation semantics and data-retention choices. Implementation: [docs/frame.md](docs/frame.md#semantic-constraints).

#### 5.7.1 Message Ordering

- The `order` field MUST increase monotonically within a message sequence.
- When ordering is time-based, `order` values SHOULD come from a reliable clock or counter source.
- Receivers MUST reject duplicate `order` values inside the same message namespace.

#### 5.7.2 Compression Requirements

- When `compactness` is present, `message` MUST hold the compressed bytes, and `compactness` MUST hold the `CompressedData` per [RFC 3274][rfc3274] that describes them, with no `eContent`.
- If the compressed bytes do not match a recognized content type, `encapContentInfo` MUST use the `id-data` content type OID.
- Compression algorithm identifiers MUST be valid OIDs. zlib uses `id-alg-zlibCompress`. zstd uses Wahid Group PEN `1.3.6.1.4.1.64586.2.1` until an S/MIME registry OID exists.
- When `compressionAlgorithm.parameters` carries a level, that level MUST stay inside the algorithm-specific valid range.
- Receivers MUST refuse a `CompressedData` whose version is not 0, that carries an `eContent`, or whose algorithm or parameters their inflator does not reverse, before they inflate the body.

#### 5.7.3 Integrity Semantics: Order of Operations

Message Integrity (MI) and Frame Integrity (FI) bind different byte ranges. Receivers MUST apply each check to the correct coverage.

| Term                   | Coverage                             | Binding rule                                                                |
| ---------------------- | ------------------------------------ | --------------------------------------------------------------------------- |
| Message Integrity (MI) | Message payload bytes                | When `Metadata.integrity` is present, MI MUST bind the message body.        |
| Frame Integrity (FI)   | DER-canonical `version` + `metadata` | FI MUST exclude `message`. FI MUST bind the frame envelope around the body. |

- FI proves only that `version` and `metadata` are intact. MI proves the message content.
- MI lives in the metadata that FI covers, so an authenticated FI (signed or consensus-backed) detects a change to MI.
- An unsigned FI MUST NOT be trusted against an attacker who can rewrite both MI and FI.

##### Optional Hiding Commitment (Salt)

By default, MI is a plain-mode commitment over the body, which is binding but not hiding. The digest travels in cleartext metadata, so if the body has low entropy, an attacker who sees the digest MAY brute-force candidate preimages.

An application MAY store a hiding commitment in the same `Metadata.integrity` field. The commitment salts the body with a secret, high-entropy blinding value.

**Commitment formula**

`H(0x01 || len(salt) || salt || DER(message))` when hiding, and `H(0x00 || DER(message))` when not.

- `len(salt)` is an 8-byte big-endian integer.
- Distinct `(salt, message)` pairs cannot collide under concatenation ambiguity.
- The leading mode byte separates the two forms, so neither verifies as the other, and neither equals `H(DER(message))`.
- A salt MUST be empty or at least 16 bytes. A shorter salt is refused, because it would not hide the body.
- Disclosing `(salt, message)` proves the committed content in constant time.
- The pattern matches the salted-hash disclose-then-verify construction in SD-JWT ([RFC 9901][rfc9901]) and ISO mdoc ([ISO/IEC 18013-5][iso-18013-5]).

**Salt ownership**

The salt belongs to the caller, which generates it and decides whether to encrypt, store, or transmit it.

| Concern                 | Owner                                  |
| ----------------------- | -------------------------------------- |
| Salt entropy            | Caller MUST provide at least 16 bytes. |
| Opening retention       | Caller MUST decide where it lives.     |
| Disclosure              | Caller MUST control it.                |
| Self-contained envelope | Caller MUST define it when needed.     |

One example of a caller-defined envelope is a credential that carries an encrypted salt beside the body for later selective disclosure.

**Recommended pattern (confidentiality enabled)**

Carry the salt inside the sealed body. The opening is then recoverable by decryption alone.

1. Wrap the payload with its blinding salt.
2. Commit to the payload under that salt.
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

When confidentiality is enabled, implementations MUST use Authenticated Encryption with Associated Data (AEAD). The requirement is checked when the code compiles.

- An encryptor is bound to the content-encryption algorithm it names, so the identifier on the wire cannot diverge from the encryptor, even when the message type has no security profile.
- The envelope is `AuthEnvelopedData` ([RFC 5083][rfc5083]), whose content cipher is an AEAD.
- AEAD tags prove that ciphertext was not modified. Examples include AES-GCM ([FIPS 197][fips197]) and ChaCha20-Poly1305 ([RFC 8439][rfc8439]).
- MI proves that decrypted plaintext matches the original message content.

When AEAD is enforced, the construction is cryptographically equivalent to Encrypt-then-MAC for ciphertext authenticity:

- An attacker cannot modify the ciphertext without failing AEAD authentication.
- An attacker cannot modify MI without breaking authenticated FI when signing is present.
- An attacker cannot decrypt without the key.

#### 5.7.4 Previous Frame Chaining

The `previousFrame` field links Frames through a cryptographic hash chain. Each digest commits to prior history by transitive hashing.

- **Causal ordering**: A Frame carries proof of its position in the sequence.
- **Tamper detection**: A change to an earlier Frame breaks every later digest.
- **Replay protection**: Receivers can detect out-of-sequence or duplicate Frames.
- **Fork detection**: Two Frames that share one `previousFrame` digest indicate a branch.
- **Stateless verification**: Ancestry can be checked without storing the entire chain.

Implementations MAY retain Frame or message bytes so they can reconstruct the chain back to a chosen root.

#### 5.7.5 Nonrepudiation Coverage and Binding

When `nonrepudiation` is present, the signature MUST cover the canonical DER encoding of the Frame fields except the `nonrepudiation` field itself. These are the covered fields:

- `version`
- `metadata`, including MI when present
- `message`
- `integrity` (FI), when FI is present

Any change to those fields invalidates the signature. The resulting binding is transitive:

- The signature binds the frame envelope, including FI when present.
- FI binds the metadata envelope, including MI when present.
- MI binds the message body.

The `SignerInfo` signs those bytes as CMS content of type `id-data` ([RFC 5652][rfc5652] §5.4). Every field has one value:

| Field             | Value                                                                                                                                                                  |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `version`         | 3 when `sid` is a `subjectKeyIdentifier`, 1 when it is an `issuerAndSerialNumber` (RFC 5652 §5.3)                                                                      |
| `sid`             | The subjectKeyIdentifier extension of the signer certificate, or its issuer and serial number when it carries none                                                     |
| `digestAlgorithm` | The digest the signature algorithm names ([RFC 5753][rfc5753] §2.1.1), so the signature type fixes both                          |
| `signedAttrs`     | Exactly three: content type `id-data`, the message digest of the bytes above, and `CMSAlgorithmProtection` ([RFC 6211][rfc6211]) |
| `signature`       | The DER `ECDSA-Sig-Value` ([RFC 3279][rfc3279] §2.2.3) over the digest of the DER signed attributes, with `s` in the low half    |

- A signer brings every value a key or a key provider returns to that DER low-`s` form before it attaches it, and refuses a value that is not DER.
- A verifier MUST refuse a raw `r‖s` signature, a digest the signature algorithm does not name, a missing or extra signed attribute, an algorithm protection that names other algorithms, and a version that breaks the `sid` rule.
- A verifier MUST accept a DER signature whose `s` is in the high half, because ECDSA verifies both values ([SEC 1][secg-sec1] v2.0 §4.1.4). It normalizes `s` to the low half before it verifies.
- The signature in that low-`s` form is the replay key of every ledger: the hive command guard, the gateway registration guard, and the gossip digest and journal. A capture with `s` flipped to `n - s` therefore finds the slot its original spent.
- A key that signs in place travels beside its certificate. The key is checked against the certificate when the two are paired, and the `sid` is read from the certificate ([§7.3](#73-cryptographic-key-management)).

**Figure: nonrepudiation binding**

```text
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
3. Encrypt with an AEAD cipher to produce authenticated ciphertext. Store the `AuthEnvelopedData` in `Metadata` and the ciphertext in `Frame.message`.
4. Compute FI over the envelope (`Version` + `Metadata` that contains MI). Store `DigestInfo` in `Frame`.
5. Sign the complete frame (`Version` + `Metadata` + ciphertext + FI). Store `SignerInfo` in `Frame`.

**Receiver verification (in order):**

1. Verify the signature over the complete Frame and message bytes in scope.
2. Verify FI over the envelope (`Version` + `Metadata`).
3. Verify the AEAD authentication tag on the ciphertext.
4. Decrypt the ciphertext to recover plaintext.
5. Verify that MI matches the decrypted plaintext.

Each layer protects one property, and tampering at any layer MUST cause verification to fail:

| Layer     | Property                                     |
| --------- | -------------------------------------------- |
| AEAD      | Ciphertext authenticity                      |
| FI        | Envelope integrity, including MI in metadata |
| MI        | Plaintext correctness after decryption       |
| Signature | Nonrepudiation over the signed frame         |

### 5.8 What is the Matrix?

The `Matrix` type carries compact application state inside a Frame. It is an **n x n** grid of octets. ASN.1 DER encodes the grid so that equal values always produce the same bytes. The application assigns meaning to each cell. The optional `Metadata.matrix` field is available in protocol version V3 and later. These bounds support the information-fidelity constraint **I(t) ∈ (0,1)**.

#### 5.8.1 Why Use the Matrix?

Applications use the matrix when they need dense, version-tolerant control state on the wire.

- A matrix holds up to 255x255 cell values in the range 0-255 (max ~63.5 KB).
- Newer senders MAY set cells that older receivers SHOULD ignore.
- Deterministic DER encoding and length checks keep invalid grids off the wire.
- Applications MAY combine the matrix with `previousFrame` to bind successive state.

The matrix carries structured control or status data that benefits from a fixed grid layout, beside the message payload.

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

```text
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
- Receivers SHOULD ignore non-zero values in cells the local application has not defined.
- If `Metadata.matrix` is omitted, the application MAY assume a default matrix state.

#### 5.8.5 Example: Flag System

The following example sets diagonal feature flags in a 3x3 matrix and embeds the matrix in a Frame:

```rust
# use tightbeam::compose;
# use tightbeam::prelude::MatrixDyn;
# use tightbeam::testing::TestMessage;
use tightbeam::prelude::{Matrix, MatrixLike};
# let my_message = TestMessage::sample(None);

// Full 3x3 matrix
let mut matrix = Matrix::<3>::default();
matrix.set(0, 0, 1); // Feature A: enabled
matrix.set(1, 1, 1); // Feature B: enabled
matrix.set(2, 2, 0); // Feature C: disabled

// Embed in a frame
let frame = compose! {
    V3: id: "config-001",
        order: 1000,
        message: my_message,
        matrix: matrix
}?;
# let carried = frame.metadata().matrix().map(MatrixDyn::as_bytes);
# assert_eq!(carried, Some(&[1, 0, 0, 0, 1, 0, 0, 0, 0][..]));
# Ok::<(), tightbeam::TightBeamError>(())
```

**Figure: resulting 3x3 flag matrix**

```text
[1, 0, 0]
[0, 1, 0]
[0, 0, 0]
```

A diagonal layout supports up to 255 distinct flags. Applications MAY extend the flag set by defining additional diagonal entries. For structured data that is not a flag, applications SHOULD use non-diagonal cells. For example, **M[0,1] = 10** MAY represent a count, and a block of cells MAY hold a public key or similar fixed-layout value.

#### 5.8.6 Advanced: Modeling with Matrix and Previous Frame

Applications MAY combine the matrix with the `previousFrame` field to track state across Frames. In this model, each Frame is a snapshot. The `previousFrame` digest binds the current Frame to an earlier Frame. When verification succeeds, the linked snapshots form a directed acyclic graph (DAG) of state.

A useful mathematical view treats the sequence as a Markov chain. The matrix **M_t** at time t depends on **M\_{t-1}**. The cryptographic digest in `previousFrame` supplies the causal link between those snapshots.

- **Snapshot**: The matrix **M_t** carried by the Frame at time t. Its entropy is at most **8n²** bits.
- **Causal link**: A verified `previousFrame` digest that binds Frame t to Frame t-1.
- **Transition**: A change in one or more cells from **M\_{t-1}** to **M_t**.
- **Branch**: Two or more Frames that share the same `previousFrame` digest but carry different matrices **M_t**.

**Figure: causal chain of matrix snapshots**

```text
Frame t-1 (M_{t-1})
        |
        |  previousFrame digest verifies against prior Frame
        v
Frame t   (M_t)
        |
        |  previousFrame digest verifies against prior Frame
        v
Frame t+1 (M_{t+1})
```

Applications MAY define a transition model **P(M_t | M\_{t-1})**. The model may capture deterministic application logic, noise, or both. Application-level fidelity MAY be expressed with mutual information, for example:

`I(t) = I(M_t; M_{t-1}) / H(M_t) ∈ (0,1)`.

That ratio is application-defined. Protocol integrity still depends on digest verification and on the matrix encoding rules in [§5.8.4](#584-usage-rules). Partial recovery of earlier state remains an application concern when some cells are unused or unknown.

#### 5.8.7 Summary

The matrix provides a bounded **n x n** octet grid for application state. DER encoding and the rules in [§5.8.4](#584-usage-rules) keep the wire form deterministic and checkable. Simple deployments MAY use diagonal flags or small game-style grids. Advanced deployments MAY chain matrices through `previousFrame` to model causal state over time.

### 5.9 Complete ASN.1 Module

The following module collects the types from this section into one ASN.1 module for reference.

```asn1
tightbeam-Protocol-V3 DEFINITIONS EXPLICIT TAGS ::= BEGIN

-- Import standard structures from CMS and PKCS
IMPORTS
	AlgorithmIdentifier FROM PKCS-1
		{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) },
	DigestInfo FROM PKCS-1
		{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) },
	CompressedData FROM CMS-2004
		{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) modules(0) cms-2004(24) },
	SignerInfo FROM CMS-2004
		{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) modules(0) cms-2004(24) },
	AuthEnvelopedData FROM CMS-AuthEnvelopedData-2007
		{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) modules(0) cms-authEnvelopedData(31) };

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
	data  OCTET STRING (SIZE(1..65025))  -- MUST be exactly n*n octets; row-major
}

-- Core message structures
Metadata ::= SEQUENCE {
	id               OCTET STRING,
	order            INTEGER,
	compactness      CompressedData OPTIONAL,
	integrity        [0] DigestInfo OPTIONAL,           -- Message Integrity (MI)
	confidentiality  [1] AuthEnvelopedData OPTIONAL,
	priority         [2] MessagePriority OPTIONAL,
	lifetime         [3] INTEGER OPTIONAL,
	previousFrame    [4] DigestInfo OPTIONAL,           -- prior Frame digest; not FI
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

A security profile declares algorithm OIDs at compile time. A crypto provider runs the operations of those algorithms at run time. Message-level requirements are specified in [§6.4](#64-message-level-security-requirements).

### 6.1 SecurityProfile Trait Architecture

A security profile is compile-time metadata about the algorithms of one security context:

- It declares which algorithm identifiers (OIDs) a message type or component MAY use.
- A crypto provider supplies the operations at run time ([§6.5](#65-crypto-provider-system)).
- An application declares a profile as a type that implements `SecurityProfile` ([§6.2](#62-security-profile-types)).

Implementation: [docs/security.md](docs/security.md#security-profiles)

#### Design Principles

A profile names six algorithms, each by its OID:

- the digest
- the AEAD cipher
- the signature
- the KDF
- the key exchange
- the key wrap

The AEAD OID names the cipher, and the cipher fixes the key length.

#### Cryptographic Roles

tightbeam splits cryptographic work into roles, so a component depends only on the roles it needs. Each role runs a family of standard algorithms:

- **Digest**: Hash and digest operations. Examples include SHA-256 ([FIPS 180-4][fips180-4]) and SHA3-256 ([FIPS 202][fips202]).
- **AEAD**: Authenticated encryption. Examples include AES-GCM variants.
- **Key wrap**: The wrap of a content key. Examples include AES key wrap ([RFC 3394][rfc3394]).
- **Signature**: Signature generation and verification. Examples include ECDSA ([FIPS 186-5][fips186-5]) and Ed25519 ([RFC 8032][rfc8032]).
- **KDF**: Key derivation. Examples include HKDF ([RFC 5869][rfc5869]).
- **Key exchange**: The ephemeral exchange of a handshake and of each rekey. Examples include ECDH over secp256k1 or P-384 ([RFC 5480][rfc5480]), X25519 ([RFC 7748][rfc7748]), and ML-KEM ([FIPS 203][fips203]). The signature role is independent of it.

A crypto provider binds one implementation to each role ([§6.5](#65-crypto-provider-system)).

### 6.2 Security Profile Types

An application implements `SecurityProfile` to fix the algorithm set for a security context. Different message types MAY use different profile types.

Implementation: [docs/security.md](docs/security.md#profile-types)

#### Implementing Custom Profiles

```rust
# use tightbeam::crypto::aead::Aes256GcmOid;
# use tightbeam::crypto::exchange::Ecdhe;
# use tightbeam::crypto::hash::Sha3_256;
# use tightbeam::crypto::k256;
# use tightbeam::crypto::kdf::HkdfSha3_256;
# use tightbeam::crypto::profiles::{Aes256Wrap, SecurityProfile};
# use tightbeam::crypto::sign::ecdsa::Secp256k1Signature;
// Example: Custom application profile
pub struct MyAppProfile;

impl SecurityProfile for MyAppProfile {
	type Digest = Sha3_256;
	type AeadOid = Aes256GcmOid;
	type SignatureAlg = Secp256k1Signature;
	type Kdf = HkdfSha3_256;
	type KeyExchange = Ecdhe<k256::Secp256k1>;
	type KeyWrapOid = Aes256Wrap;
}
```

#### Built-in Default Profile

The built-in default profile is the reference profile. It names the algorithms of the reference provider, which [§6.5](#65-crypto-provider-system) lists.

> Note: Applications MAY define additional profiles for other contexts. Examples include a high-assurance profile, a legacy-interop profile, or a post-quantum profile. Bind each profile to the message types that require it ([§6.4](#64-message-level-security-requirements)).

### 6.3 Numeric Security Levels

Numeric security levels are a shorthand for common message requirements ([§6.4](#64-message-level-security-requirements)).

Implementation: [docs/security.md](docs/security.md#numeric-security-levels)

- Level 1 or level 2 requires confidentiality and nonrepudiation, and sets the minimum Frame version to V1. A `min_version` above V1 on the same message type holds.
- Numeric levels set requirements, and a typed security profile constrains algorithms ([§6.4](#64-message-level-security-requirements)). A level 1 ("FIPS") message accepts any digest, AEAD, or signature algorithm.

### 6.4 Message-Level Security Requirements

A message type declares its security requirements, and Frame composition enforces them. Frame validation checks the resulting shape at run time. A message type MAY require:

- a minimum Frame version
- nonrepudiation
- confidentiality
- compression
- a priority
- message integrity (MI)
- frame integrity (FI)
- a typed security profile, which constrains its algorithms

By default, each of these requirements is off, and a message type's minimum version is V0.

Implementation: [docs/security.md](docs/security.md#message-requirements)

#### Profile-Based Algorithm Constraints

A typed profile selects whether composition matches algorithm OIDs:

- A message type with no typed profile takes the default profile ([§6.2](#62-security-profile-types)). Composition matches OIDs only against a typed profile.
- A message type with a typed profile MUST compose with the algorithms that profile names. The Frame builder and `compose!` refuse any other algorithm.

The typed profile MAY be any type that implements `SecurityProfile`. A message type with a typed profile therefore composes only with compatible algorithms.

#### Security Requirement Semantics

Each requirement binds a field of the Frame:

- When a message type requires nonrepudiation, the Frame MUST include `nonrepudiation`.
- When it requires confidentiality, `Metadata` MUST include `confidentiality`.
- When it requires compression, `Metadata.compactness` MUST be present.
- When it requires a priority, `Metadata` MUST include `priority`.
- When it requires message integrity, `Metadata.integrity` (MI) MUST be present.
- When it requires frame integrity, `Frame.integrity` (FI) MUST be present.
- `Frame.version` MUST be greater than or equal to the minimum version of the message type.

#### Profile Validation in the Frame Builder

When a message type has a typed profile, the Frame builder and `compose!` enforce the profile. For a `#[derive(Beamable)]` message, a mismatched algorithm type also fails to compile at the builder call.

**Using the** `compose!` **macro:**

```rust
# use tightbeam::crypto::hash::Sha3_256;
# use tightbeam::crypto::profiles::TightbeamProfile as MyAppProfile;
# use tightbeam::crypto::sign::ecdsa::Secp256k1Signature;
# use tightbeam::crypto::sign::CertifiedKey;
# use tightbeam::der::Sequence;
# use tightbeam::testing::{TestCertificate, TestKey};
# use tightbeam::{compose, Beamable};
# let signing_key = TestKey::insecure_fixed_signing();
# let certificate = TestCertificate::self_signed(&signing_key);
# let (_, cipher) = TestKey::insecure_fixed_cipher();
# let salt = [0x5a; 32];
// Example: Message with custom profile
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
#[beam(profile(MyAppProfile))]
struct SecureMessage { data: Vec<u8> }
# let message = SecureMessage { data: b"payload".to_vec() };

// compose! macro validates algorithm OIDs match MyAppProfile
let frame = compose! {
	V1: id: b"msg-001",
		order: 1696521900,
		message_integrity<Sha3_256>: salt,
		confidentiality: cipher,
		nonrepudiation<Secp256k1Signature, _>: CertifiedKey::new(&certificate, signing_key)?,
		message: message
}?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

**Using the Frame builder directly:**

```rust
# use tightbeam::builder::TypeBuilder;
# use tightbeam::crypto::hash::Sha3_256;
# use tightbeam::crypto::profiles::TightbeamProfile as MyAppProfile;
# use tightbeam::crypto::sign::ecdsa::Secp256k1Signature;
# use tightbeam::crypto::sign::CertifiedKey;
# use tightbeam::der::Sequence;
# use tightbeam::testing::{TestCertificate, TestKey};
# use tightbeam::{Beamable, Version};
# #[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
# #[beam(profile(MyAppProfile))]
# struct SecureMessage { data: Vec<u8> }
# let signing_key = TestKey::insecure_fixed_signing();
# let certificate = TestCertificate::self_signed(&signing_key);
# let (_, cipher) = TestKey::insecure_fixed_cipher();
# let (msg, timestamp, salt) = (SecureMessage { data: b"payload".to_vec() }, 1_696_521_900, [0x5a; 32]);
// The builder validates that the algorithm OIDs match MyAppProfile
let signer = CertifiedKey::new(&certificate, signing_key)?;
let frame = Version::V1.compose::<SecureMessage>()
	.with_message(msg)
	.with_id(b"msg-001")
	.with_order(timestamp)
	.with_message_hasher::<Sha3_256>(salt)          // ✓ Matches MyAppProfile::Digest
	.with_encryptor(cipher)                         // ✓ Matches MyAppProfile::AeadOid
	.with_signer::<Secp256k1Signature, _>(signer)   // ✓ Matches MyAppProfile::SignatureAlg
	.build()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

> Note: tightbeam macros are optional. The same behavior is available through the underlying builders and traits for direct use.

#### Implementation Enforcement

- **Compile time**: A derived message accepts only the algorithm types its profile names, so a mismatch is a compile error.
- **Run time**: Composition compares each algorithm OID with the profile, so the profile holds for every message type, derived or written by hand. Frame validation checks that the Frame shape matches the message requirements, at the build and at each typed decode.
- **Profile binding**: A message type names its profile with the `#[beam(profile(...))]` attribute below.

#### Derive Macro Usage

`#[derive(Beamable)]` makes a type a message type. Its security and profile attributes declare the requirements of [§6.4](#64-message-level-security-requirements).

**Security attributes:**

- `#[beam(message_integrity)]`, `#[beam(frame_integrity)]`
- `#[beam(nonrepudiable)]`, `#[beam(confidential)]`
- `#[beam(compressed)]`, `#[beam(prioritized)]`
- `#[beam(min_version = "V1")]`

**Profile attributes:**

- `#[beam(profile = 1)]` or `#[beam(profile = 2)]`: numeric levels. These set confidential and nonrepudiable requirements. OID validation comes from a typed profile ([§6.3](#63-numeric-security-levels)).
- `#[beam(profile(TypeName))]`: typed profile. This binds the profile and enables OID validation.

#### Example Message Types

```rust
# use tightbeam::crypto::profiles::TightbeamProfile as MyAppProfile;
# use tightbeam::der::Sequence;
# use tightbeam::Beamable;
// Numeric security level (convenience)
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
#[beam(profile = 1)]
struct PaymentInstruction { payee: String, amount: u64 }

// Type-based profile with algorithm enforcement
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
#[beam(profile(MyAppProfile), confidential, nonrepudiable, min_version = "V1")]
struct HighSecurityTransfer { account: String, amount: u64 }
```

### 6.5 Crypto Provider System

A crypto provider binds one implementation to each cryptographic role of a security profile: digest, AEAD, key wrap, signature, KDF, key exchange, and KEM. Each role MUST run the algorithm its profile names. The binding is checked when the code compiles, so a provider that runs AES-256-GCM under a profile that negotiates AES-128-GCM never runs. The key-encryption key MUST be at least as long as the AEAD key ([RFC 3565][rfc3565] §2.3.2).

Implementation: [docs/security.md](docs/security.md#crypto-providers)

Every role is replaceable, and the envelope, the recipients, the handshake, and the transport run the provider's algorithms and refuse any other. An AEAD cipher MUST leave the buffer of a refused seal or open unchanged, because a Frame seals and opens its body in place.

The reference provider uses:

- Digest: SHA3-256
- AEAD: AES-256-GCM
- Signature: ECDSA over secp256k1
- KDF: HKDF-SHA3-256
- Key exchange: ECDH over secp256k1
- Key wrap: AES-256 key wrap
- KEM: DHKEM(secp256k1, HKDF-SHA256)

Each endpoint holds a negotiated profile to a strength floor and refuses a profile below it (CWE-757). The default floor requires AEAD keys and digest outputs of 256 bits or more, and a key exchange of 128-bit security strength or more ([NIST SP 800-57 Part 1 Rev. 5][nist-800-57] §5.6.1), so ECDH over P-192 or P-224 falls below it. A provider built on a shorter algorithm, such as AES-128-GCM, names a floor that admits it.

### 6.6 Cryptographic Requirements

- Integrity digests MUST use a cryptographically secure hash function ([§5.7.3](#573-integrity-semantics-order-of-operations)).
- Confidentiality MUST use authenticated encryption (AEAD) ([§5.7.3](#573-integrity-semantics-order-of-operations)).
- Nonrepudiation MUST use digital signatures with securely generated key pairs ([§5.7.5](#575-nonrepudiation-coverage-and-binding)).

### 6.7 Version Security

Security-related Frame features are version-gated. Full field rules are in [§4.1](#41-version-evolution) and [§5.6](#56-version-specific-constraints).

- **V0**: No optional security fields. Identification and ordering only.
- **V1**: MAY include MI, FI, confidentiality, and Nonrepudiation.
- **V2**: Adds optional priority, lifetime, and `previousFrame` chaining.
- **V3**: Adds optional Matrix control state.

A receiver MUST reject security fields that are forbidden for the declared Frame version ([§5.6](#56-version-specific-constraints)).

### 6.8 ASN.1 Security Considerations

ASN.1 DER encoding supports four security properties of the wire format:

- DER is canonical. Equal values produce one encoding, which reduces ambiguous-parsing attacks ([ITU-T X.690][itu-x690]).
- Context-specific tags distinguish optional fields and reduce field-confusion risk.
- Explicit `Version` values support refusal of unsupported or downgraded Frames.
- Absent optional fields MUST NOT be encoded. That rule reduces injection of unexpected OPTIONAL elements ([§5.5](#55-encoding-rules)).

## 7. Implementation

Minimum implementation requirements follow. The rules they rest on live in other sections:

- Protocol field rules: [§4](#4-protocol-specification) and [§5](#5-asn1-formal-specification)
- Security enforcement: [§6](#6-security-model)
- Transport mechanics: [§8](#8-transport-layer)

### 7.1 Requirements

An implementation MUST provide at least the following:

- Memory safety and ownership guarantees (Rust)
- ASN.1 DER encoding and decoding ([ITU-T X.690][itu-x690])
- `Frame` and `Metadata` shapes that match the ASN.1 module ([§5.9](#59-complete-asn1-module))
- Enforcement of message-level security requirements ([§6.4](#64-message-level-security-requirements))
- Frame composition and verification ([§5.7](#57-semantic-constraints))
- Cryptographic abstraction for confidentiality, integrity, and Nonrepudiation ([§6.5](#65-crypto-provider-system))
- A transport abstraction that can run over more than one byte-moving protocol ([§7.2](#72-transport-layer), [§8](#8-transport-layer))

### 7.1.1 Message Security Enforcement

Implementations MUST enforce the security requirements of a message type at compile time and at run time ([§6.4](#64-message-level-security-requirements)).

Implementation: [docs/security.md](docs/security.md#enforcement)

#### Compile-Time Validation

- The type system MUST reject an unsafe message composition when the message type declares requirements or a typed security profile.
- Security requirements MUST be enforced at build time.
- A message type definition MUST check version compatibility against its minimum version.

#### Runtime Validation

- Frame encode and typed decode paths MUST validate the Frame shape against the message type requirements, and a decode validates the Frame as it arrived.
- Requirement violations MUST surface as errors.

### 7.2 Transport Layer

tightbeam MUST be usable over any transport that can carry opaque byte frames. The crate includes a TCP transport with synchronous and asynchronous APIs. Full transport architecture, policies, handshakes, multiplexing, and pooling are specified in [§8 Transport Layer](#8-transport-layer).

### 7.3 Cryptographic Key Management

tightbeam accepts standard key material and delegates key lifecycle management to the application ([NIST SP 800-57][nist-800-57]).

- **Accepted formats**: X.509 certificates, raw key material, and CMS structures.
- **Session establishment**: CMS-based and HPKE-based handshakes ([§8.5](#85-handshake-protocols)).
- **Application duties**: key generation, storage, rotation, certificate validation, and revocation checking ([RFC 6960][rfc6960]).

Implementation: [docs/security.md](docs/security.md#key-management)

#### Trust Stores

A trust store verifies certificate chains and holds the trust anchors. An endpoint uses its trust store to:

- Verify peer certificates during connection establishment
- Validate a chain from trust anchor through intermediates to the leaf
- Look up signer certificates when verifying Frame Nonrepudiation

Every trust store keeps three rules, which the handshake and the colony rely on:

- A store admits a certificate by its contents alone, whatever role the handshake reads it in.
- A check of a server's identity, such as a pin, belongs in the client's server policy. A check of a client's identity belongs in the client validators of a server that requires mutual authentication.
- Wherever a store reads a key, two keys are one key exactly when they share one canonical form under the curves the store decodes.

The built-in store runs its revocation checker at each admission, so a check of every certificate, such as a denylist, belongs in that checker:

- Path validation, with revocation as one of its checks, runs on each certificate that the store admits.
- Each lookup holds the path of the certificate it answers with to its validity period and runs the checker over that path, so an expired or a revoked certificate fails every frame verification and every key lookup.

The built-in store, public-key pinning, the hive's peer list gate, and the key index each read a key by one rule, under the curve decoders each holds:

- A point of a named curve outside the binary-field curves of SEC 2 and ANSI X9.62, in the compressed (`0x02`, `0x03`) or the uncompressed (`0x04`) SEC 1 form, reads as a point ([SEC 1][secg-sec1] v2.0 §2.3.3), so its two forms are one key and its negation is another key.
- Every other key reads as its bits: an encoding that a decoder of its curve refuses ([SEC 1][secg-sec1] v2.0 §2.3.4), a malformed point or a form that [RFC 5480][rfc5480] §2.2 refuses, an `id-ecPublicKey` key with no named curve, a key on a binary-field curve of SEC 2 or ANSI X9.62, and a key of another algorithm.
- `KeyCurves::HOUSE`, the curve set of the examples below, holds the decoder of secp256k1:
  - Public-key pinning, the peer list gate, and the key index read under it by default. A trust store states its own curves when it is built.
  - A session reads its peer's key under it, and the hive's circuit breaker keys on that key.
- An outside crate brings the decoder of its own curve. [docs/handshake.md](docs/handshake.md#key-identity) states the whole rule.

A store resolves a `SignerInfo` by its `sid`:

- A `subjectKeyIdentifier` resolves through the extension of each certificate it holds.
- An `issuerAndSerialNumber` resolves through the issuer and serial number.

Every certificate that tightbeam creates carries a subjectKeyIdentifier by [RFC 7093][rfc7093] §2 method 1: the leftmost 160 bits of the SHA-256 of the subjectPublicKey BIT STRING value. A certificate it issues also carries the authorityKeyIdentifier of its issuer.

**Building a trust store:**

```rust
# use tightbeam::crypto::policy::Secp256k1Policy;
# use tightbeam::crypto::x509::store::{CertificateTrustBuilder, NoRevocation, TrustBuilder};
# use tightbeam::crypto::x509::{Certificate, CertificateSpec, KeyCurves};
# use tightbeam::der::{pem::LineEnding, EncodePem};
# use tightbeam::testing::{TestCertificate, TestKey};
# let pem = TestCertificate::self_signed(&TestKey::insecure_fixed_signing()).to_pem(LineEnding::LF)?;
# #[allow(non_snake_case)]
# let CERT_PEM = CertificateSpec::Pem(Box::leak(pem.into_boxed_str()));
let cert = Certificate::try_from(CERT_PEM)?;
let trust_store = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation)
    .with_certificate(cert)?
    .build();
# Ok::<(), Box<dyn std::error::Error>>(())
```

**Adding a certificate chain:**

```rust
# use tightbeam::crypto::policy::Secp256k1Policy;
# use tightbeam::crypto::x509::store::{CertificateTrustBuilder, NoRevocation, TrustBuilder};
# use tightbeam::crypto::x509::KeyCurves;
# use tightbeam::testing::{TestCertificate, TestCertificateChain};
# let chain = TestCertificate::insecure_fixed_chain()?;
# let TestCertificateChain { root: root_cert, intermediate: intermediate_cert, leaf: leaf_cert, .. } = chain;
let trust_store = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation)
    .with_chain(vec![root_cert, intermediate_cert, leaf_cert])?
    .build();
# Ok::<(), Box<dyn std::error::Error>>(())
```

`CertificateTrustBuilder::new` is the one constructor, so every store states the curves it reads each key under and its revocation checker:

- `NoRevocation` is the waiver of a closed PKI with short-lived certificates.
- A static revocation list is a denylist that the operator pushes, by fingerprint or by issuer and serial number.

#### Signing Identities

A `SigningIdentity` pairs a certificate with the key backend that holds its private key:

- It refuses a certificate that is not admitted for signing ([Certificate Use](#certificate-use)), and a key whose public half differs from the certificate's SubjectPublicKeyInfo, so every signature it makes verifies under the certificate its `sid` names.
- It also refuses a key whose algorithm is not its provider's, and it brings every signature to its canonical form, the DER low-`s` form for ECDSA.
- It MAY present the issuers above its certificate, nearest first:
  - A server's handshake reply and a mutual client's Finished carry them in `certificates` ([RFC 5652][rfc5652] §5.1), so a peer of either flow validates the path when its store holds the trust anchor alone.
  - A CMS client, an HPKE client anchored in a store, and a server whose client validators hold the store each validate it this way.
  - The identity refuses a chain in which a certificate does not name the next one as its issuer, and a chain that holds more than eight certificates with its own.
- It signs under the reference provider ([§6.5](#65-crypto-provider-system)) by default. An implementor brings its own signature algorithm through its own provider, and the verification policy of that provider verifies its signatures.
- It is the one home of an endpoint's signing material.

Each endpoint signs these messages with its signing identity:

| Endpoint          | What the identity signs                                            |
| ----------------- | ------------------------------------------------------------------ |
| A server          | The server reply or Finished, and the server receipt               |
| A client          | The client Finished, and the receipt countersignature              |
| A Frame signer    | The frame                                                          |
| A colony endpoint | Its handshakes and frames, such as the rumors a gateway originates |

```rust
# use tightbeam::builder::TypeBuilder;
# use tightbeam::crypto::k256::Secp256k1;
# use tightbeam::crypto::key::SigningKeySpec;
# use tightbeam::crypto::profiles::DefaultCryptoProvider;
# use tightbeam::crypto::sign::SigningIdentity;
# use tightbeam::crypto::x509::CertificateSpec;
# use tightbeam::testing::{TestCertificate, TestKey, TestMessage};
# use tightbeam::transport::TransportEncryptionConfig;
# use tightbeam::Version;
# const SERVER_KEY: SigningKeySpec = SigningKeySpec::Bytes(&[1; 32]);
# async fn sign() -> Result<(), Box<dyn std::error::Error>> {
# #[allow(non_snake_case)]
# let SERVER_CERT = CertificateSpec::Built(Box::new(TestCertificate::self_signed(&TestKey::insecure_fixed_signing())));
# let builder = Version::V1.compose::<TestMessage>().with_id("frame-001").with_order(1);
# let mut frame = builder.with_message(TestMessage::sample(None)).build()?;
let server = SigningIdentity::from_spec(SERVER_CERT, SERVER_KEY.to_provider::<Secp256k1>()?)?;
frame.sign_with_provider(&server).await?;
let config = TransportEncryptionConfig::<DefaultCryptoProvider>::new(server);
# Ok(())
# }
# tokio::runtime::Builder::new_current_thread().build()?.block_on(sign())?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

A builder that signs synchronously, such as the `with_signer` call of [§6.4](#64-message-level-security-requirements), takes a `CertifiedKey`: a key that signs in place beside its certificate, under the same key check.

#### Certificate Use

A certificate serves only the use and the role its extensions allow ([RFC 5280][rfc5280] §4.2):

- A certificate is admitted for one use, and the key of that use is parsed once.
- The party that performs the use reads the key: the CMS signer a signing key, and the KEM recipient a recipient key.

Each use names its `keyUsage` bit and its readers:

| Use           | `keyUsage` bit                                         | Read by                                                                                      |
| ------------- | ------------------------------------------------------ | -------------------------------------------------------------------------------------------- |
| Signing       | `digitalSignature`                                     | Frame verification, every handshake signature check, the trust store, and a signing identity |
| Key agreement | The bit of the KEM, `keyAgreement` for the house DHKEM | The KEM recipient, and a key-agreement identity                                              |

A certificate that carries both bits is admitted for each use, and each use refuses a certificate in these cases:

- Its `keyUsage` is absent or lacks the bit of the use.
- It carries one extension twice, or a critical extension other than `basicConstraints`, `keyUsage`, `extendedKeyUsage`, and `subjectAltName`, the four the crate processes.
- The use's bit is `keyAgreement`, and the certificate asserts `decipherOnly` (§4.2.1.3).
- The use reads an `id-ecPublicKey` key, and the point's first octet is not `0x02`, `0x03`, or `0x04`, the compressed and uncompressed forms, or the uncompressed point's two coordinates differ in length ([RFC 5480][rfc5480] §2.2).

The role is the key purpose of `extendedKeyUsage` (§4.2.1.12). Each role maps to one purpose, and these are the defaults:

| Role   | Its certificates                                    | Default purpose         |
| ------ | --------------------------------------------------- | ----------------------- |
| Server | The server's signing and key-agreement certificates | `id-kp-serverAuth`      |
| Client | The certificate of the client identity              | `id-kp-clientAuth`      |
| Signer | The certificate of a frame or colony signer         | `1.3.6.1.4.1.64586.3.1` |

A role also admits `anyExtendedKeyUsage`, and a certificate with no `extendedKeyUsage` serves every role. These rules apply the purposes:

- A peer's certificate is admitted for the purpose of the role it plays.
- Each side of a handshake checks its own identity for its role once, when its configuration is built.
- An implementor MAY set its own purposes on the server configuration, the client, the connection pool, and the trust store.
- A colony endpoint holds its identity to the signer purpose where the identity is installed.

#### Key-Agreement Identities

A `KeyAgreementIdentity` pairs a key-agreement certificate with the backend of its private key, under one KEM. The house DHKEM asks its backend for a Diffie-Hellman agreement on its curve, and the house secp256k1 key backend runs that agreement. These rules hold:

- A signing backend and a key-agreement backend are two distinct kinds, and the compiler refuses one in the place of the other.
- A CMS server's identity pair refuses one key in both identities, so a backend of both, such as the house secp256k1 key backend, serves one identity per key.
- A key-agreement identity refuses a certificate without the `keyUsage` bit of its KEM, and a backend whose public half differs from the certificate's key.

A CMS server holds a signing identity and a key-agreement identity of one subject with two keys ([NIST SP 800-57 Part 1 Rev. 5][nist-800-57] §5.2):

- The client pins the key-agreement certificate alone in a `ProvisionedTrust`, built once with its configuration.
- The server Finished carries the signing certificate. At each reply, the trust's store admits it, and the client refuses two subjects, two trust anchors, and one key in both.

```rust,no_run
# use std::net::SocketAddr;
# use std::sync::Arc;
# use tightbeam::crypto::cms::KeyAgreementIdentity;
# use tightbeam::crypto::k256::Secp256k1;
# use tightbeam::crypto::key::{DiffieHellman, Secp256k1KeyProvider};
# use tightbeam::crypto::profiles::DefaultCryptoProvider;
# use tightbeam::testing::{TestCmsServer, TestIdentity};
# use tightbeam::transport::handshake::{HandshakeProtocolKind, ProvisionedTrust};
# use tightbeam::transport::tcp::r#async::TokioListener;
# use tightbeam::transport::{ClientBuilder, ConnectionBuilder, TransportEncryptionConfig};
# async fn dial(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
# let server = TestCmsServer::generate("server");
# let (signing_identity, trust_store) = (server.signing_identity(), Arc::new(server.store()));
# let TestCmsServer { key_agreement, key_agreement_key, .. } = server;
# let agreement_cert = Arc::new(key_agreement);
# let agreement_backend: Arc<dyn DiffieHellman<Secp256k1>> = Arc::new(Secp256k1KeyProvider::from(key_agreement_key));
# let client_identity = TestIdentity::insecure_fixed();
// The server: the signing identity signs, and the key-agreement identity
// opens the opening sealed to it.
let config = TransportEncryptionConfig::<DefaultCryptoProvider>::new(signing_identity)
    .with_key_agreement(KeyAgreementIdentity::new(Arc::clone(&agreement_cert), agreement_backend)?)?;

// The client: the key-agreement certificate alone, admitted against the
// store once. The store admits the signing certificate the reply carries.
let server_trust = ProvisionedTrust::new(agreement_cert, trust_store)?;
let client = ClientBuilder::<TokioListener>::builder()
    .with_handshake_protocol(HandshakeProtocolKind::Cms)
    .with_cms_server(server_trust)
    .with_client_identity(client_identity)
    .connect(addr)
    .await?;
# Ok(())
# }
```

Both endpoints select the CMS flow with `with_handshake_protocol(HandshakeProtocolKind::Cms)`, on the client builder and on the server's transport, and HPKE is the default.

## 8. Transport Layer

The transport layer moves Frame bytes between endpoints. It establishes connections, applies security policies, and manages session cryptographic state. These sections specify the parts:

- Policies: [§8.4](#84-transport-policies)
- Handshakes: [§8.5](#85-handshake-protocols)
- Multiplexing: [§8.6](#86-multiplexing)
- Pooling: [§8.7](#87-connection-pooling)

### 8.1 Transport Architecture

Transport behavior is split into separate roles, so an application plugs in its own byte protocol without rewriting its policy or its cryptography. Implementation: [docs/transport.md](docs/transport.md#transport-traits).

#### 8.1.1 Design Principles

- Connection setup (bind and connect) is apart from Frame read and write.
- Gate and retry policies wrap the send and receive paths, and leave the byte protocol unchanged.
- Encryption extends the same roles: an encrypted endpoint binds with its certificate, and seals and opens each envelope.

#### 8.1.2 Core Transport Traits

Each role is a trait that another crate can implement:

- Connection setup: bind a listener and connect a stream.
- Envelope I/O: read and write wire envelopes.
- Receive path: collect Frames under the gate policies.
- Send path: emit Frames under the gate and restart policies.
- Encrypted connection setup: bind a listener with transport encryption.
- Encrypted envelope I/O: seal and open envelopes on the wire, and drive the handshake.

### 8.2 Wire Format

Frames use ASN.1 DER with two envelope layers:

- `WireEnvelope`: Outer cleartext or encrypted container
- `TransportEnvelope`: Inner request, response, CMS, or mux payload

Implementation: [docs/transport.md](docs/transport.md#wire-envelopes)

When the endpoints multiplex ([§8.6](#86-multiplexing)), `TransportEnvelope` also carries mux stream envelopes. Stream metadata travels inside that envelope, so encryption hides it.

An encrypted `WireEnvelope` carries one record, the DER `TransportEnvelope` sealed as an `AuthEnvelopedData` ([RFC 5083][rfc5083]):

| Field                 | Value                                                                                                                                                           |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `recipientInfos`      | One `KEKRecipientInfo` ([RFC 5652][rfc5652] §6.2.3), version 4, under the session key of the record's direction and epoch |
| `kekid.keyIdentifier` | `tb/session/record/kekid/v1`, then the direction octet (`0x00` client to server, `0x01` server to client), then the epoch as four big-endian octets             |
| Content key and nonce | Fresh for each record, the content key wrapped under the session key                                                                                            |
| `authAttrs`           | The content type `id-data`, and a `RecordSequence ::= SEQUENCE { epoch INTEGER, sequence INTEGER }` under `1.3.6.1.4.1.64586.1.27`                              |

Before it unwraps the content key, a receiver refuses:

- A record of another epoch.
- A record whose sequence is another than the next one it expects. The tag covers the sequence, so a record moved to another position fails its tag.
- A record at the record limit. [RFC 9846 §5.5][rfc9846-5.5] sets the record limit on the sender, and the receiver's refusal at the limit is tightbeam's own renewal policy.
- A record whose `kekid` names another direction or epoch.

DER tag-length-value encoding supplies framing. Each endpoint enforces three size limits, and each one is configurable:

- Cleartext envelopes: 128 KiB by default
- Encrypted envelopes: 256 KiB by default
- Handshake messages: 16 KiB by default, so an unauthenticated peer cannot make the endpoint buffer a large message (CWE-770)

### 8.3 TCP Transport

The TCP transport maps a byte stream to the Frame API with DER length-prefixed envelopes. It supports `std::net` (synchronous) and `tokio` (asynchronous). Implementation: [docs/transport.md](docs/transport.md#tcp-transport).

```rust,no_run
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::tcp::TightBeamSocketAddr;
use tightbeam::{server, Frame};

# async fn serve() -> Result<(), Box<dyn std::error::Error>> {
let addr = "127.0.0.1:8080".parse()?;
let server_handle = server! {
	protocol TokioListener: bind_cleartext TightBeamSocketAddr(addr),
	handle: |message: Frame| async move {
		// Echo the frame back
		Ok(Some(message))
	}
};
# Ok(())
# }
```

The listener serves in the clear here, and `bind_cleartext` says so: its connections are plaintext, unprotected, and unauthenticated (CWE-319). A listener with transport encryption binds with the server's certificate, and each connection runs a handshake ([§8.5](#85-handshake-protocols)).

### 8.4 Transport Policies

Implementation: [docs/transport.md](docs/transport.md#transport-policies)

#### 8.4.1 Concept

Policies control message flow.

- `GatePolicy`: Accept or reject a Frame (rate limits, authentication, session checks)
- `RestartPolicy`: Decide retry after failure (linear or exponential backoff)
- `ReceptorPolicy`: Filter a decoded application message by type

#### 8.4.2 Specification

A gate or receptor policy answers with a `TransitStatus`. Its codes and their wire values are those of the gRPC canonical status registry (`google.rpc.Code`), from `Ok` (0) to `Unauthenticated` (16). `Ok` admits, and every other status refuses.

**Gate policy:**

A gate policy evaluates one Frame with the session facts of its connection:

- The authenticated peer certificate and its key.
- The session receipt of a metered session.

A gate receives session facts only on the server side of an authenticated connection.

The Frame is absent when a mux stream opens without a request Frame. A gate follows these rules for such a stream:

- An optional check that needs a Frame SHOULD return `Ok`.
- Authentication that needs a Frame MUST fail closed.
- Authorize streams on session facts, such as the mutually authenticated peer.

**Receptor policy:**

A receptor policy evaluates one decoded application message of one type.

**Restart policy:**

A restart policy evaluates a failed send. It receives the Frame of the failed operation, the failure, and the attempt number, which counts from 0. It answers with one of two actions:

- Retry with a Frame, the same one or a changed one, after a delay that the policy names.
- Stop, and report the error.

#### 8.4.3 Implementation

**GatePolicy (Frame-level filtering):**

```rust
use tightbeam::policy::{GatePolicy, SessionContext, TransitStatus};
use tightbeam::Frame;

// Accept only messages with specific ID patterns
#[derive(Default)]
struct IdPatternGate;

impl GatePolicy for IdPatternGate {
	fn evaluate(&self, frame: Option<&Frame>, _session: &SessionContext) -> TransitStatus {
		let Some(frame) = frame else {
			return TransitStatus::PermissionDenied;
		};
		if frame.metadata().id().starts_with(b"api-") {
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
# use tightbeam::der::Encode;
# use tightbeam::policy::{GatePolicy, SessionContext, TransitStatus};
# use tightbeam::testing::fixtures::{TestCertificate, TestKey};
#
# let banned = TestKey::insecure_fixed_signing();
# let member = TestKey::negation_of(&banned);
# let banned_spki_der = TestCertificate::self_signed(&banned).tbs_certificate.subject_public_key_info.to_der()?;
# let member_spki_der = TestCertificate::self_signed(&member).tbs_certificate.subject_public_key_info.to_der()?;

// Bar these public keys (SPKI DER) at the door. The gate matches the
// session's mutually-authenticated peer certificate, not frame signers.
let doorman = PeerListGate::deny([banned_spki_der])?;
# assert_eq!(doorman.evaluate(None, &SessionContext::default()), TransitStatus::Ok);

// Or admit only listed keys. Sessions without an authenticated peer
// fail closed (Unauthenticated).
let doorman = PeerListGate::allow([member_spki_der])?;
# assert_eq!(doorman.evaluate(None, &SessionContext::default()), TransitStatus::Unauthenticated);
# Ok::<(), Box<dyn std::error::Error>>(())
```

The gate reads each listed SubjectPublicKeyInfo by the key rule of the trust store, so a point in either SEC 1 form is one listed key. An entry that no session can match would let the peer it names pass a deny list, so the gate refuses the whole list when an entry is one of these:

- An entry that is no SubjectPublicKeyInfo, or whose canonical form exceeds the DER length cap.
- An elliptic-curve entry that reads as no point: an encoding the decoder of its curve refuses, a malformed point, the compact or a hybrid form, a key with no named curve, a key on a binary-field curve, or a key under `id-ecDH` or `id-ecMQV`.
- A point on a curve that the gate holds no decoder for.

Public-key pinning reads its pins by the same rule, so it refuses the same entries. A pin is the DER of a SubjectPublicKeyInfo, so it names a key with its algorithm and its curve.

`allow` and `deny` decode the points of secp256k1, so a list of keys on another curve needs a gate built with a decoder of that curve. The hive's circuit breaker keys on the same canonical key as the gate.

**ReceptorPolicy (message-level filtering):**

```rust
use tightbeam::der::Sequence;
use tightbeam::policy::{ReceptorPolicy, TransitStatus};
use tightbeam::Beamable;

#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
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
use core::time::Duration;

use tightbeam::transport::policy::{RestartLinearBackoff, RestartExponentialBackoff};

// Linear backoff: 1s, 2s, 3s delays
let restart = RestartLinearBackoff::new(3, Duration::from_millis(1000), 1, None);

// Exponential backoff: 1s, 2s, 4s, 8s delays
let restart = RestartExponentialBackoff::new(4, Duration::from_millis(1000), None);
```

`policy!` **macro:**

```rust
# use core::time::Duration;
#
# use tightbeam::der::Sequence;
# use tightbeam::policy::TransitStatus;
# use tightbeam::transport::policy::RetryAction;
# use tightbeam::Beamable;
#
# #[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
# struct RequestMessage {
# 	content: String,
# 	priority: u8,
# }
#
tightbeam::policy! {
	// Frame-content gate: fail closed when no request frame exists
	// (mux streaming / duplex). Pair with a session gate for stream opens.
	GatePolicy: OnlyApiMessages |frame| {
		let Some(frame) = frame else {
			return TransitStatus::PermissionDenied;
		};
		if frame.metadata().id().starts_with(b"api-") {
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
			RetryAction::Retry { frame, delay: Duration::from_millis(100) }
		} else {
			RetryAction::NoRetry
		}
	}
}
```

**Composing policies:**

```rust,no_run
# use core::time::Duration;
#
# use tightbeam::policy::TransitStatus;
# use tightbeam::transport::client::{ClientBuilder, ConnectionBuilder};
# use tightbeam::transport::policy::RestartLinearBackoff;
# use tightbeam::transport::tcp::r#async::TokioListener;
# use tightbeam::transport::tcp::TightBeamSocketAddr;
#
# // Stand-ins for the gates of the examples above.
# tightbeam::policy! {
# 	GatePolicy: IdPatternGate { TransitStatus::Ok }
# 	GatePolicy: OnlyApiMessages { TransitStatus::Ok }
# }
#
# async fn connect(addr: TightBeamSocketAddr) -> Result<(), Box<dyn std::error::Error>> {
// Client-side with policies
let builder = ClientBuilder::<TokioListener>::builder()
	.allow_cleartext()
	.with_emitter_gate(IdPatternGate)
	.with_collector_gate(OnlyApiMessages)
	.with_restart(RestartLinearBackoff::new(3, Duration::from_millis(1000), 1, None))
	.build();

let mut client = builder.connect(addr).await?;
# Ok(())
# }
```

### 8.5 Handshake Protocols

#### 8.5.1 Concept: Security Goals and Protocol Selection

Two handshake protocols establish mutual authentication and a session key:

- **CMS-based**: Full PKI with X.509 certificates and [RFC 5652][rfc5652] CMS structures
- **HPKE-based**: The shape of the TLS 1.3 handshake ([RFC 9846][rfc9846]) in CMS containers. The client learns the server from the reply, and the handshake secret derives from two ephemerals alone

Security goals for both:

- **Mutual authentication**: Each party proves identity with certificates
- **Perfect forward secrecy**: An ephemeral key exchange, such as ECDH ([NIST SP 800-56A][nist-800-56a]), protects past sessions if long-term keys leak later
- **Replay protection**: Nonces block replayed handshake messages
- **Downgrade prevention**: The transcript hash covers handshake messages, including profile negotiation ([RFC 9846 §4.2.3][rfc9846-4.2.3])
- **Confidentiality**: HKDF-derived session keys protect later messages

#### 8.5.2 Specification: Handshake Flow and State Management

**Three-phase exchange:**

```text
Phase 1: Client -> Server
┌─────────────────────────────────────────────────────────┐
│ Hello (HPKE) or Opening (CMS)                           │
│ - Client nonce (32 bytes)                               │
│ - Optional SecurityOffer (supported profiles)           │
│ - Client ephemeral R (HPKE: in clear, as the TLS 1.3    │
│   key share. CMS: sealed in the opening, beside the     │
│   base secret)                                          │
└─────────────────────────────────────────────────────────┘

Phase 2: Server -> Client
┌─────────────────────────────────────────────────────────┐
│ Reply (HPKE) or ServerFinished (CMS)                    │
│ - Server certificate (HPKE: in `certificates`)          │
│ - Server nonce (32 bytes, HPKE)                         │
│ - Selected SecurityProfile (if negotiation occurred)    │
│ - Server ephemeral E                                    │
│ - Signature over the transcript                         │
│ - Server Finished, a MAC under the handshake secret     │
└─────────────────────────────────────────────────────────┘

Phase 3: Client -> Server
┌─────────────────────────────────────────────────────────┐
│ Closing (both flows)                                    │
│ - Sealed under a key of the handshake secret            │
│ - Key-confirmation tag (one digest output wide)         │
│ - Client Finished with the client certificate           │
│   (absent for an anonymous HPKE client)                 │
│ - Sealed receipt acknowledgement (budget-bearing)       │
└─────────────────────────────────────────────────────────┘
```

**State machines** (diagram form):

Client:

```text
Init -> HelloSent -> OpeningSent -> ServerFinishedReceived -> ClientFinishedSent -> Completed
```

Server:

```text
Init -> OpeningReceived -> ServerFinishedSent -> ClientFinishedReceived -> Completed
```

**Transcript hash:**

```text
HPKE: transcript = Hello ContentInfo DER || ServerHandshake DER || certificates field DER
CMS:  transcript = Opening DER || SecurityAccept || TransportAccept || server ephemeral || certificates field DER
transcript_hash = H(transcript)
```

`H` is the negotiated digest, SHA3-256 in the default profile. The transcript hash is its whole output: 32 bytes under SHA3-256, 64 under SHA3-512.

The transcript hash binds the handshake messages, so it blocks reordering, profile downgrade, and undetected man-in-the-middle edits of the transcript. The transcript also binds these parts of the reply:

- The HPKE `ServerHandshake` carries the accepts, the certificate demand, and the server ephemeral, so a stripped certificate demand changes the hash.
- Both transcripts cover the DER of the reply's `certificates` field, which holds the signing certificate and the issuers above it that the server presents, as TLS 1.3 signs over its Certificate message ([RFC 9846 §4.5.2][rfc9846-4.5.2]).

**Handshake secret:**

Each flow derives the handshake secret `hs` from its own input:

- The CMS flow derives `hs` from `ee || base`, the hybrid shared secret `Z′ = Z || T` of [NIST SP 800-56C Rev. 2][nist-800-56c] §2: the secret of the ephemeral key exchange, followed by the client's base secret.
- The HPKE flow derives `hs` from `ee` alone, as the ECDHE secret of TLS 1.3 does ([RFC 9846 §7.1][rfc9846-7.1]).

**Key confirmation:**

Each key-confirmation tag follows the Finished construction of TLS 1.3 ([RFC 9846 §4.5.3][rfc9846-4.5.3]) under `H`, with one `MacKey` per role and tightbeam's label as the HKDF-Expand info in place of `HkdfLabel`. `hs` is the 32-byte output of the profile's KDF, too short a PRK for a 64-byte `H` ([RFC 5869][rfc5869] §2.3), so `H` extracts one first:

```text
mac_c   = HKDF-Expand-H(HKDF-Extract-H(S, hs), "tb/handshake/finished/client/mac/v1", Hash.length)
mac_s   = HKDF-Expand-H(HKDF-Extract-H(S, hs), "tb/handshake/finished/server/mac/v1", Hash.length)
confirm = HMAC-H(mac_c, transcript_hash)
server  = HMAC-H(mac_s, transcript_hash || SignerInfo.signature)
```

`S` is the handshake's salt, and the two tags follow these rules:

- The client sends `confirm` in its closing, in both flows.
- The server of either flow sends `server`, the server Finished, in its reply, over the transcript hash and the octets of the reply's one signature. The client verifies it before it builds its closing.
#### 8.5.3 Implementation: CMS-Based Handshake Protocol

CMS handshake uses [RFC 5652][rfc5652] Cryptographic Message Syntax:

- `AuthEnvelopedData` ([RFC 5083][rfc5083]): Every seal, under AES-256-GCM with `GCMParameters` ([RFC 5084][rfc5084]), the tag in `mac`, and the content type among the authenticated attributes
- `KEMRecipientInfo` ([RFC 9629][rfc9629]): The opening's recipient. DHKEM(secp256k1, HKDF-SHA256) encapsulates to the key of the server's key-agreement certificate, and HKDF-SHA3-256 derives the key that wraps the content key. [docs/dhkem-secp256k1.md](docs/dhkem-secp256k1.md) specifies the KEM
- `KEKRecipientInfo`: The recipient of the closing, under a key of the handshake secret
- `SignedData`: Transcript signatures for authentication

The CMS flow carries its keys and proofs as follows:

- The opening seals the base secret and the client's agreement ephemeral `R` to the server's key-agreement certificate, and it carries the security and transport offers as authenticated attributes.
- The server's signing certificate signs the server Finished, and the client refuses a server ephemeral that shares the x-coordinate of either certificate key.
- The server Finished carries the server Finished MAC of [§8.5.2](#852-specification-handshake-flow-and-state-management) as an unsigned attribute, as the HPKE reply does, and the client verifies it before it builds its closing.

**Mutual authentication flow:**

For mutual authentication, the client signs its Finished over the transcript and seals the whole Finished, with the certificate it embeds, under a key of the handshake secret. The HPKE flow sends the same closing:

```text
Client Side - Building the Client Finished:
┌─────────────────────────────────────────────────────────────────────┐
│ 1. Seal the Transcript                                              │
│    transcript = Opening || accepts || server_ephemeral              │
│                 || signing certificate                              │
│    transcript_hash = SHA3-256(transcript)                           │
├─────────────────────────────────────────────────────────────────────┤
│ 2. Sign the Client Finished                                         │
│    signed = client_finished_domain || transcript_hash               │
│             || SHA3-256(DER(client_certificate))                    │
│    attrs = [content_type: id-data,                                  │
│             message_digest: SHA3-256(signed),                       │
│             algorithm_protection: SHA3-256, ecdsa-with-SHA3-256]    │
│    signature = DER(Sign(SHA3-256(DER(attrs)), client_priv_key))     │
├─────────────────────────────────────────────────────────────────────┤
│ 3. Build the Client Finished                                        │
│    SignedData {                                                     │
│        content: signed,                                             │
│        signer: SignerInfo { sid: client key identifier, attrs },    │
│        certificates: [client_certificate],                          │
│        unsigned_attrs: [confirm, sealed_ack?],                      │
│    }                                                                │
├─────────────────────────────────────────────────────────────────────┤
│ 4. Seal the Finished under the Handshake Secret                     │
│    k_close = HKDF(hs, salt, "tb/session/kdf/closing/v1")            │
│    cek = random(32), nonce = random(12)                             │
│    AuthEnvelopedData {                                              │
│        recipient: KEKRecipientInfo {                                │
│            kekid: "tb/handshake/closing/kekid/v1" || hash,          │
│            encrypted_key: AES-256-KW(k_close, cek),                 │
│        },                                                           │
│        algorithm: AES-256-GCM, GCMParameters { nonce, 16 },         │
│        auth_attrs: [content_type: id-signedData, transcript_hash],  │
│        content, mac: AES-256-GCM.seal(cek, nonce,                   │
│            aad: DER(auth_attrs), plaintext: pad(Finished DER)),     │
│    }                                                                │
└─────────────────────────────────────────────────────────────────────┘
```

Server verification flow:

```text
Server Side - Verifying Client Authentication:
┌─────────────────────────────────────────────────────────────┐
│ 1. Open the Sealed Finished                                 │
│    cek = AES-256-KW.unwrap(k_close, encrypted_key)          │
│    finished = AES-256-GCM.open(cek, nonce, content, mac)    │
│    ✓ The Finished embeds a certificate                      │
├─────────────────────────────────────────────────────────────┤
│ 2. Compare R with the Certificate Key                       │
│    ✓ The agreement key R differs from the certificate key   │
├─────────────────────────────────────────────────────────────┤
│ 3. Confirm the Handshake Secret                             │
│    ✓ Key-confirmation tag matches                           │
├─────────────────────────────────────────────────────────────┤
│ 4. Validate Client Certificate                              │
│    ✓ Verify certificate is within validity period           │
│    ✓ Check certificate chain against trust anchors          │
├─────────────────────────────────────────────────────────────┤
│ 5. Verify the Client Finished                               │
│    signed = client_finished_domain || transcript_hash       │
│             || SHA3-256(DER(client_certificate))            │
│    ✓ attrs are the three, message_digest = SHA3-256(signed) │
│    Verify(signature, SHA3-256(DER(attrs)), client_pub_key)  │
│    ✓ Client witnessed same transcript                       │
└─────────────────────────────────────────────────────────────┘
```

#### 8.5.4 Implementation: HPKE-Based Handshake Protocol

The HPKE flow is the lighter handshake path, in the shape of the TLS 1.3 handshake ([RFC 9846][rfc9846]). The client learns the server from the reply, and the handshake secret derives from the two ephemerals alone, so the server's certificate key only signs. Every message is a CMS container:

- **Hello**: A `ContentInfo` of type `id-data` ([RFC 5652][rfc5652] §4) whose OCTET STRING is the `ClientHello`: the client random, the client ephemeral `R`, and the offers.
- **Reply**: The signer's `SignedData` over the `ServerHandshake`, with the server ephemeral `E`, under the content type `1.3.6.1.4.1.64586.1.26`. Its signed attributes carry the transcript hash, its `certificates` carry the signing certificate that its `sid` names and the issuers above it that the server presents, and its unsigned attributes carry the server Finished and the session receipt.
- **Closing**: The closing of both flows, an `AuthEnvelopedData` with a `KEKRecipientInfo` under a key of the handshake secret.

The flow claims these properties of [RFC 9846 Appendix F.1][rfc9846-f.1]:

| Property                                                              | Claimed | Why                                                                                           |
| --------------------------------------------------------------------- | ------- | --------------------------------------------------------------------------------------------- |
| Server authentication before the client sends its identity            | Yes     | The client verifies the reply's signature over the transcript first                           |
| The client identity's protection against passive and active attackers | Yes     | It travels only under a key of this handshake's ephemeral agreement                           |
| Forward secrecy                                                       | Yes     | The secret comes from two ephemerals alone                                                    |
| The server identity's protection against a passive attacker           | No      | The signing certificate travels in clear in `certificates`                                    |
| Explicit server key confirmation                                      | Yes     | The reply carries the server Finished, and the client verifies it before it sends its closing |

**Mutual authentication flow:**

For mutual authentication, the client signs its Finished over the transcript and seals it, with the certificates it presents, under a key of the handshake secret. An anonymous client seals the key-confirmation tag and the acknowledgement alone:

```text
Client Side - Building the Closing:
┌──────────────────────────────────────────────────────────────────────┐
│ 1. Draw R with the Hello                                             │
│    (r, R) = GenerateKeyPair()                                        │
│    hello = ContentInfo {                                             │
│        id-data, ClientHello { client_random, R, offers }             │
│    }                                                                 │
├──────────────────────────────────────────────────────────────────────┤
│ 2. Verify the Reply                                                  │
│    transcript = hello DER || ServerHandshake DER || certificates DER │
│    transcript_hash = SHA3-256(transcript)                            │
│    ✓ signed attrs carry transcript_hash                              │
│    ✓ Verify(signature, SHA3-256(DER(attrs)), server_pub_key)         │
├──────────────────────────────────────────────────────────────────────┤
│ 3. Derive the Handshake Secret                                       │
│    ee = ECDH(r, E)                                                   │
│    hs = HKDF-SHA3-256(                                               │
│        ikm: ee,                                                      │
│        salt: client_random || server_random,                         │
│        info: "tb/session/kdf/v1"                                     │
│    )                                                                 │
├──────────────────────────────────────────────────────────────────────┤
│ 4. Verify the Server Finished                                        │
│    ✓ server_finished =                                               │
│        HMAC(mac_s, transcript_hash || signature)                     │
├──────────────────────────────────────────────────────────────────────┤
│ 5. Sign the Client Finished (an identified client)                   │
│    signed = client_finished_domain || transcript_hash                │
│             || SHA3-256(DER(client_certificate))                     │
│    SignedData {                                                      │
│        content: signed,                                              │
│        certificates: [client_certificate, issuers?],                 │
│        unsigned_attrs: [confirm, sealed_ack?],                       │
│    }                                                                 │
├──────────────────────────────────────────────────────────────────────┤
│ 6. Seal the Closing under k_close                                    │
│    AuthEnvelopedData {                                               │
│        recipient: KEKRecipientInfo under k_close,                    │
│        content_type: id-signedData (Finished)                        │
│            or id-data (anonymous: [confirm, sealed_ack?]),           │
│    }                                                                 │
└──────────────────────────────────────────────────────────────────────┘
```

Server verification flow:

```text
Server Side - Verifying Client Authentication:
┌─────────────────────────────────────────────────────────────┐
│ 1. Open the Closing                                         │
│    cek = AES-256-KW.unwrap(k_close, encrypted_key)          │
│    content = AES-256-GCM.open(cek, nonce, content, mac)     │
│    ✓ The content type is id-signedData or id-data           │
├─────────────────────────────────────────────────────────────┤
│ 2. Compare R with the Certificate Key                       │
│    ✓ R differs from the key of the offered certificate      │
├─────────────────────────────────────────────────────────────┤
│ 3. Confirm the Handshake Secret                             │
│    ✓ Key-confirmation tag matches                           │
├─────────────────────────────────────────────────────────────┤
│ 4. Validate Client Certificate                              │
│    ✓ Verify certificate is within validity period           │
│    ✓ Check certificate chain against trust anchors          │
├─────────────────────────────────────────────────────────────┤
│ 5. Verify the Client Finished                               │
│    signed = client_finished_domain || transcript_hash       │
│             || SHA3-256(DER(client_certificate))            │
│    Verify(signature, SHA3-256(DER(attrs)), client_pub_key)  │
│    ✓ Client holds the key of the certificate it offers      │
└─────────────────────────────────────────────────────────────┘
```

A reply whose server Finished is absent or fails is refused before the client builds its closing, so the client sends its identity only to a server that holds the same secret. [docs/handshake.md](docs/handshake.md#client-identity) states the padding of the closing and the associated data.

**Wire format comparison:**

| Feature             | CMS-based                                                                                                                      | HPKE-based                                                                                                                               |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------- |
| Opening             | `AuthEnvelopedData` with a `KEMRecipientInfo` ([RFC 9629][rfc9629])                      | `ContentInfo` of type `id-data`                                                                                                          |
| Server identity     | The key-agreement certificate pinned before the opening, and the signing certificate from the server Finished's `certificates` | Learned from the reply's `certificates`                                                                                                  |
| Handshake secret    | The ephemeral key exchange and the base secret the opening seals                                                               | The ephemeral key exchange alone                                                                                                         |
| Server confirmation | The server Finished's signature over the transcript, and the server Finished MAC                                               | The reply's signature over the transcript, and the server Finished MAC                                                                   |
| Closing             | `AuthEnvelopedData` with a `KEKRecipientInfo`                                                                                  | The same closing                                                                                                                         |
| Standards           | RFC 5652, [RFC 5083][rfc5083], [RFC 9629][rfc9629] | RFC 5652, [RFC 5083][rfc5083], the [RFC 9846][rfc9846] shape |

**Security equivalence:**

Both protocols target the same properties: mutual authentication, forward secrecy via an ephemeral key exchange, replay protection via nonces, transcript integrity via signatures, and confidentiality via AEAD.

#### 8.5.5 Security Profile Negotiation

CMS and HPKE handshakes both negotiate algorithms through security profile descriptors. The client offers the profiles it supports in `SecurityOffer`, and the server answers with the one it selects in `SecurityAccept`.

**Negotiation process:**

```text
Client                              Server
  │                                   │
  │─── SecurityOffer ───────────────► │
  │    supported_profiles: [          │
  │      Profile1: SHA3-256           │  ◄─ Select the first
  │                AES-128-GCM,       │     mutual profile in
  |                secp256k1          │     server order
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

- The server MUST select a profile from the client's offer, in its own order of preference (CWE-757).
- The server MUST NOT select unsupported algorithms.
- The client MUST verify that the selected profile was in its offer.
- The transcript signature MUST cover the negotiation so a peer cannot downgrade algorithms unnoticed.

**Transport capability negotiation:**

CMS and HPKE handshakes MAY also negotiate multiplexing with `TransportOffer` and `TransportAccept`:

- The two structures travel in the opening handshake messages.
- They bind into the same transcript as security-profile negotiation, so a peer cannot silently enable or disable multiplexing after authentication.

**Transport negotiation process:**

```text
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
  │ Stream caps (directional):        │
  │   the client opens at most M      │
  │   the server opens at most N      │
  │   each side enforces its own      │
  └═══════════════════════════════════┘
```

**Transport validation:**

- Multiplexing MUST activate only when both sides offer it. Otherwise the connection stays single-flight.
- Each side advertises the limits it will receive: how many streams its peer MAY open, chunk size, and stream credit. Each side clamps both stream caps to 1024.
- The offer MAY request session budgets ([§8.6.2](#862-specification-stream-rules-envelopes-and-runtime)).
- The client MUST fail closed on an accept it did not ask for, or on a budget grant that differs from its request.

Stream identifier rules, envelope types, and runtime assembly are in [§8.6 Multiplexing](#86-multiplexing).

#### 8.5.6 Negotiation and Failure Modes

A failed handshake ends in one of these failures:

| Failure                      | Cause                                                                                          | Recovery            |
| ---------------------------- | ---------------------------------------------------------------------------------------------- | ------------------- |
| Certificate refused          | The certificate or its path fails validation                                                   | Reject connection   |
| Signature refused            | A signature over another transcript, such as a replayed reply, or under another key            | Abort handshake     |
| Sealed closing refused       | A closing sealed under another handshake secret, such as a replayed closing, or corrupted data | Abort handshake     |
| No mutual profile            | The offer shares no profile with the server's list                                             | Negotiate or reject |
| Unsolicited transport accept | The peer accepted a transport capability that was never offered                                | Abort handshake     |
| Authorization refused        | The server's authorizer refused the session                                                    | Abort handshake     |
| Invalid state                | Out-of-order message                                                                           | Reset state machine |

#### 8.5.7 Threat-to-Control Mapping

| Threat                     | Control                                     | Implementation                                                                                                                                                                                                                                                                |
| -------------------------- | ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Replay Attack**          | Transcript binding of the opening           | The reply signs a transcript that binds the opening with its client random, and the closing authenticates that transcript hash under a key of its own handshake, so a replayed reply fails its signature check and a replayed closing fails its authenticated transcript hash |
| **Record Replay**          | Authenticated record sequence               | Each record carries its epoch and sequence in `authAttrs`. A receiver refuses another epoch and another sequence than the next                                                                                                                                                |
| **Downgrade Attack**       | Profile list in signed transcript           | Transcript hash covers SecurityOffer/SecurityAccept                                                                                                                                                                                                                           |
| **Multiplexing Downgrade** | Transport offer/accept in signed transcript | Transcript hash covers TransportOffer/TransportAccept. Unsolicited accept fails closed                                                                                                                                                                                        |
| **MITM**                   | Transcript signatures                       | Each signature covers a labelled digest of transcript_hash. Verified against certificates                                                                                                                                                                                     |
| **Confidentiality**        | ECDH + HKDF derived AEAD key                | Session key never transmitted. Derived from ECDH shared secret                                                                                                                                                                                                                |
| **Forward Secrecy**        | Ephemeral keys on both sides                | A fresh ephemeral pair per handshake and per rekey. A later key compromise does not expose past sessions or past epochs                                                                                                                                                       |
| **DoS**                    | 16 KiB handshake size cap                   | Reject oversized handshake messages before processing                                                                                                                                                                                                                         |
| **Stream Cap Inflation**   | Cap clamp and local refusal                 | Caps clamped to 1024. An open past the local cap fails locally, and no stream opens                                                                                                                                                                                           |
| **Reassembly Exhaustion**  | Chunk + credit + cap clamps                 | Chunk size clamped to 1 KiB to 64 KiB, stream credit to 4096 chunks. Per-stream reassembly memory bounded by granted credit and concurrent partial streams by the advertised cap (CWE-770)                                                                                    |
| **Flow-Control Overrun**   | Receiver-side duplicate accounting          | Oversize chunks, credit overruns, and session-budget overspends each answered with GoAway(`ProtocolError`)                                                                                                                                                                    |
| **Rapid Reset**            | Cancel budget + GoAway                      | Peer cancels that abort in-flight handlers draw on a cancel budget, 1024 by default. Exhaustion sends GoAway(`EnhanceYourCalm`) (CVE-2023-44487 / [RFC 9113 §7][rfc9113-7])                                                     |
| **Certificate Forgery**    | X.509 chain validation                      | Verify against a configured root of trust (application responsibility)                                                                                                                                                                                                        |
| **Nonce Reuse**            | Fresh content key per record                | Each record draws a fresh content key and nonce, and wraps the content key under the session key (RFC 5084 §3.2)                                                                                                                                                              |

### 8.6 Multiplexing

Implementation: [docs/transport.md](docs/transport.md#multiplexing)

#### 8.6.1 Concept: Concurrent Streams Over One Connection

A multiplexer (mux) runs concurrent request/response streams on one connection, on the model of [RFC 9113][rfc9113] HTTP/2 streams. Without mux, a connection carries one request and its response at a time, so a slow peer response stalls later requests on that connection. With mux, independent streams interleave on the wire, so one delayed response leaves its siblings running.

Mux is an application-layer stream router over the envelope transport. It runs above TCP and the handshake, after the session is established.

**Design goals:**

- **Concurrency**: Many outstanding request/response pairs per connection without head-of-line blocking
- **Correlation**: Stream identifiers travel inside the `TransportEnvelope` payload
- **Fair limits**: Directional concurrency caps are negotiated per connection and clamped
- **Fair sharing**: Chunking bounds record size. Credit windows bound reassembly memory.
- **Metered sessions**: Optional handshake-granted per-direction budgets bound encrypted-session volume
- **Accountable sessions**: Budget-bearing sessions produce a dual-signed `SessionReceipt`.
- **Epoch renewal**: Budget-bearing sessions renew in band before the cipher record limit ([RFC 9846 §5.5][rfc9846-5.5])
- **Graceful drain**: `GoAway` completes in-flight streams at or below a threshold and rejects newer ones
- **Abuse resistance**: Rapid reset (CVE-2023-44487) exhausts a cancel budget and draws GoAway(`EnhanceYourCalm`)

**Assembly modes:**

| Mode      | Session                                                     | Settings                              | Security properties                                                 |
| --------- | ----------------------------------------------------------- | ------------------------------------- | ------------------------------------------------------------------- |
| Encrypted | CMS or HPKE handshake with matching `TransportOffer`s       | Negotiated in the handshake           | Handshake authentication + AEAD as configured for the session       |
| Cleartext | None: the transport was built as a named cleartext endpoint | Set out of band. Both ends MUST agree | NONE: no confidentiality, integrity, replay, or deletion protection |

Cleartext mux is for controlled environments and tests. It MUST NOT replace an encrypted session on a hostile network.

#### 8.6.2 Specification: Stream Rules, Envelopes, and Runtime

**Stream identifiers** ([RFC 9113 §5.1.1][rfc9113-5.1.1]/[§5.1.2][rfc9113-5.1.2]):

Stream IDs identify one logical stream on one physical connection:

- Client-initiated streams use odd IDs. Server-initiated streams use even IDs.
- Stream ID 0 is reserved and MUST NOT be allocated.
- Each endpoint MUST allocate locally-initiated IDs strictly monotonically.
- `MuxRole::Client` is the handshake initiator (odd IDs).
- `MuxRole::Server` is the responder (even IDs).

**Stream states:**

```text
Idle -> Open -> HalfClosedLocal / HalfClosedRemote -> Closed
```

Streams in `Open`, `HalfClosedLocal`, or `HalfClosedRemote` count toward the peer-advertised concurrency cap. `Idle` and `Closed` do not ([RFC 9113 §5.1.2][rfc9113-5.1.2]).

**Concurrency caps:**

Each endpoint holds two directional caps:

- How many streams this endpoint may initiate, as its peer advertised.
- How many streams the peer may initiate, as this endpoint advertised.

Each endpoint MUST enforce the cap it advertised and respect the cap its peer advertised. A local open past the cap fails locally, and no stream opens.

**Envelope types** (`TransportEnvelope` context tag 4 nests the `MuxEnvelope` CHOICE, inner context tags 0-10):

| Variant         | Role                                                                                                                                                  |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Open`          | Open a stream and carry its first payload chunk inline (`stream_id`, `last`, `kind`, `payload`, and on a routed open `target` and `hops_remaining`)   |
| `Data`          | Continuation chunk on an open stream, either direction (`stream_id`, `last`, `payload`)                                                               |
| `End`           | Responder trailer: `status` plus the final payload chunk inline                                                                                       |
| `Credit`        | Grant absolute cumulative chunk credit on a stream (QUIC MAX_STREAM_DATA, [RFC 9000 §4.1][rfc9000-4.1]) |
| `Cancel`        | Abort a single in-flight stream without tearing down the connection                                                                                   |
| `GoAway`        | Connection-level drain: streams at or below `last_stream_id` complete. Newer streams are rejected                                                     |
| `Ping`          | Liveness probe and ack (`opaque`, `ack`), answered without touching the handler                                                                       |
| `RekeyRequest`  | Client opens an epoch renewal: nonce, ephemeral key ([RFC 9846 §4.7.3][rfc9846-4.7.3] update-request)   |
| `RekeyResponse` | Server answers: nonce and ephemeral key, plus the server-signed epoch receipt that pins both ephemerals                                               |
| `RekeyAck`      | Client accepts: its countersignature. Marks the client-to-server key switch                                                                           |
| `RekeyDone`     | Server confirms settlement. Marks the server-to-client key switch                                                                                     |

**Stream grammar** (unified: a unary request is a degenerate stream, [RFC 9113 §8.1][rfc9113-8.1]):

```text
initiator:  Open(kind, last?)  Data(...)*  Data(last)
responder:  Data(...)*         End(status, payload?)
either:     Cancel(code)       Credit(limit)
```

**Chunking** (mandatory): Every message segments at the peer-advertised `chunk_payload_size` (1-64 KiB, default 16 KiB, [RFC 9113 §4.2][rfc9113-4.2]):

- Reassembly follows arrival order, because the ordered AEAD channel already proves order and completeness, so chunks carry no sequence numbers.
- An oversize chunk is a protocol violation: GoAway(`ProtocolError`).
- A unary message that fits one chunk travels in one record.

**Stream credit**: Each inbound stream gets a chunk allowance (default 64) that the receiver refills with `Credit`. A sender out of credit waits. An overrun is a protocol violation, so reassembly memory stays bounded ([RFC 9000 §4.1][rfc9000-4.1]).

**Session budgets** (optional, encrypted sessions only): The handshake MAY grant each direction a volume of data. When a budget runs out, the send fails and the connection drains.

**Session authorization**: A server-side authorizer reads the offer's opaque `authorization` token:

- It grants budgets, attaches a settlement challenge, or refuses the session.
- It runs before authentication, so keep it cheap.
- The token travels in the clear. At settlement the authorizer receives the certificate of the client that spends the token, so it can refuse a token that another client replays (CWE-294).

**Session receipts**: Every metered session produces a receipt that both peers sign, as CMS `SignedData` ([RFC 5652 §5][rfc5652-5]):

- The receipt binds the handshake transcript, the budgets, and the settlement answer, and it carries the certificate of each signer.
- A third party therefore verifies the agreement from the receipt alone: it takes each signer's certificate from the receipt, admits each against its own trust, and then verifies both signatures.
- Budgets REQUIRE mutual authentication.
- `session_receipt()` reads the receipt.

**Epoch renewal**: Metered sessions renew keys, budgets, and receipts in band before the cipher record limit ([RFC 9846 §5.5][rfc9846-5.5]):

- A renewal keeps the negotiated terms.
- A failed renewal drains the connection.
- Sessions without receipts drain via GoAway, and the caller reconnects.

**Reason codes**: Codes below 0x1000 belong to tightbeam, and applications own the rest, as in HTTP/2 ([RFC 9113 §7][rfc9113-7]). A receiver reads an unknown code as an application code, and an unknown code MUST NOT close the connection.

**Cancel reasons:**

| Reason              | Code    | Meaning                                               |
| ------------------- | ------- | ----------------------------------------------------- |
| `Cancelled`         | 0       | Requester is no longer interested                     |
| `Timeout`           | 1       | Per-stream deadline elapsed before a response arrived |
| `Rejected`          | 2       | Responder refused to process the stream               |
| `Application(code)` | 0x1000+ | Application-defined                                   |

**GoAway reasons:**

| Reason              | Code    | Meaning                                                                       |
| ------------------- | ------- | ----------------------------------------------------------------------------- |
| `Shutdown`          | 0       | Orderly shutdown initiated by the sender                                      |
| `ProtocolError`     | 1       | Peer violated multiplexing rules                                              |
| `EnhanceYourCalm`   | 2       | Peer exceeded the cancel budget (RFC 9113 §7 / CVE-2023-44487 hardening)      |
| `BudgetExhausted`   | 3       | Sender's outbound session budget reached the drain reserve                    |
| `SettlementFailed`  | 4       | A renewed receipt's settlement or approval failed with a tightbeam code       |
| `Application(code)` | 0x1000+ | Application-defined                                                           |

**Request/response flow:**

```text
Client (handle)                            Server (responder)
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

- Dropping an in-flight `emit_on_stream` future cancels the stream. Wrap the future in a timer for a per-stream timeout.
- A mux peer that receives a non-mux envelope MUST send GoAway(`ProtocolError`). A non-mux peer MUST reject muxed envelopes.
- Cancels that abort in-flight handlers draw on a per-connection budget (default 1024). Exhaustion ends the connection with GoAway(`EnhanceYourCalm`).
- Near the cipher record limit, the session renews its epoch or drains via GoAway.

**Runtime architecture:**

```text
┌─────────────────────────────────────────────────────────────┐
│ Application                                                 │
│   handle: emit_on_stream / shutdown                         │
│   responder: serve(handler)                                 │
└───────────────┬─────────────────────────────┬───────────────┘
                │                             │
                ▼                             ▼
        ┌───────────────┐             ┌───────────────┐
        │ Outbound queue│◄────────────│ Inbound queue │
        └───────┬───────┘             └───────▲───────┘
                │                             │
                ▼                             │
        ┌───────────────┐             ┌───────┴───────┐
        │ Writer driver │             │ Reader driver │
        │ (serialize)   │             │ (route)       │
        └───────┬───────┘             └───────▲───────┘
                │                             │
                ▼                             │
        Send half                     Receive half
        (encrypt or cleartext write)  (decrypt or cleartext read)
```

- **Writer driver**: Writes every outbound envelope. Spawn its `drive()` on your executor.
- **Reader driver**: Routes responses to waiting streams and peer requests to the responder. Spawn its `drive()` on your executor.
- **Handle**: Opens streams and awaits their responses.
- **Responder**: Serves peer-initiated streams concurrently with your handler.

#### 8.6.3 Implementation: Assembling MuxTransport

A transport is ready for the mux once its handshake completes, or, for cleartext, once its socket connects. The application then assembles the mux in three steps:

1. Split the transport into exclusive read and write halves.
2. Build `MuxTransport` with the endpoint role and settings.
3. Decompose it into the four parts the application MUST keep running: the handle, the reader driver, the writer driver, and the responder.

**Encrypted path:**

Both sides MUST configure multiplexing before the handshake so the offer is transcript-bound:

```rust,no_run
use tightbeam::policy::TransitStatus;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::multiplex::{MuxConnector, MuxRole};
use tightbeam::transport::ResponsePackage;
# use tightbeam::transport::tcp::r#async::{TcpTransport, TokioStream};
# use tightbeam::Frame;

# async fn emit(mut transport: TcpTransport<TokioStream>, frame: Frame) -> Result<(), Box<dyn std::error::Error>> {
transport = transport.with_mux_offer(Some(TransportOffer::mux(32)));
// Run the CMS or HPKE handshake.
transport.complete_client_handshake().await?;

let mux = transport.into_mux(MuxRole::Client)?;
let (handle, reader_drv, writer_drv, responder) = mux.into_parts();

tokio::spawn(reader_drv.drive());
tokio::spawn(writer_drv.drive());
tokio::spawn(async move {
	responder
		.serve(|_request| async move { ResponsePackage::new(TransitStatus::Ok, None) })
		.await
});

let response = handle.emit_on_stream(&frame).await?;
handle.shutdown().await?;
# Ok(())
# }
```

`shutdown` sends GoAway(`Shutdown`) and waits for open streams to finish. Wrap it in a timer to bound the drain.

A metered session renews its epoch in band only through the rekey state its handshake left, so the assembly decides how the session meets the record limit:

- `into_mux` carries that state into the mux transport, so it serves a metered session.
- A mux transport that `MuxTransport::new` assembles from split halves carries no rekey state, so it drains via GoAway near the record limit, as a session without a receipt does.

**Cleartext path:**

Use cleartext only when both endpoints deliberately skip the handshake. Nothing is negotiated, so both sides SHOULD configure the same caps. A transport built for encryption refuses `into_split` until its handshake completes.

```rust,no_run
use tightbeam::transport::handshake::negotiation::MuxSettings;
use tightbeam::transport::multiplex::{MuxRole, MuxTransport};
# use tightbeam::transport::tcp::r#async::{TcpTransport, TokioStream};
# use tightbeam::transport::TransportResult;

# fn assemble(transport: TcpTransport<TokioStream>) -> TransportResult<()> {
// Both ends MUST share this value. Cleartext mux has no negotiation.
let settings = MuxSettings::symmetric(32);
let (reader, writer) = transport.into_split()?;
let mux = MuxTransport::new(reader, writer, MuxRole::Client, settings);
let (handle, reader_drv, writer_drv, responder) = mux.into_parts();
# Ok(())
# }
```

**Server role:**

The accepting endpoint uses `MuxRole::Server` with the same assembly sequence. Either role may call `emit_on_stream` (server-initiated streams use even IDs). Either role may `serve` peer-initiated requests.

#### 8.6.4 Testing

Test multiplexed services with `environment ServiceClient`:

- The `server:` closure starts a `server!` accept loop advertising `with_mux_offer`.
- The `client:` closure drives a mux-offering `ConnectionPool` against the bound address.
- Peers that decline the offer fall back to single-flight, so the same scenario shape covers both paths.

The scenario calls three helpers of the test's own:

- `ServerMaterials`: the server's certificate and key.
- `bind_listener`: an encrypted listener that presents them.
- `mux_pool`: a pool that trusts that certificate and carries the offer.

```rust,no_run,test_harness
use tightbeam::instrumentation::events;
use tightbeam::testing::TestFrame;
# use std::sync::Arc;
#
# use tightbeam::crypto::policy::Secp256k1Policy;
# use tightbeam::crypto::sign::SigningIdentity;
# use tightbeam::crypto::x509::store::{CertificateTrustBuilder, NoRevocation, TrustBuilder};
# use tightbeam::crypto::x509::KeyCurves;
# use tightbeam::testing::fixtures::{TestCertificate, TestKey};
# use tightbeam::testing::{ClientEnv, TestIdentity};
# use tightbeam::trace::TraceCollector;
# use tightbeam::transport::client::ConnectionBuilder;
# use tightbeam::transport::handshake::negotiation::TransportOffer;
# use tightbeam::transport::tcp::r#async::TokioListener;
# use tightbeam::transport::tcp::TightBeamSocketAddr;
# use tightbeam::transport::{ConnectionPool, EncryptedProtocol, PoolConfig, TransportEncryptionConfig};
# use tightbeam::{exactly, server, tb_assert_spec, tb_scenario, Frame, TightBeamError};
#
# /// The server's certificate and the key that signs for it.
# struct ServerMaterials {
# 	identity: SigningIdentity,
# }
#
# impl ServerMaterials {
# 	fn generate() -> Self {
# 		let key = TestKey::insecure_fixed_signing();
# 		let identity = TestIdentity::presenting(TestCertificate::self_signed(&key), &key);
# 		Self { identity }
# 	}
# }
#
# /// An encrypted listener on a free loopback port that presents `materials`.
# async fn bind_listener(materials: &ServerMaterials) -> Result<(TokioListener, TightBeamSocketAddr), TightBeamError> {
# 	let config = TransportEncryptionConfig::new(materials.identity.clone());
# 	let addr = "127.0.0.1:0".parse()?;
# 	Ok(TokioListener::bind_with(addr, config).await?)
# }
#
# /// A pool that trusts the certificate of `materials` and carries `offer`.
# fn mux_pool(
# 	materials: &ServerMaterials,
# 	offer: Option<TransportOffer>,
# 	trace: &TraceCollector,
# ) -> Result<Arc<ConnectionPool<TokioListener>>, TightBeamError> {
# 	let certificate = materials.identity.certificate().to_owned();
# 	let trust = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
# 	let store = Arc::new(trust.with_certificate(certificate)?.build());
# 	let config = PoolConfig { mux_offer: offer.map(Arc::new), ..PoolConfig::default() };
# 	let builder = ConnectionPool::<TokioListener>::builder().with_config(config);
# 	Ok(Arc::new(builder.with_trust_store(store).with_trace(trace.share()).build()))
# }

tb_assert_spec! {
	pub EchoOverMuxSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(1))
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
			let pool = mux_pool(&materials, Some(TransportOffer::mux(8)), &trace)?;
			let mut lease = pool.connect(addr).await?;

			let frame = TestFrame::v0(Some("ping"), None);
			let order = frame.metadata().order();
			let reply = lease.emit(frame, None).await?;

			let echoed = reply.map(|echo| echo.metadata().order());
			assert_eq!(echoed, Some(order), "the server echoes the frame");

			Ok(())
		}
	}
}
```

#### 8.6.5 Serving and Pooling

`server!` and `ConnectionPool` assemble and drive the mux plane internally. One handler and one `emit` call serve both multiplexed and single-flight peers. Manual assembly remains available for custom setups.

**Serving with** `server!`**:**

The server decides per connection, after the handshake. A peer that negotiated multiplexing gets concurrent handlers, each behind the collector gate. The server advertises multiplexing on each accepted connection through the policy list:

```rust,no_run
# use tightbeam::transport::handshake::negotiation::TransportOffer;
# use tightbeam::transport::tcp::r#async::TokioListener;
# use tightbeam::{server, Frame};
#
# fn serve(listener: TokioListener) {
let server_handle = server! {
	protocol TokioListener: listener,
	policies: { with_mux_offer: [Some(TransportOffer::mux(32))] },
	handle: move |frame: Frame| async move { Ok(Some(frame)) }
};
# }
```

- `None` advertises nothing, so the server stays single-flight.
- `servlet!`, `hive!`, and `cluster!` inherit the option from `server!`. Hives and clusters set it with `mux_offer` in their pool config.
- Serving mux requires an async executor.

A handler that takes the session as its second argument reads the peer and the receipt of its connection. The server applies its policy list to each accepted connection, so each entry is an expression that gives a fresh value, such as a clone:

```rust,no_run
# use std::sync::Arc;
#
# use tightbeam::policy::SessionContext;
# use tightbeam::transport::handshake::negotiation::{TransportAuthorizer, TransportOffer};
# use tightbeam::transport::tcp::r#async::TokioListener;
# use tightbeam::{server, Frame};
#
# fn serve(listener: TokioListener, offer: TransportOffer, authorizer: Arc<dyn TransportAuthorizer>) {
let server_handle = server! {
	protocol TokioListener: listener,
	policies: { with_mux_offer: [Some(offer.clone())], with_transport_authorizer: [Arc::clone(&authorizer)] },
	handle: move |frame: Frame, session: SessionContext| async move {
		let certificate = session.peer_certificate();  // mutual-auth client identity
		let receipt = session.session_receipt();       // dual-signed budget receipt
		Ok(Some(frame))
	}
};
# }
```

**Pooling with** `PoolConfig::mux_offer`**:**

```rust,no_run
# use std::sync::Arc;
#
# use tightbeam::crypto::x509::store::CertificateTrust;
# use tightbeam::transport::client::ConnectionBuilder;
# use tightbeam::transport::handshake::negotiation::TransportOffer;
# use tightbeam::transport::tcp::r#async::TokioListener;
# use tightbeam::transport::tcp::TightBeamSocketAddr;
# use tightbeam::transport::{ConnectionPool, PoolConfig};
# use tightbeam::Frame;
#
# async fn emit(
# 	trust_store: Arc<dyn CertificateTrust>,
# 	server_addr: TightBeamSocketAddr,
# 	frame: Frame,
# ) -> Result<(), Box<dyn std::error::Error>> {
let pool = Arc::new(ConnectionPool::<TokioListener>::builder()
	.with_config(PoolConfig { mux_offer: Some(Arc::new(TransportOffer::mux(32))), ..Default::default() })
	.with_trust_store(trust_store)
	.build());

let mut client = pool.connect(server_addr).await?;
let response = client.emit(frame, None).await?;
# Ok(())
# }
```

With an offer configured, every `connect` to a destination leases the same multiplexed connection until its stream caps fill. `emit` is the transport-agnostic call, and it opens a fresh stream.

**Metered pooled sessions** (budgets on the offer, settlement hooks on the pool):

```rust,no_run
# use std::sync::Arc;
#
# use tightbeam::crypto::key::SigningKeyProvider;
# use tightbeam::crypto::sign::SigningIdentity;
# use tightbeam::crypto::x509::store::CertificateTrust;
# use tightbeam::crypto::x509::CertificateSpec;
# use tightbeam::transport::client::ConnectionBuilder;
# use tightbeam::transport::handshake::negotiation::{MuxBudgets, TransportOffer};
# use tightbeam::transport::handshake::receipt::ReceiptApprover;
# use tightbeam::transport::tcp::r#async::TokioListener;
# use tightbeam::transport::tcp::TightBeamSocketAddr;
# use tightbeam::transport::{ConnectionPool, PoolConfig};
#
# async fn lease(
# 	offer: TransportOffer,
# 	budgets: MuxBudgets,
# 	trust_store: Arc<dyn CertificateTrust>,
# 	client_cert: CertificateSpec,
# 	client_key: Arc<dyn SigningKeyProvider>,
# 	approver: Arc<dyn ReceiptApprover>,
# 	server_addr: TightBeamSocketAddr,
# ) -> Result<(), Box<dyn std::error::Error>> {
let pool = Arc::new(ConnectionPool::<TokioListener>::builder()
	.with_config(PoolConfig { mux_offer: Some(Arc::new(offer.with_budgets(budgets))), ..Default::default() })
	.with_trust_store(trust_store)
	.with_client_identity(SigningIdentity::from_spec(client_cert, client_key)?)  // budgets REQUIRE mutual auth
	.with_receipt_approver(approver)                 // answers settlement challenges
	.build());

let lease = pool.connect(server_addr).await?;
let receipt = lease.session_receipt();  // Option<Arc<StoredReceipt>>
# Ok(())
# }
```

- `with_receipt_approver` answers settlement challenges for every pooled connection. Without one, a session that carries a challenge fails.
- `session_receipt()` returns the connection's current receipt, or `None` for an unmetered session.
- Size an invoice against the credits left for application data: the granted send budget less the reserve the drain keeps.

**Fallback semantics** (automatic, per connection):

| Client pool     | Server      | Result                                        |
| --------------- | ----------- | --------------------------------------------- |
| `mux_offer` set | mux-serving | One shared mux connection, concurrent streams |
| `mux_offer` set | no offer    | Exclusive lease, unchanged behavior           |
| No offer        | mux-serving | Exclusive lease, unchanged behavior           |
| No offer        | no offer    | Exclusive lease, unchanged behavior           |

**Mux connection lifecycle in the pool:**

- Stream-cap exhaustion: `emit` moves to a pooled connection with stream headroom, or opens an additional mux connection to the same destination (bounded by `max_connections`), and retries there once.
- A closed connection, or a drain after a rekey GoAway: the entry is evicted and the failure is reported. The next `connect` re-establishes with fresh keys.
- Dead entries, whose connection ended, are pruned on the next `connect`. Multiple live entries round-robin.

### 8.7 Connection Pooling

`ConnectionPool` reuses connections across requests. Configure the pool once with `.builder()`. Call `.connect()` to retrieve a connection. Implementation: [docs/transport.md](docs/transport.md#connection-pooling).

**Example:**

```rust,no_run
# use core::num::NonZeroUsize;
# use core::time::Duration;
# use std::sync::Arc;
#
# use tightbeam::crypto::key::SigningKeySpec;
# use tightbeam::crypto::sign::ecdsa::Secp256k1;
# use tightbeam::crypto::sign::SigningIdentity;
# use tightbeam::crypto::x509::store::CertificateTrust;
# use tightbeam::crypto::x509::CertificateSpec;
# use tightbeam::transport::client::ConnectionBuilder;
# use tightbeam::transport::tcp::r#async::TokioListener;
# use tightbeam::transport::tcp::TightBeamSocketAddr;
# use tightbeam::transport::{ConnectionPool, PoolConfig};
# use tightbeam::Frame;
#
# // The caller supplies the client certificate and its key under the names of
# // the constants an application declares for them.
# #[allow(non_snake_case)]
# async fn emit(
# 	CLIENT_CERT: CertificateSpec,
# 	CLIENT_KEY: SigningKeySpec,
# 	trust_store: Arc<dyn CertificateTrust>,
# 	server_addr: TightBeamSocketAddr,
# 	frame: Frame,
# ) -> Result<(), Box<dyn std::error::Error>> {
// Create shared pool with configuration (once per application)
let pool = Arc::new(ConnectionPool::<TokioListener>::builder()
	.with_config(PoolConfig { max_connections: NonZeroUsize::try_from(3)?, ..Default::default() })
	.with_trust_store(trust_store)
	.with_client_identity(SigningIdentity::from_spec(CLIENT_CERT, CLIENT_KEY.to_provider::<Secp256k1>()?)?)
	.with_timeout(Duration::from_millis(5000))
	.build());

// Get connection from pool
let mut client = pool.connect(server_addr).await?;

client.emit(frame, None).await?;
// Connection automatically returned to pool on drop
# Ok(())
# }
```

**Configuration:**

The pool configuration sets four terms:

- Live connections: capped across all destinations, at 64 by default.
- Idle connections: kept until another reason evicts them, unless an idle timeout drops them first.
- Multiplexing: off unless an offer is set ([§8.6.5](#865-serving-and-pooling)).
- Clock: measures idle time, deadlines, and backoff, on the system clock by default.

### 8.8 Audit

The tightbeam transport layer and handshake protocols have not yet been independently audited. Help in this area is welcome. Implementation: [docs/transport.md](docs/transport.md#audit-trail).

#### 8.8.1 Audit Trail Deployment Requirements

Access and session verdicts are recorded only when the deployment opts in. They are:

- Gate accepts and rejects, with the refusing status and the peer SPKI hash.
- Refused session certificates.
- Receipt events.

Deployments with audit obligations (for example ISO 27001 A.8.15, NIST 800-53 AU-2) MUST:

1. Build with instrumentation, and attach a trace to every transport that terminates connections.
2. Record payload hashes in the trace if peer identity (SPKI SHA3-256) must appear on gate verdicts.
3. Provide a durable event sink. The default sink is a bounded in-memory buffer. Once full, it keeps the oldest events and drops each new one, and the exported evidence records the truncation ([§10.5](#105-configuration)).

Event timestamps count nanoseconds on the trace's clock since its origin:

- The origin is the reading the trace takes of a clock when it adopts that clock: the system clock at construction, or a clock the deployment supplies later.
- Once per origin, a `urn:tightbeam:event:trace/clock-origin` event records the origin as Unix-epoch nanoseconds, at the millisecond precision of the clock, so offline tools can map relative timestamps to absolute times.

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

Implementation: [docs/colony.md](docs/colony.md)

Think of workers as ants, servlets as ant hills, and clusters as ant colonies. Insects have specific functions with which they process organic matter using local information. These functions are often simple, but when combined in large numbers, they can perform complex tasks. The efficiency of each unit comes from its fungible nature: how well it accomplishes its singular task.

#### 9.3.1 E: Workers

Workers are the smallest unit of computation in the EEIC: the "ants" that do the work. Most business logic is independent of the network: a function that doubles a number works the same whether its input came from TCP, UDP, or an in-memory channel. Isolating that logic into workers gives:

- **Parallelism**: Multiple workers can process messages concurrently
- **Fault Isolation**: A failing worker leaves its servlet running
- **Testability**: Workers can be tested without network setup
- **Reusability**: The same worker can serve multiple servlets

Implementation: [docs/colony.md](docs/colony.md#workers)

##### Design Constraints

Workers are intentionally constrained:

1. **Single-threaded**: Each worker processes one message at a time
2. **Message-only**: Workers receive decoded messages, not raw Frames
3. **Stateless between messages**: Configuration is fixed at creation time

These constraints give EEIC its parallelism and fault isolation. Each worker transforms input to output on its own.

> Note: Do not work around the Frame limitation by stuffing a Frame into a message parameter. Handle Frame concerns at the servlet boundary instead.

##### The `worker!` Macro

Workers follow an insect-inspired structure: a "head" (configuration), optional "receptors" (gates), a "thorax" (isolation container), and an "abdomen" (handler).

```rust
# use tightbeam::der::Sequence;
# use tightbeam::policy::{ReceptorPolicy, TransitStatus};
# use tightbeam::Beamable;
# #[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
# pub struct RequestMessage {
# 	pub content: String,
# 	pub lucky_number: u32,
# }
# #[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
# pub struct PongMessage {
# 	pub result: String,
# }
# pub struct PingGate;
# impl ReceptorPolicy<RequestMessage> for PingGate {
# 	fn evaluate(&self, message: &RequestMessage) -> TransitStatus {
# 		if message.content == "PING" { TransitStatus::Ok } else { TransitStatus::PermissionDenied }
# 	}
# }
tightbeam::worker! {
	name: PingPongWorker<RequestMessage, PongMessage>,
	config: {
		response: String,
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

The examples of this section share two message types and the receptor gate of the worker above. The gate admits a message before the handler sees it:

```rust
use tightbeam::der::Sequence;
use tightbeam::policy::{ReceptorPolicy, TransitStatus};
use tightbeam::Beamable;

#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
pub struct RequestMessage {
	pub content: String,
	pub lucky_number: u32,
}

#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
pub struct PongMessage {
	pub result: String,
}

pub struct PingGate;

impl ReceptorPolicy<RequestMessage> for PingGate {
	fn evaluate(&self, message: &RequestMessage) -> TransitStatus {
		if message.content == "PING" {
			TransitStatus::Ok
		} else {
			TransitStatus::PermissionDenied
		}
	}
}
```

A worker with a config and no gates omits `policies`. The servlet below relays each request to this worker beside `PingPongWorker`:

```rust
# use tightbeam::der::Sequence;
# use tightbeam::Beamable;
# #[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
# pub struct RequestMessage {
# 	pub content: String,
# 	pub lucky_number: u32,
# }
tightbeam::worker! {
	name: LuckyNumberDeterminer<RequestMessage, bool>,
	config: {
		lotto_number: u32,
	},
	handle: |message, _trace, config| async move {
		message.lucky_number == config.lotto_number
	}
}
```

##### Testing

Workers can be tested using the `tb_scenario!` macro with `environment Worker`:

```rust,test_harness
use std::sync::Arc;

use tightbeam::colony::worker::Worker;
use tightbeam::testing::WorkerEnv;
use tightbeam::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_scenario, urn};
# use tightbeam::der::Sequence;
# use tightbeam::policy::{ReceptorPolicy, TransitStatus};
# use tightbeam::Beamable;
# #[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
# pub struct RequestMessage {
# 	pub content: String,
# 	pub lucky_number: u32,
# }
# #[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
# pub struct PongMessage {
# 	pub result: String,
# }
# pub struct PingGate;
# impl ReceptorPolicy<RequestMessage> for PingGate {
# 	fn evaluate(&self, message: &RequestMessage) -> TransitStatus {
# 		if message.content == "PING" { TransitStatus::Ok } else { TransitStatus::PermissionDenied }
# 	}
# }
# tightbeam::worker! {
# 	name: PingPongWorker<RequestMessage, PongMessage>,
# 	config: {
# 		response: String,
# 	},
# 	policies: {
# 		with_receptor_gate: [PingGate]
# 	},
# 	handle: |_message, _trace, config| async move {
# 		PongMessage { result: config.response.to_string() }
# 	}
# }

const WORKER_CALLED: Urn<'static> = urn!("test", "event:worker/called");
const RESPONSE_RECEIVED: Urn<'static> = urn!("test", "event:worker/response-received");

tb_assert_spec! {
	pub PingPongSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(WORKER_CALLED, exactly!(1)),
			(RESPONSE_RECEIVED, exactly!(1), equals!("pong"))
		]
	}
}

tb_scenario! {
	name: test_ping_pong_worker,
	spec: PingPongSpec,
	environment Worker {
		setup: |_env| {
			PingPongWorker::new(PingPongWorkerConfig {
				response: "pong".to_string(),
			})
		},
		stimulus: |WorkerEnv { trace, worker, .. }| async move {
			trace.event_with(WORKER_CALLED, &[], ())?;

			let request = RequestMessage { content: "PING".to_string(), lucky_number: 7 };
			let response = worker.relay(Arc::new(request)).await?;

			trace.event_with(RESPONSE_RECEIVED, &[], response.result)?;
			Ok(())
		}
	}
}
```

The `environment Worker` syntax provides:

- `setup`: Creates the worker builder from a `SetupEnv` (sync)
- `stimulus`: Drives the started worker through `WorkerEnv` via `relay()` and records trace events

Assertion labels are `Urn` constants shared by emit sites and the spec (exact string match). The `spec:` key expands to a `ScenarioConfig` with that spec's latest version.

#### 9.3.2 E: Servlets

Servlets are the network endpoints of the EEIC: the "anthills" where messages arrive and are processed. Workers own pure business logic. Servlets own the protocol layer: accept connections, decode frames, dispatch to workers, and send responses.

Implementation: [docs/colony.md](docs/colony.md#servlets)

##### Architecture

Servlets sit between the network and workers:

1. **Listen** on a protocol-specific endpoint (e.g., TCP port)
2. **Receive** raw Frames from clients
3. **Decode** and validate incoming messages
4. **Dispatch** to one or more workers for processing
5. **Compose** the response Frame and send it back

Servlets therefore own connection management, frame validation, and response composition, so workers stay free of those concerns.

##### Single Message Type Rule

Each servlet is responsible for exactly one message type. This keeps servlets focused and predictable. When you need to handle multiple related message types, use an ASN.1 Choice type to group them:

```rust
# use tightbeam::der::{Choice, Sequence};
# use tightbeam::Beamable;
# #[derive(Clone, Debug, PartialEq, Sequence)]
# pub struct AddParams {
# 	pub a: u64,
# 	pub b: u64,
# }
# #[derive(Clone, Debug, PartialEq, Sequence)]
# pub struct MultiplyParams {
# 	pub a: u64,
# 	pub b: u64,
# }
# #[derive(Clone, Debug, PartialEq, Sequence)]
# pub struct DivideParams {
# 	pub dividend: u64,
# 	pub divisor: u64,
# }
// A Choice type groups related messages, each under its own tag
#[derive(Beamable, Choice, Clone, Debug, PartialEq)]
pub enum CalcRequest {
	#[asn1(context_specific = "0", constructed = "true")]
	Add(AddParams),
	#[asn1(context_specific = "1", constructed = "true")]
	Multiply(MultiplyParams),
	#[asn1(context_specific = "2", constructed = "true")]
	Divide(DivideParams),
}
```

> Note: Keep a strict separation of concerns between servlets. Each servlet should handle only one message type, and a Choice type that groups unrelated message types is poor form.

##### Gate Policies

Servlets can apply gate policies to filter or validate incoming messages before processing. The servlet's configuration carries the gates, and the handler runs only when every gate passes:

```rust,no_run
# use std::sync::Arc;
# use tightbeam::colony::hive::PeerListGate;
# use tightbeam::colony::servlet::ServletConfig;
# use tightbeam::crypto::key::Secp256k1KeyProvider;
# use tightbeam::crypto::sign::ecdsa::Secp256k1SigningKey;
# use tightbeam::crypto::x509::policy::CertificateValidation;
# use tightbeam::crypto::x509::{Certificate, CertificateSpec};
# use tightbeam::der::Sequence;
# use tightbeam::trace::TraceCollector;
# use tightbeam::transport::TokioListener;
# use tightbeam::{compose, servlet, Beamable};
# #[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
# pub struct Request {
# 	pub value: u32,
# }
# servlet! {
# 	pub SecureServlet<Request, EnvConfig = ()>,
# 	protocol: TokioListener,
# 	handle: |request, frame, _ctx| async move {
# 		Ok(Some(compose! { V0: id: frame.metadata().id(), message: request }?))
# 	}
# }
# async fn start_gated(
# 	trace: Arc<TraceCollector>,
# 	cert: Certificate,
# 	key: Secp256k1SigningKey,
# 	client_spki: Vec<u8>,
# 	validators: Vec<Arc<dyn CertificateValidation>>,
# ) -> Result<(), Box<dyn core::error::Error>> {
// Admit only the clients whose certificate keys the list names
let clients = PeerListGate::allow([client_spki])?;

let servlet_conf = ServletConfig::<TokioListener, Request>::builder()
	.with_collector_gate(clients)
	// A non-empty validator list turns on the client certificates the gate reads
	.with_certificate(CertificateSpec::Built(Box::new(cert)), Arc::new(Secp256k1KeyProvider::from(key)), validators)?
	.build();

let servlet = SecureServlet::start(trace, servlet_conf).await?;
# servlet.stop();
# Ok(())
# }
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
# use std::sync::Arc;
# use tightbeam::der::Sequence;
# use tightbeam::policy::{ReceptorPolicy, TransitStatus};
# use tightbeam::transport::TokioListener;
# use tightbeam::urn::Urn;
# use tightbeam::{compose, urn, Beamable};
# #[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
# pub struct RequestMessage {
# 	pub content: String,
# 	pub lucky_number: u32,
# }
# #[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
# pub struct PongMessage {
# 	pub result: String,
# }
# pub struct PingGate;
# impl ReceptorPolicy<RequestMessage> for PingGate {
# 	fn evaluate(&self, message: &RequestMessage) -> TransitStatus {
# 		if message.content == "PING" { TransitStatus::Ok } else { TransitStatus::PermissionDenied }
# 	}
# }
# tightbeam::worker! {
# 	name: PingPongWorker<RequestMessage, PongMessage>,
# 	config: { response: String },
# 	policies: { with_receptor_gate: [PingGate] },
# 	handle: |_message, _trace, config| async move {
# 		PongMessage { result: config.response.to_string() }
# 	}
# }
# tightbeam::worker! {
# 	name: LuckyNumberDeterminer<RequestMessage, bool>,
# 	config: { lotto_number: u32 },
# 	handle: |message, _trace, config| async move {
# 		message.lucky_number == config.lotto_number
# 	}
# }
# #[derive(Clone)]
# pub struct PingPongServletConfig {
# 	pub service_name: String,
# }
const REQUEST_RECEIVED: Urn<'static> = urn!("test", "event:servlet/request-received");

#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
pub struct ResponseMessage {
	pub result: String,
	pub is_winner: bool,
}

tightbeam::servlet! {
	pub PingPongServletWithWorker<RequestMessage, EnvConfig = PingPongServletConfig>,
	protocol: TokioListener,
	handle: |request, _frame, ctx| async move {
		// Access context members
		let trace = ctx.trace();
		let config: &PingPongServletConfig = ctx.env_config();
		trace.event_with(REQUEST_RECEIVED, &[], config.service_name.clone())?;

		// The handler receives the decoded message beside its frame
		let request = Arc::new(request);

		// Workers are accessed via ctx.relay
		let (ping_result, lucky_result) = tokio::join!(
			ctx.relay::<PingPongWorker>(Arc::clone(&request)),
			ctx.relay::<LuckyNumberDeterminer>(Arc::clone(&request))
		);

		// A relay answers the worker's output, or the error that refused it
		let reply = ping_result?;
		let is_winner = lucky_result?;

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

```rust,no_run
# use std::sync::Arc;
# use tightbeam::colony::servlet::ServletConfig;
# use tightbeam::trace::TraceCollector;
# use tightbeam::transport::TokioListener;
# use tightbeam::der::Sequence;
# use tightbeam::policy::{ReceptorPolicy, TransitStatus};
# use tightbeam::urn::Urn;
# use tightbeam::{urn, Beamable};
# #[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
# pub struct RequestMessage {
# 	pub content: String,
# 	pub lucky_number: u32,
# }
# #[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
# pub struct PongMessage {
# 	pub result: String,
# }
# #[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
# pub struct ResponseMessage {
# 	pub result: String,
# 	pub is_winner: bool,
# }
# pub struct PingGate;
# impl ReceptorPolicy<RequestMessage> for PingGate {
# 	fn evaluate(&self, message: &RequestMessage) -> TransitStatus {
# 		if message.content == "PING" { TransitStatus::Ok } else { TransitStatus::PermissionDenied }
# 	}
# }
# tightbeam::worker! {
# 	name: PingPongWorker<RequestMessage, PongMessage>,
# 	config: { response: String },
# 	policies: { with_receptor_gate: [PingGate] },
# 	handle: |_message, _trace, config| async move {
# 		PongMessage { result: config.response.to_string() }
# 	}
# }
# tightbeam::worker! {
# 	name: LuckyNumberDeterminer<RequestMessage, bool>,
# 	config: { lotto_number: u32 },
# 	handle: |message, _trace, config| async move {
# 		message.lucky_number == config.lotto_number
# 	}
# }
# #[derive(Clone)]
# pub struct PingPongServletConfig {
# 	pub service_name: String,
# }
# const REQUEST_RECEIVED: Urn<'static> = urn!("test", "event:servlet/request-received");
# tightbeam::servlet! {
# 	pub PingPongServletWithWorker<RequestMessage, EnvConfig = PingPongServletConfig>,
# 	protocol: TokioListener,
# 	handle: |request, _frame, ctx| async move {
# 		let config: &PingPongServletConfig = ctx.env_config();
# 		ctx.trace().event_with(REQUEST_RECEIVED, &[], config.service_name.clone())?;
# 		let request = Arc::new(request);
# 		let (ping_result, lucky_result) = tokio::join!(
# 			ctx.relay::<PingPongWorker>(Arc::clone(&request)),
# 			ctx.relay::<LuckyNumberDeterminer>(Arc::clone(&request))
# 		);
# 		let reply = ping_result?;
# 		let is_winner = lucky_result?;
# 		Ok(Some(tightbeam::compose! {
# 			V0: id: b"response-id",
# 				message: ResponseMessage { result: reply.result, is_winner }
# 		}?))
# 	}
# }
# async fn start_servlet(trace: Arc<TraceCollector>) -> Result<(), tightbeam::TightBeamError> {
// Create workers (use ::new, not .start - servlet auto-starts them)
let ping_pong_worker = PingPongWorker::new(PingPongWorkerConfig {
	response: "pong".to_string(),
});
let lucky_number_worker = LuckyNumberDeterminer::new(LuckyNumberDeterminerConfig {
	lotto_number: 42,
});

// Build servlet configuration
let servlet_conf = ServletConfig::<TokioListener, RequestMessage>::builder()
	.with_config(Arc::new(PingPongServletConfig { service_name: "ping-pong".to_string() }))
	.with_worker(ping_pong_worker)
	.with_worker(lucky_number_worker)
	.allow_cleartext()
	.build();

// Start the servlet (workers are auto-started with servlet's trace)
let servlet = PingPongServletWithWorker::start(trace, servlet_conf).await?;
# servlet.stop();
# Ok(())
# }
```

A servlet serves in the clear only where its configuration says so (CWE-319):

- `.allow_cleartext()` on the builder names cleartext. `ServletConfig::cleartext()` is that choice over the default env.
- `.with_certificate(..)` turns the handshake on under the reference provider, and `.with_identity(..)` turns it on under a signing identity of any provider.

The builder offers `build` only after one of these calls.

**Macro-free path**

`servlet!` is shorthand for a servlet runtime and its request handlers. Code without the macro builds the two itself, as [docs/colony.md](docs/colony.md#macro-free-servlet) describes.

A builder that never calls `with_config` gives the servlet the unit env, `EnvConfig = ()`.

**Worker Lifecycle**

Workers follow a two-phase lifecycle:

1. **Creation** (`::new(config)`) - Creates the worker in an unstarted state
2. **Starting** (`.start(trace)`) - Spawns the worker's async task loop with a trace collector

When workers are added to a servlet via `ServletConfig::builder().with_worker(worker)`:

- The servlet automatically calls `.start(trace)` on each worker during servlet startup
- Workers inherit the servlet's trace collector for instrumentation
- All worker events are captured in the servlet's trace

For standalone worker testing (outside servlets), start the worker yourself:

```rust
# use std::sync::Arc;
# use tightbeam::colony::worker::{Worker, WorkerRelayError};
# use tightbeam::testing::TestMessage;
# use tightbeam::trace::TraceCollector;
# tightbeam::worker! {
# 	name: MyWorker<TestMessage, usize>,
# 	config: { scale: usize },
# 	handle: |message, _trace, config| async move { message.content.len() * config.scale }
# }
# #[tokio::main(flavor = "current_thread")]
# async fn main() -> Result<(), WorkerRelayError> {
# let config = MyWorkerConfig { scale: 2 };
let worker = MyWorker::new(config);
let trace = Arc::new(TraceCollector::new());
let started_worker = worker.start(trace);
# let doubled = Worker::relay(&started_worker, Arc::new(TestMessage::sample(Some("ping")))).await?;
# assert_eq!(doubled, 8);
# Ok(())
# }
```

**Efficient Parallel Worker Processing**

A worker takes its input message behind an `Arc`, so several workers can read one decoded message at once with no copy. Wrap the message once, and give each worker a clone, here with `tokio::join!`:

```rust
# use std::sync::Arc;
# use tightbeam::colony::servlet::ServletContext;
# use tightbeam::testing::TestMessage;
# tightbeam::worker! {
# 	name: WorkerA<TestMessage, usize>,
# 	handle: |message, _trace| async move { message.content.len() }
# }
# tightbeam::worker! {
# 	name: WorkerB<TestMessage, bool>,
# 	handle: |message, _trace| async move { message.content.is_empty() }
# }
# async fn handle(ctx: &ServletContext, decoded: TestMessage) -> Result<(), tightbeam::TightBeamError> {
let decoded_arc = Arc::new(decoded);
let (result1, result2) = tokio::join!(
	ctx.relay::<WorkerA>(Arc::clone(&decoded_arc)),
	ctx.relay::<WorkerB>(Arc::clone(&decoded_arc))
);
# let (_length, _empty) = (result1?, result2?);
# Ok(())
# }
```

##### Testing

Servlets with workers can be tested using `environment Servlet`. This scenario tests the servlet of [Defining a Servlet](#defining-a-servlet):

```rust,no_run,test_harness
use tightbeam::{compose, exactly, tb_assert_spec, tb_scenario, TightBeamError};
use tightbeam::instrumentation::events;
use tightbeam::testing::{fixtures::TestTrace, ScenarioConfig};
# use std::sync::Arc;
# use tightbeam::colony::servlet::ServletConfig;
# use tightbeam::transport::{ClientBuilder, ConnectionBuilder, TokioListener};
# use tightbeam::der::Sequence;
# use tightbeam::policy::{ReceptorPolicy, TransitStatus};
# use tightbeam::urn::Urn;
# use tightbeam::{urn, Beamable};
# #[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
# pub struct RequestMessage {
# 	pub content: String,
# 	pub lucky_number: u32,
# }
# #[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
# pub struct PongMessage {
# 	pub result: String,
# }
# #[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
# pub struct ResponseMessage {
# 	pub result: String,
# 	pub is_winner: bool,
# }
# pub struct PingGate;
# impl ReceptorPolicy<RequestMessage> for PingGate {
# 	fn evaluate(&self, message: &RequestMessage) -> TransitStatus {
# 		if message.content == "PING" { TransitStatus::Ok } else { TransitStatus::PermissionDenied }
# 	}
# }
# tightbeam::worker! {
# 	name: PingPongWorker<RequestMessage, PongMessage>,
# 	config: { response: String },
# 	policies: { with_receptor_gate: [PingGate] },
# 	handle: |_message, _trace, config| async move {
# 		PongMessage { result: config.response.to_string() }
# 	}
# }
# tightbeam::worker! {
# 	name: LuckyNumberDeterminer<RequestMessage, bool>,
# 	config: { lotto_number: u32 },
# 	handle: |message, _trace, config| async move {
# 		message.lucky_number == config.lotto_number
# 	}
# }
# #[derive(Clone)]
# pub struct PingPongServletConfig {
# 	pub service_name: String,
# }
# const REQUEST_RECEIVED: Urn<'static> = urn!("test", "event:servlet/request-received");
# tightbeam::servlet! {
# 	pub PingPongServletWithWorker<RequestMessage, EnvConfig = PingPongServletConfig>,
# 	protocol: TokioListener,
# 	handle: |request, _frame, ctx| async move {
# 		let config: &PingPongServletConfig = ctx.env_config();
# 		ctx.trace().event_with(REQUEST_RECEIVED, &[], config.service_name.clone())?;
# 		let request = Arc::new(request);
# 		let (ping_result, lucky_result) = tokio::join!(
# 			ctx.relay::<PingPongWorker>(Arc::clone(&request)),
# 			ctx.relay::<LuckyNumberDeterminer>(Arc::clone(&request))
# 		);
# 		let reply = ping_result?;
# 		let is_winner = lucky_result?;
# 		Ok(Some(tightbeam::compose! {
# 			V0: id: b"response-id",
# 				message: ResponseMessage { result: reply.result, is_winner }
# 		}?))
# 	}
# }

tb_assert_spec! {
	pub PingPongServletSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::HANDLER_ENTER, exactly!(1)),
			(REQUEST_RECEIVED, exactly!(1), equals!("ping-pong")),
			(events::HANDLER_EXIT, exactly!(1))
		]
	}
}

tb_scenario! {
	name: test_ping_pong_servlet,
	// The handler events are internal detail, so the trace turns detail on.
	config: ScenarioConfig::builder()
		.with_spec(PingPongServletSpec::latest())
		.with_trace(TestTrace::with_detail(true))
		.build(),
	environment Servlet {
		context: PingPongServletConfig { service_name: "ping-pong".to_string() },
		start: |env| async move {
			let ping_pong_worker = PingPongWorker::new(PingPongWorkerConfig {
				response: "pong".to_string(),
			});
			let lucky_number_worker = LuckyNumberDeterminer::new(LuckyNumberDeterminerConfig {
				lotto_number: 42,
			});

			let servlet_conf = ServletConfig::<TokioListener, RequestMessage>::builder()
				.with_config(env.context)
				.with_worker(ping_pong_worker)
				.with_worker(lucky_number_worker)
				.allow_cleartext()
				.build();

			PingPongServletWithWorker::start(Arc::new(env.trace), servlet_conf).await
		},
		setup: |env| async move {
			let builder = ClientBuilder::<TokioListener>::builder().allow_cleartext().build();
			let client = builder.connect(env.addr).await?;
			Ok(client)
		},
		client: |env| async move {
			let mut client = env.client;
			let request = compose! {
				V0: id: b"ping-req",
					message: RequestMessage { content: "PING".to_string(), lucky_number: 42 }
			}?;

			let response_frame = client.emit(request, None).await?
				.ok_or(TightBeamError::MissingResponse)?;
			let response: ResponseMessage = response_frame.decode_message()?;

			assert_eq!(response.result, "pong", "the worker answers its configured response");
			assert!(response.is_winner, "42 is the lotto number");
			Ok(())
		}
	}
}
```

The `environment Servlet` syntax provides:

- `context`: Scenario fixture shared as `Arc<C>` with every closure (unit when omitted)
- `start`: Configures and starts the servlet with workers from a `SetupEnv`
- `setup`: Builds the client connection from a `ClientEnv` (optional). Default connects a plain `TokioListener` client
- `client`: Sends requests through `ServletEnv` and asserts each response on the scenario task

#### 9.3.3 I: Hives

Hives sit between clusters and servlets. A servlet handles one message type on one listener. A hive can manage multiple servlets and coordinate with a cluster for work distribution. Think of hives as "ant nests" that house specialized workers (servlets).

Implementation: [docs/colony.md](docs/colony.md#hives)

##### Operating Modes

Hives support two operating modes:

**Single-Servlet Mode** lets a hive "morph" between servlet types. The cluster sends an `ActivateServletRequest`. The hive stops its current servlet and starts the requested one. That supports dynamic workload reallocation, such as a switch from "analysis" to "calculation" on cluster demand.

**Multi-Servlet Mode** runs all registered servlets at once, each on a different port. That requires a "mycelial" protocol (like TCP) which supports multiple endpoints. Call `establish(trace)` after `register` to spawn registered servlets, then register with a cluster to advertise capabilities.

The protocol's capabilities select the mode. On mycelial protocols, multi-servlet mode usually gives the best throughput.

##### Mycelial Protocols

"Mycelial" means a protocol can spawn multiple endpoints from one base address, as fungal mycelium branches from a central point. TCP is mycelial: one host address (for example `192.168.1.100`) can bind multiple ports (`SocketAddress`). A hive can then spawn servlets on ports 8001, 8002, 8003, and so on, each handling a different message type.

Non-mycelial protocols (like in-memory channels) stay in single-servlet mode.

##### The `hive!` Macro

`hive!` names a hive type for one protocol. Register servlets on it at runtime:

```rust
# use tightbeam::hive;
# use tightbeam::transport::TokioListener;
hive! {
	pub MyHive,
	protocol: TokioListener
}
```

The hive builds the gates of its control plane from its configuration:

- Command authentication comes from its trust store ([Cluster Trust](#cluster-trust)).
- Backpressure comes from its control settings ([Resilience Features](#resilience-features)).

##### Hive Lifecycle

A typical hive lifecycle with cluster integration:

```rust,no_run
# use std::sync::Arc;
# use tightbeam::colony::hive::{Hive, HiveConfig};
# use tightbeam::colony::servlet::ServletConfig;
# use tightbeam::colony::urn::ColonyNamespace;
# use tightbeam::testing::TestMessage;
# use tightbeam::trace::TraceCollector;
# use tightbeam::transport::tcp::TightBeamSocketAddr;
# use tightbeam::transport::TokioListener;
# use tightbeam::urn::Urn;
# use tightbeam::{compose, hive, servlet, TightBeamError};
# hive! {
# 	pub MyHive,
# 	protocol: TokioListener
# }
# servlet! {
# 	pub PingServlet<TestMessage, EnvConfig = ()>,
# 	protocol: TokioListener,
# 	handle: |message, frame, _ctx| async move {
# 		Ok(Some(compose! { V0: id: frame.metadata().id(), message: message }?))
# 	}
# }
# servlet! {
# 	pub CalculatorServlet<TestMessage, EnvConfig = ()>,
# 	protocol: TokioListener,
# 	handle: |message, frame, _ctx| async move {
# 		Ok(Some(compose! { V0: id: frame.metadata().id(), message: message }?))
# 	}
# }
# fn ping_urn() -> Urn<'static> {
# 	ColonyNamespace::default().servlet("ping").expect("a valid servlet name")
# }
# fn calc_urn() -> Urn<'static> {
# 	ColonyNamespace::default().servlet("calc").expect("a valid servlet name")
# }
# async fn run_hive(
# 	hive_conf: HiveConfig,
# 	ping_servlet: PingServlet,
# 	calc_servlet: CalculatorServlet,
# 	trace: Arc<TraceCollector>,
# 	cluster_addr: TightBeamSocketAddr,
# ) -> Result<(), TightBeamError> {
// 1. Construct the hive (does not bind yet). Registration with a cluster
//    needs the `hive_tls` that TLS Configuration below sets.
let mut hive = MyHive::new(Some(hive_conf))?;

// 2. Register servlet types with spawners for auto-scale. A servlet gets a
//    route only when its config names a certificate.
hive.register(ping_urn(), ping_servlet, |t| PingServlet::start(t, ServletConfig::cleartext()))?;
hive.register(calc_urn(), calc_servlet, |t| CalculatorServlet::start(t, ServletConfig::cleartext()))?;

// 3. Establish: bind control plane and spawn registered servlets
hive.establish(trace).await?;

// 4. Announce servlet slate to a cluster gateway
hive.register_with_cluster(&cluster_addr).await?;

// 5. Clean shutdown
hive.stop();
# Ok(())
# }
```

##### Cluster Trust

For hives to accept commands from a cluster (heartbeats, management requests), they must trust the cluster's certificate. Configure this via `HiveConfig.trust_store`:

```rust
# use std::sync::Arc;
# use tightbeam::colony::hive::HiveConfig;
# use tightbeam::crypto::policy::Secp256k1Policy;
# use tightbeam::crypto::x509::store::{CertificateTrustBuilder, NoRevocation, TrustBuilder};
# use tightbeam::crypto::x509::KeyCurves;
# use tightbeam::testing::{TestCertificate, TestKey};
# let cluster_certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
# let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
# let cluster_trust_store = builder.with_certificate(cluster_certificate)?.build();
let hive_conf = HiveConfig {
	trust_store: Some(Arc::new(cluster_trust_store)),
	..Default::default()
};
# Ok::<(), tightbeam::TightBeamError>(())
```

Without a trust store, all cluster commands are rejected. See [Trust Stores](#trust-stores) for building trust stores from cluster certificates.

Signed commands are also checked for freshness. Each signed command frame states its issue time in the `order` field of its Metadata, in Unix milliseconds, and the issue times of one signer increase strictly ([§5.7.1](#571-message-ordering)). The hive rejects three kinds of command:

- A command whose issue time falls outside the command freshness window of the hive's clock.
- A command whose signature it already saw inside that window (replay protection).
- A command whose signer already sent another command with the same issue time inside that window (a duplicate `order`).

##### Resilience Features

Hives include built-in resilience mechanisms:

**Backpressure**: When utilization exceeds the threshold (default: 90%), the hive signals to the cluster that it is overloaded. The cluster can then route new work to less-loaded hives.

**Circuit Breaker**: The hive keeps one circuit per signer:

- After consecutive authentication failures from one signer (default: 3), the hive refuses that signer's commands.
- After a cooldown, the circuit admits commands again.
- A command whose signature verifies closes it and clears its count, and a failure that comes first opens it for another cooldown.

**Drain**: A draining hive refuses new commands, waits for in-flight work up to its drain timeout, and stops its servlets. It then tells gateways to drop its routes.

These are configured via nested `HiveControlConfig`:

```rust
# use core::time::Duration;
# use tightbeam::colony::hive::{HiveConfig, HiveControlConfig};
let hive_conf = HiveConfig {
	control: HiveControlConfig {
		backpressure_threshold: tightbeam::bps!(8000),  // 80%
		circuit_breaker_threshold: 5,                   // Open after 5 failures
		circuit_breaker_cooldown: Duration::from_secs(60), // 1 minute cooldown
		..Default::default()
	},
	..Default::default()
};
```

**Refused commands**: The hive answers a refused command with a response of the same kind, so a refused spawn gets a spawn response. The table shows whether a resend of the same signed frame can succeed (slot released) or is refused as a replay (slot kept).

| Management refusal                                       | Status              | Replay slot |
| -------------------------------------------------------- | ------------------- | ----------- |
| The hive is at or over its backpressure threshold        | `ResourceExhausted` | Released    |
| The spawner produced no servlet                          | `Unavailable`       | Released    |
| The servlet registry refused the spawned servlet         | `Unavailable`       | Released    |
| The hive is draining                                     | `Unavailable`       | Kept        |
| No spawner is registered for the servlet type            | `PermissionDenied`  | Kept        |
| The spawned servlet's address is not an instance locator | `PermissionDenied`  | Kept        |
| The stop names no running instance                       | `PermissionDenied`  | Kept        |

##### Load Balancing

A hive resolves each servlet type to a single instance address. Selecting among a type's replicas is the cluster gateway's job: see [Cluster load balancing](#load-balancing-1). Within a hive, message-to-type dispatch is derived directly from the message type.

##### TLS Configuration

For secure communication, configure TLS on the hive:

```rust
# use std::sync::Arc;
# use tightbeam::colony::hive::{HiveConfig, HiveTlsConfig};
# use tightbeam::crypto::key::Secp256k1KeyProvider;
# use tightbeam::crypto::x509::CertificateSpec;
# use tightbeam::testing::{TestCertificate, TestKey};
# use tightbeam::transport::handshake::PeerAuthentication;
# let signing_key = TestKey::insecure_fixed_signing();
# let cert = TestCertificate::self_signed(&signing_key);
let tls_config = Arc::new(HiveTlsConfig::new(
	CertificateSpec::Built(Box::new(cert)),
	Arc::new(Secp256k1KeyProvider::from(signing_key)),
	PeerAuthentication::Anonymous,  // Or `PeerAuthentication::Anonymous.and(validator)`: validate client certificates
)?);

let hive_conf = HiveConfig {
	hive_tls: Some(tls_config),
	..Default::default()
};
# Ok::<(), tightbeam::TightBeamError>(())
```

The TLS settings act on the control plane:

- When `hive_tls` is set, the hive control server binds with TLS, and the hive signs its outbound control frames (registration, scaling updates) with the hive key.
- Cluster gateways reject control frames they cannot verify against `hive_trust`, so a hive in a cluster requires a signing identity.
- When `trust_store` is set too, the control server demands a client certificate that the store validates, because the hive authenticates each cluster command against the peer its handshake proves.
- A peer authentication that names validators, the third argument above, adds their checks to that store.

##### HiveConfig Reference

[docs/colony.md](docs/colony.md#hiveconfig) lists each field of `HiveConfig` and its default: the namespace, the scaling and control settings, the servlet pool, the trust store, the TLS identity, and the clock.

##### Testing

Standalone hive behavior (control plane gates, circuit breaker, backpressure, drain) is tested with `environment Hive`:

```rust,no_run,test_harness
use tightbeam::instrumentation::events;
# use std::sync::Arc;
# use tightbeam::basis_points::BasisPoints;
# use tightbeam::builder::TypeBuilder;
# use tightbeam::clock::UnixMillis;
# use tightbeam::colony::hive::{Hive, HiveConfig, HiveRuntime, HiveTlsConfig};
# use tightbeam::colony::protocol::{ClusterCommand, ClusterCommandResponse, HiveManagement, HiveManagementOutcome, StopServletParams};
# use tightbeam::colony::urn::ColonyNamespace;
# use tightbeam::crypto::hash::Sha3_256;
# use tightbeam::crypto::policy::Secp256k1Policy;
# use tightbeam::crypto::sign::SigningIdentity;
# use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
# use tightbeam::crypto::x509::{Certificate, CertificateSpec, KeyCurves};
# use tightbeam::policy::TransitStatus;
# use tightbeam::testing::error::TestingError;
# use tightbeam::testing::{HiveEnv, SetupEnv, TestCertificate, TestIdentity, TestKey};
# use tightbeam::trace::TraceCollector;
# use tightbeam::transport::handshake::PeerAuthentication;
# use tightbeam::transport::{ClientBuilder, ConnectionBuilder, GenericClient, TokioListener};
# use tightbeam::{exactly, tb_assert_spec, tb_scenario, Frame, TightBeamError, Version};
# type TestHive = HiveRuntime<TokioListener>;
# struct TrustedSigner {
# 	certificate: Certificate,
# 	identity: SigningIdentity,
# }
# fn trusted_signer(subject: &str) -> TrustedSigner {
# 	let key = TestKey::insecure_fixed_signing();
# 	let certificate = TestCertificate::with_cn_and_uri_sans(&key, subject, &[]);
# 	let identity = TestIdentity::presenting(certificate.clone(), &key);
# 	TrustedSigner { certificate, identity }
# }
# fn trust_store(certificate: &Certificate) -> Result<Arc<dyn CertificateTrust>, TightBeamError> {
# 	let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
# 	Ok(Arc::new(builder.with_certificate(certificate.clone())?.build()))
# }
# async fn start_trusted_hive(trace: &TraceCollector, signer: &TrustedSigner, mut conf: HiveConfig) -> Result<TestHive, TightBeamError> {
# 	let spec = CertificateSpec::Built(Box::new(signer.certificate.clone()));
# 	let tls = HiveTlsConfig::new(spec, signer.identity.provider_arc(), PeerAuthentication::Anonymous)?;
# 	conf.trust_store = Some(trust_store(&signer.certificate)?);
# 	conf.hive_tls = Some(Arc::new(tls));
# 	let mut hive = TestHive::new(Some(conf))?;
# 	hive.establish(Arc::new(trace.share())).await?;
# 	Ok(hive)
# }
# async fn connect_hive(hive: &TestHive, signer: &TrustedSigner) -> Result<GenericClient<TokioListener>, TightBeamError> {
# 	let builder = ClientBuilder::<TokioListener>::builder().with_trust_store(trust_store(&signer.certificate)?);
# 	let client = builder.with_client_identity(signer.identity.clone()).build();
# 	let addr = hive.addr().ok_or(TightBeamError::NotEstablished)?;
# 	Ok(client.connect(addr.to_owned()).await?)
# }
# async fn signed_stop_frame(identity: &SigningIdentity, id: &[u8]) -> Result<Frame, TightBeamError> {
# 	let servlet_id = ColonyNamespace::default().servlet("none")?.servlet_instance("127.0.0.1:0")?;
# 	let command = ClusterCommand::Manage(HiveManagement::Stop(StopServletParams { servlet_id }));
# 	let builder = Version::V1.compose().with_id(id).with_order(UnixMillis::now().get());
# 	let mut frame = builder.with_message(command).with_witness_hasher::<Sha3_256>().build()?;
# 	frame.sign_with_provider(identity).await?;
# 	Ok(frame)
# }
# async fn emit_command(client: &mut GenericClient<TokioListener>, frame: Frame) -> Result<ClusterCommandResponse, TightBeamError> {
# 	let response = client.emit(frame, None).await?.ok_or(TightBeamError::MissingResponse)?;
# 	response.decode_message()
# }
# fn manage_stop_shape_status(response: ClusterCommandResponse) -> Result<TransitStatus, TightBeamError> {
# 	match response {
# 		ClusterCommandResponse::Manage(HiveManagementOutcome::Stop(stop)) => Ok(stop.status),
# 		_ => Err(TestingError::UnexpectedOutcome("a stop command answers in the stop alternative").into()),
# 	}
# }

tb_assert_spec! {
	pub HiveBackpressureShapeSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::HIVE_COMMAND_REFUSED, exactly!(1), equals!(TransitStatus::ResourceExhausted))
		]
	}
}

tb_scenario! {
	name: hive_backpressure_reply_shape,
	spec: HiveBackpressureShapeSpec,
	environment Hive {
		// Signer pinned by the hive trust store
		context: trusted_signer("CN=Hive Backpressure Cluster"),
		// Returns the established hive
		start: |SetupEnv { trace, context: signer, .. }| async move {
			let mut conf = HiveConfig::default();
			conf.control.backpressure_threshold = BasisPoints::default();
			start_trusted_hive(&trace, &signer, conf).await
		},
		// Owns the hive for drain, registry checks, and stop
		client: |HiveEnv { context: signer, hive, .. }| async move {
			let mut client = connect_hive(&hive, &signer).await?;

			let signed_stop = signed_stop_frame(&signer.identity, b"manage-bp").await?;
			let response = emit_command(&mut client, signed_stop).await?;

			// The client reads the status from the stop alternative, so a
			// reply in any other alternative fails the scenario.
			let status = manage_stop_shape_status(response)?;
			assert_eq!(status, TransitStatus::ResourceExhausted, "a saturated hive refuses a signed stop");

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

Clusters are the "ant colonies" of the EEIC: gateways that coordinate hives. A hive manages servlets. A cluster routes work across hives, watches their health, and federates with peer gateways.

Implementation: [docs/colony.md](docs/colony.md#clusters)

##### Architecture

A cluster gateway has five jobs:

1. **Hive Registry**: Tracks connected hives and the servlet types each one registers. A route belongs to the hive or peer that installed it, and no other party can change it. Only two peer routes may share a socket.
2. **Work Routing**: Forwards each `ClusterWorkRequest` to a local or peer route chosen by the load balancer.
3. **Health Monitoring**: Sends heartbeats to every hive and evicts hives that stop answering.
4. **Peer Federation** (optional): Shares servlet types with peer gateways, so work can hop one step to another colony.
5. **Colony Gossip** (optional): Floods signed rumors across the gateways of every colony it trusts.

A poisoned internal lock ends the background loop that reads it. The gateway traces the end, and the loop stays stopped until the gateway restarts.

##### The `cluster!` Macro

Define a cluster type using the `cluster!` macro:

```rust
# use tightbeam::cluster;
# use tightbeam::transport::TokioListener;
cluster! {
	pub MyCluster,
	protocol: TokioListener
}
```

The gateway digests under the crypto provider its protocol names. That digest names each gateway by the fingerprint of its certificate, and it digests each gossip rumor and frame witness. Every gateway of one colony runs the same provider, so each one names a peer and digests a rumor alike.

Runtime configuration is supplied when the gateway starts:

```rust,no_run
# use std::sync::Arc;
# use tightbeam::colony::cluster::{Cluster, ClusterConfig, ClusterTlsConfig};
# use tightbeam::trace::TraceCollector;
# use tightbeam::transport::TokioListener;
# tightbeam::cluster! {
# 	pub MyCluster,
# 	protocol: TokioListener
# }
# async fn start_gateway(trace: Arc<TraceCollector>, tls: ClusterTlsConfig) -> Result<(), tightbeam::TightBeamError> {
let cluster = MyCluster::start(trace, ClusterConfig::new(tls)).await?;
# cluster.stop();
# Ok(())
# }
```

##### Mutual TLS

Clusters require TLS configuration for secure communication with hives and, when federating, with peer gateways. The cluster acts as a TLS client when connecting outbound, presenting its certificate for mutual authentication.

```rust
# use std::sync::Arc;
# use tightbeam::colony::cluster::ClusterTlsConfig;
# use tightbeam::crypto::key::Secp256k1KeyProvider;
# use tightbeam::crypto::policy::Secp256k1Policy;
# use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
# use tightbeam::crypto::x509::{Certificate, CertificateSpec, KeyCurves};
# use tightbeam::testing::{TestCertificate, TestKey};
# use tightbeam::transport::handshake::PeerAuthentication;
# let key = TestKey::insecure_fixed_signing();
# let cert = TestCertificate::self_signed(&key);
# let peer_cert = TestCertificate::self_signed(&TestKey::negation_of(&key));
# let anchor = |certificate: Certificate| CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation).with_certificate(certificate);
# let hive_trust: Arc<dyn CertificateTrust> = Arc::new(anchor(cert.clone())?.build());
# let peer_trust: Arc<dyn CertificateTrust> = Arc::new(anchor(peer_cert)?.build());
let tls = ClusterTlsConfig::new(CertificateSpec::Built(Box::new(cert)), Arc::new(Secp256k1KeyProvider::from(key)))?
	.with_validators(vec![])         // Optional: server policy of each dial (both planes)
	.with_client_authentication(PeerAuthentication::Anonymous)  // Or `PeerAuthentication::Anonymous.and(validator)`: gateway requires client certs (mTLS)
	.with_hive_trust(hive_trust)     // Hive-plane: registration, address updates, PublishGossip
	.with_peer_trust(peer_trust);    // Peer-plane: AdvertisePeer, relayed Gossip, ReconcileGossip
# Ok::<(), tightbeam::TightBeamError>(())
```

`with_validators` sets the server policy of each outbound dial. Every gateway dial runs the HPKE flow, so each validator evaluates the signing certificate that the dialed server's reply names.

The store alone admits each issuer and each root. A check of every certificate, such as a denylist, belongs in the store's revocation checker, which the built-in store also runs at each frame verification and each plane check. [docs/handshake.md](docs/handshake.md#the-server-policy) states when each check runs.

The two trust stores are separate planes and MUST NOT cross:

- `hive_trust`: Verifies hive frames: registration, address updates, and `PublishGossip`. `None` refuses them.
- `peer_trust`: Verifies peer advertisements and relayed gossip. `None` turns off inbound federation.

A hive certificate cannot act as a peer, and a peer certificate cannot publish as a hive.

Hives must also trust the cluster's certificate to accept its heartbeats. See [Trust Stores](#trust-stores) for details.

##### Colony Membership

A gateway belongs to the colony named by the URN in its certificate's URI Subject Alternative Name, checked against `ClusterConfig::namespace`. A non-member still registers hives and routes work, but it refuses federation and gossip.

Colonies of one namespace federate. A gateway shares work and gossip with every gateway that its peer trust store admits and that carries a colony URN of the namespace, whichever colony that is. The peer trust store is therefore the one list of the parties a gateway deals with.

Four rules follow from that list:

- Enroll the certificate of each peer gateway. A signed frame verifies against the certificate the store holds for the signing key, so a certificate authority in the store admits no peer.
- A gateway with a peer trust store sends gossip only to a peer whose signed frames it would admit, so the two directions agree.
- A gateway with no peer trust store publishes only. It sends advertisements and gossip to the configured peers its hive trust store holds, and it admits nothing from a peer.
- The gateway reads the store on every frame and every send. A store that changes while the gateway runs takes effect at once, and a peer removed from it receives nothing further.

##### Peer Federation

Peer federation lets gateways learn which servlet types neighboring colonies export and forward work one hop. Think of it as trail-sharing between nests: each gateway re-advertises what its local hives currently serve.

Configure outbound advertisement with a dial list and beat cadence:

```rust
# use core::time::Duration;
# use std::net::SocketAddr;
# use std::sync::Arc;
# use tightbeam::colony::cluster::{ClusterConfig, ClusterTlsConfig};
# use tightbeam::colony::urn::ColonyNamespace;
# use tightbeam::crypto::key::Secp256k1KeyProvider;
# use tightbeam::crypto::x509::CertificateSpec;
# use tightbeam::testing::{TestCertificate, TestKey};
# let key = TestKey::insecure_fixed_signing();
# let certificate = CertificateSpec::Built(Box::new(TestCertificate::self_signed(&key)));
# let tls = ClusterTlsConfig::new(certificate, Arc::new(Secp256k1KeyProvider::from(key)))?;
# let peer_addr: SocketAddr = "127.0.0.1:9000".parse()?;
# let namespace = ColonyNamespace::default();
let conf = ClusterConfig::builder(tls)
	.with_peers([peer_addr.to_string()])?
	.with_advertise_interval(Duration::from_secs(5))
	// Optional: only accept peer ads that claim dial addresses in this list
	.with_peer_dial_allowlist([peer_addr.to_string()])?
	.build();
# Ok::<(), Box<dyn core::error::Error>>(())
```

Behavior:

1. Each beat sends peers a signed `AdvertisePeer` that lists the servlet types local hives serve.
2. The receiver checks the signature, freshness, and claimed dial address, and that both gateways carry a colony URN, then installs peer routes.
3. Peer routes are soft state, and four things remove them:
   - An empty advertisement withdraws them.
   - Repeated failures abandon them.
   - An address the peer table evicts loses every peer route that dials it, relay trails through it included.
   - Relay trails also expire by age.
4. A hive route and a peer route never share a socket. The gateway refuses whichever claim arrives second with `PermissionDenied`. Sockets compare as parsed addresses, so any spelling of one socket is the same socket.
5. The load balancer chooses among local and peer routes together.
6. Each forward spends a hop budget (`with_max_hops`, default 1), so work cannot bounce between peers.
7. A forward goes out only when the gateway that answers holds the key that signed the advertisement, or the relay's key for a relay trail.
   - Any other answer ends the hop before a frame is sent. The trail counts a failure, and the client reads `Unavailable` unless another trail serves the retry.
   - A forward that may have run answers `Unknown`, and the gateway does not retry it.
   - Only a fault that proves the frame never left moves to the next instance: a refused connect, a refused handshake, a failed write, or a gate's `Unavailable` backpressure refusal.
8. A gateway of another colony is a peer like any other: it advertises, serves work, gossips, and is discovered. A learned address that answers with no colony URN of the namespace leaves the peer table and keeps its routes. A configured peer keeps its place in the dial list.

A gateway with an advertise beat that binds a wildcard address (`0.0.0.0` or `[::]`) MUST set `with_advertise_addr`, or it refuses to start.

**Claimed dial addresses.** One policy decides which addresses a peer may ask this gateway to dial. The rules apply in this order:

| Setting                              | Rule                                                                                                           |
| ------------------------------------ | -------------------------------------------------------------------------------------------------------------- |
| Every plane                          | The unspecified address (`0.0.0.0`, `[::]`) is refused, because a connect to it lands on loopback.             |
| Every plane                          | A multicast, broadcast, reserved (`240.0.0.0/4`), or `0.0.0.0/8` address is refused.                           |
| `with_peer_dial_allowlist`, when set | The list decides alone.                                                                                        |
| No allowlist                         | Every other address is admitted, including private and loopback addresses.                                     |

Without an allowlist, a verified peer can point this gateway at any unicast address, including services on its own host (CWE-918). A gateway reachable from an internal network SHOULD set `with_peer_dial_allowlist`.

Hive registrations skip this policy, because `hive_trust` signs them. A hive may register a loopback address. A servlet at `0.0.0.0:P` counts as the same socket as every address on port P.

Member gateways also flood their advertisement as a rumor, so peers of peers learn exported types. With a hop budget of 2 or more, work can reach such a type through the relaying peer when the direct address fails.

##### Servlet Export Boundary

By default a federated gateway advertises and serves every locally registered servlet type. The export boundary restricts what crosses the organization edge.

**Planes**

- **Discoverability**: Advertisements list only exported types.
- **Enforcement**: A work or stream request for an unexported type is refused with `PermissionDenied`, unless a grant opens it.

Checks run in this order:

1. Gate policies (`with_gate_policy`)
2. The `exported_types` allowlist
3. `ExportGrant` grants, when the allowlist refuses
4. `ExportGate` deny gates, which override a grant
5. The servlet

```rust
# use core::time::Duration;
# use std::net::SocketAddr;
# use std::sync::Arc;
# use tightbeam::colony::cluster::{ClusterConfig, ClusterTlsConfig};
# use tightbeam::colony::urn::ColonyNamespace;
# use tightbeam::crypto::key::Secp256k1KeyProvider;
# use tightbeam::crypto::x509::CertificateSpec;
# use tightbeam::testing::{TestCertificate, TestKey};
# let key = TestKey::insecure_fixed_signing();
# let certificate = CertificateSpec::Built(Box::new(TestCertificate::self_signed(&key)));
# let tls = ClusterTlsConfig::new(certificate, Arc::new(Secp256k1KeyProvider::from(key)))?;
# let peer_addr: SocketAddr = "127.0.0.1:9000".parse()?;
# let namespace = ColonyNamespace::default();
let conf = ClusterConfig::builder(tls)
	.with_peers([peer_addr.to_string()])?
	.with_advertise_interval(Duration::from_secs(5))
	// Advertise and export only these types to external peers
	.with_exported_types([namespace.servlet("ping")?])
	.build();
# Ok::<(), Box<dyn core::error::Error>>(())
```

**Allowlist**

`with_exported_types` sets a fail-closed allowlist:

1. An exported type passes for every caller.
2. An unexported type passes only for a first-party caller: a direct session whose certificate is in `hive_trust` and not in `peer_trust`.
3. Every other request is refused, unless a grant opens the type.

**Grants**

`ExportGrant` opens one unexported target to selected caller identities:

- A target passes when it is exported, granted, or a first-party origin request, and every deny gate must then agree.
- A grant or a gate that keys on the caller's key asks a `PeerListGate` through `GatePolicy::evaluate`, which reads the key identity that the trust store reads.

```rust
# use core::time::Duration;
# use std::net::SocketAddr;
# use std::sync::Arc;
# use tightbeam::colony::cluster::{ClusterConfig, ClusterTlsConfig};
# use tightbeam::colony::urn::ColonyNamespace;
# use tightbeam::crypto::key::Secp256k1KeyProvider;
# use tightbeam::crypto::x509::CertificateSpec;
# use tightbeam::testing::{TestCertificate, TestKey};
# let key = TestKey::insecure_fixed_signing();
# let certificate = CertificateSpec::Built(Box::new(TestCertificate::self_signed(&key)));
# let tls = ClusterTlsConfig::new(certificate, Arc::new(Secp256k1KeyProvider::from(key)))?;
# let peer_addr: SocketAddr = "127.0.0.1:9000".parse()?;
# let namespace = ColonyNamespace::default();
# use tightbeam::colony::cluster::ExportGrant;
# use tightbeam::colony::hive::PeerListGate;
# use tightbeam::der::Encode;
# use tightbeam::policy::{GatePolicy, SessionContext, TransitStatus};
# use tightbeam::urn::Urn;
# let partner = TestCertificate::self_signed(&TestKey::negation_of(&TestKey::insecure_fixed_signing()));
# let granted_spki = partner.tbs_certificate.subject_public_key_info.to_der()?;
struct PartnerGrant {
	partners: PeerListGate,
	target: Urn<'static>,
}

impl ExportGrant for PartnerGrant {
	fn grants(&self, target: &Urn<'_>, session: &SessionContext, _relayed: bool) -> bool {
		*target == self.target && GatePolicy::evaluate(&self.partners, None, session) == TransitStatus::Ok
	}
}

let partners = PeerListGate::allow([granted_spki])?;
let conf = ClusterConfig::builder(tls)
	.with_exported_types([namespace.servlet("search")?])
	// Partner B may reach "ledger" without it being advertised
	.with_export_grant(Arc::new(PartnerGrant { partners, target: namespace.servlet("ledger")? }))
	.build();
# Ok::<(), Box<dyn core::error::Error>>(())
```

Grant semantics:

- On a relayed request, the grant sees the relaying gateway, not the original caller. A conservative grant checks `!relayed`.
- A granted type is never advertised. The partner learns its URN out of band.
- Use a grant, not an exported type with a deny-everyone-else gate. That workaround fails open and advertises the type.

**Custom gates**

Custom gates add per-identity deny rules. Every gate must pass, and a deny overrides a grant. Each gate receives `TrustPlanes` so it can reuse the built-in first-party check.

```rust
# use core::time::Duration;
# use std::net::SocketAddr;
# use std::sync::Arc;
# use tightbeam::colony::cluster::{ClusterConfig, ClusterTlsConfig};
# use tightbeam::colony::urn::ColonyNamespace;
# use tightbeam::crypto::key::Secp256k1KeyProvider;
# use tightbeam::crypto::x509::CertificateSpec;
# use tightbeam::testing::{TestCertificate, TestKey};
# let key = TestKey::insecure_fixed_signing();
# let certificate = CertificateSpec::Built(Box::new(TestCertificate::self_signed(&key)));
# let tls = ClusterTlsConfig::new(certificate, Arc::new(Secp256k1KeyProvider::from(key)))?;
# let peer_addr: SocketAddr = "127.0.0.1:9000".parse()?;
# let namespace = ColonyNamespace::default();
# use tightbeam::colony::cluster::{ExportGate, TrustPlanes};
# use tightbeam::colony::hive::PeerListGate;
# use tightbeam::der::Encode;
# use tightbeam::policy::{GatePolicy, SessionContext, TransitStatus};
# use tightbeam::urn::Urn;
# let stranger = TestCertificate::self_signed(&TestKey::negation_of(&TestKey::insecure_fixed_signing()));
# let denied_spki = stranger.tbs_certificate.subject_public_key_info.to_der()?;
struct DenyPeerKeyGate {
	denied: PeerListGate,
	target: Urn<'static>,
}

impl ExportGate for DenyPeerKeyGate {
	fn evaluate(&self, target: &Urn<'_>, session: &SessionContext, _planes: &TrustPlanes<'_>, _relayed: bool) -> TransitStatus {
		if *target == self.target {
			return GatePolicy::evaluate(&self.denied, None, session);
		}

		TransitStatus::Ok
	}
}

let denied = PeerListGate::deny([denied_spki])?;
let conf = ClusterConfig::builder(tls)
	.with_exported_types([namespace.servlet("ping")?])
	.with_export_gate(Arc::new(DenyPeerKeyGate { denied, target: namespace.servlet("ping")? }))
	.build();
# Ok::<(), Box<dyn core::error::Error>>(())
```

**Mutual TLS**

First-party checks need mutual TLS. When `client_authentication` is `PeerAuthentication::Anonymous`, every session is anonymous, so peers reach exported types only.

**Configuration**

- `None` (the default) exports every type.
- An empty list exports nothing.
- Only `exported_types` filters advertisements.
- A certificate in `peer_trust` is never first-party, even when `hive_trust` also holds it.

**Auditing**

A refusal traces `CLUSTER_EXPORT_REFUSED` and a grant traces `CLUSTER_EXPORT_GRANTED`, each with the caller's certificate fingerprint.

**Gossip ingress**

Gossip delivery (`with_gossip_ingress`) is outside the export boundary. The operator chooses the delivery type, not the peer.

##### Heartbeat Mechanism

Clusters continuously monitor hive health through heartbeats. Each heartbeat is a signed frame sent to the hive, which responds with its current utilization. This serves two purposes:

- **Liveness Detection**: Hives that fail to respond are marked unhealthy and eventually evicted from the registry.
- **Load Metrics**: Utilization data informs the routing decisions of the load balancer.

Configure heartbeat behavior via `HeartbeatConfig`:

```rust
# use core::num::NonZeroUsize;
# use core::time::Duration;
# use tightbeam::colony::cluster::HeartbeatConfig;
let heartbeat_conf = HeartbeatConfig::builder()
	.with_interval(Duration::from_secs(5))   // Check every 5 seconds
	.with_timeout(Duration::from_secs(15))   // Evict a hive silent this long
	.with_max_failures(3)                    // Evict after 3 failures
	.with_max_concurrent(NonZeroUsize::new(10).expect("a nonzero cap")) // Parallel heartbeat limit
	.build();
```

A heartbeat callback receives each heartbeat result, for monitoring and metrics collection:

```rust
# use std::sync::atomic::{AtomicU64, Ordering};
# use std::sync::Arc;
# use tightbeam::colony::cluster::{HeartbeatConfig, HeartbeatEvent};
let failures = Arc::new(AtomicU64::new(0));
let counter = Arc::clone(&failures);
let heartbeat_conf = HeartbeatConfig::builder()
	.with_callback(Arc::new(move |event: HeartbeatEvent| {
		if !event.success {
			counter.fetch_add(1, Ordering::Relaxed);
		}
	}))
	.build();
```

##### Load Balancing

When more than one instance serves one type, a load balancer picks one across local and peer routes.

- The default `StochasticForager` picks in proportion to each route's pheromone strength, and it never starves or monopolizes an instance.
- Swap it with `with_load_balancer` for `RoundRobin`, `PowerOfTwoChoices`, or your own.

##### Colony Gossip

Colony gossip floods origin-signed rumors across member gateways: the pheromone broadcast of the swarm. A publisher asks the local gateway to create a rumor. Peers relay and repair until hop budget or freshness expires.

The flood is the namespace. A rumor travels between the gateways that federate under [Colony Membership](#colony-membership), so many parties can share state while each keeps its own colony.

- Every rumor a hive publishes reaches every party the gateway trusts. A party that wants private gossip runs it on a gateway whose peer trust holds its own colony alone.
- Trust stores need not agree. A gateway accepts a rumor only when it trusts the origin, and it relays only what it accepted. The gateways that trust one origin therefore form that origin's subnet.
- A subnet must be connected through its own members. A gateway in two subnets receives both and carries nothing between them.
- A rumor from an origin the receiver does not trust is dropped. The relay pays one token of its rate budget and keeps its routes. It then stops offering that origin to that receiver for one freshness window (`GossipConfig::seen_ttl`).

```rust
# use core::time::Duration;
# use std::net::SocketAddr;
# use std::sync::Arc;
# use tightbeam::colony::cluster::{ClusterConfig, ClusterTlsConfig};
# use tightbeam::colony::urn::ColonyNamespace;
# use tightbeam::crypto::key::Secp256k1KeyProvider;
# use tightbeam::crypto::x509::CertificateSpec;
# use tightbeam::testing::{TestCertificate, TestKey};
# let key = TestKey::insecure_fixed_signing();
# let certificate = CertificateSpec::Built(Box::new(TestCertificate::self_signed(&key)));
# let tls = ClusterTlsConfig::new(certificate, Arc::new(Secp256k1KeyProvider::from(key)))?;
# let peer_addr: SocketAddr = "127.0.0.1:9000".parse()?;
# let namespace = ColonyNamespace::default();
# use tightbeam::colony::cluster::GossipConfig;
# let servlet_type_urn = namespace.servlet("feed")?;
let conf = ClusterConfig::builder(tls)
	.with_peers([peer_addr.to_string()])?
	.with_advertise_interval(Duration::from_secs(5))
	.with_gossip_config(GossipConfig {
		ttl: 4, // hop radius cap (clamped to MAX_GOSSIP_TTL)
		..GossipConfig::default()
	})
	.with_gossip_ingress(servlet_type_urn)? // optional local delivery target
	.build();
# assert!(conf.gossip.ingress.is_some());
# Ok::<(), Box<dyn core::error::Error>>(())
```

Flow:

1. **Publish**: A hive sends a signed `PublishGossip`. The origin gateway signs the rumor and starts the flood.
2. **Relay**: Peers forward the rumor unchanged under the origin's signature. A gateway sends rumors only to a flood member, and accepts one only from a member and under an origin it trusts.
3. **Admit**: Each gateway checks size, freshness, hop limit, and sender rate, and drops duplicates.
4. **Deliver**: The gossip ingress names the local servlet type that receives rumors. The servlet receives the origin-signed rumor frame: its message decodes as `GossipRumor`, and its signature names the gateway that published it. A gateway with no ingress only relays.
5. **Reflood**: The rumor continues to peers while hops remain.
6. **Repair**: `ReconcileGossip` compares held digests, so peers fill gaps.

A tampered relay weakens that peer's routes.

##### Work Request Flow

The work plane is request-reply. The client's frame reaches the servlet unchanged, and the servlet's response comes back unchanged, so end-to-end signatures and integrity survive the route.

1. The client builds its frame and sends it with `submit_work_to`.
2. The gateway chooses a local or peer route for the servlet type.
3. The servlet verifies the frame and answers with its own frame.
4. `submit_work_to` returns the servlet's frame, or the gateway's refusal status.

```rust,no_run
use tightbeam::builder::TypeBuilder;
use tightbeam::colony::SubmitWork;
# use tightbeam::clock::UnixMillis;
# use tightbeam::crypto::profiles::DefaultCryptoProvider;
# use tightbeam::crypto::sign::SigningIdentity;
# use tightbeam::crypto::x509::{Certificate, KeyPurposes, PeerCertificate, Signing};
# use tightbeam::der::Sequence;
# use tightbeam::transport::{GenericClient, TokioListener};
# use tightbeam::urn::Urn;
# use tightbeam::{Beamable, Version};
# #[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
# pub struct CalcRequest {
# 	pub value: u32,
# }
# #[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
# pub struct CalcResponse {
# 	pub doubled: u32,
# }
# async fn submit(
# 	client: &mut GenericClient<TokioListener>,
# 	identity: SigningIdentity,
# 	calculator_urn: Urn<'static>,
# 	servlet_certificate: Certificate,
# ) -> Result<(), Box<dyn core::error::Error>> {

// Sign the end-to-end frame so the servlet can verify the sender.
let mut work = Version::V2
	.compose()
	.with_id(b"calc-001")
	.with_order(UnixMillis::now().get())
	.with_message(CalcRequest { value: 42 })
	.build()?;
work.sign_with_provider(&identity).await?;

// One method call on a connected client: wraps the work frame in the
// hop-local transport envelope and resolves the gateway's reply down
// to the servlet's complete response frame.
let response = client.submit_work_to(calculator_urn, &work).await?;

// The servlet's envelope is verifiable end to end, under the servlet's
// certificate admitted for signing under the house frame signer purpose.
let servlet = PeerCertificate::<Signing<DefaultCryptoProvider>>::parse(servlet_certificate, KeyPurposes::HOUSE.signer)?;
response.verify(&servlet)?;
let result: CalcResponse = response.decode_message()?;
# Ok(())
# }
```

A refusal surfaces as an error that carries the gateway's transit status, for example:

- `Unavailable` when no route serves the type.
- `InvalidArgument` when the payload is not a frame.

A caller that needs the raw wire envelope decodes the `ClusterWorkResponse` itself.

**Plane guarantees**

`submit_work_to` completes the family of routed client methods. All three verbs route by servlet-type URN through the same pheromone trails, hop budget, and gate wall. They differ in what each direction protects:

| Verb             | Request protection                         | Reply protection                                |
| ---------------- | ------------------------------------------ | ----------------------------------------------- |
| `submit_work_to` | complete `Frame`, byte-for-byte end to end | complete `Frame` back, byte-for-byte end to end |
| `open_stream_to` | raw chunks, hop-protected only             | complete `Frame` back (relayed unchanged)       |
| `open_duplex_to` | raw chunks, hop-protected only             | raw chunks, hop-protected only                  |

Each hop's transport encryption protects stream chunks, and only the final reply, a complete frame, can carry a signature. Use unary work when both directions must be non-repudiable.

##### ClusterConfig Reference

`ClusterConfig::builder(tls)` has one method per setting, and [docs/colony.md](docs/colony.md#clusterconfig) lists each with its default, from the namespace and the load balancer to the pheromone trails and gossip.

The colony URN comes from the gateway certificate. Read it with `ClusterConfig::colony_urn()`.

##### Cluster Testing

Clusters can be tested using `environment Cluster`:

```rust,no_run,test_harness
use tightbeam::{cluster, compose, exactly, hive, servlet, tb_assert_spec, tb_scenario, TightBeamError};

use tightbeam::instrumentation::events;
# use std::sync::Arc;
# use tightbeam::colony::cluster::{Cluster, ClusterConfig, ClusterTlsConfig};
# use tightbeam::colony::hive::{Hive, HiveConfig, HiveTlsConfig};
# use tightbeam::colony::servlet::ServletConfig;
# use tightbeam::colony::urn::ColonyNamespace;
# use tightbeam::colony::SubmitWork;
# use tightbeam::crypto::key::Secp256k1KeyProvider;
# use tightbeam::crypto::policy::Secp256k1Policy;
# use tightbeam::crypto::sign::ecdsa::Secp256k1SigningKey;
# use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
# use tightbeam::crypto::x509::{Certificate, CertificateSpec, KeyCurves};
# use tightbeam::der::Sequence;
# use tightbeam::testing::{ClusterEnv, SetupEnv, TestCertificate, TestKey};
# use tightbeam::trace::TraceCollector;
# use tightbeam::transport::handshake::negotiation::TransportOffer;
# use tightbeam::transport::handshake::PeerAuthentication;
# use tightbeam::transport::tcp::TightBeamSocketAddr;
# use tightbeam::transport::{ClientBuilder, ConnectionBuilder, GenericClient, TokioListener};
# use tightbeam::urn::Urn;
# use tightbeam::{Beamable, Message};
# #[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
# pub struct PingRequest {
# 	pub value: u32,
# }
# #[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
# pub struct PingResponse {
# 	pub doubled: u32,
# }
# struct ClusterCerts {
# 	cert: Certificate,
# 	key: Secp256k1SigningKey,
# 	trust: Arc<dyn CertificateTrust>,
# }
# fn cluster_certs() -> ClusterCerts {
# 	let key = TestKey::insecure_fixed_signing();
# 	let cert = TestCertificate::self_signed(&key);
# 	let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
# 	let anchored = builder.with_certificate(cert.clone()).expect("a test certificate anchors");
# 	ClusterCerts { cert, key, trust: Arc::new(anchored.build()) }
# }
# fn provider(certs: &ClusterCerts) -> Arc<Secp256k1KeyProvider> {
# 	Arc::new(Secp256k1KeyProvider::from(certs.key.clone()))
# }
# fn cluster_tls_config(certs: &ClusterCerts) -> ClusterTlsConfig {
# 	let spec = CertificateSpec::Built(Box::new(certs.cert.clone()));
# 	let tls = ClusterTlsConfig::new(spec, provider(certs)).expect("the test certificate decodes");
# 	tls.with_hive_trust(Arc::clone(&certs.trust))
# }
# fn hive_tls_config(certs: &ClusterCerts) -> HiveConfig {
# 	let spec = CertificateSpec::Built(Box::new(certs.cert.clone()));
# 	let tls = HiveTlsConfig::new(spec, provider(certs), PeerAuthentication::Anonymous).expect("the test certificate decodes");
# 	let mut conf = HiveConfig { hive_tls: Some(Arc::new(tls)), trust_store: Some(Arc::clone(&certs.trust)), ..HiveConfig::default() };
# 	conf.pool.mux_offer = Some(Arc::new(TransportOffer::mux(8)));
# 	conf
# }
# fn servlet_tls_config<M: Message>(certs: &ClusterCerts) -> Result<ServletConfig<TokioListener, M>, TightBeamError> {
# 	let spec = CertificateSpec::Built(Box::new(certs.cert.clone()));
# 	let builder = ServletConfig::<TokioListener, M>::builder().with_certificate(spec, provider(certs), vec![])?;
# 	Ok(builder.with_mux_offer(Some(TransportOffer::mux(8))).build())
# }
# fn servlet_urn(name: &str) -> Urn<'static> {
# 	ColonyNamespace::default().servlet(name).expect("a valid servlet name")
# }
# async fn connect_cluster(certs: &ClusterCerts, addr: &TightBeamSocketAddr) -> Result<GenericClient<TokioListener>, TightBeamError> {
# 	let client = ClientBuilder::<TokioListener>::builder().with_trust_store(Arc::clone(&certs.trust)).build();
# 	Ok(client.connect(addr.to_owned()).await?)
# }

// The certificate, config, and client helpers and the ping messages are
// those of tests/colony/cluster/common.rs.

cluster! {
	pub TestCluster,
	protocol: TokioListener
}

hive! {
	pub TestHive,
	protocol: TokioListener
}

servlet! {
	pub PingServlet<PingRequest, EnvConfig = ()>,
	protocol: TokioListener,
	handle: |request, frame, _ctx| async move {
		Ok(Some(compose! {
			V0: id: frame.metadata().id(),
				message: PingResponse { doubled: request.value * 2 }
		}?))
	}
}

tb_assert_spec! {
	pub ClusterRoutingSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_WORK_ROUTED, exactly!(1))
		]
	}
}

tb_scenario! {
	name: cluster_work_routing,
	spec: ClusterRoutingSpec,
	environment Cluster {
		// Shared as Arc<C> with every closure
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			let mut conf = ClusterConfig::new(cluster_tls_config(&certs));
			// With both offers set, the client and the hive each reach the
			// cluster over one multiplexed connection
			conf.pool_config.mux_offer = Some(Arc::new(TransportOffer::mux(8)));
			TestCluster::start(Arc::new(trace), conf).await
		},
		// Optional: awaited and registered with the cluster.
		// Omit when driving registration from the client.
		hives: |SetupEnv { context: certs, .. }| vec![async move {
			// The servlet config names a certificate, so the hive gives the
			// servlet a route
			let servlet_conf = servlet_tls_config(&certs)?;
			let servlet = PingServlet::start(Arc::new(TraceCollector::new()), servlet_conf).await?;
			// hive_tls_config sets pool.mux_offer, so the hive multiplexes
			// its calls to its servlets
			let mut hive = TestHive::new(Some(hive_tls_config(&certs)))?;
			hive.register(servlet_urn("ping"), servlet, |t| PingServlet::start(t, ServletConfig::cleartext()))?;
			hive.establish(Arc::new(TraceCollector::new())).await?;
			Ok::<_, TightBeamError>(hive)
		}],
		// Owns the cluster for registry checks and stop
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let mut client = connect_cluster(&certs, cluster.addr()).await?;

			// The end-to-end work frame the servlet receives unmodified.
			let work = compose! {
				V0: id: b"work-001", message: PingRequest { value: 21 }
			}?;

			// submit_work_to wraps the frame in the hop-local transport
			// envelope and resolves the reply to the servlet's response
			// frame. A refusal surfaces as an error that carries its status.
			let response = client.submit_work_to(servlet_urn("ping"), &work).await?;
			let echoed: PingResponse = response.decode_message()?;

			assert_eq!(echoed.doubled, 42, "the ping servlet doubles the request");

			cluster.stop();
			Ok(())
		}
	}
}
```

The `environment Cluster` syntax provides:

- `context`: Scenario fixture shared as `Arc<C>` with every closure
- `start`: Starts the gateway (or a peered topology) under test and returns it
- `hives` (optional): Hive futures to register with the gateway `start` returned
- `client`: Owns the cluster through `ClusterEnv.cluster`, asserts behavior, and stops it

Omit `hives:` when registration itself is under test. For federation and gossip scenarios, see `tests/colony/cluster/` and `fuzz/colony/`.

A scenario that depends on elapsed time installs a manual clock and advances it in place of a sleep. It passes that clock to every part that reads time:

- the gateway
- each hive
- each servlet
- each connection pool
- the trace collector

A multiplexed writer adopts the clock of the connection it splits from. [docs/colony.md](docs/colony.md#manual-clock) names the setter of each part.

An advance wakes sleeping beats, but their work runs on separate tasks. Poll the trace collector for the expected event, and advance again if it has not landed.

##### Conclusion

This document leaves the model of a colony to the deployment. Workers, servlets, hives, and clusters are its building blocks, and a deployment combines them into larger systems. The swarm is yours to command.

## 10. Instrumentation

Instrumentation produces a semantic event sequence for verification and audit:

- Tests MUST NOT assert against instrumentation events by inspecting or branching on individual events at runtime.
- Tests MUST declare expectations as a spec.
- Verification MUST treat the finalized event stream as the authoritative truth for a single execution.

Feature gating:

- Instrumentation is enabled only by the crate feature `instrument`.
- A trace MUST build with `std` alone, so a production build records one without a testing feature.

Implementation: [docs/instrumentation.md](docs/instrumentation.md#the-trace-collector)

### 10.1 Objectives

- Emission MUST be amortized O(1) per event.
- Ordering MUST be strictly increasing by sequence number per trace.
- Evidence artifacts MUST be deterministic and hash-stable for identical executions.
- Detail level MUST be feature-gated to avoid unnecessary overhead.
- Payload handling MUST preserve privacy (hash or summarize).

Implementation: [docs/instrumentation.md](docs/instrumentation.md#objectives)

### 10.2 Event Kind Taxonomy

Each emitted event carries a kind URN from a closed inventory. Format:

```text
urn:tightbeam:event:<domain>/<event-name>
```

Domains include `core`, `gate`, `handler`, `transport`, `connection`, `assert`, `mux`, `pool`, `session`, `hive`, and `cluster`. Two domains need a testing feature:

- `process` needs `testing-csp`.
- `fdr` needs `testing-fdr`.

The module `tightbeam::instrumentation::events` lists every event, and the doc of each event names the step where it fires.

Implementation: [docs/instrumentation.md](docs/instrumentation.md#event-kind-taxonomy)

A decision of production code records an event on the trace of the component that decides it. Each component emits its events in these builds:

- A gateway or a hive emits the event in every build:
  - A `testing` build records the value for a spec.
  - An `instrument` build files the event under its own URN, with its label, the payload hash, and the trace clock stamp. An event that defines no label files an empty label.
- A transport, a pool, or a server plane emits the event in an `instrument` build, which files it, and a `testing` build also records the value for a spec.

The label of an event names why the event fired, its value is what a spec asserts with `equals!`, and its payload names who, such as an address, a fingerprint, or a canonical public key.

A scenario asserts these refusal and decision events in place of a test marker (see [§12.2.8](#1228-recording-trace-events)):

| Domain                         | Refusal and decision events                                                                                                                                                                                                                                                       |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cluster` (gateway)            | `gate-blocked`, `hive-registered`, `register-refused`, `update-accepted`, `update-refused`, `work-routed`, `work-refused`, `work-unavailable`, `work-failed`, `work-forwarded`, `edge-refused`, `heartbeat-failed`, `hive-evicted`, `dial-refused`                                |
| `cluster` (exports)            | `export-granted`, `export-refused`, `export-unbounded`, `export-identity-unavailable`                                                                                                                                                                                             |
| `cluster` (peer advertisement) | `peer-advertised`, `peer-advertise-refused`, `peer-ad-learned`, `peer-ad-dropped`, `peer-ad-publish-failed`, `peer-discovered`, `peer-evicted`, `peer-expelled`, `peer-hints-learned`, `peer-routes-installed`, `peer-routes-withdrawn`, `peer-route-abandoned`                   |
| `cluster` (relay)              | `relay-trail-installed`                                                                                                                                                                                                                                                           |
| `cluster` (gossip)             | `gossip-admitted`, `gossip-delivered`, `gossip-duplicate`, `gossip-refused`, `gossip-relay-weakened`, `gossip-drop-signal`, `gossip-fanout-unreached`, `gossip-origin-unknown`, `gossip-origin-refused-by-peer`, `gossip-repair-pushed`, `reconcile-answered`, `reconcile-failed` |
| `hive`                         | `established`, `command-refused`, `reregistered`                                                                                                                                                                                                                                  |
| `gate`                         | `accept`, `reject`, with the normalized status of the verdict as the value                                                                                                                                                                                                        |
| `handler`                      | `failed`, for a handler error that a plane answers with a status other than `Unimplemented`                                                                                                                                                                                       |
| `mux`                          | `stream-refused`, `budget-refused`, `streams-exhausted`, `emit-draining`, `protocol-error`, `cancel-budget`, `rekey-refused`, `rekey-verify-failed`, `rekey-expired`, `rekey-renewed`, `goaway-sent`, `goaway-recv`                                                               |
| `connection`                   | `accepted`, `closed`                                                                                                                                                                                                                                                              |
| `pool`                         | `exhausted`, `mux-declined`, `failover`, `failover-refused`, `evicted`                                                                                                                                                                                                            |
| `session`                      | `cert-rejected`, `receipt-refused`, `receipt-settled`, `authorization-refused`, `handshake-expired`                                                                                                                                                                               |
| `transport`                    | `envelope-refused`, `rekey-required`                                                                                                                                                                                                                                              |

Internal detail, a setting that is off by default ([§10.5](#105-configuration)), turns on six internal events:

- `handler/enter` and `handler/exit`
- `policy/eval`
- `route/step`
- `crypto/step`
- `compress/step`

Accept and refuse events always fire, and so does `mux/stream-cancelled`, which closes a call that the peer cancels on a mux stream in place of its `handler/exit`.

> Warning: A long-lived owner of a trace needs a sink that forwards each event, or a reader that drains the trace, because the trace of a servlet, a hive, or a gateway fills:

- A servlet, a hive, and a gateway record every connection they accept into their own trace, from before the handshake, so their trace also holds the handshake refusal of a peer that never authenticates.
- A hive and a gateway also record every connection they dial, so the pool and session events of each dial land on the same trace:
  - The hive dials for its registrations, its scaling updates, and the calls between its servlets.
  - The gateway dials through its hive and peer pools.
- The default sink keeps the first events up to the event bound of the trace ([§10.5](#105-configuration)), keeps one `core/warn` event in place of the next, drops each later one, the owner's own refusals included, and sets its overflow latch.

An FDR exploration ([§12.4](#124-layer-3-refinement-checking-fdr)) records the `fdr` exploration events that three settings ask for:

- It records one event per state of each explored process, in the order of the state names.
- A scenario explores into a trace of its own, under the instrumentation settings and the clock of the scenario's trace.
- The verdict of the scenario carries that trace, so the exploration events stay apart from the trace of the run.
- That trace reports overflow when its sink dropped events.
- Each label names the process, the state, and the events in CSPM notation.

| Setting               | Event                    | Label                                                                                                                                                                                            |
| --------------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Enabled-set sampling  | `fdr/enabled-set-sample` | At each state a seed visited, the observable events the state offers, such as `Spin.S0: {a, b}`                                                                                                  |
| Refusal sampling      | `fdr/refusal-snapshot`   | At each visited stable or accepting state, the observable events it refuses as the CSP failures model defines them, such as `Spin.S2: {a, b}`. An accepting state refuses every observable event |
| Divergence heuristics | `fdr/divergence-detect`  | At each state where a seed diverged, the hidden events of a run from the state to a cycle of hidden events and once around it, such as `Spin.S1: <t, u>`                                         |

A state diverges in either of two cases:

- A run of hidden events from it reaches a cycle of hidden events. Every exploration decides that exactly, whatever the settings say and whatever the length of the run.
- A run of hidden events from it passes the configured limit of the exploration.

Each `divergence-detect` event names a state where a seed refuted divergence freedom.

> Note: Instrumentation has two URN forms:

- Production control-plane events use the `event:<domain>/<name>` inventory above.
- Application and test labels use the form `urn:tightbeam:instrumentation:<resource_type>/<resource_id>` ([§11.1.1](#1111-urns)).

Assertion matching compares full URN strings for equality. Specs and emit sites MUST share the same rendered URN (or the same `events::*` constant).

### 10.3 Event Structure

An event has this shape, which the `TbEvent` of [§10.6](#106-evidence-artifact-format) encodes:

```text
seq | urn | label? | payload_hash? | duration_ns? | timestamp_ns? | flags | extras?
```

Implementation: [docs/instrumentation.md](docs/instrumentation.md#event-structure)

Requirements:

- `seq` MUST start at 0 and increment by 1 for each emitted event on a trace.
- `urn` MUST be a member of the event inventory (or an application URN the deployment treats as first-class).
- `label` MAY carry a human-readable or numeric annotation (for example the Unix-epoch nanoseconds on the `trace/clock-origin` event).
- `payload_hash` MAY be present only when payloads are enabled and the emit site captures one.
- `duration_ns` MAY appear on exit or boundary events and MUST be a monotonic span length in nanoseconds.
- `timestamp_ns` MAY appear as nanoseconds on the trace clock since its origin. The `trace/clock-origin` event records each origin once as Unix-epoch nanoseconds, so an offline tool can reconstruct absolute times (see [§8.8.1](#881-audit-trail-deployment-requirements)).
- `flags` MUST be a bitset.
- `extras` MAY carry a bounded byte sketch for extended metrics.

### 10.4 Payload Representation

Runtime values captured under the `assert/payload` event MUST be transformed before emission:

- Algorithm: SHA3-256 digest over the canonical byte representation.
- Representation: The full 32-byte SHA3-256 output MUST be stored. Truncation below 32 bytes is forbidden.
- Literal integers MAY be emitted directly as 64-bit unsigned values if they are not sensitive.
- Structured values SHOULD emit a static schema tag plus digest.

Implementation: [docs/instrumentation.md](docs/instrumentation.md#payload-representation)

> Warning: Secret or potentially sensitive raw data MUST NOT be emitted.

### 10.5 Configuration

In an `instrument` build, the instrumentation settings of a trace MUST control what the trace records. By default, each of these detail settings is off:

- Payload hashes ([§10.4](#104-payload-representation))
- Internal detail ([§10.2](#102-event-kind-taxonomy))
- Enabled-set sampling, refusal sampling, and divergence heuristics of an FDR exploration ([§10.2](#102-event-kind-taxonomy))
- Durations

The default event bound is 1024 events. Tests MAY override each setting per scenario.

Implementation: [docs/instrumentation.md](docs/instrumentation.md#configuration)

Every emitted event goes to exactly one sink. When no sink is configured, the trace keeps its events in a bounded memory sink sized by the event bound. If that bound is exceeded, the implementation MUST:

- set an OVERFLOW condition
- emit a single `core/warn` event
- drop subsequent events

The `core/warn` event takes the place and the sequence number of the first event past the bound, and its label is the URN of that event. It sits in the events that the trace hash covers ([§10.6](#106-evidence-artifact-format)), so the evidence shows where truncation began. A configured sink that drops events MUST keep the same warning in place of the first event it drops.

The `overflow` field of the evidence records the truncation, and the evidence hash covers it ([§10.6](#106-evidence-artifact-format)).

### 10.6 Evidence Artifact Format

For every finalized trace an artifact MUST be producible as ASN.1 DER (`EvidenceArtifact`).

Implementation: [docs/instrumentation.md](docs/instrumentation.md#evidence-artifact-format)

Wire shape:

```asn1
EvidenceArtifact ::= SEQUENCE {
	specHash      OCTET STRING,           -- SHA3-256(spec definition)
	traceHash     OCTET STRING,           -- SHA3-256 over the DER of events
	evidenceHash  OCTET STRING,           -- SHA3-256(specHash || traceHash || DER(overflow))
	events        SEQUENCE OF TbEvent,
	overflow      BOOLEAN                 -- true if the trace misses events of its run
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
- A decoder MUST refuse an artifact whose `specHash` is not 32 bytes, or whose `traceHash` or `evidenceHash` differs from the hash it recomputes from the decoded fields.

Artifact integrity:

- `traceHash` MUST be SHA3-256 over the DER of the `events` field, a SEQUENCE OF TbEvent, so an absent OPTIONAL field and an empty one hash apart.
- `overflow` MUST be true for a trace that misses events of its run.
- `evidenceHash` MUST be SHA3-256(`specHash` || `traceHash` || DER(`overflow`)), where `||` is raw byte concatenation.

Privacy:

- Raw payload bytes MUST NOT appear. Only hashed representation or non-sensitive numeric scalars MAY be represented.

### 10.7 Failure Handling

- Emission errors MUST NOT panic. They MUST degrade gracefully (for example drop the event and set OVERFLOW).
- Verification MUST treat missing expected instrumentation events as spec violations (for example an absent assertion label).

Implementation: [docs/instrumentation.md](docs/instrumentation.md#failure-handling)

### 10.8 Logging Subsystem

The logging subsystem grades each record by the [RFC 5424][rfc5424] severity levels, and writes it to a replaceable backend.

Implementation: [docs/instrumentation.md](docs/instrumentation.md#logging-subsystem)

#### RFC 5424 Severity Levels

A log level is one of the eight severities of [RFC 5424][rfc5424] §6.2.1. A lower number is a higher severity, and a number past 7 is refused.

| Number | Level         | Meaning                            |
| ------ | ------------- | ---------------------------------- |
| 0      | Emergency     | The system is unusable             |
| 1      | Alert         | Immediate action is necessary      |
| 2      | Critical      | A critical condition               |
| 3      | Error         | An error condition                 |
| 4      | Warning       | A warning condition                |
| 5      | Notice        | A normal but significant condition |
| 6      | Informational | An informational message           |
| 7      | Debug         | A debug-level message              |

#### Log Backends

A backend writes each log record that it accepts, and a deployment can supply its own backend. Two backends are built in:

- The standard output backend writes each record to standard output, as the example in [Integration](#integration) does.
- The multiplex backend sends each record to every inner backend that accepts its level, so one record can reach standard output, a file, and a SIEM at once.

#### Log Filtering

A filter admits a record at its minimum level or a more severe one. A named component can have a minimum level of its own. This filter admits Warning and more severe records, and every record of the `security` component:

```rust
# use tightbeam::trace::{LogFilter, LogLevel};
let filter = LogFilter::new(LogLevel::Warning)
	.with_component("security", LogLevel::Debug);
```

#### Integration

A trace logs an event at the level the event names, or else at the default level of its logger, when the filter admits that level and the backend accepts it:

```rust
use tightbeam::instrumentation::events;
use tightbeam::trace::{LogFilter, LogLevel, LoggerConfig, StdoutBackend, TraceCollector, TraceConfig};

let backend = StdoutBackend;
let filter = LogFilter::new(LogLevel::Warning);
let config = LoggerConfig::new(backend, filter)
	.with_default_level(LogLevel::Informational);

let trace = TraceCollector::from(TraceConfig::default().with_logger(config));

trace.event(events::ERROR)?.with_log_level(LogLevel::Error).emit();
# Ok::<(), tightbeam::TightBeamError>(())
```

> Note: The call to `emit` may be left out, because the event emits when it goes out of scope.

## 11. Misc

### 11.1 Utilities

Three utilities cut across the protocol layers:

- URNs name events and resources.
- Jobs wrap units of work.
- Job pipelines chain jobs.

Implementation: [docs/instrumentation.md](docs/instrumentation.md#utilities)

#### 11.1.1 URNs

**Module**: `tightbeam::urn`

The URN subsystem provides:

- The URN of [RFC 8141][rfc8141], `urn:<nid>:<nss>`, with its optional r-, q-, and f-components and its URN-equivalence.
- `UrnBuilder`, which constructs and validates a URN from either a raw NID and NSS or structured components.
- Namespace-specific validation, which an application defines for its own namespace and which reports a `UrnValidationError`.
- A built-in spec for application and test instrumentation labels, of the form `urn:tightbeam:instrumentation:<resource_type>/<resource_id>`.
- The control-plane event URNs, `urn:tightbeam:event:<domain>/<name>` (see [§10.2](#102-event-kind-taxonomy)).

The instrumentation label spec constrains:

- `resource_type`: one of `trace`, `event`, `seed`, `verdict` (case-insensitive, normalized to lowercase)
- `resource_id`: an application-defined identifier of one or more ASCII letters, digits, or hyphens

Applications MAY use these URNs to name resources in a stable, parseable way. They are distinct from the control-plane event inventory in [§10.2](#102-event-kind-taxonomy).

**Example: Building a custom application URN**

```rust
use tightbeam::urn::{UrnBuilder, UrnValidationError};

fn build_customer_urn() -> Result<(), UrnValidationError> {
	let urn = UrnBuilder::default()
		.with_nid("example")
		.with_nss("customer:1234")
		.build()?;

	assert_eq!(urn.to_string(), "urn:example:customer:1234");

	Ok(())
}
# fn main() -> Result<(), UrnValidationError> { build_customer_urn() }
```

#### 11.1.2 Jobs

**Module**: `tightbeam::task`

The `job!` macro wraps a unit of work as a named type with one `run` function, sync or async.

```rust
use tightbeam::job;
```

Properties:

- A job is stateless, so creating one is free.
- A job has a name, which a pipeline, a test, and a trace event refer to.
- A job is sync or async, and is independent of the protocol.

**Syntax:**

```rust
# use tightbeam::job;
# type Type1 = u32;
# type Type2 = u32;
# type ReturnType = ();
// Async job with tuple input
job! {
	name: AsyncJobName,
	async fn run((param1, param2): (Type1, Type2)) -> ReturnType {
		// Implementation
	}
}

// Sync job with tuple input
job! {
	name: SyncJobName,
	fn run((param1, param2): (Type1, Type2)) -> ReturnType {
		// Implementation
	}
}

// No-parameter job
job! {
	name: NoParamJob,
	fn run() -> ReturnType {
		// Implementation
	}
}
```

A call passes one input value, often a tuple, such as `AddNumbers::run((1, 2))`. A job with no parameters takes no input. An async job returns a future that can move between threads.

#### 11.1.3 Job Pipelines

**Module**: `tightbeam::task`

Every `Result` is a pipeline. Jobs that return `Result` chain with familiar `and_then`, `map`, and `or_else`. Closures that return `Result` are pipelines too. `run` ends a pipeline and returns its result.

```rust
use tightbeam::job;
use tightbeam::task::{Pipeline, PipelineBuilder, join};
```

**Basic usage:**

```rust
# use tightbeam::task::Pipeline;
# use tightbeam::{job, TightBeamError};
# pub struct Request;
# impl Request { fn with_timestamp(self, _at: u64) -> Self { self } }
# fn now() -> u64 { 0 }
# job! { name: CreateHandshakeRequest, fn run((_id, _nonce): (String, String)) -> Result<Request, TightBeamError> { Ok(Request) } }
# job! { name: ValidateRequest, fn run((req,): (Request,)) -> Result<Request, std::io::Error> { Ok(req) } }
# job! { name: SendRequest, fn run((_req,): (Request,)) -> Result<Vec<u8>, TightBeamError> { Ok(Vec::new()) } }
# let (client_id, nonce) = (String::from("client-1"), String::from("nonce-1"));
let frame = CreateHandshakeRequest::run((client_id, nonce))
	.map(|req| req.with_timestamp(now()))
	.and_then(|req| ValidateRequest::run((req,)).map_err(TightBeamError::from))
	.and_then(|req| SendRequest::run((req,)))
	.run()?;
# Ok::<(), TightBeamError>(())
```

**Mixed composition** (start from any `Result`):

```rust
# use tightbeam::task::Pipeline;
# use tightbeam::{job, TightBeamError};
# pub struct Config;
# fn parse_config_file(_path: &str) -> Result<Config, TightBeamError> { Ok(Config) }
# job! { name: ValidateConfig, fn run((cfg,): (Config,)) -> Result<Config, TightBeamError> { Ok(cfg) } }
# job! { name: SaveConfig, fn run((cfg,): (Config,)) -> Result<Config, TightBeamError> { Ok(cfg) } }
# job! { name: NotifyUser, fn run((_msg,): (&'static str,)) -> Result<(), TightBeamError> { Ok(()) } }
# let path = "tightbeam.toml";
let config: Result<Config, TightBeamError> = parse_config_file(path);

config
	.and_then(|cfg| ValidateConfig::run((cfg,)))
	.and_then(|cfg| SaveConfig::run((cfg,)))
	.map(|_| "Configuration saved successfully")
	.and_then(|msg| NotifyUser::run((msg,)))
	.run()?;
# Ok::<(), TightBeamError>(())
```

**Joined pipelines with** `join()`**:**

A join runs the first pipeline and then the second, and pairs their outputs. The first error ends the run.

```rust
# use tightbeam::task::{join, Pipeline};
# use tightbeam::{job, TightBeamError};
# job! { name: EncryptPayload, fn run((_payload,): (&'static [u8],)) -> Result<Vec<u8>, TightBeamError> { Ok(Vec::new()) } }
# job! { name: SignPayload, fn run((_payload,): (&'static [u8],)) -> Result<Vec<u8>, TightBeamError> { Ok(Vec::new()) } }
# job! { name: SendRequest, fn run((_encrypted, _signed): (Vec<u8>, Vec<u8>)) -> Result<(), TightBeamError> { Ok(()) } }
# let payload: &'static [u8] = b"telemetry";
let (encrypted, signed) = join(
	EncryptPayload::run((payload,)),
	SignPayload::run((payload,))
).run()?;

SendRequest::run((encrypted, signed))?;
# Ok::<(), TightBeamError>(())
```

**Error recovery** with `or_else`:

```rust
# use tightbeam::task::Pipeline;
# use tightbeam::{job, TightBeamError};
# pub struct Request;
# pub struct Response;
# job! { name: SendRequest, fn run((_request,): (Request,)) -> Result<Response, TightBeamError> { Err(TightBeamError::ChannelClosed) } }
# job! { name: UseCachedResponse, fn run() -> Result<Response, TightBeamError> { Ok(Response) } }
# job! { name: HandleError, fn run((error,): (TightBeamError,)) -> Result<Response, TightBeamError> { Err(error) } }
# let request = Request;
let frame = SendRequest::run((request,))
	.or_else(|_| UseCachedResponse::run())
	.or_else(|e| HandleError::run((e,)))
	.run()?;
# Ok::<(), TightBeamError>(())
```

**Automatic trace with** `PipelineBuilder`**:**

`PipelineBuilder` (feature `testing`) attaches a trace. Each `then_job` step emits job lifecycle URNs, and a closure step through `and_then` chains its result alone:

```text
urn:tightbeam:event:job/<job-name>-<start|success|error>
```

A job name is the type name that `job!` declares, in lowercase words joined by hyphens, with a new word at each capital (for example `CreateHandshakeRequest` becomes `create-handshake-request`).

```rust
# use std::sync::Arc;
# use tightbeam::task::{Pipeline, PipelineBuilder};
# use tightbeam::trace::TraceCollector;
# use tightbeam::{job, TightBeamError};
# pub struct Request;
# impl Request { fn validate(self) -> Self { self } }
# job! { name: CreateHandshakeRequest, fn run((_id, _nonce): (String, String)) -> Result<Request, TightBeamError> { Ok(Request) } }
# job! { name: ValidateRequest, fn run((req,): (Request,)) -> Result<Request, TightBeamError> { Ok(req) } }
# job! { name: SendRequest, fn run((_req,): (Request,)) -> Result<(), TightBeamError> { Ok(()) } }
# let trace = Arc::new(TraceCollector::new());
# let (client_id, nonce) = (String::from("client-1"), String::from("nonce-1"));
PipelineBuilder::new(trace)
	.start((client_id, nonce))
	// Emits: urn:tightbeam:event:job/create-handshake-request-start
	//        urn:tightbeam:event:job/create-handshake-request-success
	.then_job::<CreateHandshakeRequest, _>()
	.map(|req| (req.validate(),)) // no job URN (plain map)
	.then_job::<ValidateRequest, _>()
	.and_then(|req| SendRequest::run((req,))) // no job URN (closure step)
	.run()?;
# Ok::<(), TightBeamError>(())
```

**Testing integration:**

Assert the full job URNs, as an exact string match (see [§10.2](#102-event-kind-taxonomy)):

```rust,test_harness
# use tightbeam::task::Pipeline;
# use tightbeam::testing::ScenarioConfig;
# use tightbeam::urn::Urn;
# use tightbeam::{exactly, job, tb_assert_spec, tb_process_spec, tb_scenario, urn, TightBeamError};
# pub struct Request;
# impl Request { fn with_metadata(self) -> Self { self } }
# job! { name: CreateHandshakeRequest, fn run((_id, _nonce): (String, String)) -> Result<Request, TightBeamError> { Ok(Request) } }
# job! { name: ValidateRequest, fn run((req,): (Request,)) -> Result<Request, TightBeamError> { Ok(req) } }
const CREATE_HS_START: Urn<'static> =
	urn!("tightbeam", "event:job/create-handshake-request-start");
const CREATE_HS_SUCCESS: Urn<'static> =
	urn!("tightbeam", "event:job/create-handshake-request-success");
const VALIDATE_START: Urn<'static> =
	urn!("tightbeam", "event:job/validate-request-start");
const VALIDATE_SUCCESS: Urn<'static> =
	urn!("tightbeam", "event:job/validate-request-success");

tb_assert_spec! {
	pub PipelineSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(CREATE_HS_START, exactly!(1)),
			(CREATE_HS_SUCCESS, exactly!(1)),
			(VALIDATE_START, exactly!(1)),
			(VALIDATE_SUCCESS, exactly!(1))
		]
	}
}

tb_process_spec! {
	pub PipelineProcess,
	events {
		observable {
			CREATE_HS_START,
			CREATE_HS_SUCCESS,
			VALIDATE_START,
			VALIDATE_SUCCESS
		}
		hidden {}
	}
	states {
		Idle => { CREATE_HS_START => Creating },
		Creating => { CREATE_HS_SUCCESS => Validating },
		Validating => { VALIDATE_START => ValidatingRun },
		ValidatingRun => { VALIDATE_SUCCESS => Done },
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
				.then_job::<CreateHandshakeRequest, _>()
				.map(|req| (req.with_metadata(),))
				.then_job::<ValidateRequest, _>()
				.run()
		}
	}
}
```

**Complete example:**

```rust
use tightbeam::task::{Pipeline, PipelineBuilder, join};
# use std::sync::Arc;
# use tightbeam::trace::TraceCollector;
# use tightbeam::{job, TightBeamError};
# pub struct Request;
# impl Request { fn with_timestamp(self, _at: u64) -> Self { self } }
# pub struct Response;
# fn now() -> u64 { 0 }
# job! { name: CreateHandshakeRequest, fn run((_id, _nonce): (String, String)) -> Result<Request, TightBeamError> { Ok(Request) } }
# job! { name: EncryptPayload, fn run((_payload,): (&'static [u8],)) -> Result<Vec<u8>, TightBeamError> { Ok(Vec::new()) } }
# job! { name: SignPayload, fn run((_payload,): (&'static [u8],)) -> Result<Vec<u8>, TightBeamError> { Ok(Vec::new()) } }
# job! { name: SendRequest, fn run((_req, _enc, _sig): (Request, Vec<u8>, Vec<u8>)) -> Result<Response, TightBeamError> { Ok(Response) } }
# job! { name: UseCachedResponse, fn run() -> Result<Response, TightBeamError> { Ok(Response) } }
# job! { name: HandleError, fn run((error,): (TightBeamError,)) -> Result<Response, TightBeamError> { Err(error) } }
# job! { name: ExtractSessionId, fn run((_resp,): (Response,)) -> Result<u64, TightBeamError> { Ok(7) } }
# let trace = Arc::new(TraceCollector::new());
# let (client_id, nonce) = (String::from("client-1"), String::from("nonce-1"));
# let payload: &'static [u8] = b"telemetry";

let session_id = PipelineBuilder::new(trace)
	.start((client_id, nonce))
	.then_job::<CreateHandshakeRequest, _>()
	.map(|req| req.with_timestamp(now()))
	.and_then(|req| {
		let encrypted = EncryptPayload::run((payload,));
		let signed = SignPayload::run((payload,));
		join(encrypted, signed).map(|(e, s)| (req, e, s)).run()
	})
	.and_then(|(req, enc, sig)| SendRequest::run((req, enc, sig)))
	.or_else(|_| UseCachedResponse::run())
	.or_else(|e| HandleError::run((e,)))
	.and_then(|resp| ExtractSessionId::run((resp,)))
	.run()?;
# Ok::<(), TightBeamError>(())
```

## 12. Testing Framework

tightbeam tests protocol behavior through three progressive verification layers. Layers stack: start with assertions, then add CSP, then FDR.

### 12.1 Architecture and Concepts

Two formal-methods ideas underpin the stack:

#### Communicating Sequential Processes (CSP)

CSP describes concurrent interaction patterns (Hoare, Roscoe).[^hoare1978][^roscoe2010] In tightbeam, CSP models protocol behavior as a labeled transition system (LTS). Each process specification defines:

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

| Layer          | Feature Flag  | Purpose                        | Specification      | Usage                                       |
| -------------- | ------------- | ------------------------------ | ------------------ | ------------------------------------------- |
| L1 AssertSpec  | `testing`     | Runtime assertion verification | `tb_assert_spec!`  | Required: `.with_spec()` or `.with_specs()` |
| L2 ProcessSpec | `testing-csp` | CSP state machine modeling     | `tb_process_spec!` | Optional: `.with_csp()`                     |
| L3 Refinement  | `testing-fdr` | Trace/failures refinement      | Inline config      | Optional: `.with_fdr()`                     |

**Layer 1 (Assertions)**: Declares expected labels, cardinalities, and optional values. Verifies that the recorded assertion stream matches.

**Layer 2 (CSP)**: Adds a process model. Validates that the trace follows valid transitions and separates observable vs hidden events.

**Layer 3 (FDR)**: Multi-seed exploration for trace refinement, failures refinement, and divergence freedom.

#### 12.1.2 Unified Entry Point: tb_scenario!

All three layers run through `tb_scenario!`:

- One syntax for L1, L1+L2, and L1+L2+L3
- Environments: `Bare`, `Worker`, `ServiceClient`, `Servlet`, `Pipeline`, `Cluster`, `Hive`
- Trace / instrumentation hooks (`TraceConfig`)
- Optional policy and fault configuration

#### 12.1.3 Feature Flag Architecture

Progressive flags (each builds on the previous where noted):

- `testing`: L1 assertion verification
- `testing-csp`: L1+L2 CSP process modeling (requires `testing`)
- `testing-fdr`: L1+L2+L3 refinement checking (requires `testing-csp`)
- `testing-timing`: WCET, deadline, jitter, slack (requires `testing` + `testing-csp`, pulls `instrument`)
- `testing-schedulability`: RMA/EDF analysis (requires `testing-timing`)
- `testing-fault`: Deterministic/probabilistic fault injection (requires `testing-fdr`)
- `testing-fmea`: FMEA campaign helpers (requires `testing-fault` + `instrument`)
- `testing-fuzz` / `testing-fuzz-ijon`: AFL fuzzing with optional IJON. Both require `testing-csp`, which `testing-fuzz` enables

### 12.2 Layer 1: Assertion Specifications

Implementation: [docs/testing.md](docs/testing.md#assertion-specifications)

#### 12.2.1 Concept

An AssertSpec declares expected behavioral invariants per semantic version. Each version lists:

- Assertion labels (`Urn` expressions)
- Cardinality constraints (`exactly`, `at_least`, `at_most`, `between`, `present`, `absent`)
- Optional value checks (`equals!`)
- Execution mode (`Accept`, `Reject`, or `Error`)
- Gate expectation (`Ok` or a rejection status)

Versions use major.minor.patch and produce a deterministic SHA3-256 hash over their canonical representation.

#### 12.2.2 Specification: tb_assert_spec! Syntax

```rust
# use tightbeam::urn::Urn;
# use tightbeam::{exactly, tb_assert_spec, urn};
const RECEIVED: Urn<'static> = urn!("test", "event:demo/received");
const RESPONDED: Urn<'static> = urn!("test", "event:demo/responded");

tb_assert_spec! {
	pub MySpec,
	V(1,0,0): {
		mode: Accept,
		tag_filter: ["v1"],
		assertions: [
			(RECEIVED, exactly!(1)),
			(RESPONDED, exactly!(1), equals!("ok"))
		]
	},
	V(1,1,0): {
		mode: Accept,
		tag_filter: ["v1.1"],
		assertions: [
			(RECEIVED, exactly!(1)),
			(RESPONDED, exactly!(2))
		]
	},
}
#
# assert_eq!(MySpec::latest().version(), (1, 1, 0));
```

**Version Block Syntax**:

```text
V(major, minor, patch): {
	mode: <ExecutionMode>,              // Accept, Reject, or Error
	gate: <TransitStatus>,              // Optional: the gate decision the run must reach
	response: Present | Absent,         // Optional: whether the run must leave a response
	tag_filter: ["tag1", "tag2"],       // Optional: filter assertions by tags
	assertions: [                       // Array of (label, cardinality) with an optional equals!(value) and tags: [..]
		(LABEL, cardinality),
		(LABEL, cardinality, equals!(value)),
		(LABEL, cardinality, tags: ["tag"]),
		...
	],
	events: [KIND, ...],                // Optional: needs instrument, or the spec fails to compile
	event_counts: [(KIND, cardinality), ...],  // Optional: needs instrument, or the spec fails to compile
	schedulability: {                   // Optional: needs testing-timing, or the spec fails to compile
		task_set: <TaskSet>,
		scheduler: RateMonotonic | EarliestDeadlineFirst,
		must_be_schedulable: <bool>,
	}
}
```

Each `LABEL` and `KIND` is a URN. A scenario takes no gate, so a spec that a scenario grades omits `gate:`, and a `gate:` that the run never reached fails Layer 1.

**Deterministic Hashing**: Each version produces a 32-byte SHA3-256 hash over:

- Domain tag `"TBSP"` (tightbeam Spec Protocol)
- Version triple (major, minor, patch)
- Spec identifier
- Mode code
- Gate presence and value
- Response presence and value
- Tag filter presence and tags
- Normalized assertions (sorted by label), each with its cardinality, tags, and optional value
- Assertion order labels, in their own order
- Required events and event counts (when `instrument` enabled)
- Schedulability presence and parameters (when `testing-timing` enabled)

#### 12.2.3 Implementation Examples

**Basic specification** (same URN constants as in §12.2.2):

```rust
# use tightbeam::urn::Urn;
# use tightbeam::{exactly, tb_assert_spec, urn};
# const RECEIVED: Urn<'static> = urn!("test", "event:demo/received");
# const RESPONDED: Urn<'static> = urn!("test", "event:demo/responded");
tb_assert_spec! {
	pub DemoSpec,
	V(1,0,0): {
		mode: Accept,
		tag_filter: ["v1"],
		assertions: [
			(RECEIVED, exactly!(1)),
			(RESPONDED, exactly!(1))
		]
	},
	V(1,1,0): {
		mode: Accept,
		tag_filter: ["v1.1"],
		assertions: [
			(RECEIVED, exactly!(1)),
			(RESPONDED, exactly!(2))
		]
	},
}
```

#### 12.2.4 Generated API

Each `tb_assert_spec!` defines a spec type that holds its versions:

- `MySpec::latest()` returns the highest version.
- `MySpec::get(1, 1, 0)` returns one version.
- `MySpec::all()` returns every version.

An assertion label in the `assertions:` list is a URN, typically a `Urn<'static>` constant in scope. Emit sites and the spec MUST use the same rendered URN string, as an exact match (see [§10.2](#102-event-kind-taxonomy)).

#### 12.2.5 Cardinality Helpers

Cardinality macros:

- `exactly!(n)`: Exactly n occurrences
- `at_least!(n)`: Minimum n occurrences
- `at_most!(n)`: Maximum n occurrences
- `between!(min, max)`: Range [min, max] occurrences
- `present!()`: At least one occurrence
- `absent!()`: Zero occurrences

#### 12.2.6 Value Assertion Helpers

Value check:

- `equals!(value)`: Assert equality on the recorded payload

**Supported Types**:

- **Primitives**: `String`, `&str`, `bool`, `u8`, `u32`, `u64`, `usize`, `i32`, `i64`
- **Numeric literals**: `equals!(3_600u64)`, `equals!(42u32)`
- **Enums**: `MessagePriority`, `Version`, `TransitStatus` (e.g., `equals!(MessagePriority::LowLatency)`, `equals!(Version::V2)`)
- **Option presence**: `equals!(IsSome)` (matches any `Some(_)`), `equals!(IsNone)` (matches `None`), where the emit site records `Presence::of_option(&value)`. `IsSome`, `IsNone`, and `Presence` come from `tightbeam::testing::assertions`

**Examples**:

```rust
# use tightbeam::testing::assertions::{IsNone, IsSome};
# use tightbeam::testing::TBSpec;
# use tightbeam::urn::Urn;
# use tightbeam::{exactly, tb_assert_spec, urn, MessagePriority, Version};
# const PRIORITY: Urn<'static> = urn!("test", "event:frame/priority");
# const LIFETIME: Urn<'static> = urn!("test", "event:frame/lifetime");
# const VERSION: Urn<'static> = urn!("test", "event:frame/version");
# const CONFIDENTIALITY: Urn<'static> = urn!("test", "event:frame/confidentiality");
# const OPTIONAL_FIELD: Urn<'static> = urn!("test", "event:frame/optional-field");
# tb_assert_spec! {
# 	pub FrameValueSpec,
# 	V(1,0,0): {
# 		mode: Accept,
assertions: [
	(PRIORITY, exactly!(1), equals!(MessagePriority::LowLatency)),
	(LIFETIME, exactly!(1), equals!(3_600u64)),
	(VERSION, exactly!(1), equals!(Version::V2)),
	(CONFIDENTIALITY, exactly!(1), equals!(IsSome)),
	(OPTIONAL_FIELD, exactly!(1), equals!(IsNone))
]
# 	},
# }
#
# assert_eq!(FrameValueSpec::latest().required_assertions().len(), 5);
```

#### 12.2.7 Tag-Based Assertion Filtering

An assertion can carry arbitrary string tags, which a spec categorizes and filters on. Tags enable version-scoped testing, where a single scenario can validate multiple protocol versions.

#### 12.2.8 Recording Trace Events

The trace records an assertion label from a URN, or from a CSP event when `testing-csp` is on. A string literal fails to compile, so every label resolves to a URN.

- `trace.event(URN)` records a label-only assertion and, with `instrument`, also emits the `assert/label` event (§10.2).
- `trace.event_with(URN, &["tag"], value)` adds tags plus an optional value, which a spec asserts with `equals!`.
- `trace.recorded(URN)` (feature `testing`) counts the recorded assertions that carry that label, without draining them. A scenario that waits on a background task polls it for the event the task traces.

A test marker is a `test`-namespace URN that a test records itself. It records a fact that the suite itself decides or observes, for one of these reasons:

- The testing framework is the subject, and the marker is a synthetic input to FDR, CSP, fault injection, FMEA, timing, or the spec macros.
- An application that the suite defines emits it from its own handlers, such as the DTN rover or the payment servlets.
- A harness step orders a process together with production events, such as the capture, the tamper, and the inject of an attacker.
- A test double observes the fact on a task of its own, such as a servlet that a frame reached, where the verdict of the scenario reads the trace.

A marker sits next to its one user, or in the shared module of the test doubles that record it, and takes the name of what it records. Two other kinds of fact take another form:

- A decision of production code is a production event (§10.2).
- A value that a scenario reads on its own task is a plain assertion.

**Scenario shape:**

A scenario drives production code with the scenario trace and asserts what production decided:

1. A decision of production code is a production event in the spec, such as `(events::CLUSTER_REGISTER_REFUSED, exactly!(1), equals!(TransitStatus::Unauthenticated))`. Before the step, the scenario gives the trace to every component whose decision it asserts:

- `start_cluster(&trace, ..)` gives it to a gateway.
- `establish(Arc::new(trace.share()))` gives it to a hive.
- `with_trace(trace.share())` gives it to a server, a pool, or a transport, before its first handshake message.

2. A wait polls the event of the decision that it waits for, not state: `poll_until(n, interval, || trace.recorded(events::CLUSTER_PEER_EVICTED) >= 1)`. A wait polls state only where no event can stand for it:

- The state of a test double, or of an application that the suite defines.
- A value that no event carries and that the scenario then asserts, such as the receipt that a renewal rotates.
- A step that records no event, such as a rumor that waits in the gossip journal.
- The routes or peers of one gateway, where several gateways record the same event on one trace, because a count is the sum over the gateways (rule 7).

3. The scenario task asserts each value that the test reads: `assert_eq!(cluster.hive_count()?, 0, "a refused registration installs no hive")`. It asserts a reply field, an echo, an accessor, and a counter of a test double where it reads each one.
4. For one event with mixed values in one scenario, the spec counts the event and the body asserts each status that the client received. A spec holds one assertion per label, and `equals!` binds every matching record.
5. A zero count on a production event, `absent!()` or `exactly!(0)`, has a positive control in the same spec that proves the trace reached the component, such as `(events::POLICY_EVAL, exactly!(1))` beside `(events::HANDLER_ENTER, absent!())`.
6. A spec that asserts production events has no spec-wide `tag_filter`, because production assertions carry no tags.
7. Every gateway of a scenario writes to the one trace, so a count is the sum over the gateways. `at_least!` fits only where a beat repeats a decision a nondeterministic number of times, and `exactly!` fits everywhere else.
8. A spec with nothing left to assert means the scenario is a plain `#[tokio::test]`, because `.build()` refuses a configuration that cannot fail.

```rust
# use tightbeam::colony::cluster::Cluster;
# use tightbeam::colony::protocol::RegisterHiveResponse;
# use tightbeam::instrumentation::events;
# use tightbeam::policy::TransitStatus;
# use tightbeam::{exactly, tb_assert_spec, Frame};
tb_assert_spec! {
	pub ClusterUnsignedRegistrationSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_REGISTER_REFUSED, exactly!(1), equals!(TransitStatus::Unauthenticated))
		]
	}
}

// client body
# fn client_body(cluster: &impl Cluster, response_frame: &Frame) -> Result<(), Box<dyn core::error::Error>> {
let response: RegisterHiveResponse = response_frame.decode_message()?;
assert!(response.hive_id.is_none(), "a refused registration assigns no hive id");
assert_eq!(cluster.hive_count()?, 0, "a refused registration installs no hive");
# Ok(())
# }
```

**Recording a marker:**

```rust
use tightbeam::urn::Urn;
# use tightbeam::trace::TraceCollector;
# use tightbeam::urn;
# let trace = TraceCollector::new();

const RELAY_START: Urn<'static> = urn!("test", "event:demo/relay-start");
const RESPONSE_OK: Urn<'static> = urn!("test", "event:demo/response-ok");

trace.event(RELAY_START)?;
trace.event_with(RESPONSE_OK, &["tag_a"], true)?;
#
# assert_eq!(trace.recorded(RELAY_START), 1);
# Ok::<(), tightbeam::TightBeamError>(())
```

**Tags:**

- Emit with tags: `trace.event_with(FEATURE, &["v0", "v1"], ())`
- Specs filter with `tag_filter: ["v0"]`, so only matching tagged assertions count
- One emit can satisfy more than one versioned spec by listing multiple tags

**Example: version-scoped testing:**

```rust,test_harness
# use tightbeam::testing::assertions::{IsNone, Presence};
# use tightbeam::testing::{ScenarioConfig, SetupEnv};
# use tightbeam::urn::Urn;
# use tightbeam::{exactly, tb_assert_spec, tb_scenario, urn};
const FEATURE: Urn<'static> = urn!("test", "event:demo/feature");
const V1_SPECIFIC: Urn<'static> = urn!("test", "event:demo/v1-specific");

tb_assert_spec! {
	pub VersionSpec,
	V(0,0,0): {
		mode: Accept,
		tag_filter: ["v0"],
		assertions: [
			(FEATURE, exactly!(1), equals!(IsNone)),
		]
	},
	V(1,0,0): {
		mode: Accept,
		tag_filter: ["v1"],
		assertions: [
			(FEATURE, exactly!(1), equals!(IsNone)),
			(V1_SPECIFIC, exactly!(1))
		]
	}
}

tb_scenario! {
	name: test_all_versions,
	config: ScenarioConfig::builder()
		.with_specs(VersionSpec::all())
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			# let some_option: Option<u32> = None;
			trace.event_with(FEATURE, &["v0", "v1"], Presence::of_option(&some_option))?;
			trace.event_with(V1_SPECIFIC, &["v1"], ())?;
			Ok(())
		}
	}
}
```

Layer 1 matches each label as an exact URN string. With `instrument` enabled, the same emit also writes an `assert/label` or `assert/payload` event into the §10 event sink. A production event takes its own emit path instead (§10.2):

- The component that decides it emits it: a gateway, a hive, a transport, a pool, or a server plane.
- Under `testing`, the emit also records the value for a spec, so a spec asserts a production event as it asserts a marker.
- The sink files the event under its own URN.

#### 12.2.9 Schedulability Analysis

Assertion specs support schedulability verification via the `schedulability: { }` block when `testing-timing` is enabled. A spec with the block fails to compile without it:

```rust
# use core::time::Duration;
#
# use tightbeam::testing::schedulability::{SchedulerType, Task, TaskSet};
# use tightbeam::testing::TBSpec;
# use tightbeam::trace::ConsumedTrace;
# use tightbeam::{exactly, tb_assert_spec, urn};
#
# fn my_task_set() -> TaskSet {
# 	let task = |id: &str, period_ms, wcet_ms| Task {
# 		id: id.to_string(),
# 		period: Duration::from_millis(period_ms),
# 		deadline: Duration::from_millis(period_ms),
# 		wcet: Duration::from_millis(wcet_ms),
# 		priority: None,
# 	};
# 	TaskSet { tasks: vec![task("slow", 20, 5), task("fast", 10, 3)], scheduler: SchedulerType::RateMonotonic }
# }
#
# tb_assert_spec! {
# 	pub ScheduleSpec,
# 	V(1,0,0): {
# 		mode: Accept,
# 		assertions: [ (urn!("test", "event:schedule/tick"), exactly!(1)) ],
schedulability: {
	task_set: my_task_set(),
	scheduler: RateMonotonic, // or EarliestDeadlineFirst
	must_be_schedulable: true,
}
# 	},
# }
#
# assert!(ScheduleSpec::latest().validate_trace(&ConsumedTrace::new()).is_ok());
```

Supported schedulers:

- **Rate Monotonic Analysis (RMA)**: Fixed-priority scheduling. The Liu & Layland utilization bound is a sufficient-only fast path (implicit deadlines), with RTA arbitrating above the bound or for constrained deadlines
- **Earliest Deadline First (EDF)**: Dynamic priority scheduling with utilization bound ≤ 1.0 (exact for implicit deadlines)
- **Response Time Analysis (RTA)**: Exact schedulability test for fixed-priority task sets (D ≤ T). EDF task sets are rejected since the fixed-priority recurrence does not model dynamic priorities

Additional features include percentile-based WCET analysis (P50-P99.99), confidence intervals, and fixed-point arithmetic for deterministic calculations. See §12.3.5 for timing constraints in process specifications.

### 12.3 Layer 2: Process Specifications (CSP)

Implementation: [docs/testing.md](docs/testing.md#process-specifications)

#### 12.3.1 Concept

ProcessSpec defines labeled transition systems (LTS) for formal process modeling using Communicating Sequential Processes (CSP) theory. A process specification declares:

- **Observable alphabet (Σ)**: External events visible to the environment
- **Hidden alphabet (τ)**: Internal events not visible externally
- **State space**: Named states and their transitions
- **Terminal states**: Valid end states
- **Nondeterministic states**: States with internal choice

The `testing-csp` feature flag enables it.

#### 12.3.2 Specification: tb_process_spec! Syntax

```rust
# use core::time::Duration;
#
# use tightbeam::urn::Urn;
# use tightbeam::{deadline, jitter, tb_process_spec, urn, wcet};
#
# const EVENT1: Urn<'static> = urn!("test", "event:syntax/event1");
# const EVENT2: Urn<'static> = urn!("test", "event:syntax/event2");
# const EVENT3: Urn<'static> = urn!("test", "event:syntax/event3");
# const EVENT4: Urn<'static> = urn!("test", "event:syntax/event4");
# const EVENT5: Urn<'static> = urn!("test", "event:syntax/event5");
# const INTERNAL1: Urn<'static> = urn!("test", "event:syntax/internal1");
# const INTERNAL2: Urn<'static> = urn!("test", "event:syntax/internal2");
tb_process_spec! {
	pub ProcessName,
	events {
		observable { EVENT1, EVENT2, EVENT3, EVENT4, EVENT5 }  // External alphabet (Σ)
		hidden { INTERNAL1, INTERNAL2 }                        // Internal alphabet (τ)
	}
	states {
		S0 => { EVENT1 => S1 },                   // State transitions
		S1 => { EVENT2 => S2, EVENT3 => S3 },     // Branches on two events
		S2 => { EVENT4 [ clock1 < Duration::from_millis(10) ] => S3 },  // Timed transition with guard
		S3 => { EVENT5 [ clock2 >= Duration::from_millis(5), reset: [clock1] ] => S4 },  // Guard with clock reset
		S4 => {}                                  // Terminal state
	}
	terminal { S4 }                               // Valid end states
	choice { S1 }                                 // Nondeterministic states
	annotations { description: "..." }            // Optional metadata
	clocks: { clock1, clock2 }                    // Required by a guard: when testing-timing enabled
	timing {                                      // Optional: when testing-timing enabled
		wcet: { EVENT1 => wcet!(Duration::from_millis(10)) },
		jitter: { EVENT2 => jitter!(Duration::from_millis(5)) },
		deadline: { EVENT1 => EVENT5, deadline!(duration: Duration::from_millis(100), slack: Duration::from_millis(5)) }
	}
	schedulability {                              // Optional: when testing-schedulability enabled
		scheduler: RateMonotonic,                 // or EarliestDeadlineFirst
		periods: {
			EVENT1 => Duration::from_millis(50),
			EVENT2 => Duration::from_millis(100)
		}
	}
}
#
# let process = ProcessName::process()?;
# assert!(process.is_terminal(tightbeam::testing::specs::csp::State("S4")));
# Ok::<(), Box<dyn core::error::Error>>(())
```

Each event is a URN, typically a `Urn<'static>` constant, and each duration is a `core::time::Duration`. The blocks after `states` keep the order shown.

#### 12.3.3 Validation Rules

When CSP is configured via `.with_csp()` in `tb_scenario!`:

1. **Projection**: The check projects the trace onto the process alphabet by exact URN, as Hoare's restriction `tr ↾ A` does, so a label outside the alphabet falls outside the check
2. **Runtime**: Observed events MUST form valid CSP trace (framework tracks state)
3. **Post-Execution**: Trace MUST terminate in valid terminal state

#### 12.3.4 Example: CSP Process Specification

```rust
use tightbeam::testing::*;
use tightbeam::urn::Urn;
use tightbeam::{tb_process_spec, urn};

const RECEIVED: Urn<'static> = urn!("test", "event:csp/received");
const RESPONDED: Urn<'static> = urn!("test", "event:csp/responded");
const INTERNAL_PROCESSING: Urn<'static> = urn!("test", "event:csp/internal-processing");

tb_process_spec! {
	pub SimpleProcess,
	events {
		observable { RECEIVED, RESPONDED }
		hidden { INTERNAL_PROCESSING }
	}
	states {
		Idle       => { RECEIVED => Processing },
		Processing => { INTERNAL_PROCESSING => Processing, RESPONDED => Idle }
	}
	terminal { Idle }
	choice { Processing }
	annotations { description: "Simple request-response with internal processing" }
}
```

#### 12.3.5 Timing and Schedulability Verification

When `testing-timing` is enabled, process specifications support timing constraints and timed automata semantics. Each timing part of a spec fails to compile without its feature:

- A `clocks:` or `timing` block, or a guard, needs `testing-timing`.
- A `schedulability` block needs `testing-schedulability`.

**Timing Constraints:**

Process specs support four types of timing constraints via the `timing { }` block:

- **WCET (Worst-Case Execution Time)**: `wcet: { EVENT => wcet!(Duration::from_millis(10)) }` - Maximum allowed execution time per event
- **Deadline**: `deadline: { START => END, deadline!(duration: Duration::from_millis(100)) }` - Maximum latency between start and end events
- **Jitter**: `jitter: { EVENT => jitter!(Duration::from_millis(5)) }` - Maximum timing variation for an event
- **Slack**: Specified via `deadline!(duration: Duration::from_millis(100), slack: Duration::from_millis(5))` - Minimum safety margin

**Timed CSP Semantics:**

Process specs support timed automata semantics with clock variables and timing guards:

- **Clock Variables**: `clocks: { clock1, clock2 }` - Named clocks that start at zero and advance during execution. Each clock that a guard or a reset names needs a declaration here, so a misspelt clock name fails the build
- **Timing Guards**: `EVENT [ clock1 < Duration::from_millis(10) ] => State` - Transitions enabled only when guard conditions are satisfied
- **Clock Resets**: `EVENT [ clock2 >= Duration::from_millis(5), reset: [clock1] ] => State` - Clocks that reset to zero when the transition fires

Guard expressions support: `<`, `<=`, `>`, `>=`, `==`, and ranges (`LOW <= x <= HIGH`, where a bound of more than one token takes parentheses).

A guard takes effect only in a check that reads the clocks:

- FDR exploration takes a guarded transition only where the clocks satisfy its guard. Exploration starts each clock at zero.
- The CSP trace check of `tb_scenario!` and the FDR refinement checks ignore the clocks, so they accept a guarded event at any time.
- Hiding, renaming, sequential composition, and the two choices keep each guard. A parallel composition (§12.3.6) refuses a process that has a timed transition.
- Every composition keeps the timing constraints and the schedulability periods of its operands, and refuses two operands whose timing for one event does not agree.

**Early Pruning and FDR Integration:**

FDR exploration works from the model alone, so each observable event adds its WCET to the elapsed time of its trace. The runtime timing check compares each measured duration with its WCET. Timing violations prune traces during FDR exploration:

- Deadline violations prune when detected
- Path-based WCET violations prune compositional violations
- Exploration offers a guarded transition only where its guard holds, and a non-terminal state with nothing left to offer is a deadlock

When `testing-schedulability` is also enabled, timing constraints and task periods are combined into task sets for Rate Monotonic or EDF analysis. See §12.2.9 for schedulability configuration in assertion specs.

#### 12.3.6 Process Composition: tb_compose_spec!

In addition to individual process specifications, tightbeam supports **composed processes** via the `tb_compose_spec!` macro. Compositions allow you to build larger CSP models from smaller ones using standard parallel composition operators:

- **Synchronized**: All shared events synchronize (`P || Q`)
- **Interleaved**: No synchronization, pure interleaving (`P ||| Q`)
- **Interface**: Synchronize on an explicit event set (`P [| A |] Q`)
- **Alphabetized**: Per-process alphabets with synchronization on intersection (`P [| αP | αQ |] Q`)

A composed process can be used anywhere a process spec is expected, including with `.with_csp()` in `tb_scenario!`.

**Example: Interleaved request/response and retry flows**

```rust,test_harness
use tightbeam::testing::*;
use tightbeam::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_compose_spec, tb_process_spec, tb_scenario, urn};

const REQUEST: Urn<'static> = urn!("test", "event:flow/request");
const RESPONSE: Urn<'static> = urn!("test", "event:flow/response");
const RETRY: Urn<'static> = urn!("test", "event:flow/retry");

tb_assert_spec! {
	pub RequestRetrySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(REQUEST, exactly!(1)),
			(RETRY, exactly!(1)),
			(RESPONSE, exactly!(1))
		]
	},
}

// Two simple processes
tb_process_spec! {
	pub RequestFlow,
	events { observable { REQUEST, RESPONSE } hidden { } }
	states {
		Idle => { REQUEST => Waiting },
		Waiting => { RESPONSE => Idle }
	}
	terminal { Idle }
}

tb_process_spec! {
	pub RetryFlow,
	events { observable { RETRY } hidden { } }
	states {
		RetryIdle => { RETRY => RetryIdle }
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
		deterministic: true
	}
}

// Use the composed process in a scenario
tb_scenario! {
	name: test_request_with_retry,
	config: ScenarioConfig::builder()
		.with_spec(RequestRetrySpec::latest())
		.with_csp(RequestWithRetry)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			trace.event(REQUEST)?;
			trace.event(RETRY)?;
			trace.event(RESPONSE)?;
			Ok(())
		}
	}
}
```

The scenario configuration checks each composition property (`deadlock_free`, `livelock_free`, `deterministic`) once when it builds, and a property that fails its check refuses the configuration, before any FDR refinement runs.

### 12.4 Layer 3: Refinement Checking (FDR)

Implementation: [docs/testing.md](docs/testing.md#refinement-checking)

#### 12.4.1 Concept

Refinement checking applies Failures-Divergences Refinement (FDR) from CSP theory, with multi-seed exploration for trace and failures refinement verification. Formal definitions of traces, failures, and divergences are in §12.1 and §12.5, and configuration and verdict structure follow. Enable it with the `testing-fdr` feature flag.

**Verification Properties**:

- **Trace Refinement (⊑T)**: All observed traces ∈ spec traces
- **Failures Refinement (⊑F)**: No invalid refusals at choice points
- **Divergence Freedom**: No visited state reaches a cycle of hidden events through a run of hidden events, and no run of hidden events passes `max_internal_run`
- **Determinism**: Branching only at declared nondeterministic states

**Requirements**: Layer 3 requires `testing-fdr` feature flag. Refinement checking requires the `specs` field in `FdrConfig` to be populated with specification processes.

#### 12.4.2 Specification: FdrConfig Syntax

```rust
# use tightbeam::testing::fdr::FdrConfig;
let fdr = FdrConfig {
	seeds: 64,               // Number of exploration seeds
	max_depth: 128,          // Maximum trace depth
	max_internal_run: 32,    // Divergence detection threshold
	timeout_ms: 5000,        // Time budget of each refinement search
	specs: vec![],           // Processes for refinement checking (empty = exploration mode)
	fail_fast: true,         // Stop on first violation (default: true)

	// Optional resource-constraint model (feature `testing-fault`)
	scheduler: None,         // Some(SchedulerConstraint::new(model, counts)?)

	// Optional fault/FMEA configuration (features `testing-fault`, `testing-fmea`)
	fault_model: None,
	fmea_config: None,
};
```

A scenario takes the configuration through `.with_fdr(fdr)` on its builder (§12.4.3).

**Operational Modes**:

- **Mode 1** (specs empty): Single-process exploration - verifies determinism, deadlock freedom, divergence freedom
- **Mode 2** (specs provided): Refinement checking - verifies Spec ⊑ Impl (trace/failures/divergence refinement)
- **Mode 3** (specs and a fault model): Fault exploration - runs each spec under the faults of the fault model (§12.6.4)

#### 12.4.3 Implementation Examples

**Simple Example**:

```rust,test_harness
# use tightbeam::testing::fdr::FdrConfig;
# use tightbeam::testing::{ScenarioConfig, SetupEnv};
# use tightbeam::urn::Urn;
# use tightbeam::{exactly, tb_assert_spec, tb_process_spec, tb_scenario, urn};
const START: Urn<'static> = urn!("test", "event:simple/start");
const FINISH: Urn<'static> = urn!("test", "event:simple/finish");

// Define a simple two-state process
tb_process_spec! {
	pub SimpleProcess,
	events {
		observable { START, FINISH }
		hidden { }
	}
	states {
		Idle => { START => Working },
		Working => { FINISH => Idle }
	}
	terminal { Idle }
}

// Define assertion spec
tb_assert_spec! {
	pub SimpleSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(START, exactly!(1)),
			(FINISH, exactly!(1))
		]
	},
}

// Configure refinement checking against the process
fn simple_config() -> Result<ScenarioConfig, Box<dyn core::error::Error>> {
	let fdr = FdrConfig {
		seeds: 4,
		max_depth: 10,
		max_internal_run: 8,
		timeout_ms: 500,
		specs: vec![SimpleProcess::process()?],
		fail_fast: true,
		..FdrConfig::default()
	};

	Ok(ScenarioConfig::builder().with_spec(SimpleSpec::latest()).with_fdr(fdr).build()?)
}

// Test with refinement checking
tb_scenario! {
	name: test_simple_refinement,
	config: simple_config(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			trace.event(START)?;
			trace.event(FINISH)?;
			Ok(())
		}
	}
}
```

#### 12.4.4 Multi-Seed Exploration

The `seeds` parameter controls how many different execution paths are explored during verification. Each seed produces a different scheduling of concurrent operations, uncovering race conditions and nondeterministic behavior:

```rust
# use tightbeam::testing::fdr::FdrConfig;
let fdr = FdrConfig {
	seeds: 64,  // Try 64 different execution orderings
	..FdrConfig::default()
};
```

Each seed explores different interleaving at nondeterministic choice points, verifying trace refinement, failures refinement, and divergence freedom across all executions.

#### 12.4.5 FDR Verdict Structure

After multi-seed exploration, tightbeam produces a verdict. It decides each property that the run asserts:

- **Divergence freedom**: no infinite τ-loop.
- **Deadlock freedom**: no unexpected STOP state.
- **Schedulability**: every declared task set meets its deadlines.
- **Trace refinement**: traces(Impl) ⊆ traces(Spec), when the configuration names a spec.
- **Failures refinement**: failures(Impl) ⊆ failures(Spec), when the configuration names a spec.
- **Divergence refinement**: divergences(Impl) ⊆ divergences(Spec), when the configuration names a spec.

Each decision is one of four:

- **Holds**: the check completed, and everything it searched satisfied the property.
- **Refuted**: the check found a counterexample, and the verdict carries its witness.
- **Unknown**: the check stopped at a bound, such as the time budget of a search, before it found a violation or finished.
- **Not asserted**: the run left the property out.

The outcome of the verdict is its firmest decision, where a refutation outranks an unknown and an unknown outranks a hold.

A refutation carries its witness:

- Trace refinement: a trace of Impl that Spec lacks.
- Failures refinement: a trace and a refusal set of Impl that Spec does not allow.
- Divergence refinement: a divergent trace of Impl that Spec lacks.
- Divergence: the seed and the hidden events of the run that diverges.
- Deadlock: the seed, the trace, and the state.

Determinism stands apart from the outcome, because it records a modeling choice. A structural proof shows a process deterministic when no state has a hidden action or an event with more than one target, a sufficient condition (Roscoe, §10.5).[^roscoe2010] Otherwise the verdict names the first such state and event.

The verdict also counts the traces explored, the states visited, and the seeds completed, and it names the seed of the last deadlock or divergence.

### 12.5 Formal CSP Theory

Implementation: [docs/testing.md](docs/testing.md#csp-export-and-trace-analysis)

#### 12.5.1 Three Semantic Models

| CSP Model                     | tightbeam Layer | Verification Property           | Refinement Check                |
| ----------------------------- | --------------- | ------------------------------- | ------------------------------- |
| **Traces (T)**                | L1 AssertSpec   | Observable event sequences      | traces(Impl) ⊆ traces(Spec)     |
| **Stable Failures (F)**       | L2 ProcessSpec  | Valid refusals at choice points | failures(Impl) ⊆ failures(Spec) |
| **Failures-Divergences (FD)** | L3 FDR          | Livelock freedom (no τ-loops)   | divergences(Impl) = ∅           |

**Traces Model**: Verifies that the specification allows every observable event sequence the implementation produces. That is basic behavioral correctness: every sequence of external events the system produces is one the specification expects.

**Stable Failures Model**: Extends trace verification by checking what events a process can _refuse_ after each trace. A stable state is one where no internal progress (τ-transitions) can occur. At choice points, the implementation must not refuse events the specification accepts, preventing incorrect nondeterminism.

**Failures-Divergences Model**: Adds divergence detection to identify processes that can make infinite internal progress without external interaction. A state diverges when a run of hidden events from it reaches a cycle of hidden events (a τ-loop), so the process can stay unstable forever. Exploration decides exactly whether each state it visits diverges, and the `max_internal_run` parameter also counts a run of more hidden events than it allows as a divergence.

#### 12.5.2 Observable vs. Hidden Events

CSP distinguishes between observable events (external alphabet Σ) and hidden events (internal actions τ). This distinction is fundamental to process refinement:

```rust
# use tightbeam::urn::Urn;
# use tightbeam::{tb_process_spec, urn};
# const CONNECT: Urn<'static> = urn!("test", "event:client-server/connect");
# const REQUEST: Urn<'static> = urn!("test", "event:client-server/request");
# const RESPONSE: Urn<'static> = urn!("test", "event:client-server/response");
# const DISCONNECT: Urn<'static> = urn!("test", "event:client-server/disconnect");
# const SERIALIZE: Urn<'static> = urn!("test", "event:client-server/serialize");
# const ENCRYPT: Urn<'static> = urn!("test", "event:client-server/encrypt");
# const DECRYPT: Urn<'static> = urn!("test", "event:client-server/decrypt");
# const DESERIALIZE: Urn<'static> = urn!("test", "event:client-server/deserialize");
tb_process_spec! {
	pub ClientServerProcess,
	events {
		// Observable alphabet (Σ): externally visible protocol events
		observable { CONNECT, REQUEST, RESPONSE, DISCONNECT }

		// Hidden alphabet (τ): internal implementation details
		hidden { SERIALIZE, ENCRYPT, DECRYPT, DESERIALIZE }
	}
	// ...
# 	states {
# 		Idle       => { CONNECT => Connected },
# 		Connected  => { SERIALIZE => Encoding, DISCONNECT => Idle },
# 		Encoding   => { ENCRYPT => Sending },
# 		Sending    => { REQUEST => Waiting },
# 		Waiting    => { RESPONSE => Decoding },
# 		Decoding   => { DECRYPT => Reading },
# 		Reading    => { DESERIALIZE => Connected }
# 	}
# 	terminal { Idle }
}
#
# let process = ClientServerProcess::process()?;
# assert_eq!(process.hidden_alphabet().len(), 4);
# Ok::<(), Box<dyn core::error::Error>>(())
```

**Observable events** represent the process's contract with its environment. These form the basis of trace refinement - implementations and specifications must agree on observable behavior.

**Hidden events** model internal implementation details. They enable refinement checking where implementations contain details absent from abstract specifications. Hidden events are projected away when comparing traces: `trace \ {τ}`.

The instrumentation taxonomy (§10.2) maps tightbeam events to categories:

- **Observable**: `gate/accept`, `gate/reject`, `transport/request-recv`, `transport/response-send`, `assert/label`
- **Hidden (τ)**: `handler/enter`, `handler/exit`, `crypto/step`, `compress/step`, `route/step`, `policy/eval`, `process/hidden`

#### 12.5.3 Nondeterministic Choice and Refusal Sets

CSP provides two choice operators:

- **External choice (□)**: Environment selects which event occurs
- **Internal choice (⊓)**: Process selects non-deterministically

At choice points, a process has an _acceptance set_ (events it can engage) and _refusal set_ (events it cannot engage in stable state). Failures refinement ensures implementations do not introduce invalid refusals:

```rust
# use tightbeam::urn::Urn;
# use tightbeam::{tb_process_spec, urn};
# const REQUEST: Urn<'static> = urn!("test", "event:choice/request");
# const DISCONNECT: Urn<'static> = urn!("test", "event:choice/disconnect");
# const RESPONSE: Urn<'static> = urn!("test", "event:choice/response");
# const ERROR: Urn<'static> = urn!("test", "event:choice/error");
# tb_process_spec! {
# 	pub ChoiceProcess,
# 	events {
# 		observable { REQUEST, DISCONNECT, RESPONSE, ERROR }
# 		hidden { }
# 	}
states {
	// External choice: environment determines next event
	Connected  => { REQUEST => Processing, DISCONNECT => Idle },

	// Internal choice: process may non-deterministically choose path
	Processing => { RESPONSE => Responded, ERROR => ErrorState },
}
choice { Processing }  // Annotate nondeterministic states
# }
#
# let process = ChoiceProcess::process()?;
# assert!(process.is_choice(tightbeam::testing::specs::csp::State("Processing")));
# Ok::<(), Box<dyn core::error::Error>>(())
```

The `choice` annotation declares states where internal nondeterminism may occur. FDR exploration uses different seeds to explore all possible nondeterministic branches, ensuring the specification covers all implementation behaviors.

#### 12.5.4 Multi-Seed Exploration and Scheduler Interleaving

Based on research by Pedersen & Chalmers,[^pedersen2024] refinement in cooperatively scheduled systems depends on resource availability. With `n` concurrent processes and `m` schedulers where `m < n`, some traces become impossible due to scheduling constraints. With `testing-fault`, the `scheduler` setting of the FDR configuration states such a constraint:

- It names `m` schedulers that run `n` processes.
- It runs them under a cooperative or a preemptive model.
- It refuses more schedulers than processes.

Each walk and each refinement check run the subject under that constraint. Implementation: [docs/testing.md](docs/testing.md#fdrconfig).

**tightbeam addresses this through multi-seed exploration**: Each seed represents a different scheduling strategy, exploring alternative interleaving of concurrent events:

```rust
# use tightbeam::testing::fdr::FdrConfig;
let fdr = FdrConfig {
    seeds: 64,              // Explore 64 different scheduling
    max_depth: 128,         // Bound trace length
    max_internal_run: 32,   // Divergence detection threshold
    timeout_ms: 5000,       // Time budget of each refinement search
    ..FdrConfig::default()
};
```

At nondeterministic choice points, the seed determines which branch to explore. Across all seeds, the framework verifies that:

1. **Trace refinement**: All observable traces are valid
2. **Failures refinement**: No invalid refusals at choice points
3. **Divergence freedom**: No seed produces infinite τ-loops

#### 12.5.5 CSPM Export for FDR4 Integration

tightbeam can export process specifications as CSPM (CSP Machine-readable) format for verification with external tools like FDR4:[^fdr4]

```rust,no_run
use tightbeam::testing::fdr::CspmExporter;
# use tightbeam::urn::Urn;
# use tightbeam::{tb_process_spec, urn};
# const CONNECT: Urn<'static> = urn!("test", "event:client-server/connect");
# const DISCONNECT: Urn<'static> = urn!("test", "event:client-server/disconnect");
# tb_process_spec! {
# 	pub ClientServerProcess,
# 	events { observable { CONNECT, DISCONNECT } hidden { } }
# 	states {
# 		Idle      => { CONNECT => Connected },
# 		Connected => { DISCONNECT => Idle }
# 	}
# 	terminal { Idle }
# }

let process = ClientServerProcess::process()?;
let exporter = CspmExporter::new(&process);

let mut file = std::fs::File::create("target/tb_csp/client_server.csp")?;
exporter.export(&mut file)?;
# Ok::<(), Box<dyn core::error::Error>>(())
```

Generated CSPM includes:

- Observable and hidden alphabet declarations
- State space enumeration
- Labeled transition system as CSP processes
- Main process with τ-hiding: `Main_Name = P_Initial \ {| hid |}`

The output is a complete CSPM script. Implementation: [docs/testing.md](docs/testing.md#csp-export-and-trace-analysis).

#### 12.5.6 Trace Analysis Extensions

A hook reads the FDR verdict of the run, and with `FdrTraceExt` in scope it also analyzes the trace in CSP terms:

```rust
use tightbeam::testing::fdr::FdrTraceExt;
# use tightbeam::testing::fdr::{Decision, FdrConfig};
# use tightbeam::testing::{ScenarioConfig, TestHooks};
# use tightbeam::urn::Urn;
# use tightbeam::{exactly, tb_assert_spec, urn};
# const STEP: Urn<'static> = urn!("test", "event:hooks/step");
# tb_assert_spec! {
# 	pub StepSpec,
# 	V(1,0,0): {
# 		mode: Accept,
# 		assertions: [ (STEP, exactly!(1)) ]
# 	},
# }
# let config = ScenarioConfig::builder()
# 	.with_spec(StepSpec::latest())
# 	.with_fdr(FdrConfig::default())

.with_hooks(TestHooks::on_pass(|context| {
	// Refinement properties
	if let Some(fdr_verdict) = context.verdict().fdr() {
		assert_eq!(fdr_verdict.trace_refines, Decision::Holds);
		assert_eq!(fdr_verdict.divergence_free, Decision::Holds);
		assert!(fdr_verdict.is_deterministic);
	}

	// Trace analysis
	assert!(context.trace().terminated_in_valid_state());
}))
# .build()?;
# assert!(config.hooks().is_some());
# Ok::<(), Box<dyn core::error::Error>>(())
```

**Acceptance and Refusal Queries**: Each state of the request path accepts a set of events and can refuse every other event:

```rust
use tightbeam::testing::fdr::RequestPathState;
use tightbeam::testing::specs::csp::Event;

// Acceptance: the handler state accepts the response
assert!(RequestPathState::Handler.acceptance().contains(&Event("response")));

// Refusal: the handler state can refuse a new request
assert!(RequestPathState::Handler.refuses("request"));
```

These queries enable CSP-style reasoning about the request path at specific states.

### 12.6 Fault Injection

Fault injection enables systematic error testing in two ways, and both require the `testing-fault` feature flag:

- CSP state-driven fault injection during refinement checking, at a process state and an event.
- Runtime injection at trace events. A runtime fault keys on an event label in every state, with its probability in basis points. Once the trace holds the fault model, a record of that label returns the injected error at that probability.

Implementation: [docs/testing.md](docs/testing.md#fault-injection)

#### 12.6.1 FaultModel Configuration

```rust
use tightbeam::testing::{FaultModel, InjectionStrategy};
# use tightbeam::urn::Urn;
# use tightbeam::{tb_gen_process_types, urn, TightBeamError};
# const RESPONSE: Urn<'static> = urn!("test", "event:fault/response");
# tb_gen_process_types!(FaultTolerantProcess, Idle, Sending, Retrying, Success, Fallback);
# use fault_tolerant_process::States;

let fault_model = FaultModel::from(InjectionStrategy::Random)
	.with_fault(
		States::Sending,                      // Type-safe state enum
		RESPONSE,                             // Event URN
		|| TightBeamError::RecvTimeoutError,  // Error factory
		tightbeam::bps!(3000),                // 30% probability
	)
	.with_seed(0xDEADBEEF);                   // Reproducibility
```

#### 12.6.2 Injection Strategies

**Deterministic (Counter-Based):**

```rust
# use tightbeam::testing::InjectionStrategy;
# let strategy =
InjectionStrategy::Deterministic
# ;
```

- Call counters per event label
- Predictable fault sequences
- Ideal for [DO-178C][do-178c] DAL A, [IEC 61508][iec-61508] SIL 4

**Random (Seeded RNG):**

```rust
# use tightbeam::testing::InjectionStrategy;
# let strategy =
InjectionStrategy::Random
# ;
```

- Linear Congruential Generator (LCG) with seed
- Statistical coverage analysis
- Same seed produces same fault sequence

The strategy decides injection at runtime trace events and in each walk of FDR exploration (§12.4.4).

#### 12.6.3 Type-Safe State and Event Identifiers

Generate type-safe enums via `tb_gen_process_types!`:

```rust
# use tightbeam::tb_gen_process_types;
# use tightbeam::testing::{ProcessEvent, ProcessState};
# use tightbeam::urn::Urn;
# const RESPONSE: Urn<'static> = tightbeam::urn!("test", "event:fault/response");
tb_gen_process_types!(FaultTolerantProcess, Idle, Sending, Retrying, Success, Fallback);

// Generates:
// - fault_tolerant_process::States enum
// - fault_tolerant_process::Event struct, which wraps an event URN
#
# assert_eq!(fault_tolerant_process::States::Sending.full_key(), "FaultTolerantProcess.Sending");
# assert_eq!(fault_tolerant_process::Event(RESPONSE).event_label(), "urn:test:event:fault/response");
```

A fault model keys each fault by a state and an event:

- A state keys as `Process.State`.
- An event keys by its label, so an event URN, such as `RESPONSE` in §12.6.1, or the generated `Event` that wraps one, keys a fault by the label that the trace records.
- A hand-written state or event type can take the place of the generated ones.

#### 12.6.4 Integration with FDR

```rust
# use tightbeam::testing::fdr::FdrConfig;
# use tightbeam::testing::FaultModel;
# use tightbeam::urn::Urn;
# use tightbeam::{tb_process_spec, urn};
# const SEND: Urn<'static> = urn!("test", "event:fault/send");
# tb_process_spec! {
# 	pub MyProcess,
# 	events { observable { SEND } hidden { } }
# 	states { Idle => { SEND => Idle } }
# 	terminal { Idle }
# }
# let fault_model = FaultModel::default();
let fdr = FdrConfig {
	seeds: 64,
	fault_model: Some(fault_model),
	specs: vec![MyProcess::process()?],
	..FdrConfig::default()
};
# Ok::<(), Box<dyn core::error::Error>>(())
```

Faults are injected during CSP exploration before state transitions. The verdict records each injected fault with full traceability (state, event, error message, probability).

**Example:** See `tightbeam/tests/fault/basic.rs` for a full fault injection demonstration.

### 12.7 Unified Testing: tb_scenario! Macro

`tb_scenario!` is the single entry point for L1 to L3 under a chosen environment.

Implementation: [docs/testing.md](docs/testing.md#scenarios)

**Design principles:**

- One syntax for all verification layers
- Progressive enhancement: L1, then L1+L2, then L1+L2+L3
- Environments: `Bare`, `Worker`, `ServiceClient`, `Servlet`, `Pipeline`, `Cluster`, `Hive`
- Optional `TraceConfig` / hooks / fault models

#### 12.7.1 Syntax

```text
tb_scenario! {
	name: test_function_name,        // REQUIRED: names the #[test] function
	spec: AssertSpecType,            // Layer 1 latest version. Use config: for anything more
	config: ScenarioConfig::builder()  // Full configuration (alternative to spec:)
		.with_spec(AssertSpecType::latest())          // Layer 1
		.with_csp(ProcessSpecType)                    // OPTIONAL: L2 (testing-csp)
		.with_fdr(FdrConfig { ... })                  // OPTIONAL: L3 (testing-fdr)
		.with_trace(TraceCollector::from(            // OPTIONAL: §10
			TraceConfig::with_instrumentation(TbInstrumentationConfig { ... })
				.with_logger(LoggerConfig::new(...))))
		.with_hooks(TestHooks::on_pass(..))           // OPTIONAL: observers (§12.7.3)
		.with_expect(Expect::Violation(Layer::Csp))   // OPTIONAL: the layer that must reject the run
		.build(),
	environment <Variant> { ... },   // REQUIRED: Bare | Worker | ServiceClient | Servlet | Pipeline | Cluster | Hive
}

tb_scenario! {
	fuzz: afl,                       // AFL mode (testing-fuzz), in place of name:
	csp: ProcessSpecType,            // REQUIRED with fuzz: afl, the process that steers the oracle
	spec: AssertSpecType,            // or config:
	environment <Variant> { ... },   // REQUIRED: Bare | Servlet | Hive | Cluster
}
```

Exactly one of `spec:` or `config:` configures the scenario:

- `spec:` expands to a `ScenarioConfig` with that AssertSpec's latest version.
- `config:` accepts the result of `.build()`, or of a function that returns a `ScenarioConfig` result.
- A refused configuration fails the test.

Each closure receives one environment struct, and the Pipeline `exec` receives a `PipelineBuilder`. The conventional parameter name is `env`, and a closure pattern can destructure the struct when field aliases read better:

- Setup-phase closures take `SetupEnv { trace, context }`.
- `ClientEnv` adds `addr`.
- `ClusterEnv`, `HiveEnv`, `ServletEnv`, and `WorkerEnv` add the owned instance.

The `context:` key inside the environment block is evaluated once per test and shared with every closure (unit when omitted).

Environment examples also appear in [§9.3](#93-components) (Worker, Servlet, Hive, Cluster) and [§12.7.2](#1272-examples).

#### 12.7.2 Examples

**Bare Environment Example**: Pure logic/function invocation

```rust,test_harness
use tightbeam::testing::*;
use tightbeam::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_process_spec, tb_scenario, urn};

const RECEIVED: Urn<'static> = urn!("test", "event:bare/received");
const RESPONDED: Urn<'static> = urn!("test", "event:bare/responded");

tb_assert_spec! {
	pub BareSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(RECEIVED, exactly!(1)),
			(RESPONDED, exactly!(1))
		]
	},
}

tb_process_spec! {
	pub BareProcess,
	events {
		observable { RECEIVED, RESPONDED }
		hidden { }
	}
	states {
		Idle       => { RECEIVED => Processing },
		Processing => { RESPONDED => Idle }
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
			trace.event(RECEIVED)?;
			trace.event(RESPONDED)?;
			Ok(())
		}
	}
}
```

**Full Example: All Three Layers with ServiceClient Environment**

```rust,no_run,test_harness
use tightbeam::testing::*;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::tcp::TightBeamSocketAddr;
use tightbeam::transport::{EndpointConfig, MessageEmitter, Protocol};
use tightbeam::urn::Urn;
use tightbeam::{compose, equals, exactly, server, tb_assert_spec, tb_process_spec, tb_scenario, urn, Frame};

const CONNECT: Urn<'static> = urn!("test", "event:client-server/connect");
const REQUEST: Urn<'static> = urn!("test", "event:client-server/request");
const RESPONSE: Urn<'static> = urn!("test", "event:client-server/response");
const DISCONNECT: Urn<'static> = urn!("test", "event:client-server/disconnect");
const MESSAGE_CONTENT: Urn<'static> = urn!("test", "event:client-server/message-content");
const SERIALIZE: Urn<'static> = urn!("test", "event:client-server/serialize");
const ENCRYPT: Urn<'static> = urn!("test", "event:client-server/encrypt");
const DECRYPT: Urn<'static> = urn!("test", "event:client-server/decrypt");
const DESERIALIZE: Urn<'static> = urn!("test", "event:client-server/deserialize");

// Layer 1: Assert spec - defines expected assertions and cardinalities
tb_assert_spec! {
	pub ClientServerSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(CONNECT, exactly!(1)),
			(REQUEST, exactly!(1)),
			(RESPONSE, exactly!(1)),
			(MESSAGE_CONTENT, exactly!(1), equals!("test")),
			(DISCONNECT, exactly!(1))
		]
	},
}

// Layer 2: CSP process spec - models state machine with internal events
tb_process_spec! {
	pub ClientServerProcess,
	events {
		observable { CONNECT, REQUEST, RESPONSE, MESSAGE_CONTENT, DISCONNECT }
		hidden { SERIALIZE, ENCRYPT, DECRYPT, DESERIALIZE }
	}
	states {
		Idle        => { CONNECT => Connected },
		Connected   => { REQUEST => Processing, SERIALIZE => Serializing },
		Serializing => { ENCRYPT => Encrypting },
		Encrypting  => { REQUEST => Processing },
		Processing  => { DECRYPT => Decrypting, RESPONSE => Responded },
		Decrypting  => { DESERIALIZE => Decoded },
		Decoded     => { RESPONSE => Responded },
		Responded   => { MESSAGE_CONTENT => Received },
		Received    => { DISCONNECT => Idle }
	}
	terminal { Idle }
	choice { Connected, Processing }
	annotations { description: "Client-server with crypto and nondeterminism" }
}

// Layer 3: refinement of the run against the process
fn client_server_config() -> Result<ScenarioConfig, Box<dyn core::error::Error>> {
	let fdr = FdrConfig {
		seeds: 64,
		max_depth: 128,
		max_internal_run: 32,
		timeout_ms: 5000,
		specs: vec![ClientServerProcess::process()?],
		fail_fast: true,
		..FdrConfig::default()
	};

	let hooks = TestHooks::on_pass(|_context| {
		// Optional: custom logic on test pass
	})
	.with_on_fail(|_context, _violations| {
		// Optional: custom logic on test fail
	});

	let builder = ScenarioConfig::builder().with_spec(ClientServerSpec::latest());
	let builder = builder.with_csp(ClientServerProcess).with_fdr(fdr);
	Ok(builder.with_hooks(hooks).build()?)
}

tb_scenario! {
	name: test_client_server_all_layers,
	config: client_server_config(),
	environment ServiceClient {
		worker_threads: 2,
		server: |SetupEnv { trace, .. }| async move {
			let bind_addr = "127.0.0.1:0".parse::<TightBeamSocketAddr>()?;
			let (listener, addr) = <TokioListener as Protocol>::bind_cleartext(bind_addr).await?;
			let handle = server! {
				protocol TokioListener: listener,
				handle: move |frame: Frame| {
					let trace = trace.share();
					async move {
						trace.event(RESPONSE)?;
						Ok(Some(frame))
					}
				}
			};
			Ok((handle, addr))
		},
		client: |ClientEnv { trace, addr, .. }| async move {
			trace.event(CONNECT)?;
			let stream = <TokioListener as Protocol>::connect(addr).await?;
			let mut client = <TokioListener as Protocol>::create_transport(stream, EndpointConfig::cleartext());

			trace.event(REQUEST)?;
			let frame = compose! {
				V0: id: "test",
					order: 1u64,
					message: TestMessage { content: "test".to_string() }
			}?;
			let response = client.emit(frame, None).await?;

			// Decode the response and record its content as a value assertion
			if let Some(resp_frame) = response {
				let decoded: TestMessage = resp_frame.decode_message()?;
				trace.event_with(MESSAGE_CONTENT, &[], decoded.content)?;
			}

			trace.event(DISCONNECT)?;
			Ok(())
		}
	}
}
```

This test verifies:

- **L1**: Correct assertion labels and cardinalities
- **L2**: Valid state transitions with internal events
- **L3**: Trace refinement across multiple exploration seeds

`environment ServiceClient` accepts a `context:` key for state both sides need, such as certificates, synchronization primitives, and observation flags:

- The test evaluates the expression once and shares it with both closures.
- The server closure receives a `SetupEnv`.
- The client closure receives a `ClientEnv` with the bound server address and builds its own connection.

The helpers in the sketch below, such as `bind_encrypted_listener` and `build_pool`, stand for the code of a test suite:

```rust,no_run,test_harness
# use std::net::SocketAddr;
# use std::sync::Arc;
#
# use tightbeam::testing::{ClientEnv, ScenarioConfig};
# use tightbeam::transport::handshake::negotiation::TransportOffer;
# use tightbeam::transport::tcp::r#async::TokioListener;
# use tightbeam::transport::tcp::TightBeamSocketAddr;
# use tightbeam::transport::ConnectionPool;
# use tightbeam::urn::Urn;
# use tightbeam::{exactly, tb_assert_spec, tb_scenario, urn, TightBeamError};
#
# const EXCHANGED: Urn<'static> = urn!("test", "event:context/exchanged");
#
# tb_assert_spec! {
# 	pub ExchangeSpec,
# 	V(1,0,0): {
# 		mode: Accept,
# 		assertions: [ (EXCHANGED, exactly!(1)) ]
# 	},
# }
#
# struct ServerMaterials;
#
# impl ServerMaterials {
# 	fn generate() -> Self {
# 		Self
# 	}
# }
#
# async fn bind_encrypted_listener(_: &ServerMaterials) -> Result<(TokioListener, SocketAddr), TightBeamError> {
# 	unimplemented!("a test suite binds its listener here")
# }
#
# fn spawn_server(_: TokioListener) -> tokio::task::JoinHandle<()> {
# 	unimplemented!("a test suite serves its listener here")
# }
#
# fn mux_offer() -> TransportOffer {
# 	TransportOffer::mux(8)
# }
#
# fn build_pool(_: &ServerMaterials, _: TransportOffer, _: usize) -> Result<Arc<ConnectionPool<TokioListener>>, TightBeamError> {
# 	unimplemented!("a test suite builds its pool here")
# }
#
# tb_scenario! {
# 	name: service_client_with_context,
# 	config: ScenarioConfig::builder().with_spec(ExchangeSpec::latest()).build(),
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
# }
```

#### 12.7.3 Hook Semantics

Hooks observe a graded scenario. Set them with `.with_hooks(..)` on the `ScenarioConfig` builder:

- `TestHooks::on_pass(..)` observes a scenario that every layer accepted.
- `TestHooks::on_fail(..)` observes a scenario that a layer rejected, before the test fails.
- `TestHooks::on_pass(..).with_on_fail(..)` sets both.

Each hook receives a context with the trace, the first assertion spec, and the verdict of every layer. The harness decides the outcome, and a hook only reports on it.

A scenario that a layer must reject states that layer with `.with_expect(Expect::Violation(layer))`.

### 12.8 Coverage-Guided Fuzzing with AFL

Implementation: [docs/testing.md](docs/testing.md#fuzz-harness)

#### 12.8.1 Concept

tightbeam integrates [AFL.rs](https://github.com/rust-fuzz/afl.rs), a Rust port of American Fuzzy Lop, for coverage-guided fuzzing of protocol implementations. Unlike deterministic random testing, AFL uses evolutionary algorithms with compile-time instrumentation to discover inputs that trigger new code paths.

**How AFL Works**:

1. **Instrumentation**: Code is compiled with coverage tracking (edge counters)
2. **Input Corpus**: Starts with seed inputs, mutates them intelligently
3. **Feedback Loop**: Monitors code coverage, keeps inputs that discover new paths
4. **Crash Detection**: Automatically detects crashes, hangs, and assertion failures

**Integration with tb_scenario!**: The `fuzz: afl` parameter generates AFL-compatible fuzz targets that use the oracle for guided exploration. A fuzz target needs the `testing-fuzz` feature, which the doctest feature set leaves out, so the block below is `ignore`:

```rust,ignore
tb_scenario! {
	fuzz: afl,                        // AFL fuzzing mode
	csp: MyProcess,                   // The one process: the oracle reads the input through it, and the trace is verified against it
	config: ScenarioConfig::builder()
		.with_spec(MySpec::latest())
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// AFL provides random bytes, oracle navigates state machine
			let oracle = trace.oracle();
			oracle.fuzz_from_bytes()?;

			for event in oracle.trace() {
				trace.collector().event(event)?;
			}

			Ok::<(), tightbeam::TightBeamError>(())
		}
	}
}
```

The oracle returns its own error for each way a run stops short of a terminal state: a deadlock, an event it refuses, and an input that runs out. The harness grades a run that ends with either of the first two, and a run whose input ran out ends ungraded, because it drove only a prefix of the scenario.

**Feature Requirements**:

- `testing-fuzz` feature flag (enables `testing-csp`, required for the CSP oracle)
- `cargo-afl` installed (via `make setup`)
- `std` feature flag (required for most fuzz targets)

#### 12.8.2 Creating Fuzz Targets

A fuzz target is a `[[bin]]` in `tightbeam/Cargo.toml` whose name starts with `fuzz_`, with `required-features` that include `testing-fuzz`. `make fuzz-build` builds every such target.

**Example Fuzz Target** (`tightbeam/fuzz/simple_workflow.rs`, declared as `fuzz_simple_workflow`). The file builds as a binary under the `testing-fuzz` feature, which the doctest feature set leaves out, so the block is `ignore`:

```rust,ignore
//! A simple three-state workflow fuzz target for AFL.
//!
//! Run it with these commands:
//!   cargo install cargo-afl
//!   cargo afl build --bin fuzz_simple_workflow --features "std,testing-fuzz"
//!   mkdir -p fuzz_in && echo "seed" > fuzz_in/seed.txt
//!   cargo afl fuzz -i fuzz_in -o fuzz_out target/debug/fuzz_simple_workflow

#![allow(unexpected_cfgs)]
#![cfg(all(feature = "std", feature = "testing-csp"))]

use tightbeam::testing::fuzz::OracleAccess;
use tightbeam::testing::{ScenarioConfig, SetupEnv};
use tightbeam::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_process_spec, tb_scenario};

const START: Urn<'static> = tightbeam::urn!("fuzz", "event:simple/start");
const ACTION_A: Urn<'static> = tightbeam::urn!("fuzz", "event:simple/action-a");
const ACTION_B: Urn<'static> = tightbeam::urn!("fuzz", "event:simple/action-b");
const DONE: Urn<'static> = tightbeam::urn!("fuzz", "event:simple/done");

tb_assert_spec! {
	pub SimpleFuzzSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(START, exactly!(1)),
			(DONE, exactly!(1))
		]
	},
}

tb_process_spec! {
	pub SimpleFuzzProc,
	events {
		observable { START, ACTION_A, ACTION_B, DONE }
		hidden { }
	}
	states {
		S0 => { START => S1 },
		S1 => { ACTION_A => S1, ACTION_B => S1, DONE => S2 }
	}
	terminal { S2 }
}

tb_scenario! {
	fuzz: afl,
	csp: SimpleFuzzProc,
	config: ScenarioConfig::builder()
		.with_spec(SimpleFuzzSpec::latest())
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// The oracle reads the AFL input as event choices.
			let oracle = trace.oracle();
			oracle.fuzz_from_bytes()?;

			// The collector records the oracle trace, which the spec checks.
			for event in oracle.trace() {
				trace.collector().event(event)?;
			}

			Ok::<(), tightbeam::TightBeamError>(())
		}
	}
}
```

#### 12.8.3 Building and Running Fuzz Targets

**Prerequisites**:

```bash
make setup   # installs cargo-afl
```

**Run AFL Fuzzer**:

```bash
# Build one fuzz target with its required features (or: make fuzz-build, which builds every target)
RUSTFLAGS="--cfg fuzzing" cargo afl build --bin fuzz_simple_workflow --features "std,testing-fuzz"

# Create seed input directory
mkdir -p fuzz_in
echo "seed" > fuzz_in/seed.txt

# Run AFL fuzzer on the binary
cargo afl fuzz -i fuzz_in -o fuzz_out target/debug/fuzz_simple_workflow
```

`make fuzz-test seconds=N` builds every target and fuzzes each for N seconds, and it fails on a crash or a hang.

#### 12.8.4 Advanced: CSP Oracle Integration

The CSP oracle interprets AFL's random bytes as choices among state machine transitions, ensuring fuzz inputs trigger valid protocol behavior:

**How It Works**:

```text
AFL Random Bytes          CSP oracle               State Machine
─────────────────  ───►  ───────────────  ───►  ─────────────────
[0x7A, 0x3F, ...]        byte % events.len()     S0 -> S1 -> S2 -> ...
                         selects valid event      (valid trace)
```

The oracle reads the bytes in a fixed order:

- Valid events are sorted by label, so the byte-to-event mapping is deterministic across runs, and AFL crash inputs replay.
- When a chosen event has multiple target states (a nondeterministic transition), the oracle consumes one additional byte to select the target (`byte % targets.len()` over name-sorted targets), so every branch is reachable under mutation.

**Benefits**:

1. **Valid Traces Only**: Oracle ensures all fuzz inputs produce valid traces
2. **Nondeterminism Exploration**: AFL discovers which byte patterns lead to different branches
3. **Coverage Feedback**: AFL learns which choices uncover new code paths
4. **Crash Attribution**: Crashes map to specific state sequences

**Example Trace** (from crash analysis):

```text
Input: [0x00, 0x00, 0x01]
Trace: START -> ACTION_A -> ACTION_B
State: S0 -> S1 -> S1 -> S1
Result: Crash at state S1 after ACTION_B
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

When built with `--features testing-fuzz-ijon` under `cargo afl`, the CSP oracle reports its state and its coverage score to IJON after each step it takes.

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

The tightbeam equivalent:

```rust
# use tightbeam::urn::Urn;
# use tightbeam::{tb_process_spec, urn};
const MAGIC_DETECTED: Urn<'static> = urn!("test", "event:parser/magic-detected");
const PARSE_CONTINUE: Urn<'static> = urn!("test", "event:parser/parse-continue");

tb_process_spec! {
	pub ParserProcess,
	events { observable { MAGIC_DETECTED, PARSE_CONTINUE } hidden { } }
	states {
		Init   => { MAGIC_DETECTED => SpecialState, PARSE_CONTINUE => Parsing },
		SpecialState => { /* ... */ }
	}
	// IJON automatically reports when SpecialState is reached
}
```

### 12.9 Feature Matrix

Capabilities by testing layer:

| Capability                                      | `testing`        | `testing-csp`            | `testing-fdr`                    | `testing-fuzz`      |
| ----------------------------------------------- | ---------------- | ------------------------ | -------------------------------- | ------------------- |
| **Basic Verification**                          |                  |                          |                                  |                     |
| Single trace verification                       | ✓                | ✓                        | ✓                                | ✓                   |
| Assertion cardinality checks                    | ✓                | ✓                        | ✓                                | ✓                   |
| Crash/panic detection                           | ✓                | ✓                        | ✓                                | ✓                   |
| **CSP Modeling**                                |                  |                          |                                  |                     |
| CSP process modeling                            | -                | ✓                        | ✓                                | -                   |
| Compile-time label validation                   | -                | ✓                        | ✓                                | -                   |
| Runtime trace validation                        | -                | ✓                        | ✓                                | -                   |
| Terminal state verification                     | -                | ✓                        | ✓                                | -                   |
| **FDR Refinement**                              |                  |                          |                                  |                     |
| Multi-seed exploration                          | -                | -                        | ✓                                | -                   |
| Trace refinement (⊑T)                           | -                | -                        | ✓                                | -                   |
| Failures refinement (⊑F)                        | -                | -                        | ✓                                | -                   |
| Divergence detection (τ-loops)                  | -                | -                        | ✓                                | -                   |
| Determinism checking                            | -                | -                        | ✓                                | -                   |
| Refusal set analysis                            | -                | -                        | ✓                                | -                   |
| Acceptance set queries                          | -                | -                        | ✓                                | -                   |
| CSPM export (FDR4)                              | -                | -                        | ✓                                | -                   |
| **AFL Fuzzing**                                 |                  |                          |                                  |                     |
| Coverage-guided fuzzing                         | -                | -                        | -                                | ✓                   |
| Edge coverage tracking                          | -                | -                        | -                                | ✓                   |
| Input corpus evolution                          | -                | -                        | -                                | ✓                   |
| **Timing Verification**                         |                  |                          |                                  |                     |
| Timing constraints (WCET/Deadline/Jitter/Slack) | `testing-timing` | `testing-timing`         | `testing-timing`                 | -                   |
| Timed CSP (clocks, guards)                      | -                | `testing-timing`         | `testing-timing`                 | -                   |
| Schedulability analysis (RMA/EDF)               | `testing-timing` | `testing-schedulability` | `testing-schedulability`         | -                   |
| Early pruning (timing violations)               | -                | -                        | `testing-fdr` + `testing-timing` | -                   |
| **Combined Capabilities**                       |                  |                          |                                  |                     |
| CSP oracle for fuzzing                          | -                | -                        | -                                | `csp` + `fuzz`      |
| IJON state annotations                          | -                | -                        | -                                | `csp` + `fuzz-ijon` |

### 12.10 Standards Compliance Mapping

The subsections below map tightbeam verification features to common high-assurance standards. The crate supports many evidence needs. Final certification evidence and process compliance remain the integrator's responsibility.

Implementation: [docs/testing.md](docs/testing.md#fmea-reports)

#### 12.10.1 DO-178C DAL A / ISO 26262 ASIL-D

**Requirements**: 100% MC/DC coverage, systematic fault injection, and complete traceability from requirements to test evidence.

**tightbeam Support**:

- Deterministic fault injection tied to CSP states/events via `FaultModel` (§12.6.1), configured with `with_fault()` for specific state-event pairs
- Probabilistic fault coverage with `BasisPoints` (0-10000) for precise injection rates
- The FDR verdict records every injected fault with its state, event, error, and probability, for complete fault campaign traceability
- URN-based evidence artifacts (§10, §11.1.1) link instrumentation events to test assertions
- CSP process specifications (§12.3) model state machines for formal trace verification

#### 12.10.2 IEC 61508 SIL 4

**Requirements**: Systematic fault injection with proof that all error paths are exercised and tested.

**tightbeam Support**:

- `FaultModel` with `InjectionStrategy::Deterministic` ensures reproducible fault campaigns (§12.6.2)
- FDR refinement checking (§12.4) explores all modeled error paths across multiple seeds
- The FDR verdict counts the seeds that recover from an injected fault and the seeds that do not
- Multi-seed exploration (default 64 seeds) verifies behavior under different scheduling interleavings

#### 12.10.3 NASA/ESA ECSS-E-HB-40A

**Requirements**: Fault tree analysis with coverage of all single-event upsets (SEUs) and failure propagation paths.

**tightbeam Support**:

- Per-transition fault injection models SEUs at the CSP state machine level
- FDR exploration traces fault propagation through the state space
- Process composition (§12.3.6) enables hierarchical fault tree modeling via CSP parallel composition
- Instrumentation events (§10) capture fault propagation sequences for post-hoc analysis

#### 12.10.4 Common Criteria EAL7

**Requirements**: Formal verification methods with machine-checkable evidence and complete attack/failure tree coverage.

**tightbeam Support**:

- CSP formal semantics with trace/failures/divergence refinement checking (§12.4)
- Instrumentation evidence artifacts tagged with [RFC 8141][rfc8141]-compliant URNs (§11.1.1)
- The FDR verdict provides machine-readable witnesses to violations (trace/failure/divergence witnesses)
- Process specifications export to standard CSP notations for external tool verification

#### 12.10.5 FMEA/FMECA (MIL-STD-1629, ISO 26262)

**Requirements**: Enumerate all failure modes, inject each mode, observe effects, and calculate Risk Priority Numbers (RPN) based on Severity × Occurrence × Detection ratings.

**tightbeam Support**:

- `FmeaConfig` with configurable severity scales (`MilStd1629`, `Iso26262`) and RPN thresholds (default: 100)
- An FMEA report, generated through `fmea_config` from each FDR verdict that injected a fault, which holds:
  - one failure mode per injection point that fired, with its severity, occurrence, and detection ratings
  - the aggregate risk priority
  - the failure modes whose RPN exceeds the threshold
- `FaultModel::with_fault()` allows precise failure mode specification with error factories and injection probabilities
- The FDR verdict records every injected fault with its CSP state and event, for traceability

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

- MIL-STD-1629: ⌊bps / 1000⌋ + 1, at most 10 (maps 0-10000 onto 1-10)
- ISO 26262: ⌊bps / 2500⌋ + 1, at most 4 (maps 0-10000 onto 1-4)

3. **Detection** (calculated from error recovery statistics):

- Based on the count of seeds that recover from an injected fault against the count that do not
- Inverted success rate: high recovery = low detection number (easily detected)
- 100% recovery success gives Detection = 1 (easily detected/recoverable)
- 0% recovery success gives Detection = max scale (undetectable/unrecoverable)

Each failure mode of the report carries its RPN, severity × occurrence × detection.

**Example Configuration**:

```rust
# use tightbeam::testing::fdr::FdrConfig;
# use tightbeam::testing::{FaultModel, FmeaConfig, SeverityScale};
# use tightbeam::urn::Urn;
# use tightbeam::{tb_gen_process_types, urn, TightBeamError};
# const SEND: Urn<'static> = urn!("test", "event:fmea/send");
# tb_gen_process_types!(Link, Active, Idle);
# use link::States;
let fdr = FdrConfig {
	fault_model: Some(FaultModel::default()
		.with_fault(
			States::Active,
			SEND,
			|| TightBeamError::ChannelClosed,
			tightbeam::bps!(2500)  // 25% occurrence
		)
	),
	fmea_config: Some(FmeaConfig {
		severity_scale: SeverityScale::MilStd1629,
		rpn_critical_threshold: 100,
		auto_generate: true,
	}),
	..FdrConfig::default()  // other FDR config
};
```

#### 12.10.6 Standards Compliance Summary

The following table summarizes tightbeam's native support for high-assurance standards requirements:

| Standard        | Level  | Key Requirements                           | tightbeam Features                         | Feature Flags                  |
| --------------- | ------ | ------------------------------------------ | ------------------------------------------ | ------------------------------ |
| DO-178C         | DAL A  | 100% MC/DC, fault injection, traceability  | `FaultModel`, CSP specs, URN evidence      | `testing-fdr`, `testing-fault` |
| ISO 26262       | ASIL-D | Systematic fault injection, FMEA/FMECA     | Auto-FMEA (ISO scale), fault campaigns     | `testing-fdr`, `testing-fmea`  |
| IEC 61508       | SIL 4  | Error path coverage, reproducibility       | Deterministic injection, multi-seed FDR    | `testing-fdr`, `testing-fault` |
| ECSS-E-HB-40A   | -      | SEU coverage, fault tree analysis          | Per-transition injection, CSP composition  | `testing-fdr`, `testing-fault` |
| Common Criteria | EAL7   | Formal methods, machine-checkable evidence | CSP refinement, URN artifacts, CSPM export | `testing-fdr`                  |
| MIL-STD-1629    | -      | FMEA with RPN calculation                  | Auto-severity (1-10), auto-RPN             | `testing-fmea`                 |

**Legend**:

- All features require base `testing` feature
- `testing-fdr` enables FDR refinement checking and multi-seed exploration
- `testing-fault` enables `FaultModel` and deterministic fault injection
- `testing-fmea` enables automatic FMEA report generation
- `instrument` enables URN-based evidence artifacts (independent of testing)

## 13. End-to-End Examples

### 13.1 Complete Client-Server Application

Each example runs one flow end to end under `tb_scenario!`. A run passes only when its trace meets the assertion spec and follows the CSP process. Assertion and process labels are `Urn` constants, and a label matches only the identical URN.

The examples reuse the workers and the servlet of [§9.3.1](#931-e-workers) and [§9.3.2](#932-e-servlets).

#### Worker Integration Example

The worker relays a `PING`, which its receptor gate admits, and then a `PONG`, which the gate refuses.

```rust,test_harness
use std::sync::Arc;

use tightbeam::colony::worker::Worker;
use tightbeam::testing::{ScenarioConfig, WorkerEnv};
use tightbeam::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_process_spec, tb_scenario, urn};
# use tightbeam::der::Sequence;
# use tightbeam::policy::{ReceptorPolicy, TransitStatus};
# use tightbeam::Beamable;
#
# #[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
# pub struct RequestMessage {
# 	pub content: String,
# 	pub lucky_number: u32,
# }
#
# #[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
# pub struct PongMessage {
# 	pub result: String,
# }
#
# pub struct PingGate;
#
# impl ReceptorPolicy<RequestMessage> for PingGate {
# 	fn evaluate(&self, message: &RequestMessage) -> TransitStatus {
# 		if message.content == "PING" {
# 			TransitStatus::Ok
# 		} else {
# 			TransitStatus::PermissionDenied
# 		}
# 	}
# }
#
# tightbeam::worker! {
# 	name: PingPongWorker<RequestMessage, PongMessage>,
# 	config: {
# 		response: String,
# 	},
# 	policies: {
# 		with_receptor_gate: [PingGate]
# 	},
# 	handle: |_message, _trace, config| async move {
# 		PongMessage {
# 			result: config.response.to_string(),
# 		}
# 	}
# }

const RELAY_START: Urn<'static> = urn!("test", "event:worker/relay-start");
const RELAY_SUCCESS: Urn<'static> = urn!("test", "event:worker/relay-success");
const RELAY_REJECTED: Urn<'static> = urn!("test", "event:worker/relay-rejected");
const RESPONSE_RESULT: Urn<'static> = urn!("test", "event:worker/response-result");
const VALIDATE_MESSAGE: Urn<'static> = urn!("test", "event:worker/validate-message");
const PROCESS_MESSAGE: Urn<'static> = urn!("test", "event:worker/process-message");

tb_assert_spec! {
	pub PingPongWorkerSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(RELAY_START, exactly!(2)),
			(RELAY_SUCCESS, exactly!(1)),
			(RESPONSE_RESULT, exactly!(1), equals!("PONG")),
			(RELAY_REJECTED, exactly!(1))
		]
	},
}

tb_process_spec! {
	pub PingPongWorkerProcess,
	events {
		observable { RELAY_START, RELAY_SUCCESS, RELAY_REJECTED }
		hidden { VALIDATE_MESSAGE, PROCESS_MESSAGE }
	}
	states {
		Idle       => { RELAY_START => Processing },
		Processing => { VALIDATE_MESSAGE => Validating },
		Validating => { PROCESS_MESSAGE => Responding, RELAY_REJECTED => Idle },
		Responding => { RELAY_SUCCESS => Idle }
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
			PingPongWorker::new(PingPongWorkerConfig { response: "PONG".to_string() })
		},
		stimulus: |WorkerEnv { trace, worker, .. }| async move {
			trace.event(RELAY_START)?;

			let ping_msg = RequestMessage {
				content: "PING".to_string(),
				lucky_number: 42,
			};

			let pong = worker.relay(Arc::new(ping_msg)).await?;
			trace.event(RELAY_SUCCESS)?;
			trace.event_with(RESPONSE_RESULT, &[], pong.result)?;

			trace.event(RELAY_START)?;

			let pong_msg = RequestMessage {
				content: "PONG".to_string(),
				lucky_number: 42,
			};

			let result = worker.relay(Arc::new(pong_msg)).await;
			if result.is_err() {
				trace.event(RELAY_REJECTED)?;
			}

			Ok(())
		}
	}
}
```

#### Servlet Integration Example

The client sends one request. The servlet handler records `REQUEST_RECEIVED` and relays the request to both workers. The client then records the result, the winner flag, and `PONG_SENT`.

```rust,no_run,test_harness
use std::sync::Arc;

use tightbeam::colony::servlet::ServletConfig;
use tightbeam::testing::ScenarioConfig;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::urn::Urn;
use tightbeam::{compose, exactly, tb_assert_spec, tb_process_spec, tb_scenario, urn, TightBeamError};
# use tightbeam::der::Sequence;
# use tightbeam::policy::{ReceptorPolicy, TransitStatus};
# use tightbeam::Beamable;
#
# #[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
# pub struct RequestMessage {
# 	pub content: String,
# 	pub lucky_number: u32,
# }
#
# #[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
# pub struct PongMessage {
# 	pub result: String,
# }
#
# pub struct PingGate;
#
# impl ReceptorPolicy<RequestMessage> for PingGate {
# 	fn evaluate(&self, message: &RequestMessage) -> TransitStatus {
# 		if message.content == "PING" {
# 			TransitStatus::Ok
# 		} else {
# 			TransitStatus::PermissionDenied
# 		}
# 	}
# }
#
# tightbeam::worker! {
# 	name: PingPongWorker<RequestMessage, PongMessage>,
# 	config: {
# 		response: String,
# 	},
# 	policies: {
# 		with_receptor_gate: [PingGate]
# 	},
# 	handle: |_message, _trace, config| async move {
# 		PongMessage {
# 			result: config.response.to_string(),
# 		}
# 	}
# }
#
# tightbeam::worker! {
# 	name: LuckyNumberDeterminer<RequestMessage, bool>,
# 	config: {
# 		lotto_number: u32,
# 	},
# 	handle: |message, _trace, config| async move {
# 		message.lucky_number == config.lotto_number
# 	}
# }
#
# #[derive(Clone)]
# pub struct PingPongServletConfig {
# 	pub service_name: String,
# }
#
# #[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
# pub struct ResponseMessage {
# 	pub result: String,
# 	pub is_winner: bool,
# }
#
# tightbeam::servlet! {
# 	pub PingPongServletWithWorker<RequestMessage, EnvConfig = PingPongServletConfig>,
# 	protocol: TokioListener,
# 	handle: |request, _frame, ctx| async move {
# 		let trace = ctx.trace();
# 		let config: &PingPongServletConfig = ctx.env_config();
# 		trace.event_with(REQUEST_RECEIVED, &[], config.service_name.clone())?;
#
# 		let request = Arc::new(request);
# 		let (ping_result, lucky_result) = tokio::join!(
# 			ctx.relay::<PingPongWorker>(Arc::clone(&request)),
# 			ctx.relay::<LuckyNumberDeterminer>(Arc::clone(&request))
# 		);
#
# 		let reply = ping_result?;
# 		let is_winner = lucky_result?;
#
# 		Ok(Some(compose! {
# 			V0: id: b"response-id",
# 				message: ResponseMessage {
# 					result: reply.result,
# 					is_winner,
# 				}
# 		}?))
# 	}
# }

const REQUEST_RECEIVED: Urn<'static> = urn!("test", "event:servlet/request-received");
const PONG_SENT: Urn<'static> = urn!("test", "event:servlet/pong-sent");
const RESPONSE_RESULT: Urn<'static> = urn!("test", "event:servlet/response-result");
const IS_WINNER: Urn<'static> = urn!("test", "event:servlet/is-winner");
const VALIDATE_LUCKY_NUMBER: Urn<'static> = urn!("test", "event:servlet/validate-lucky-number");
const FORMAT_RESPONSE: Urn<'static> = urn!("test", "event:servlet/format-response");

tb_assert_spec! {
	pub PingPongSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(REQUEST_RECEIVED, exactly!(1)),
			(PONG_SENT, exactly!(1)),
			(RESPONSE_RESULT, exactly!(1), equals!("PONG")),
			(IS_WINNER, exactly!(1), equals!(true))
		]
	},
}

tb_process_spec! {
	pub PingPongProcess,
	events {
		observable { REQUEST_RECEIVED, PONG_SENT }
		hidden { VALIDATE_LUCKY_NUMBER, FORMAT_RESPONSE }
	}
	states {
		Idle       => { REQUEST_RECEIVED => Processing },
		Processing => { VALIDATE_LUCKY_NUMBER => Validating },
		Validating => { FORMAT_RESPONSE => Responding },
		Responding => { PONG_SENT => Idle }
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
			let servlet_conf = ServletConfig::<TokioListener, RequestMessage>::builder()
				.with_config(Arc::new(PingPongServletConfig { service_name: "ping-pong".to_string() }))
				.with_worker(PingPongWorker::new(PingPongWorkerConfig { response: "PONG".to_string() }))
				.with_worker(LuckyNumberDeterminer::new(LuckyNumberDeterminerConfig { lotto_number: 42 }))
				.allow_cleartext()
				.build();

			PingPongServletWithWorker::start(Arc::new(env.trace), servlet_conf).await
		},
		client: |env| async move {
			let (trace, mut client) = (env.trace, env.client);
			let ping_message = compose! {
				V0: id: b"test-ping",
					message: RequestMessage {
						content: "PING".to_string(),
						lucky_number: 42,
					}
			}?;

			let response = client.emit(ping_message, None).await?.ok_or(TightBeamError::MissingResponse)?;
			let response_message: ResponseMessage = response.decode_message()?;

			trace.event_with(RESPONSE_RESULT, &[], response_message.result)?;
			trace.event_with(IS_WINNER, &[], response_message.is_winner)?;
			trace.event(PONG_SENT)?;

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
- [NIST SP 800-56C][nist-800-56c]: Recommendation for Key-Derivation Methods in Key-Establishment Schemes
- [RFC 2119][rfc2119]: Key words for use in RFCs to Indicate Requirement Levels
- [RFC 3274][rfc3274]: Compressed Data Content Type for Cryptographic Message Syntax (CMS)
- [RFC 3279][rfc3279]: Algorithms and Identifiers for the Internet X.509 Public Key Infrastructure Certificate and CRL Profile
- [RFC 3394][rfc3394]: Advanced Encryption Standard (AES) Key Wrap Algorithm
- [RFC 3447][rfc3447]: Public-Key Cryptography Standards (PKCS) #1: RSA Cryptography Specifications Version 2.1
- [RFC 3565][rfc3565]: Use of the Advanced Encryption Standard (AES) Encryption Algorithm in Cryptographic Message Syntax (CMS)
- [RFC 5083][rfc5083]: Cryptographic Message Syntax (CMS) Authenticated-Enveloped-Data Content Type
- [RFC 5084][rfc5084]: Using AES-CCM and AES-GCM Authenticated Encryption in the Cryptographic Message Syntax (CMS)
- [RFC 5246][rfc5246]: The Transport Layer Security (TLS) Protocol Version 1.2
- [RFC 5280][rfc5280]: Internet X.509 Public Key Infrastructure Certificate and CRL Profile
- [RFC 5480][rfc5480]: Elliptic Curve Cryptography Subject Public Key Information
- [RFC 5652][rfc5652]: Cryptographic Message Syntax (CMS)
- [RFC 5753][rfc5753]: Use of Elliptic Curve Cryptography (ECC) Algorithms in Cryptographic Message Syntax (CMS)
- [RFC 5869][rfc5869]: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- [RFC 6211][rfc6211]: Cryptographic Message Syntax (CMS) Algorithm Identifier Protection Attribute
- [RFC 7093][rfc7093]: Additional Methods for Generating Key Identifiers Values
- [RFC 8032][rfc8032]: Edwards-Curve Digital Signature Algorithm (EdDSA)
- [RFC 8141][rfc8141]: Uniform Resource Names (URNs)
- [RFC 8174][rfc8174]: Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words
- [RFC 8439][rfc8439]: ChaCha20 and Poly1305 for IETF Protocols
- [RFC 9180][rfc9180]: Hybrid Public Key Encryption
- [RFC 9629][rfc9629]: Using Key Encapsulation Mechanism (KEM) Algorithms in the Cryptographic Message Syntax (CMS)
- [RFC 9688][rfc9688]: Use of the SHA3 One-Way Hash Functions in the Cryptographic Message Syntax (CMS)
- [RFC 9846][rfc9846]: The Transport Layer Security (TLS) Protocol Version 1.3 (obsoletes RFC 8446)
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
- [RFC 9901][rfc9901]: Selective Disclosure for JSON Web Tokens (SD-JWT)
- [RFC Editor Style Guide][rfc-style-guide]: Web Portion of the Style Guide

## 15. License

### For Users (Outbound Licensing)

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0))
- MIT license ([LICENSE-MIT](LICENSE-MIT) or [http://opensource.org/licenses/MIT](http://opensource.org/licenses/MIT))

**at your option**. You may choose whichever license best fits your needs:

- **Choose MIT** if you prefer simplicity and broad compatibility
- **Choose Apache-2.0** if you want explicit patent protection and retaliation clauses

### For Contributors (Inbound Licensing)

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

**Contributors therefore grant rights under BOTH licenses**, which provides:

- MIT's simplicity for users who prefer it
- Apache-2.0's patent grants for enhanced protection

## 16. Implementation Notes

#### Project Structure

The workspace holds the protocol crate, its derive macros, and the crates and documents around them:

- **tightbeam/**: The protocol crate, published as `tightbeam-rs`
- **tightbeam/tests/**: Integration test suites
- **tightbeam-derive/**: The derive macros, which `tightbeam-rs` re-exports
- **consumers/**: Crates that depend on `tightbeam-rs` as a downstream user does, each with one feature selection ([consumers/README.md](consumers/README.md))
- **docs/**: The specifications that drill down from this README, indexed in [docs/README.md](docs/README.md)
- **tips/**: tightbeam Improvement Proposals ([TIP 1](tips/tip-0001.md))

[CONTRIBUTING.md](CONTRIBUTING.md) states the toolchain, the build and lint commands, and the pull request rules. Each code block of this README marked `rust` compiles as a doctest of `tightbeam-rs`, so `cargo test --doc` fails on a stale one.

#### Extensions

The official tightbeam extensions live in [tightbeam-ext](https://github.com/wahidgroup/tightbeam-ext).

[crate-image]: https://img.shields.io/crates/v/tightbeam-rs.svg
[crate-link]: https://crates.io/crates/tightbeam-rs
[docs-image]: https://img.shields.io/docsrs/tightbeam-rs
[docs-link]: https://docs.rs/tightbeam-rs
[build-image]: https://img.shields.io/github/actions/workflow/status/wahidgroup/tightbeam/ci.yml?branch=master
[build-link]: https://github.com/wahidgroup/tightbeam/actions/workflows/ci.yml
[license-image]: https://img.shields.io/badge/license-MIT%2FApache--2.0-blue
[rustc-image]: https://img.shields.io/badge/rustc-1.88.0%2B-orange?logo=rust
[chat-image]: https://img.shields.io/badge/chat-Discussions-blue?logo=github
[chat-link]: https://github.com/wahidgroup/tightbeam/discussions
[rfc-style-guide]: https://www.rfc-editor.org/styleguide/part2/
[rfc2119]: https://datatracker.ietf.org/doc/html/rfc2119
[rfc2474]: https://datatracker.ietf.org/doc/html/rfc2474
[rfc3246]: https://datatracker.ietf.org/doc/html/rfc3246
[rfc3274]: https://datatracker.ietf.org/doc/html/rfc3274
[rfc3279]: https://datatracker.ietf.org/doc/html/rfc3279
[rfc3394]: https://datatracker.ietf.org/doc/html/rfc3394
[rfc3447]: https://datatracker.ietf.org/doc/html/rfc3447
[rfc3565]: https://datatracker.ietf.org/doc/html/rfc3565
[rfc4594]: https://datatracker.ietf.org/doc/html/rfc4594
[rfc5083]: https://datatracker.ietf.org/doc/html/rfc5083
[rfc5084]: https://datatracker.ietf.org/doc/html/rfc5084
[rfc5246]: https://datatracker.ietf.org/doc/html/rfc5246
[rfc5280]: https://datatracker.ietf.org/doc/html/rfc5280
[rfc5424]: https://datatracker.ietf.org/doc/html/rfc5424
[rfc5480]: https://datatracker.ietf.org/doc/html/rfc5480
[rfc5652]: https://datatracker.ietf.org/doc/html/rfc5652
[rfc5652-5]: https://datatracker.ietf.org/doc/html/rfc5652#section-5
[rfc5753]: https://datatracker.ietf.org/doc/html/rfc5753
[rfc5869]: https://datatracker.ietf.org/doc/html/rfc5869
[rfc6211]: https://datatracker.ietf.org/doc/html/rfc6211
[rfc6960]: https://datatracker.ietf.org/doc/html/rfc6960
[rfc7093]: https://datatracker.ietf.org/doc/html/rfc7093
[rfc7322]: https://datatracker.ietf.org/doc/html/rfc7322
[rfc7748]: https://datatracker.ietf.org/doc/html/rfc7748
[rfc8032]: https://datatracker.ietf.org/doc/html/rfc8032
[rfc8141]: https://datatracker.ietf.org/doc/html/rfc8141
[rfc8174]: https://datatracker.ietf.org/doc/html/rfc8174
[rfc8439]: https://datatracker.ietf.org/doc/html/rfc8439
[rfc8622]: https://datatracker.ietf.org/doc/html/rfc8622
[rfc9000-4.1]: https://datatracker.ietf.org/doc/html/rfc9000#section-4.1
[rfc9113]: https://datatracker.ietf.org/doc/html/rfc9113
[rfc9113-4.2]: https://datatracker.ietf.org/doc/html/rfc9113#section-4.2
[rfc9113-5.1.1]: https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.1
[rfc9113-5.1.2]: https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.2
[rfc9113-7]: https://datatracker.ietf.org/doc/html/rfc9113#section-7
[rfc9113-8.1]: https://datatracker.ietf.org/doc/html/rfc9113#section-8.1
[rfc9180]: https://datatracker.ietf.org/doc/html/rfc9180
[rfc9629]: https://datatracker.ietf.org/doc/html/rfc9629
[rfc9688]: https://datatracker.ietf.org/doc/html/rfc9688
[rfc9846]: https://datatracker.ietf.org/doc/html/rfc9846
[rfc9846-4.2.3]: https://datatracker.ietf.org/doc/html/rfc9846#section-4.2.3
[rfc9846-4.5.2]: https://datatracker.ietf.org/doc/html/rfc9846#section-4.5.2
[rfc9846-4.5.3]: https://datatracker.ietf.org/doc/html/rfc9846#section-4.5.3
[rfc9846-4.7.3]: https://datatracker.ietf.org/doc/html/rfc9846#section-4.7.3
[rfc9846-5.5]: https://datatracker.ietf.org/doc/html/rfc9846#section-5.5
[rfc9846-7.1]: https://datatracker.ietf.org/doc/html/rfc9846#section-7.1
[rfc9846-f.1]: https://datatracker.ietf.org/doc/html/rfc9846#appendix-F.1
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
[fips203]: https://csrc.nist.gov/pubs/fips/203/final
[nist-800-56a]: https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final
[nist-800-56c]: https://csrc.nist.gov/publications/detail/sp/800-56c/rev-2/final
[nist-800-57]: https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final
[iso-18013-5]: https://www.iso.org/standard/69084.html
[iso-26262]: https://www.iso.org/standard/68383.html
[iec-61508]: https://webstore.iec.ch/publication/5515
[do-178c]: https://www.rtca.org/do-178/
[mil-std-1629]: https://everyspec.com/MIL-STD/MIL-STD-1600-1699/MIL_STD_1629A_1556/
[secg-sec1]: https://www.secg.org/sec1-v2.pdf
