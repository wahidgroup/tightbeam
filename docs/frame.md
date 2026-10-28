# The TightBeam Frame

This page specifies how the tightbeam crate holds, builds, encodes, and checks a Frame:

- the types of the Frame, its metadata, and its matrix
- the builder methods and the `compose!` keys that set each field
- the code that enforces each version gate and each semantic rule
- the error each check returns

It drills down from [README §4](../README.md#4-protocol-specification) and [README §5](../README.md#5-asn1-formal-specification) for engineers who build, decode, or review frames. The README states what each field is, why it exists, and the standards it follows.

## Contents

- [Versions and gated fields](#versions-and-gated-fields)
- [Frame and Metadata](#frame-and-metadata)
- [FrameBuilder and compose!](#framebuilder-and-compose)
- [Enumerated types](#enumerated-types)
- [Cryptographic structures](#cryptographic-structures)
- [Encoding](#encoding)
- [Semantic constraints](#semantic-constraints)
- [Matrix](#matrix)
- [Sources](#sources)

## Versions and gated fields

[README §4.1](../README.md#41-version-evolution) states what each version adds, and [README §5.6](../README.md#56-version-specific-constraints) states the fields each version forbids.

`GatedField` (`tightbeam::asn1::GatedField`) names each optional field that a later version introduces. `GatedField::since` returns the version that introduced it, and `Version::allows(field)` holds when a version is at or above that one.

| `GatedField` | Field | Since |
| --- | --- | --- |
| `MessageIntegrity` | `Metadata.integrity` (MI) | V1 |
| `Confidentiality` | `Metadata.confidentiality` | V1 |
| `FrameIntegrity` | `Frame.integrity` (FI) | V1 |
| `Nonrepudiation` | `Frame.nonrepudiation` | V1 |
| `Priority` | `Metadata.priority` | V2 |
| `Lifetime` | `Metadata.lifetime` | V2 |
| `PreviousFrame` | `Metadata.previousFrame` | V2 |
| `Matrix` | `Metadata.matrix` | V3 |

Every version carries `id`, `order`, `message`, and `compactness`, so they have no gate.

Four paths refuse a gated field below its version:

| Path | Refuses | Error |
| --- | --- | --- |
| `MetadataBuilder::build`, which `FrameBuilder::build` runs | A metadata field | `BuildError::InvalidMetadata(MetadataError::UnsupportedField { field, version })`, as `TightBeamError::BuildError` from `FrameBuilder::build` |
| `FrameBuilder::build` | FI or a signature on a V0 frame | `TightBeamError::UnsupportedVersion`, which names the frame version and the version of the field |
| `Frame::attach_signer_info`, `Frame::sign_with_provider`, `Frame::encrypt_with_provider` | The field the method adds | `TightBeamError::UnsupportedVersion` |
| The DER decoder of `Frame` | Every gated field, once the fields decode | A `der` value error on the `SEQUENCE` tag |

```rust
use tightbeam::asn1::GatedField;
use tightbeam::builder::error::{BuildError, MetadataError};
use tightbeam::prelude::MatrixDyn;
use tightbeam::testing::TestMessage;
use tightbeam::{compose, TightBeamError, Version};

assert_eq!(GatedField::Matrix.since(), Version::V3);
assert!(!Version::V2.allows(GatedField::Matrix));

let refused = compose! {
    V2: id: "grid-1",
        order: 1u64,
        message: TestMessage::sample(None),
        matrix: MatrixDyn::default()
};

let gate = MetadataError::UnsupportedField { field: GatedField::Matrix, version: Version::V2 };
assert!(matches!(
    refused,
    Err(TightBeamError::BuildError(BuildError::InvalidMetadata(error))) if error == gate
));
```

## Frame and Metadata

[README §4.2](../README.md#42-frame-structure) to [README §4.4](../README.md#44-frame-encapsulation) state what a Frame carries, and [README §5.3](../README.md#53-message-structure) gives the ASN.1.

`Frame` and `Metadata` (`tightbeam::{Frame, Metadata}`) keep their fields private. A frame enters memory through [`FrameBuilder`](#framebuilder-and-compose) or the DER decoder, and each field has a read accessor of the same name.

| `Metadata` field | Accessor | Returns |
| --- | --- | --- |
| `id` | `id()` | `&[u8]` |
| `order` | `order()` | `u64` |
| `compactness` | `compactness()` | `Option<&CompressedData>` |
| `integrity` | `integrity()` | `Option<&DigestInfo>` |
| `confidentiality` | `confidentiality()` | `Option<&AuthEnvelopedData>` |
| `priority` | `priority()` | `Option<MessagePriority>` |
| `lifetime` | `lifetime()` | `Option<u64>`, in seconds |
| `previousFrame` | `previous_frame()` | `Option<&DigestInfo>` |
| `matrix` | `matrix()` | `Option<&MatrixDyn>` |

| `Frame` field | Accessor | Returns |
| --- | --- | --- |
| `version` | `version()` | `Version` |
| `metadata` | `metadata()` | `&Metadata` |
| `message` | `message()`, `into_message()` | `&[u8]`, `Vec<u8>` |
| `integrity` | `integrity()` | `Option<&DigestInfo>` |
| `nonrepudiation` | `nonrepudiation()` | `Option<&Signed<SignerInfo>>` |

Each type stores some fields in a wrapper:

- `Metadata` holds the envelope as a `WireDer<AuthEnvelopedData>`: the value beside the DER bytes it was built or arrived as. An open reads the authenticated attributes from those bytes (RFC 5083 §2.1).
- `Frame` holds the signature as a `Signed<SignerInfo>` (`tightbeam::crypto::sign::Signed`). The CMS signer builds every value the crate emits, and the decoder admits every value it reads under the CMS rules of [Encoding](#encoding). A decoded signature is trusted only after [`Frame::verify` or `Frame::verify_under`](#nonrepudiation) checks it.

A frame also answers these questions:

| Method | Returns |
| --- | --- |
| `body_transform()` | `Some(BodyTransform::Decrypt)` while `confidentiality` is set, `Some(BodyTransform::Inflate)` while only `compactness` is set, and `None` when the body decodes as it is |
| `signer_id()` | The DER of the `SignerIdentifier` the signature claims, the key of per-signer budgets, replay slots, refusal journals, and gossip attribution |
| `to_tbs()` | The bytes the signature covers ([Nonrepudiation](#nonrepudiation)) |
| `compute_hash::<D>()` | The `DigestInfo` of the whole frame ([Previous frame chaining](#previous-frame-chaining)) |

`Display` prints the version and the id as hex, and `Debug` prints the message as its length, so an error that carries a frame keeps the body out of a log (CWE-532). With the `zeroize` feature, a dropped frame wipes its message, and its metadata wipes `id`, `order`, `lifetime`, and `matrix`.

A frame converts into its parts:

- `Metadata::from(frame)` and `Version::from(&frame)` take the metadata and the version.
- `Signed::<SignerInfo>::try_from(frame)` takes the signature, or returns `TightBeamError::MissingSignature`.
- `AuthEnvelopedData::try_from(frame)` takes the envelope, or returns `TightBeamError::MissingEncryptionInfo`.

An open in place, such as `decrypt_in_place`, `decrypt_with_provider`, or `inflate_in_place`, rewrites the body and the metadata that described it. FI and the signature fail to verify after that, so the open moves both into the `Opened` (`tightbeam::asn1::Opened`) it returns. A caller verifies them before the open and reads them from `Opened` after it, such as to name the signer.

```rust
use tightbeam::der::{Decode, Encode};
use tightbeam::testing::TestMessage;
use tightbeam::{compose, Frame, Version};

let frame = compose! { V0: id: "ping-1", order: 1u64, message: TestMessage::sample(None) }?;
let decoded = Frame::from_der(&frame.to_der()?)?;

assert_eq!(decoded, frame);
assert_eq!(decoded.version(), Version::V0);
assert_eq!(decoded.metadata().id(), b"ping-1");
# Ok::<(), tightbeam::TightBeamError>(())
```

## FrameBuilder and compose!

[README §4.4](../README.md#44-frame-encapsulation) states that building a Frame refuses a field its version forbids.

`FrameBuilder<T>` (`tightbeam::builder::FrameBuilder`) builds a `Frame` around a message `T: Message`. `FrameBuilder::from(version)` or `Version::compose::<T>()` starts one, and `TypeBuilder::build` returns `Result<Frame, TightBeamError>`. The `compose!` macro expands to the same calls. Its first token names the `Version` variant, each `key: value` pair calls one method, and an unknown key fails to compile.

| `compose!` key | Method | Sets | Feature |
| --- | --- | --- | --- |
| `id` | `with_id(impl AsRef<[u8]>)` | `Metadata.id` | `builder` |
| `order` | `with_order(u64)` | `Metadata.order` | `builder` |
| `message` | `with_message(T)` | `Frame.message` | `builder` |
| `message_integrity<D>` | `with_message_hasher::<D>(salt)` | `Metadata.integrity` (MI) | `digest` |
| `frame_integrity: type D` | `with_witness_hasher::<D>()` | `Frame.integrity` (FI) | `digest` |
| `confidentiality`, `encryptor<C, _>` | `with_encryptor::<C, E>(encryptor)` | `Metadata.confidentiality`, and the ciphertext in `Frame.message` | `aead` |
| `nonrepudiation<S, _>` | `with_signer::<S, X>(CertifiedKey<X>)` | `Frame.nonrepudiation` | `signature` |
| `compactness` | `with_compression(impl Compressor)` | `Metadata.compactness` | `compress` |
| `priority` | `with_priority(MessagePriority)` | `Metadata.priority` | `builder` |
| `lifetime` | `with_lifetime(u64)`, in seconds | `Metadata.lifetime` | `builder` |
| `previous_frame` | `with_previous_hash(DigestInfo)` | `Metadata.previousFrame` | `builder` |
| `matrix` | `with_matrix(impl IntoMatrixDyn)` | `Metadata.matrix` | `builder` |

Three methods have no key:

- `with_matrix_dyn(MatrixDyn)` sets the matrix from a `MatrixDyn`.
- `with_content_oid(ObjectIdentifier)` names the content type the encryptor seals the body as, or `id-data` when unset.
- `with_rng(impl CryptoRngCore)` sets the random source of the content key, the nonce, and the recipient values, or the OS source when unset.

With a host clock, a build with no order takes the current Unix time in seconds.

A method that fails records its error, and `build` returns it before any other step. One recorded error returns as it is, and two or more return as `TightBeamError::Sequence`. `build` then checks the version and the markers of the `Message` trait:

| Check | Error |
| --- | --- |
| The version is below `T::MIN_VERSION` | `UnsupportedVersion` |
| `MUST_BE_CONFIDENTIAL` with no encryptor | `MissingProtection { marker: "MUST_BE_CONFIDENTIAL", call: "with_encryptor" }` |
| `MUST_BE_NON_REPUDIABLE` with no signer | `MissingProtection { .., call: "with_signer" }` |
| `MUST_BE_COMPRESSED` with no compressor | `MissingProtection { .., call: "with_compression" }` |
| `MUST_HAVE_MESSAGE_INTEGRITY` with no message hasher | `MissingProtection { .., call: "with_message_hasher" }` |
| `MUST_HAVE_FRAME_INTEGRITY` with no witness hasher | `MissingProtection { .., call: "with_witness_hasher" }` |
| `MUST_BE_PRIORITIZED` with no priority | `MissingProtection { .., call: "with_priority" }` |
| No message | `InvalidBody` |

The methods that name an algorithm hold it to the security profile of `T` ([README §6](../README.md#6-security-model)):

- Each one bounds `T` by a checker: `CheckDigestOid<D>`, `CheckAeadOid<C>`, or `CheckSignatureOid<S>` (`tightbeam::builder`).
- `#[derive(Beamable)]` implements the checker for every algorithm when the message names no profile, and for the algorithm of its profile alone when it names one, so a mismatch fails to compile.
- Any type can implement a checker, so the method also compares the OID with `T::Profile` at run time and records `TightBeamError::UnexpectedAlgorithm` on a mismatch.

The stages of `build` run in the order of [Security property chain](#security-property-chain).

## Enumerated types

[README §5.1](../README.md#51-enumerated-types) gives the ASN.1 of both enumerations.

`Version` and `MessagePriority` (`tightbeam::{Version, MessagePriority}`) are `#[repr(u8)]` enums that derive `Enumerated` and `Ord`, so the Rust order is the order of the ASN.1 values. `Version` maps `vN(N)` to `Version::VN`. A higher priority compares greater.

| ASN.1 value | `MessagePriority` variant |
| --- | --- |
| `lowEffort(0)` | `LowEffort` |
| `standard(1)` | `Standard` |
| `highThroughput(2)` | `HighThroughput` |
| `lowLatency(3)` | `LowLatency` |
| `expedited(4)` | `Expedited` |
| `networkControl(5)` | `NetworkControl` |

## Cryptographic structures

[README §5.2](../README.md#52-cryptographic-structures) and [README §5.4](../README.md#54-external-dependencies) give the ASN.1 of each structure the Frame imports.

The crate takes each structure from the RustCrypto crate that defines it, and re-exports those crates as `tightbeam::{cms, der, pkcs12, spki}`. `tightbeam::asn1` re-exports each type below.

| ASN.1 type | Rust type | Defined in | Frame slot |
| --- | --- | --- | --- |
| `DigestInfo` | `DigestInfo` | `pkcs12::digest_info` | `Option<DigestInfo>` for MI, FI, and `previousFrame` |
| `AuthEnvelopedData` | `AuthEnvelopedData` | `tightbeam::asn1`, checked field by field against RFC 5083 | `Option<WireDer<AuthEnvelopedData>>` |
| `SignerInfo` | `SignerInfo` | `cms::signed_data` | `Option<Signed<SignerInfo>>` |
| `CompressedData` | `CompressedData` | `cms::compressed_data` | `Option<CompressedData>` |
| `AlgorithmIdentifier` | `AlgorithmIdentifier`, `AlgorithmIdentifierOwned` | `spki` | Inside each structure above |
| `Matrix` | `MatrixDyn` | `tightbeam::matrix` | `Option<MatrixDyn>` |

`tightbeam::oids` names the compression OIDs:

| Constant | OID | ASN.1 name |
| --- | --- | --- |
| `COMPRESSION_ZLIB` | `1.2.840.113549.1.9.16.3.8` | `id-alg-zlibCompress` |
| `COMPRESSION_ZSTD` | `1.3.6.1.4.1.64586.2.1` | `id-alg-zstdCompress`, under the Wahid Group PEN |
| `COMPRESSION_CONTENT` | `1.2.840.113549.1.9.16.1.9` | `id-ct-compressedData` |

## Encoding

[README §5.5](../README.md#55-encoding-rules) states the encoding rules.

The crate encodes and decodes with the `der` 0.7 crate:

- `tightbeam::encode` writes DER and puts each universal SET OF in DER order, which `der` 0.7 misses for a SET OF a CHOICE.
- `tightbeam::decode` refuses a universal SET OF out of DER order before `der` decodes the value.
- `Frame` and `Metadata` implement `der::Encode` and `der::Decode`, so `to_der` and `from_der` take them directly.

`der_derive` 0.7 encodes a `Vec<u8>` field as `SEQUENCE OF INTEGER`, so the crate writes the `Frame` and `Metadata` codecs with its own `wire_sequence!` macro:

| Field kind | Fields | Wire form |
| --- | --- | --- |
| Octets | `Metadata.id`, `Frame.message` | `OCTET STRING` |
| Plain | `version`, `metadata`, `order`, `compactness` | The field type's own DER codec |
| Context | `Metadata.integrity` to `Metadata.matrix`, `Frame.integrity`, and `Frame.nonrepudiation` | `[n] EXPLICIT`, left out when `None` |

The decoder refuses four kinds of input:

- A context field numbered below the one it reads next, so a repeated field and a field out of schema order both fail (X.690 § 8.9.2). `der` 0.7 alone skips such a field as absent.
- A gated field below the frame version ([Versions and gated fields](#versions-and-gated-fields)).
- A matrix whose `data` length differs from `n * n` ([Matrix](#matrix)).
- An envelope or a signature whose SETs break the CMS admission rules: a universal SET out of DER order or with a repeated element, and a SET of more than 32 elements.

Every SET of a frame sits inside the envelope or the signature. `WireDer` and `Signed` each run the admission walk on their contents and hold the value to the bytes it arrived as.

## Semantic constraints

[README §5.7](../README.md#57-semantic-constraints) states the rules. This section names the code that applies each one.

### Message ordering

[README §5.7.1](../README.md#571-message-ordering) states the ordering rules.

- `order` is a `u64` that the frame layer carries as it is.
- `with_order` sets it. With a host clock, a build with no order takes the current Unix time in seconds.
- Monotonic order and duplicate refusal belong to the receiver. The colony's signed control frames carry their issue time in `order` as Unix milliseconds, and the colony's replay guards admit each one once inside a freshness window.

### Compression

[README §5.7.2](../README.md#572-compression-requirements) states the compression rules.

`Compressor` compresses a body into bytes and the `CompressedData` that describes them, and `Inflator` reverses it (`tightbeam::compress`). `ZstdCompression` implements both under the `zstd` feature:

| Property | `ZstdCompression` |
| --- | --- |
| Algorithm | `COMPRESSION_ZSTD`, with no parameters |
| Level | 3, the zstd default |
| `encapContentInfo` | `id-data` with no `eContent`, and the compressed bytes travel in `Frame.message` |
| Output cap | `DEFAULT_MAX_DECOMPRESSED_LEN` (16 MiB), or the value of `with_max_output` |
| Window cap | The output cap rounded up to a power of two, within the window bounds of zstd |

A decompression fails with one `CompressionError`:

| Variant | Cause |
| --- | --- |
| `OutputLimitExceeded` | The output passes the cap (CWE-409) |
| `Truncated` | The input ends inside the zstd frame |
| `Stalled` | The decoder consumes no input and produces no output |
| `TrailingBytes` | Octets follow the zstd frame |
| `ZSTD` | The codec refuses the frame, with its numeric code |

`Frame::inflate_in_place(&dyn Inflator)` inflates a compressed cleartext body, clears `compactness`, and returns an `Opened`. A failed inflate restores the frame. `decrypt_in_place` inflates an encrypted body after it decrypts it. The router refuses a compressed body with `RouterError::CompressedFrame`, and a servlet inflates it with the inflator of its context.

### Message integrity

[README §5.7.3](../README.md#573-integrity-semantics-order-of-operations) states the commitment and its rules.

`with_message_hasher::<D>(salt)` commits to the DER of the message before compression and encryption, and stores the `DigestInfo` in `Metadata.integrity`. `CommitmentSalt::parse` (`tightbeam::crypto::commitment`) reads the salt:

| Salt | Mode | Commitment |
| --- | --- | --- |
| Empty | `CommitmentSalt::Plain` | Binds the body |
| 16 bytes or more (`MIN_SALT_SIZE`) | `CommitmentSalt::Hiding` | Binds and hides the body |
| 1 to 15 bytes | Refused | `TightBeamError::InvalidSaltLength`, which `build` returns |

`Opening` holds the opening `(salt, DER(message))`:

- `Opening::prove::<D, M>(&message, salt)` returns the commitment and its opening.
- `Opening::verify::<D>(&commitment)` compares the digests in constant time, and returns `false` for another algorithm.

A receiver checks MI on the frame:

| Method | Returns |
| --- | --- |
| `message_commitment_verdict::<D>(&opening)` | An `IntegrityVerdict` |
| `verify_message_commitment::<D>(&opening)` | `true` for `IntegrityVerdict::Verified` alone |
| `verify_commitment_of::<D, M>(&message, salt)` | The same `bool`, for an opening it proves again from a decoded message |

`IntegrityVerdict` (`tightbeam::core`) is `Verified`, `Absent`, `AlgorithmMismatch`, or `Mismatch`, so a caller can tell a stripped commitment from a tampered one.

```rust
use tightbeam::crypto::commitment::Opening;
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::testing::TestMessage;
use tightbeam::TightBeamError;

let message = TestMessage::sample(None);
let (commitment, opening) = Opening::prove::<Sha3_256, _>(&message, [0x5a; 16])?;
assert!(opening.verify::<Sha3_256>(&commitment)?);

let short = Opening::prove::<Sha3_256, _>(&message, [0x5a; 8]);
assert!(matches!(short, Err(TightBeamError::InvalidSaltLength(_))));
# Ok::<(), TightBeamError>(())
```

### Frame integrity

[README §5.7.3](../README.md#573-integrity-semantics-order-of-operations) states the coverage of FI.

`with_witness_hasher::<D>()` sets FI: the digest under `D` of `SEQUENCE { version, metadata }`. The builder and the verifier encode one borrowed view of those two fields, so the preimage is the same on both sides. `frame_integrity_verdict::<D>()` returns an `IntegrityVerdict`, and `verify_frame_integrity::<D>()` returns `true` for `Verified` alone. FI covers `confidentiality` and `compactness`, so a receiver verifies it before an open rewrites them.

### Confidentiality

[README §5.7.3](../README.md#573-integrity-semantics-order-of-operations) states the AEAD rules.

`with_encryptor::<C, E>(encryptor)` seals the body:

- `C: AssociatedOid` names the content-encryption algorithm, `E: Encryptor<C>` seals as an `AuthEnvelopedData` under `C`, and `T: CheckAeadOid<C>` admits `C` for the message. The compiler checks all three.
- The build moves the ciphertext out of the envelope into `Frame.message`, and stores the envelope in `Metadata.confidentiality` (RFC 5652 §6.1).

The frame opens and seals in place through these methods:

| Method | Effect | Errors |
| --- | --- | --- |
| `decrypt_in_place(&decryptor, inflator)` | Opens the body, inflates it when compressed, clears `confidentiality` and `compactness`, returns `Opened` | `MissingEncryptionInfo`, `MissingInflator`, and the errors of the decryptor and the inflator |
| `decrypt::<T>(decryptor, inflator)` | Runs `decrypt_in_place` on the frame it takes, then decodes `T` | Those of `decrypt_in_place`, and `SerializationError` |
| `decrypt_bytes(decryptor)` | Takes the frame and returns the plaintext as a `SecretSlice<u8>`, still compressed when the body was | `MissingEncryptionInfo`, and the errors of the decryptor |
| `encrypt_with_provider::<P>(&provider)` | Seals the body under a key-encryption key an `EncryptingKeyProvider` holds | `UnsupportedVersion`, `CoveredBeforeSeal`, `EnvelopeError` |
| `decrypt_with_provider::<P>(&provider)` | Opens a body sealed to a provider, clears `confidentiality`, returns `Opened` | `MissingEncryptionInfo`, `EnvelopeError` |

All five are async. The in-place methods leave the frame unchanged on error. `encrypt_with_provider` refuses a frame that already carries FI or a signature, since both would cover the body before the seal.

### Previous frame chaining

[README §5.7.4](../README.md#574-previous-frame-chaining) states what the chain proves.

- `with_previous_hash(DigestInfo)`, the `previous_frame` key, sets `Metadata.previousFrame` from V2 on.
- `Frame::compute_hash::<D>()` returns the `DigestInfo` under `D` of the DER of the whole frame, signature included.
- The application walks the chain and verifies each link.

```rust
use tightbeam::compose;
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::testing::TestMessage;

let parent = compose! { V2: id: "step-1", order: 1u64, message: TestMessage::sample(None) }?;
let link = parent.compute_hash::<Sha3_256>()?;
let child = compose! {
    V2: id: "step-2",
        order: 2u64,
        message: TestMessage::sample(None),
        previous_frame: link
}?;

assert_eq!(child.metadata().previous_frame(), Some(&parent.compute_hash::<Sha3_256>()?));
# Ok::<(), tightbeam::TightBeamError>(())
```

### Nonrepudiation

[README §5.7.5](../README.md#575-nonrepudiation-coverage-and-binding) states the coverage and the value of each `SignerInfo` field.

`Frame::to_tbs()` returns the bytes the signature covers: the DER of the frame with `nonrepudiation` absent, from a view that borrows the first four fields. A frame takes its signature through one of three paths:

| Path | Key |
| --- | --- |
| `with_signer::<S, X>(CertifiedKey<X>)`, the `nonrepudiation<S, _>` key | An `X: PrehashSigner<S>` beside its certificate, which signs as the last stage of `build` |
| `Frame::sign_with_provider(&SigningIdentity)` | A key provider, such as an HSM or a KMS |
| `Frame::signing_draft::<S>(&Certificate)`, then `SignerInfoDraft::complete` and `Frame::attach_signer_info` | An external backend that signs `SignerInfoDraft::prehash` |

`CertifiedKey::new` admits the certificate for signing, refuses a key whose public half differs from it, and reads the `sid` from it ([README §7.3](../README.md#73-cryptographic-key-management)). Each path brings the signature value to its canonical form through `CanonicalForm` before it attaches it.

A receiver verifies through one of two methods:

| Method | Signer certificate | Algorithms |
| --- | --- | --- |
| `Frame::verify::<P>(&PeerCertificate<Signing<P>>)` | Admitted for signing under the provider `P` | The signature algorithm of `P` and the digest it names |
| `Frame::verify_under(&PeerCertificate<ErasedSigning>, &dyn VerificationPolicy)` | Admitted for signing, as a trust store resolves it | Those the policy admits |

`verify` checks that the `sid` names the signer, then that the signed attributes match the TBS, then that the signature verifies over the attributes (RFC 5652 §5.4). Both methods return a `VerifiedSignature`, the signature in canonical form, which every replay ledger keys on. Their errors:

| Error | `verify` | `verify_under` | Cause |
| --- | --- | --- | --- |
| `MissingSignature` | Yes | Yes | The frame carries no signature |
| `SerializationError` | Yes | Yes | The TBS or a signed attribute fails to encode |
| `UnexpectedAlgorithm` | Yes | | The `SignerInfo` names another algorithm or digest than `P` |
| `SignatureError` | Yes | | The signature is no value of `P`, or fails to verify |
| `CertificateValidationError` | Yes | Yes | The key identifier fails to decode, or the policy refuses an algorithm, the key, or the signature |
| `Signer` | Yes | Yes | The `sid`, the version, or the signed attributes break a CMS rule |

### Security property chain

[README §5.7.6](../README.md#576-security-property-chain) states the order of operations.

`FrameBuilder::build` runs the sender steps in that order:

| Step | Stage of `build` | Set by |
| --- | --- | --- |
| 0 | Return a recorded error, then check the version and the markers | |
| 1 | Encode the message as DER and commit to it (MI) | `with_message_hasher` |
| 2 | Compress the DER | `with_compression` |
| 3 | Encrypt, and move the ciphertext into `Frame.message` | `with_encryptor` |
| 4 | Digest `SEQUENCE { version, metadata }` (FI) | `with_witness_hasher` |
| 5 | Sign the TBS | `with_signer` |

A receiver runs the receiver steps through these calls:

| Step | Call |
| --- | --- |
| 1 | `Frame::verify` or `Frame::verify_under` |
| 2 | `Frame::verify_frame_integrity` |
| 3, 4 | `Frame::decrypt_in_place`, which also inflates |
| 5 | `Frame::verify_commitment_of` |

```rust
use tightbeam::compose;
use tightbeam::compress::ZstdCompression;
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::sign::ecdsa::Secp256k1Signature;
use tightbeam::crypto::x509::{KeyPurposes, PeerCertificate, Signing};
use tightbeam::testing::{TestCertificate, TestIdentity, TestKey, TestMessage};

# let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
# runtime.block_on(async {
let message = TestMessage::sample(None);
let salt = [0x5a; 16];
let (_, sealer) = TestKey::insecure_fixed_cipher();
let signer = TestIdentity::certified(TestKey::insecure_fixed_signing());

// The sender: the build runs steps 1 to 5.
let mut frame = compose! {
    V1: id: "chain-1",
        order: 1u64,
        message: message.clone(),
        message_integrity<Sha3_256>: salt,
        compactness: ZstdCompression::default(),
        confidentiality: sealer,
        frame_integrity: type Sha3_256,
        nonrepudiation<Secp256k1Signature, _>: signer
}?;

// The receiver: the signature and FI, then the open, then MI.
let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
let peer = PeerCertificate::<Signing<DefaultCryptoProvider>>::parse(certificate, KeyPurposes::HOUSE.signer)?;
let _replay_key = frame.verify(&peer)?;
assert!(frame.verify_frame_integrity::<Sha3_256>()?);

let (_, opener) = TestKey::insecure_fixed_cipher();
let opened = frame.decrypt_in_place(&opener, Some(&ZstdCompression::default())).await?;
assert!(opened.nonrepudiation().is_some());
assert!(frame.verify_commitment_of::<Sha3_256, _>(&message, salt)?);
# Ok::<(), tightbeam::TightBeamError>(())
# })?;
# Ok::<(), Box<dyn core::error::Error>>(())
```

## Matrix

[README §5.8](../README.md#58-what-is-the-matrix) defines the matrix and its rules.

`MatrixDyn` (`tightbeam::matrix`, also in the prelude) is the wire type of `Metadata.matrix`. Its fields are private, and each way in builds exactly `n * n` cells:

| Way in | Builds | Refuses |
| --- | --- | --- |
| `MatrixDyn::try_from(n: u8)` | An `n` x `n` grid of zeros | `n = 0`, with `MatrixError::InvalidN` |
| `MatrixDyn::from_row_major(n, bytes)` | The grid of `n * n` row-major bytes | `n = 0` or another length, with `None` |
| `MatrixDyn::default()` | The 1 x 1 grid of zero | |
| `MatrixDyn::try_from(Matrix<N>)`, or a `&Matrix<N>` | The `N` x `N` cells of the matrix, row by row | `N` outside `1..=255`, at compile time |
| The DER decoder | The grid on the wire | A `data` length other than `n * n`, with a `der` length error |

`MatrixDyn` lends its cells through `as_bytes`, `as_bytes_mut`, and `row(r)`, and zeroizes on drop with the `zeroize` feature.

`MatrixLike` is the interface of every grid: `n()`, `get(r, c)`, `set(r, c, value)`, `fill(value)`, and `clear()`. A `get` out of bounds returns 0, and a `set` out of bounds leaves the grid unchanged.

| Type | Dimension | Cells |
| --- | --- | --- |
| `MatrixDyn` | At run time, `1..=255` | Every cell |
| `Matrix<N>` | At compile time, and `N` outside `1..=255` fails to compile | Every cell |
| `flags::Flags<N>` | At compile time, as `Matrix<N>` | The diagonal: an off-diagonal cell reads 0 and drops a write |
| A `flagset!` type | The number of flag types it registers | One diagonal cell for each flag type |

`with_matrix` takes any `IntoMatrixDyn`: a `MatrixDyn`, a `Matrix<N>`, a `Flags<N>`, or a `flagset!` type. A conversion error becomes `TightBeamError::MatrixError` at `build`. `MatrixError` has three variants:

| Variant | Cause |
| --- | --- |
| `InvalidN(n)` | `MatrixDyn::try_from(0)` |
| `LengthMismatch { n, len }` | `Matrix::<N>::try_from(&[u8])` with other than `N * N` bytes |
| `DimensionMismatch { expected, n }` | A `flagset!` type read from a `MatrixDyn` of another size |

```rust
use tightbeam::flags::Flags;
use tightbeam::prelude::{Matrix, MatrixDyn, MatrixLike};

let grid = MatrixDyn::from_row_major(2, vec![1, 0, 0, 2]).expect("four cells fill a 2 x 2 grid");
assert_eq!(grid.get(1, 1), 2);
assert_eq!(grid.get(5, 5), 0);
assert!(MatrixDyn::from_row_major(2, vec![0; 3]).is_none());

let mut fixed = Matrix::<2>::default();
fixed.set(1, 0, 4);
let carried = MatrixDyn::try_from(fixed)?;
assert_eq!(carried.as_bytes(), &[0, 0, 4, 0]);

let flags = Flags::<3>::from([1u8, 1, 0]);
let diagonal = MatrixDyn::try_from(flags)?;
assert_eq!(diagonal.as_bytes(), &[1, 0, 0, 0, 1, 0, 0, 0, 0]);
# Ok::<(), tightbeam::TightBeamError>(())
```

## Sources

- ITU-T X.690, ASN.1 encoding rules, § 8.9.2 and § 11.6: <https://www.itu.int/rec/T-REC-X.690>
- RFC 5652, Cryptographic Message Syntax, § 5.4 and § 6.1: <https://datatracker.ietf.org/doc/html/rfc5652>
- RFC 5083, CMS Authenticated-Enveloped-Data Content Type, § 2.1: <https://datatracker.ietf.org/doc/html/rfc5083>
- RFC 3274, Compressed Data Content Type for CMS: <https://datatracker.ietf.org/doc/html/rfc3274>
- CWE-409, Improper Handling of Highly Compressed Data: <https://cwe.mitre.org/data/definitions/409.html>
- CWE-532, Insertion of Sensitive Information into Log File: <https://cwe.mitre.org/data/definitions/532.html>
