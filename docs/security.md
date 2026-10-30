# Security Profiles, Providers, and Keys

This page specifies the types that carry the tightbeam security model and its key management:

- the security profile traits and the provider roles that run them
- the requirement constants of a message type, and how the Frame builder enforces them
- the crypto provider trait and its strength floor
- the key material, the trust store, and the two kinds of identity

It drills down from [README §6](../README.md#6-security-model) and [README §7.3](../README.md#73-cryptographic-key-management) for engineers who implement a profile or a provider, provision the keys of an endpoint, or review how the crate enforces each rule. The README states what each part is, why it is shaped this way, and the standards it follows.

## Contents

- [Security profiles](#security-profiles)
- [Profile types](#profile-types)
- [Numeric security levels](#numeric-security-levels)
- [Message requirements](#message-requirements)
- [Crypto providers](#crypto-providers)
- [Key management](#key-management)
- [Sources](#sources)

## Security profiles

This section drills down from [README §6.1](../README.md#61-securityprofile-trait-architecture).

`SecurityProfile` declares six associated types, and each names its algorithm by an OID. The feature of each algorithm gates its type:

| Associated type | Bound                          | Feature     | Names                       |
| --------------- | ------------------------------ | ----------- | --------------------------- |
| `Digest`        | `AssociatedOid`                | `digest`    | The digest                  |
| `AeadOid`       | `AssociatedOid`                | `aead`      | The AEAD cipher             |
| `SignatureAlg`  | `SignatureAlgorithmIdentifier` | `signature` | The signature algorithm     |
| `Kdf`           | `AssociatedOid`                | `kdf`       | The key derivation function |
| `KeyExchange`   | `AssociatedOid`                | `ecdh`      | The key exchange            |
| `KeyWrapOid`    | `AssociatedOid`                | `aead`      | The key wrap                |

The trait holds identifiers alone. A [crypto provider](#crypto-providers) runs the algorithms.

### Provider roles

Each cryptographic role is a trait of its own, so a component bounds on the roles it uses, such as `SigningProvider + DigestProvider`:

| Role         | Trait                 | Associated types            | Feature     | Provided methods                                |
| ------------ | --------------------- | --------------------------- | ----------- | ----------------------------------------------- |
| Digest       | `DigestProvider`      | `Digest`                    | `digest`    | `to_digest_algorithm_identifier`, `as_digestor` |
| AEAD         | `AeadProvider`        | `AeadCipher`                | `aead`      | `to_aead_algorithm_identifier`                  |
| Key wrap     | `KeyWrapProvider`     | `KeyWrap`                   | `aead`      |                                                 |
| Signature    | `SigningProvider`     | `Signature`, `VerifyingKey` | `signature` | `to_signature_algorithm_identifier`             |
| KDF          | `KdfProvider`         | `Kdf`                       | `kdf`       |                                                 |
| Key exchange | `KeyExchangeProvider` | `KeyExchange`               | `ecdh`      |                                                 |

`CryptoProvider` composes the six. The KEM of a provider is its associated type `CryptoProvider::Kem`, a `RecipientKem`.

`KemProvider`, under the `kem` feature, is the role of a KEM of the RustCrypto `kem` traits, which `tightbeam::crypto::kem` re-exports:

| Associated type    | Bound                                       | Names                                                        |
| ------------------ | ------------------------------------------- | ------------------------------------------------------------ |
| `EncappedKey`      | `EncappedKey`                               | The encapsulated key, the recipient key, and the secret size |
| `Kem`              | `Encapsulator<EncappedKey> + Default`       | The encapsulation, which binds no sender key                 |
| `DecapsulationKey` | `Decapsulator<EncappedKey>`                 | The private key of a recipient                               |

- `ProviderKem<P>` is a `RecipientKem` that runs the role of `P`, so a provider that names `ProviderKem<Self>` as its `CryptoProvider::Kem` seals and opens every `KEMRecipientInfo` under the role. The `kem` field names the `AssociatedOid` of `Kem`, a recipient certificate asserts `keyEncipherment` (RFC 9629 §3), and `DecapsulationKey` is a `KeyBackend`.
- `DefaultCryptoProvider` implements the role with DHKEM(secp256k1, HKDF-SHA256): `DhKemSecp256k1Enc`, `DhKemSecp256k1`, and `Secp256k1KeyProvider`. The vectors B.1.1 and B.2.1 of draft-wahby-cfrg-hpke-kem-secp256k1-01 run through the role and through `ProviderKem`.

### Negotiated form

Peers negotiate a `SecurityProfileDesc`: the six OIDs of a profile, which `From<&P>` builds from any `SecurityProfile`.

- Each field is an `Option<ObjectIdentifier>`. `None` marks an algorithm whose feature the build of the sender disables.
- The fields `digest`, `aead`, `signature`, `kdf`, `key_exchange`, and `key_wrap` carry the context tags `[0]` to `[5]`, so each OID decodes into its own field when an earlier one is absent.

## Profile types

This section drills down from [README §6.2](../README.md#62-security-profile-types).

`TightbeamProfile` is the profile of the reference provider, a unit struct with `Debug`, `Default`, `Clone`, and `Copy`. Its types are the ones a custom profile names to run the house algorithms:

| Associated type | Type                 | Path                                                        |
| --------------- | -------------------- | ----------------------------------------------------------- |
| `Digest`        | `Sha3_256`           | `tightbeam::crypto::hash`                                   |
| `AeadOid`       | `Aes256GcmOid`       | `tightbeam::crypto::aead`                                   |
| `SignatureAlg`  | `Secp256k1Signature` | `tightbeam::crypto::sign::ecdsa`                            |
| `Kdf`           | `HkdfSha3_256`       | `tightbeam::crypto::kdf`                                    |
| `KeyExchange`   | `Ecdhe<Secp256k1>`   | `tightbeam::crypto::exchange` and `tightbeam::crypto::k256` |
| `KeyWrapOid`    | `Aes256Wrap`         | `tightbeam::crypto::profiles`                               |

- The crate also names `Aes128GcmOid`, `Aes128Wrap`, and `Aes192Wrap`, for a profile on a shorter key.
- A profile that a message type names needs `SecurityProfile` alone. A profile that a provider runs also needs `Default`.

## Numeric security levels

This section drills down from [README §6.3](../README.md#63-numeric-security-levels).

`#[derive(Beamable)]` maps `#[beam(profile = N)]` to requirement constants:

| `N` | Level    | `MUST_BE_CONFIDENTIAL` | `MUST_BE_NON_REPUDIABLE` | `MIN_VERSION` |
| --- | -------- | ---------------------- | ------------------------ | ------------- |
| 1   | FIPS     | `true`                 | `true`                   | `V1`          |
| 2   | Standard | `true`                 | `true`                   | `V1`          |

- `HAS_PROFILE` stays `false`, and `Profile` is `TightbeamProfile`, so the builder compares no OID.
- `MIN_VERSION` is the higher of `V1` and a `min_version` attribute on the same type.
- The derive refuses any other `N`, and `profile = N` beside `profile(Type)`, at compile time.

## Message requirements

This section drills down from [README §6.4](../README.md#64-message-level-security-requirements).

The `Message` trait holds the requirements of a message type as constants, and `#[derive(Beamable)]` sets each from one `#[beam(...)]` attribute:

| Constant                      | Default       | Attribute            | Feature     | The Frame then carries         | Builder call                                   |
| ----------------------------- | ------------- | -------------------- | ----------- | ------------------------------ | ---------------------------------------------- |
| `MIN_VERSION`                 | `Version::V0` | `min_version = "V1"` |             | A `Frame.version` at or above it | The version of `Version::compose` or `FrameBuilder::from` |
| `MUST_BE_NON_REPUDIABLE`      | `false`       | `nonrepudiable`      | `signature` | `nonrepudiation`               | `with_signer`                                  |
| `MUST_BE_CONFIDENTIAL`        | `false`       | `confidential`       | `aead`      | `Metadata.confidentiality`     | `with_encryptor`                               |
| `MUST_BE_COMPRESSED`          | `false`       | `compressed`         | `compress`  | `Metadata.compactness`         | `with_compression`                             |
| `MUST_BE_PRIORITIZED`         | `false`       | `prioritized`        |             | `Metadata.priority`            | `with_priority`                                |
| `MUST_HAVE_MESSAGE_INTEGRITY` | `false`       | `message_integrity`  | `digest`    | `Metadata.integrity`           | `with_message_hasher`                          |
| `MUST_HAVE_FRAME_INTEGRITY`   | `false`       | `frame_integrity`    | `digest`    | `Frame.integrity`              | `with_witness_hasher`                          |
| `HAS_PROFILE`                 | `false`       | `profile(Type)`      |             |                                |                                                |

- The associated type `Profile: SecurityProfile`, under the `crypto` feature, is the type that `profile(Type)` names. The derive sets it to `TightbeamProfile` for a type that names none. A hand-written impl names it.
- The derive fails to compile a type whose attribute needs a feature that the build disables, and the error names the feature.

### Typed profiles

`profile(Type)` sets `HAS_PROFILE` and `Profile`. The builder checks the algorithms a Frame carries, at compile time and at run time:

| Builder call                                         | Algorithm | Compile-time bound       | Run-time comparison                                   |
| ---------------------------------------------------- | --------- | ------------------------ | ----------------------------------------------------- |
| `with_message_hasher::<D>`, `with_witness_hasher::<D>` | Digest    | `T: CheckDigestOid<D>`    | `D::OID` with `Profile::Digest`                       |
| `with_encryptor::<C, _>`                             | AEAD      | `T: CheckAeadOid<C>`      | `C::OID` with `Profile::AeadOid`                      |
| `with_signer::<S, _>`                                | Signature | `T: CheckSignatureOid<S>` | `S::ALGORITHM_OID` with `Profile::SignatureAlg`       |
| `build`                                              | Key wrap  |                          | The wrap of each recipient with `Profile::KeyWrapOid` |

- The derive implements each checker trait for the algorithm of the profile alone, so a mismatched algorithm type fails to compile at the call. For a type with no typed profile, it implements each checker for every algorithm.
- Any type can implement a checker, so the run-time comparison is the enforcement. When `HAS_PROFILE` is `true` and the OIDs differ, the call records `TightBeamError::UnexpectedAlgorithm` with the received and the expected OID, and leaves the builder as it was.
- The encryptor names its AEAD alone, and its envelope names the key wrap of each recipient. `build` holds the built Frame to the profile through `Frame::validate_for`, so a wrap outside it fails the build with `TightBeamError::Requirement(RequirementError::Algorithm)`.
- `compose!` expands to these calls, so it checks the same way.

### Build refusals

`FrameBuilder::build` returns the first refusal in this order:

1. The error a builder call recorded, or `TightBeamError::Sequence` when two or more calls recorded one.
2. `Requirement(RequirementError::Version)`, when the version is below `MIN_VERSION`, the refusal of every typed decode.
3. `MissingProtection { marker, call }`, when a `MUST_*` constant is `true` and its builder call is absent. `marker` names the constant and `call` names the method. The constants are checked in this order: confidential, nonrepudiable, compressed, message integrity, frame integrity, prioritized.
4. `InvalidBody`, when no message is set.
5. `BuildError`, when the metadata fails its validation.
6. `Requirement`, when the built Frame fails a requirement of the message type in `Frame::validate_for`, such as a key wrap outside the profile.

```rust
use tightbeam::der::Sequence;
use tightbeam::{compose, Beamable, TightBeamError};

#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
#[beam(confidential)]
struct Note {
	text: String,
}

// The type requires confidentiality, and the composition names no encryptor.
let built = compose! {
	V1:
		id: "note-1",
		order: 1_696_521_600,
		message: Note { text: "sealed".into() },
};

let refused = matches!(built, Err(TightBeamError::MissingProtection { marker: "MUST_BE_CONFIDENTIAL", call: "with_encryptor" }));
assert!(refused);
```

### Enforcement

This section drills down from [README §7.1.1](../README.md#711-message-security-enforcement). Each stage enforces its part:

| Stage        | Home                                 | What it checks                                                                   |
| ------------ | ------------------------------------ | -------------------------------------------------------------------------------- |
| Compile time | The derive                           | A known numeric level, one profile form, and the feature of each requirement     |
| Compile time | The checker bounds of the builder    | The algorithm types of a typed profile, for a derived type                       |
| Build        | Each builder call                    | The OID of each algorithm, under a typed profile                                 |
| Build        | `FrameBuilder::build`                | The version and every `MUST_*` constant                                          |
| Build        | `FrameBuilder::build`, through `Frame::validate_for` | The built Frame, against every requirement, and the key wrap of each recipient under a typed profile |
| Decode       | The Frame decoder                    | The fields each version admits ([README §5.6](../README.md#56-version-specific-constraints)) |
| Typed decode | `Frame::validate_for`                | The Frame as it arrived: its version, the field of every `MUST_*` constant, and each algorithm under a typed profile |

Each typed decode calls `Frame::validate_for` before a decrypt or an inflate takes a protection out of the Frame, and a refusal is a `RequirementError`:

- `CleartextFrame::decode` of the router, on the shape that `CleartextFrame::admit`, `CleartextFrame::decrypt`, or `CleartextFrame::inflate` took before the open. The router returns `RouterError::Requirement`.
- `Frame::decode_message::<T>`, on a borrowed Frame that arrived in cleartext, in every build. It refuses an encrypted or a compressed body with `TightBeamError::OpaqueBody`, and a Frame that fails a requirement with `TightBeamError::Requirement`. Every decode of a colony protocol type, such as a `ClusterRequest` at the gateway or a `ClusterCommand` at the hive, runs it.
- `Frame::decrypt::<T>`, before its decrypt in place. It returns `TightBeamError::Requirement`.
- The typed delivery of a servlet, `Frame::open_typed`, before `Frame::prepare_typed`. `Frame::dispatch_typed_unary` and the `handle: |msg, frame, ctx|` arm of `servlet!` decode through it. It returns `TightBeamError::Requirement`.
- `ExpectedMatcher` of the `testing` feature, when a test matches a typed value against a Frame. It decodes through `Frame::decode_message::<T>`, and a refused Frame matches no value.

## Crypto providers

This section drills down from [README §6.5](../README.md#65-crypto-provider-system).

### The CryptoProvider trait

`CryptoProvider` composes the six role traits, under the features `digest`, `aead`, `signature`, `kdf`, and `ecdh`:

| Item                                    | Kind                            | Rule                                                                                  |
| --------------------------------------- | ------------------------------- | ------------------------------------------------------------------------------------- |
| `Default + Copy`                        | Supertraits                     | Every layer makes and copies the provider as a value                                  |
| The six role traits                     | Supertraits                     | Each binds the type of one role                                                       |
| `KeyWrap: KeyWrapAlgorithm<KekSize: IsGreaterOrEqual<AeadKeySize<Self>, Output = B1>>` | Bound on `KeyWrapProvider` | The KEK is at least as long as the AEAD key (RFC 3565 §2.3.2) |
| `type Profile`                          | Associated type                 | A `SecurityProfile + Default` whose six types are the types of the roles             |
| `type Kem`                              | Associated type, under `hpke` and `signature` | A `RecipientKem`                                                       |
| `fn profile(&self) -> &Self::Profile`   | Method                          | The profile the provider runs                                                         |
| `fn strength_floor()`                   | Provided function               | The floor of [Strength floor](#strength-floor)                                        |

`Profile` binds each of its types to the type of one role, so a provider whose role runs another algorithm than its profile names fails to compile:

| `Profile` type | Equals                                     |
| -------------- | ------------------------------------------ |
| `Digest`       | `Self::Digest`                             |
| `AeadOid`      | `<Self::AeadCipher as AeadAlgorithm>::Oid` |
| `SignatureAlg` | `Self::Signature`                          |
| `Kdf`          | `Self::Kdf`                                |
| `KeyExchange`  | `Self::KeyExchange`                        |
| `KeyWrapOid`   | `<Self::KeyWrap as KeyWrapAlgorithm>::Oid` |

`AeadKeySize<P>` is the key size of the AEAD cipher of `P`, as a `typenum` number. The compile-fail tests `tests/compile/provider_profile_mismatch.rs` and `tests/compile/provider_kek_size_mismatch.rs` hold both bounds.

### Role types

An implementor brings its own algorithm as a type that implements the trait of its role:

| Role          | Associated type                    | The type implements                                                           | House type              |
| ------------- | ---------------------------------- | ----------------------------------------------------------------------------- | ----------------------- |
| Digest        | `DigestProvider::Digest`           | `Digest`, `AssociatedOid`, `BlockSizeUser`, and `CoreProxy` over a `HashCore` | `Sha3_256`              |
| AEAD          | `AeadProvider::AeadCipher`         | `AeadAlgorithm`, and `ContentEncryption` to seal an envelope                  | `Aes256Gcm`             |
| Key wrap      | `KeyWrapProvider::KeyWrap`         | `KeyWrapAlgorithm`                                                            | `Aes256Wrap`            |
| Signature     | `SigningProvider::Signature`       | `SignatureEncoding`, `SignatureAlgorithmIdentifier`, and `CanonicalForm`      | `Secp256k1Signature`    |
| Verifying key | `SigningProvider::VerifyingKey`    | `PrehashVerifier` of the signature                                            | `Secp256k1VerifyingKey` |
| KDF           | `KdfProvider::Kdf`                 | `KdfFunction` and `AssociatedOid`                                             | `HkdfSha3_256`          |
| Key exchange  | `KeyExchangeProvider::KeyExchange` | `KeyExchange`, whose `Offer` and `Reply` are each a `KeyShare` of it          | `Ecdhe<Secp256k1>`      |
| KEM           | `CryptoProvider::Kem`              | `RecipientKem`                                                                | `DhKemSecp256k1`        |

The digest, the cipher, the signature, and the verifying key are also `Send + Sync`, and the digest is also `Clone + Default`. Each role type keeps the contract of its trait:

- **Digest.** The `HashCore` wipes its state on drop, because an HMAC over the core holds the key XOR `ipad` in that state (RFC 2104 §2).
- **AEAD.** `AeadAlgorithm::Oid` names the identifier, and `KeySizeUser` the key length. `ContentEncryption` adds the parameters of a seal under a nonce, and reads the nonce back from them.
- **Key wrap.** `KeyWrapAlgorithm` names `Oid` and `KekSize`, and runs `wrap`, `unwrap`, and `unwrap_into` under a `Kek` of that size (RFC 3394).
- **Signature.** The signature parses its own encoding alone and names its canonical form: for ECDSA, the DER `ECDSA-Sig-Value` with a low `s`.
- **KDF.** `KdfFunction::derive_dynamic_key` takes a key size at run time, and wipes the pseudorandom key, each chained output block, and each buffered input when it ends (NIST SP 800-56C Rev. 2 §5.1).
- **Key exchange.** `KeyExchange` runs the ephemeral exchange of a handshake and of each rekey in the shape of a KEM: `offer`, `respond`, and `complete` (RFC 9180 §4.1). It reads the static keys a share must differ from, and rates its own strength. `Ecdhe<C>` runs ECDH over any `HandshakeCurve`, such as secp256k1, P-256, P-384, and P-521, and its secret is the x-coordinate, as wide as the field (SEC 1 v2.0 §3.3.1). [The handshake](handshake.md#key-exchange) states the contract of an exchange and the carriers of its shares.
- **KEM.** `RecipientKem` names its `OID`, the `keyUsage` bit `USAGE` of its certificate, its `PublicKey`, and its `PrivateKey`, a `KeyBackend`. It runs `encapsulate` and `decapsulate` (RFC 9180 §4). A DHKEM names `DiffieHellman` as its private key.

### The reference provider

`DefaultCryptoProvider` runs `TightbeamProfile` and keeps the default floor. Its role types are the house types of [Role types](#role-types), and `Secp256k1Policy`, the alias of `ProviderPolicy<DefaultCryptoProvider>`, verifies its signatures.

### The handshake and the transport

The layers above the envelope take the provider as a type parameter:

- **Handshake.** `HandshakeProvider` is the one bound of the handshake layer. It is a `CryptoProvider` whose cipher is `KeyInit + ContentEncryption`, whose signature parses from its bytes, and whose verifying key parses from an SPKI. The key exchange is a role of its own, so a provider may sign under one algorithm and exchange keys under another. Every provider that meets the bounds is a handshake provider, and it runs both flows with no HPKE suite.
- **Transport.** `TokioListener<P>` and `TcpListener<L, P>` take `DefaultCryptoProvider` as the default of `P`. A call names `P` when no other type in the call names it, such as `TokioListener::<DefaultCryptoProvider>::bind_cleartext(addr)`, `TcpListener::<_, DefaultCryptoProvider>::from_listener_cleartext(listener)`, or `TransportEncryptionConfig::<DefaultCryptoProvider>::new(identity)`.
- **Signatures.** `SigningIdentity::with_provider::<P>` signs under the signature of `P`, and `ProviderPolicy::<P>` verifies it.

### Strength floor

Each handshake endpoint holds its profile to the floor of its provider. [The handshake](handshake.md#rules-of-both-flows) states where each side applies it.

| Item                             | Kind                  | Rule                                                                                                        |
| -------------------------------- | --------------------- | ----------------------------------------------------------------------------------------------------------- |
| `ProfileStrengthPolicy`          | Trait                 | `meets_floor(&ProfileStrength) -> bool`                                                                     |
| `ProfileStrength`                | Struct                | `descriptor`, `aead_key_bytes`, `digest_bytes`, and `key_exchange`, read from the types of the provider     |
| `SecurityStrength`               | Struct                | A strength in bits, one constant for each row of NIST SP 800-57 Part 1 Rev. 5 Table 2                       |
| `DefaultStrengthFloor`           | Policy                | The AEAD key and the digest output are 32 bytes or more, and the key exchange rates 128 bits or more        |
| `NoStrengthFloor`                | Policy                | Admits every profile                                                                                        |
| `CryptoProvider::strength_floor` | Provided function     | `DefaultStrengthFloor`, unless the provider names another policy                                            |
| `RunnableProfile::<P>::strength` | Method                | The strength of a profile that `P` runs                                                                     |
| `NegotiationError::BelowStrengthFloor` | Error           | No runnable profile meets the floor, or the selection of the server is below it                             |

A provider whose profile falls below `DefaultStrengthFloor` names `NoStrengthFloor`, and so does a downgrade-attack test. Any other provider SHOULD keep `DefaultStrengthFloor` (CWE-757).

### Run a provider below the default floor

A provider on AES-128-GCM pairs it with AES-128 key wrap, whose KEK is as long as the AEAD key, and names a floor that admits its profile:

```rust
use tightbeam::crypto::aead::{Aes128Gcm, Aes128GcmOid};
use tightbeam::crypto::exchange::Ecdhe;
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::hpke::DhKemSecp256k1;
use tightbeam::crypto::k256::Secp256k1;
use tightbeam::crypto::kdf::HkdfSha3_256;
use tightbeam::crypto::profiles::{AeadProvider, Aes128Wrap, CryptoProvider, DefaultStrengthFloor};
use tightbeam::crypto::profiles::{DigestProvider, KdfProvider, KeyExchangeProvider, KeyWrapProvider, NoStrengthFloor};
use tightbeam::crypto::profiles::{ProfileStrengthPolicy, SecurityProfile, SigningProvider};
use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1VerifyingKey};
use tightbeam::transport::handshake::negotiation::RunnableProfile;
use tightbeam::transport::handshake::HandshakeProvider;

#[derive(Debug, Default, Clone, Copy)]
struct Aes128Profile;

impl SecurityProfile for Aes128Profile {
	type Digest = Sha3_256;
	type AeadOid = Aes128GcmOid;
	type SignatureAlg = Secp256k1Signature;
	type Kdf = HkdfSha3_256;
	type KeyExchange = Ecdhe<Secp256k1>;
	type KeyWrapOid = Aes128Wrap;
}

#[derive(Debug, Default, Clone, Copy)]
struct Aes128Provider {
	profile: Aes128Profile,
}

impl DigestProvider for Aes128Provider {
	type Digest = Sha3_256;
}

impl AeadProvider for Aes128Provider {
	type AeadCipher = Aes128Gcm;
}

impl KeyWrapProvider for Aes128Provider {
	type KeyWrap = Aes128Wrap;
}

impl SigningProvider for Aes128Provider {
	type Signature = Secp256k1Signature;
	type VerifyingKey = Secp256k1VerifyingKey;
}

impl KdfProvider for Aes128Provider {
	type Kdf = HkdfSha3_256;
}

impl KeyExchangeProvider for Aes128Provider {
	type KeyExchange = Ecdhe<Secp256k1>;
}

impl CryptoProvider for Aes128Provider {
	type Profile = Aes128Profile;
	type Kem = DhKemSecp256k1;

	fn profile(&self) -> &Self::Profile {
		&self.profile
	}

	// A 128-bit AEAD key falls below the default floor.
	fn strength_floor() -> &'static (dyn ProfileStrengthPolicy + Send + Sync) {
		&NoStrengthFloor
	}
}

fn runs_a_handshake<P: HandshakeProvider>() {}
runs_a_handshake::<Aes128Provider>();

let strength = RunnableProfile::<Aes128Provider>::native().strength();
assert_eq!(strength.aead_key_bytes, 16);
assert!(!DefaultStrengthFloor.meets_floor(&strength));
assert!(Aes128Provider::strength_floor().meets_floor(&strength));
```

## Key management

This section drills down from [README §7.3](../README.md#73-cryptographic-key-management).

### Key material

An endpoint takes its certificate and its signing key in one of these forms:

| Type             | Variants                                                            | Becomes                                                                                       |
| ---------------- | ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `CertificateSpec` | `Pem(&'static str)`, `Der(&'static [u8])`, `Built(Box<Certificate>)` | A `Certificate` through `TryFrom`, which trims each PEM line first                            |
| `SigningKeySpec`  | `Bytes(&'static [u8])`, `Provider(Arc<dyn SigningKeyProvider>)`      | A key backend through `to_provider::<C>()`: an `EcdsaKeyProvider<C>` from the bytes, or the held handle |

- The `'static` forms suit a `const` item or a macro such as `servlet!`.
- `to_provider` refuses bytes of another length than the field of `C` (`KeyError::KeyLengthError`), and bytes that are no key of `C` (`KeyError::SignatureError`).
- The `Debug` of `SigningKeySpec::Bytes` prints the byte length alone (CWE-532).

A private key stays behind a backend, so a Hardware Security Module, a Key Management Service, or an enclave can hold it:

| Backend trait           | Operation                                                                 | House implementation                     |
| ----------------------- | ------------------------------------------------------------------------- | ---------------------------------------- |
| `KeyBackend`            | `algorithm()` and `to_public_key_bytes()`, the supertrait of `SigningKeyProvider` and `DiffieHellman` | `EcdsaKeyProvider<C>` |
| `SigningKeyProvider`    | `sign_prehash`, async. An ECDSA result MUST be a DER `ECDSA-Sig-Value` with a low `s` | `EcdsaKeyProvider<C>`                    |
| `DiffieHellman<C>`      | `agree`, async, which returns the x-coordinate as a `SecretSlice`         | `EcdsaKeyProvider<C>`, under `ecdh`      |
| `EncryptingKeyProvider` | The wrap and unwrap of a content key under a KEK of a `KEKRecipientInfo` (RFC 5652 §6.2.3) | `InMemoryEncryptingKeyProvider<P>` |

`Secp256k1KeyProvider` is the alias of `EcdsaKeyProvider<Secp256k1>`, and `Aes256GcmKeyProvider` the alias of `InMemoryEncryptingKeyProvider<DefaultCryptoProvider>`.

### Trust stores

[README §7.3](../README.md#trust-stores) states the three rules of every store, and [the handshake](handshake.md#trust-anchors-and-issuers) states which method each flow admits through. `CertificateTrust` extends `CertificateValidation`, whose `evaluate` and `evaluate_presented` validate one certificate:

| Method                         | Answers                                                                         | Default                                     |
| ------------------------------ | ------------------------------------------------------------------------------- | ------------------------------------------- |
| `is_trusted(cert)`             | Whether the store holds `cert`, by fingerprint                                  | Required                                    |
| `trusts_public_key(cert)`      | Whether the store holds a certificate for the key of `cert`                     | Reads `enrolled_certificate`                |
| `enrolled_certificate(cert)`   | The held certificate for the key of `cert`, so a rotated certificate resolves   | Reads `find_by_public_key`                  |
| `find_by_public_key(spki)`     | The held certificate of a key                                                   | Required                                    |
| `find_by_canonical_key(key)`   | The held certificate of a `CanonicalKey`                                        | Decodes the key, then `find_by_public_key`  |
| `verify_chain(chain)`          | The trust anchor of a chain, issuer first, once its path validates              | Required                                    |
| `verify_presented(issuers, leaf)` | The trust anchor of the path a peer presents                                 | Joins the path, then `verify_chain`         |
| `trust_anchor(cert)`           | The trust anchor of the path of `cert` (RFC 5280 §6.1.1 (d))                    | Required                                    |
| `find_by_signer_identifier(sid)` | The certificate admitted for signing that `sid` names                         | Required                                    |
| `find_by_signer_info(info)`    | The same, from the `sid` of a `SignerInfo`                                      | Reads `find_by_signer_identifier`           |
| `to_policy_ref()`              | The verification policy of its signatures                                       | Required                                    |
| `verify_frame(frame)`          | A `TrustVerification` of the signature of the frame                             | Resolves the signer, then `Frame::verify_under` |

Every lookup reads a key by one rule, which [the handshake](handshake.md#key-identity) states whole. `verify_frame` answers with one of four variants, so a caller applies one consequence to each:

| `TrustVerification` | The frame                                                                                 |
| ------------------- | ----------------------------------------------------------------------------------------- |
| `MissingSignature`  | Carries no nonrepudiation signature                                                       |
| `UnknownSigner`     | Names a signer the store holds no certificate for                                         |
| `Invalid`           | Names a signer the store holds, and its signature fails                                   |
| `Verified(certificate, signature)` | Verifies, and the verified signature is the replay key of the frame        |

`CertificateTrustStore` is the built-in store, under `std`. `CertificateTrustBuilder` builds it:

- `CertificateTrustBuilder::new(policy, curves, revocation)` is the one constructor. It takes a `VerificationPolicy`, the `KeyCurves` the store reads each key under, and a `RevocationChecker`.
- `with_key_purposes` sets the purposes the store admits its signers under, `KeyPurposes::HOUSE` by default.
- `with_clock` sets the clock that each validity check of the store reads. The default is the reading of `UnixMillis::now`, the system clock where the host has one.
- `TrustBuilder::with_certificate` and `TrustBuilder::with_chain` add certificates, and `TrustBuilder::build` seals the store.
- The builder indexes each certificate by its SHA3-256 fingerprint, by its `subjectKeyIdentifier` value, and by the canonical form of its key. `build` admits the signers among them under the signer purpose, so a certificate the signer role refuses stays a path certificate and resolves no signer.

The builder refuses a certificate in these cases:

| Error                                       | Cause                                                                      |
| ------------------------------------------- | -------------------------------------------------------------------------- |
| An error of the validity check              | The certificate is outside its validity period on the clock of the store   |
| `CertificateValidationError::EncodingError` | The certificate fails to encode, or a key identifier fails to decode       |
| `CertificateValidationError::DuplicateExtension` | A key identifier extension repeats                                    |
| `CertificateValidationError::SkidCollision` | Another certificate holds the same `subjectKeyIdentifier`                  |
| `CertificateValidationError::PublicKeyCollision` | Another certificate holds the same key                                |
| `CertificateValidationError::EmptyChain`    | `with_chain` takes no certificate                                          |
| `CertificateValidationError::InvalidChain`  | In `with_chain`, an issuer name differs from the subject name before it    |

### Revocation

A `RevocationChecker` checks one certificate beside its issuer, `check(issuer, cert)`. The built-in store consults it in two places:

- Path validation, once per certificate, as the revocation step of RFC 5280 §6.1.3 (a) (3).
- Each lookup, over the held path of the certificate it answers with.

An implementation MUST fail closed, with `CertificateRevoked` for a revoked certificate and `RevocationStatusUnknown` when it cannot establish the status. The crate ships two checkers:

| Checker                   | Revokes                                                                                       |
| ------------------------- | --------------------------------------------------------------------------------------------- |
| `NoRevocation`            | Nothing. A store states this waiver at `CertificateTrustBuilder::new`                         |
| `StaticRevocationList<D>` | Each certificate that `with_fingerprint`, `with_certificate`, or `with_serial(issuer, serial)` names. It needs `std` |

- A fingerprint under `D` revokes one DER encoding. Under a policy that accepts a high ECDSA `s`, a revoked certificate can return with `n - s` in its signature, and the fingerprint misses it (SEC 1 v2.0 §4.1.4).
- An issuer and serial number revoke every encoding of the certificates they name. The list scopes each serial to its issuer, because a serial is unique within one CA alone (RFC 5280 §4.1.2.2).
- A certificate that fails to encode has no status, so the list fails it with `RevocationStatusUnknown`.

```rust
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::x509::error::CertificateValidationError;
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, StaticRevocationList, TrustBuilder};
use tightbeam::crypto::x509::KeyCurves;
use tightbeam::testing::{TestCertificate, TestCertificateChain};

let TestCertificateChain { root, intermediate, leaf, .. } = TestCertificate::insecure_fixed_chain()?;

// The list revokes the leaf by its issuer and serial number.
let issuer = &leaf.tbs_certificate.issuer;
let serial = leaf.tbs_certificate.serial_number.as_bytes();
let revoked = StaticRevocationList::<Sha3_256>::default().with_serial(issuer, serial)?;

let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, revoked);
let store = builder.with_certificate(root)?.with_certificate(intermediate)?.build();
let refused = store.trust_anchor(&leaf);
assert!(matches!(refused, Err(CertificateValidationError::CertificateRevoked)));
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Path validation

Every method of the built-in store that validates a path runs one routine, issuer first, over the whole path ([RFC 5280 §6.1](https://datatracker.ietf.org/doc/html/rfc5280#section-6.1)):

| Check                                                              | RFC 5280             |
| ------------------------------------------------------------------ | -------------------- |
| The validity period                                                | §6.1.3 (a) (2)       |
| A refusal of `nameConstraints`, critical or not                    | §6.1.4 (g)           |
| A refusal of an unprocessed critical extension and of a repeated extension | §4.2, §6.1.3 (f) |
| One signature algorithm in the certificate and its TBS             | §4.1.1.2             |
| Issuer and subject name chaining                                   | §6.1.3 (a) (4)       |
| `basicConstraints.cA` and `keyUsage.keyCertSign` on each issuer    | §6.1.4 (k), (n)      |
| The signature of each certificate                                  | §6.1.3 (a) (1)       |
| Revocation, through the `RevocationChecker`                        | §6.1.3 (a) (3)       |
| `pathLenConstraint`                                                | §6.1.4 (l), (m)      |

The store runs a closed PKI, so the routine is stricter than RFC 5280. The refusal of `nameConstraints`, where §6.1.4 (g) applies them to the names below, is one rule, and these are the others:

- §6.1.4 (k) applies to v1 and v2 issuers too.
- A self-issued intermediate counts against `pathLenConstraint`, because a key rollover reissues the store.
- The trust anchor takes the checks of validity, name constraints, extensions, algorithm, revocation, and path length, and the issuer check when it issues the next certificate.
- Name chaining compares DER bytes, in place of the case-insensitive match of §7.1.
- The terminal certificate of a path of two or more certificates MUST NOT assert `basicConstraints.cA`.

Certificate policies (§6.1.3 to §6.1.5) and the fetch of a CRL or an OCSP response are out of scope. Revocation status comes from the `RevocationChecker` alone.

### Key identifiers

`Skid` is the 20-octet key identifier of RFC 7093 §2 method 1, and `Skid::of_public_key` derives it from a SubjectPublicKeyInfo. The `cert!` macro and the test fixtures give each certificate its own as its `subjectKeyIdentifier`, and an issued one its issuer's as its `authorityKeyIdentifier`.

`find_by_signer_identifier` resolves a `sid` (RFC 5652 §5.3):

- The `subjectKeyIdentifier` form matches the extension value of a held certificate, through the index of the store.
- The `issuerAndSerialNumber` form matches the issuer and the serial number.
- The built-in store answers while each certificate of the path is within its validity period and its `RevocationChecker` admits the path.

### Signing identities

A `SigningIdentity` holds its certificate, admitted for signing, beside an `Arc<dyn SigningKeyProvider>`. Each constructor checks the key against the certificate once:

| Constructor                                 | Signs under                                                    | Takes                                                    |
| ------------------------------------------- | -------------------------------------------------------------- | -------------------------------------------------------- |
| `SigningIdentity::new(certificate, key)`    | `DefaultCryptoProvider`                                        | `impl Into<Arc<Certificate>>` and the key backend        |
| `SigningIdentity::with_provider::<P>(certificate, key)` | `P: SigningProvider`, whose verifying key is `DecodePublicKey + PartialEq` | The same                          |
| `SigningIdentity::from_spec(certificate, key)` | `DefaultCryptoProvider`                                     | A `CertificateSpec` and the key backend                  |
| `CertifiedKey::new(&certificate, key)`      | The key's own signature, in place                              | A `Keypair` whose verifying key is `DecodePublicKey + PartialEq` |

`with_provider` refuses with a `SignerError`:

| Variant                | Cause                                                                                 |
| ---------------------- | ------------------------------------------------------------------------------------- |
| `Certificate`          | The certificate is refused for signing, or its key identifier fails to decode         |
| `UnsupportedAlgorithm` | The key declares another algorithm than `P`, or its public half is no key of `P`      |
| `Key`                  | The backend fails to return its public key                                            |
| `Encoding`             | The `certificates` field or the SubjectPublicKeyInfo fails to encode                  |
| `PublicKey`            | The key of the certificate is no key of `P`                                           |
| `KeyMismatch`          | The public half of the key differs from the key of the certificate                    |

`SigningIdentity::with_chain(intermediates)` sets the issuers it presents, nearest first, in place of an earlier chain. It refuses with `SignerError::Certificate` a chain with any of these faults:

- A certificate does not name the next one as its issuer.
- A self-issued certificate sits below another.
- The chain repeats a subject, or returns to a certificate it holds.
- The chain holds more than `MAX_PRESENTED_PATH` (8) certificates with the certificate of the identity.

The identity encodes its `certificates` field when it is built and when its chain is set, and every handshake message it signs presents that encoding.

The identity signs and answers through these methods:

| Method                     | Returns                                                                             |
| -------------------------- | ----------------------------------------------------------------------------------- |
| `sign(content)`            | A `Signed<SignerInfo>`, async, over a `SignedContent` it takes by value             |
| `draft(content)`           | A `SignerInfoDraft` under the digest of the signature algorithm                     |
| `sign_prehash(prehash)`    | The signature in its canonical form, async                                          |
| `signer_identifier()`      | The `sid` that names the certificate                                                |
| `signing_certificate()`    | The certificate as the signing use admitted it                                      |
| `policy()`                 | The `'static` verification policy of its scheme                                     |
| `certificate()`, `certificate_arc()` | The certificate, borrowed or shared                                      |
| `provider()`, `provider_arc()` | The key backend, borrowed or shared                                             |

An endpoint installs its identity in one place. [The handshake](handshake.md#signatures) lists the settings of each flow and the client builders, and these calls install the rest:

| Call                                                     | Endpoint                                           |
| -------------------------------------------------------- | -------------------------------------------------- |
| `TransportEncryptionConfig::new(identity)`               | A transport server                                 |
| `Frame::sign_with_provider(&identity)`                   | A frame signer, async                              |
| `ClusterTlsConfig::from_identity(identity, purposes)`    | A cluster gateway                                  |
| `HiveTlsConfig::from_identity(identity, authentication, purposes)` | A hive                                   |
| `ServletConfigBuilder::with_identity(identity, validators)`, or `with_certificate(certificate, key, validators)` through `SigningIdentity::from_spec` | A servlet |

A builder that signs synchronously, such as `FrameBuilder::with_signer`, takes a `CertifiedKey`. A store then verifies the frame against the certificate it holds:

```rust
use tightbeam::builder::TypeBuilder;
use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::sign::ecdsa::Secp256k1Signature;
use tightbeam::crypto::sign::CertifiedKey;
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
use tightbeam::crypto::x509::store::TrustVerification;
use tightbeam::crypto::x509::KeyCurves;
use tightbeam::testing::{TestCertificate, TestKey, TestMessage};
use tightbeam::Version;

let key = TestKey::insecure_fixed_signing();
let certificate = TestCertificate::self_signed(&key);
let signer = CertifiedKey::new(&certificate, key)?;

let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
let store = builder.with_certificate(certificate)?.build();

let frame = Version::V1
	.compose::<TestMessage>()
	.with_id("signed-1")
	.with_order(1_696_521_600)
	.with_message(TestMessage::sample(None))
	.with_signer::<Secp256k1Signature, _>(signer)
	.build()?;

assert!(matches!(store.verify_frame(&frame), TrustVerification::Verified(..)));
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Certificate use

[The handshake](handshake.md#certificate-use) specifies each use, its `keyUsage` bit, its readers, and the parse that admits a certificate for it. A frame reads the signing use too: `Frame::verify` takes a `PeerCertificate<Signing<P>>`, and `Frame::verify_under` takes a `PeerCertificate<ErasedSigning>` beside a policy.

`KeyPurposes` holds the purpose of each role in its fields `server`, `client`, and `signer`, and `KeyPurposes::HOUSE` is its `Default`. A colony identity is held to the signer purpose where it is installed:

- `ClusterTlsConfig::from_identity` and `HiveTlsConfig::from_identity` call `require_purpose(purposes.signer)` on the certificate.
- A certificate whose `extendedKeyUsage` names neither the signer purpose nor `anyExtendedKeyUsage` fails with `CertificateValidationError::ExcludedKeyPurpose`.

### Key-agreement identities

A `KeyAgreementIdentity<K>` holds a key-agreement certificate beside an `Arc<K::PrivateKey>`, the backend of the KEM `K`. For `DhKemSecp256k1`, that backend is a `dyn DiffieHellman<Secp256k1>`, which `Secp256k1KeyProvider` implements.

`KeyAgreementIdentity::new(certificate, key)` admits the certificate for key agreement under `K`, then compares the backend with it, and refuses with an `EnvelopeError`:

| Variant       | Cause                                                                                           |
| ------------- | ----------------------------------------------------------------------------------------------- |
| `Certificate` | The certificate is refused for key agreement under `K`, or the key of the backend is no key of `K` |
| `Key`         | The backend fails to return its public key                                                      |
| `Encoding`    | The key of the backend is no DER SubjectPublicKeyInfo                                           |
| `KeyMismatch` | The key of the backend differs from the key of the certificate                                  |

A CMS server pairs its two identities once, through `TransportEncryptionConfig::with_key_agreement`, which builds a `CmsIdentityPair`. Its client pins the key-agreement certificate in a `ProvisionedTrust::new(key_agreement, store)`, where `key_agreement` is an `Arc<Certificate>` or a `CmsServerChain` and `store` is an `Arc<dyn CertificateTrust>`. [The CMS server's two certificates](handshake.md#the-cms-servers-two-certificates) states the rules both sides apply.

## Sources

- RFC 2104, HMAC, § 2: <https://datatracker.ietf.org/doc/html/rfc2104#section-2>
- RFC 3394, AES Key Wrap, and RFC 3565, AES in CMS, § 2.3.2: <https://datatracker.ietf.org/doc/html/rfc3394>, <https://datatracker.ietf.org/doc/html/rfc3565#section-2.3.2>
- RFC 5280, X.509 Certificate and CRL Profile, § 4.1.2.2, § 4.2, § 6.1, and § 7.1: <https://datatracker.ietf.org/doc/html/rfc5280>
- RFC 5652, Cryptographic Message Syntax, § 5.3 and § 6.2.3: <https://datatracker.ietf.org/doc/html/rfc5652>
- RFC 7093, Additional Methods for Generating Key Identifiers, § 2: <https://datatracker.ietf.org/doc/html/rfc7093#section-2>
- RFC 9180, Hybrid Public Key Encryption, § 4: <https://datatracker.ietf.org/doc/html/rfc9180#section-4>
- SEC 1 v2.0, Elliptic Curve Cryptography, § 3.3.1 and § 4.1.4: <https://www.secg.org/sec1-v2.pdf>
- NIST SP 800-56C Rev. 2, Key-Derivation Methods, § 5.1: <https://doi.org/10.6028/NIST.SP.800-56Cr2>
- CWE-532, Insertion of Sensitive Information into Log File: <https://cwe.mitre.org/data/definitions/532.html>
- CWE-757, Selection of Less-Secure Algorithm During Negotiation: <https://cwe.mitre.org/data/definitions/757.html>
