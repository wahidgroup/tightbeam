# DHKEM over secp256k1 in CMS

This document specifies DHKEM(secp256k1, HKDF-SHA256) as the KEM of a CMS `KEMRecipientInfo` ([RFC 9629][rfc9629]). It takes the shape of [RFC 9629][rfc9629] § 6.1, and [RFC 9936][rfc9936], which does the same for ML-KEM, is its model. tightbeam seals its CMS opening, and each frame sealed to a recipient key, with this KEM.

## Contents

- [The KEM](#the-kem)
- [Identifier](#identifier)
- [KEM-ALGORITHM](#kem-algorithm)
- [RecipientInfo conventions](#recipientinfo-conventions)
- [Key derivation](#key-derivation)
- [Certificate conventions](#certificate-conventions)
- [Security considerations](#security-considerations)
- [Test vectors](#test-vectors)
- [References](#references)

## The KEM

The KEM is the DHKEM of [RFC 9180][rfc9180] § 4.1 on the curve secp256k1 with the KDF HKDF-SHA256: the HPKE KEM `0x0016`, which [draft-wahby-cfrg-hpke-kem-secp256k1-01][wahby] registers. Its `suite_id` is `"KEM" || I2OSP(0x0016, 2)`.

- `Encap(pkR)` draws an ephemeral key pair `(skE, pkE)` and computes `dh = DH(skE, pkR)`. It returns `enc = SerializePublicKey(pkE)` and `shared_secret = ExtractAndExpand(dh, enc || SerializePublicKey(pkR))`.
- `Decap(enc, skR)` computes `dh = DH(skR, DeserializePublicKey(enc))` and the same `shared_secret`.
- `SerializePublicKey` is the uncompressed SEC1 encoding ([draft-wahby-cfrg-hpke-kem-secp256k1-01][wahby] § 3.1). `DeserializePublicKey` refuses a point off the curve and the point at infinity ([RFC 9180][rfc9180] § 7.1.4).

| Size      | Octets | Meaning                       |
| --------- | ------ | ----------------------------- |
| `Nsecret` | 32     | The shared secret             |
| `Nenc`    | 65     | The encapsulated key, `kemct` |
| `Npk`     | 65     | The public key, uncompressed  |
| `Nsk`     | 32     | The private key               |

## Identifier

The KEM is identified by `id-alg-dhkem-secp256k1`, under the algorithms arc of Wahid Group, LLC, IANA Private Enterprise Number 64586. No registry assigns an object identifier to a DHKEM over secp256k1. The parameters are absent.

```asn1
id-alg-dhkem-secp256k1 OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) dod(6) internet(1) private(4)
    enterprise(1) 64586 algorithms(2) 3 }
```

tightbeam names it `oids::DHKEM_SECP256K1`, `1.3.6.1.4.1.64586.2.3`.

## KEM-ALGORITHM

The definition follows the `KEM-ALGORITHM` class of [RFC 9629][rfc9629] § 6.1. `pk-ec` is the elliptic-curve public key that the `PKIXAlgs-2009` module of [RFC 5912][rfc5912] § 6 defines for the keys of [RFC 5480][rfc5480], restricted here to the named curve secp256k1, `1.3.132.0.10`.

```asn1
kema-dhkem-secp256k1 KEM-ALGORITHM ::= {
    IDENTIFIER id-alg-dhkem-secp256k1
    PARAMS ARE absent
    PUBLIC-KEYS { pk-ec }
    UKM ARE optional
    SMIME-CAPS { IDENTIFIED BY id-alg-dhkem-secp256k1 } }
```

## RecipientInfo conventions

A `KEMRecipientInfo` ([RFC 9629][rfc9629] § 3) under this KEM sets its fields as follows.

| Field       | Value                                                                                                                                                  |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `version`   | 0                                                                                                                                                      |
| `rid`       | The recipient certificate's `subjectKeyIdentifier`, else its issuer and serial number. A bare key's is its [RFC 7093][rfc7093] § 2 method 1 identifier |
| `kem`       | `id-alg-dhkem-secp256k1`, parameters absent                                                                                                            |
| `kemct`     | `enc`, the 65-octet uncompressed point of the ephemeral that `Encap` drew                                                                              |
| `kdf`       | `id-alg-hkdf-with-sha3-256` ([RFC 9688][rfc9688] § 5.1), parameters absent                                                                             |
| `kekLength` | The key size of `wrap`: 32 for `id-aes256-wrap`                                                                                                        |
| `ukm`       | Optional. A sender MAY carry one, and a recipient that expects a purpose MUST refuse another                                                           |
| `wrap`      | `id-aes256-wrap` ([RFC 3565][rfc3565])                                                                                                                 |

A recipient MUST confirm that `kekLength` is the key size of `wrap` ([RFC 9629][rfc9629] § 3), and it MUST refuse a `kemct` of another length or form before it runs `Decap`.

In tightbeam's CMS opening, the `ukm` is the purpose label `tb/handshake/opening/ukm/v1` followed by 32 random octets that each seal draws for itself, and the server refuses a `ukm` of another label or length. A frame sealed to a recipient key carries the label `tb/frame/ukm/v1` in the same form, and a frame decryptor refuses a `ukm` of another label or length.

## Key derivation

The shared secret of the KEM is the input keying material of the KDF of [RFC 9629][rfc9629] § 5, and it derives the key-encryption key alone.

```text
KEK = HKDF-SHA3-256(IKM = shared_secret, salt = "", info = DER(CMSORIforKEMOtherInfo), L = kekLength)
```

- `CMSORIforKEMOtherInfo` holds the `wrap`, the `kekLength`, and the `ukm` of the `KEMRecipientInfo`.
- The salt is the zero-length string, as [RFC 9936][rfc9936] § 2.2.1 states for its KEM. HKDF reads it as `HashLen` zero octets ([RFC 5869][rfc5869] § 2.2).
- The KEM derives its shared secret with HKDF-SHA256, which its registration fixes, and the key-encryption key derives with HKDF-SHA3-256. [RFC 9936][rfc9936] § 2.1 allows the KDF of the `RecipientInfo` to differ from the KDF inside the KEM.

## Certificate conventions

The recipient's public key travels in a certificate whose SubjectPublicKeyInfo is `id-ecPublicKey` with the named curve secp256k1 ([RFC 5480][rfc5480] § 2). Its point MUST be compressed or uncompressed, and the sender and the recipient refuse a first octet other than `0x02`, `0x03`, or `0x04` ([RFC 5480][rfc5480] § 2.2).

The certificate MUST carry a `keyUsage` extension, it MUST assert `keyAgreement`, and it MUST NOT assert `decipherOnly`, which would limit the agreed key to deciphering ([RFC 5280][rfc5280] § 4.2.1.3). Two standards disagree on the bit, and this specification follows the second:

- [RFC 9629][rfc9629] § 3 says that "a recipient X.509 version 3 certificate that contains a key usage extension MUST assert the keyEncipherment bit".
- [RFC 5480][rfc5480] § 3 limits the `keyUsage` of an `id-ecPublicKey` end-entity certificate to `digitalSignature`, `nonRepudiation`, and `keyAgreement`, so no conforming certificate of this key type carries `keyEncipherment`. [RFC 5280][rfc5280] § 4.2.1.3 names `keyAgreement` for a key used in key agreement, which DHKEM is.

A certificate with no `keyUsage` extension would leave its use unchecked. The sender refuses to encapsulate to a certificate whose `keyUsage` is absent, lacks `keyAgreement`, or asserts `decipherOnly`, and the recipient refuses to open under one. tightbeam makes these checks in one place, the parse of `PeerCertificate<KeyAgreement<K>>`: a `KemRecipient` is built from that parse, and `KeyAgreementIdentity::new` runs it, so an outside KEM gets the checks without writing them. The bit is the KEM's `RecipientKem::USAGE`, `keyAgreement` for this KEM, so an outside KEM whose certificate profile names `keyEncipherment`, as ML-KEM's does ([RFC 9935][rfc9935] § 5, [RFC 9629][rfc9629] § 3), sets that bit instead. A certificate whose `keyUsage` also asserts `digitalSignature` is admitted, as RFC 5480 § 3 allows on one `id-ecPublicKey` end-entity certificate.

## Security considerations

- secp256k1 offers about 128 bits of security. HKDF-SHA256 and HKDF-SHA3-256 offer at least that, as [RFC 9629][rfc9629] § 7 asks of the KDF.
- Each encapsulation draws a fresh ephemeral, and its shared secret serves one `KEMRecipientInfo` alone. The shared secret MUST NOT be reused for any other purpose ([RFC 9629][rfc9629] § 7).
- `Decap` runs only on a point that `DeserializePublicKey` admitted, so no scalar multiplication runs on an invalid point.
- A recipient key that also signs serves two purposes. A deployment SHOULD certify the KEM recipient key apart from its signing key ([NIST SP 800-57 Part 1 Rev. 5][sp800-57] § 5.2). The tightbeam CMS handshake does: its server holds a key-agreement certificate apart from its signing certificate, and refuses one key in both.

## Test vectors

The KEM layer has published vectors in [draft-wahby-cfrg-hpke-kem-secp256k1-01][wahby] Appendix B: B.1.1 and B.2.1 give an ephemeral key, a recipient key, and the `shared_secret` they encapsulate to. tightbeam runs both through `Encap` and `Decap`, and pins the key-encryption key of one `CMSORIforKEMOtherInfo` against an independent HKDF-SHA3-256. It also pins one whole seal to the B.1.1 recipient key under fixed random draws: `kemct`, `ukm`, `encryptedKey`, the ciphertext, and `mac`, each from an independent implementation.

## References

- [RFC 9629][rfc9629]: Using Key Encapsulation Mechanism (KEM) Algorithms in the Cryptographic Message Syntax (CMS)
- [RFC 9936][rfc9936]: Use of ML-KEM in the Cryptographic Message Syntax (CMS)
- [RFC 9935][rfc9935]: Algorithm Identifiers for the Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM) in the Internet X.509 Public Key Infrastructure
- [RFC 9180][rfc9180]: Hybrid Public Key Encryption
- [draft-wahby-cfrg-hpke-kem-secp256k1-01][wahby]: Hybrid Public Key Encryption with secp256k1
- [RFC 9688][rfc9688]: Use of the SHA3 One-Way Hash Functions in the Cryptographic Message Syntax (CMS)
- [RFC 5869][rfc5869]: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- [RFC 5480][rfc5480]: Elliptic Curve Cryptography Subject Public Key Information
- [RFC 5912][rfc5912]: New ASN.1 Modules for the Public Key Infrastructure Using X.509 (PKIX)
- [RFC 5280][rfc5280]: Internet X.509 Public Key Infrastructure Certificate and CRL Profile
- [RFC 3565][rfc3565]: Use of the Advanced Encryption Standard (AES) Encryption Algorithm in Cryptographic Message Syntax (CMS)
- [RFC 7093][rfc7093]: Additional Methods for Generating Key Identifiers Values
- [NIST SP 800-57 Part 1 Rev. 5][sp800-57]: Recommendation for Key Management

[rfc9629]: https://datatracker.ietf.org/doc/html/rfc9629
[rfc9936]: https://datatracker.ietf.org/doc/html/rfc9936
[rfc9935]: https://datatracker.ietf.org/doc/html/rfc9935
[rfc9180]: https://datatracker.ietf.org/doc/html/rfc9180
[wahby]: https://datatracker.ietf.org/doc/html/draft-wahby-cfrg-hpke-kem-secp256k1-01
[rfc9688]: https://datatracker.ietf.org/doc/html/rfc9688
[rfc5869]: https://datatracker.ietf.org/doc/html/rfc5869
[rfc5480]: https://datatracker.ietf.org/doc/html/rfc5480
[rfc5912]: https://datatracker.ietf.org/doc/html/rfc5912#section-6
[rfc5280]: https://datatracker.ietf.org/doc/html/rfc5280
[rfc3565]: https://datatracker.ietf.org/doc/html/rfc3565
[rfc7093]: https://datatracker.ietf.org/doc/html/rfc7093#section-2
[sp800-57]: https://doi.org/10.6028/NIST.SP.800-57pt1r5
