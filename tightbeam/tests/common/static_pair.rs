//! The static certificate pair the transport suites share: a server and a
//! client certificate, each self-issued over a fixed key with
//! `digitalSignature` in its `keyUsage`, beside its key and a server's pin of
//! the client's key.

use tightbeam::crypto::key::SigningKeySpec;
use tightbeam::crypto::x509::policy::PublicKeyPinning;
use tightbeam::crypto::x509::CertificateSpec;
use tightbeam::hex;

/// The server certificate, `CN=Static Test Server`, over [`SERVER_KEY`].
pub(crate) const SERVER_CERT: CertificateSpec = CertificateSpec::Pem(
	r#"-----BEGIN CERTIFICATE-----
MIIBZzCCAQygAwIBAgIBATALBglghkgBZQMEAwowHTEbMBkGA1UEAwwSU3RhdGlj
IFRlc3QgU2VydmVyMB4XDTI2MTAxODA4MTc1NloXDTM2MTAxNTA4MTc1NlowHTEb
MBkGA1UEAwwSU3RhdGljIFRlc3QgU2VydmVyMFYwEAYHKoZIzj0CAQYFK4EEAAoD
QgAEG4TFVnsSZECZXT7VqroFZdceGDRgSBn/nBf16dXdB49wvq+PWItUFQf+1qZC
xatC39+BIKf2Od5RItR6aajo0aM/MD0wHQYDVR0OBBYEFEOubLl6za81S4KG3bKb
SSyV6VhwMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMAsGCWCGSAFlAwQD
CgNIADBFAiEAlp/TRBnhnxAQxLoQ4eBqBauz03K3Ani0nF0DEZg/8lkCIGBVC3de
wDOYnbX8OyLKqHBEdIMhClGSkTgmDgdLLZdF
-----END CERTIFICATE-----"#,
);

/// The client certificate, `CN=Static Test Client`, over [`CLIENT_KEY`].
pub(crate) const CLIENT_CERT: CertificateSpec = CertificateSpec::Pem(
	r#"-----BEGIN CERTIFICATE-----
MIIBZjCCAQygAwIBAgIBATALBglghkgBZQMEAwowHTEbMBkGA1UEAwwSU3RhdGlj
IFRlc3QgQ2xpZW50MB4XDTI2MTAxODA4MTc1NloXDTM2MTAxNTA4MTc1NlowHTEb
MBkGA1UEAwwSU3RhdGljIFRlc3QgQ2xpZW50MFYwEAYHKoZIzj0CAQYFK4EEAAoD
QgAETUts0TYQMsqb0q652QCqTUXZ6tgKyUIzdMRRpyVNB2YqPq2i0P4gi20lfOsP
BkKEZi6Ff1e2a1TBmL0xDe020KM/MD0wHQYDVR0OBBYEFKPczeMV5zGTz6VPSCJD
QZFgb0XEMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMAsGCWCGSAFlAwQD
CgNHADBEAiA/0DiQJ0IwfYjUwF44j05dusktPpsUfxFkCpWUwbXMYAIgHiPjP+Kt
V7HCKsAv0TojaTFaNWH+8VmvBnXlI3E8J0c=
-----END CERTIFICATE-----"#,
);

/// The server's key, the scalar of 32 `0x01` octets.
pub(crate) const SERVER_KEY: SigningKeySpec =
	SigningKeySpec::Bytes(&hex!("0101010101010101010101010101010101010101010101010101010101010101"));

/// The client's key, the scalar of 32 `0x02` octets.
pub(crate) const CLIENT_KEY: SigningKeySpec =
	SigningKeySpec::Bytes(&hex!("0202020202020202020202020202020202020202020202020202020202020202"));

/// The client's public key, which [`CLIENT_PINNING`] pins.
const CLIENT_PUB_KEY: &[u8] = &hex!("044d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d07662a3eada2d0fe208b6d257ceb0f064284662e857f57b66b54c198bd310ded36d0");

/// A server's pin of the client's key, which admits the client certificate.
pub(crate) const CLIENT_PINNING: PublicKeyPinning<1> = PublicKeyPinning::new([CLIENT_PUB_KEY]);
