//! The static certificate pair the transport tests share: a server and a
//! client certificate, each self-issued over a fixed key with
//! `digitalSignature` in its `keyUsage`, beside its key and a server's pin of
//! the client's key. The client's trust of the server, the client's identity,
//! and the server's validators of the client derive from them.

use std::sync::Arc;

use tightbeam::crypto::key::SigningKeySpec;
use tightbeam::crypto::sign::ecdsa::Secp256k1;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::policy::{CertificateValidation, PublicKeyPinning};
use tightbeam::crypto::x509::CertificateSpec;
use tightbeam::hex;

#[cfg(feature = "testing")]
use tightbeam::crypto::x509::store::CertificateTrust;
#[cfg(feature = "testing")]
use tightbeam::x509::Certificate;

#[cfg(feature = "testing")]
use crate::common::security::combined_trust;

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

/// The server's key, the scalar of 32 `0x01` octets. It is the key of
/// `TestKey::insecure_fixed_signing` and of `ServerMaterials`.
pub(crate) const SERVER_KEY: SigningKeySpec =
	SigningKeySpec::Bytes(&hex!("0101010101010101010101010101010101010101010101010101010101010101"));

/// The client's key, the scalar of 32 `0x02` octets. It is the key of the
/// static client alone.
pub(crate) const CLIENT_KEY: SigningKeySpec =
	SigningKeySpec::Bytes(&hex!("0202020202020202020202020202020202020202020202020202020202020202"));

/// The SubjectPublicKeyInfo DER of the client's key, which
/// [`client_pinning`] pins.
const CLIENT_SPKI: &[u8] = &hex!("3056301006072a8648ce3d020106052b8104000a034200044d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d07662a3eada2d0fe208b6d257ceb0f064284662e857f57b66b54c198bd310ded36d0");

/// A server's pin of the client's key, which admits the client certificate.
pub(crate) fn client_pinning() -> PublicKeyPinning {
	PublicKeyPinning::new([CLIENT_SPKI]).expect("the client pin is a SubjectPublicKeyInfo of a point")
}

/// The server's validators of its clients, which admit the client
/// certificate alone through [`client_pinning`].
pub(crate) fn client_validators() -> Vec<Arc<dyn CertificateValidation>> {
	vec![Arc::new(client_pinning())]
}

/// The client's trust store, which anchors [`SERVER_CERT`].
#[cfg(feature = "testing")]
pub(crate) fn server_trust() -> Arc<dyn CertificateTrust> {
	let certificate = Certificate::try_from(SERVER_CERT).expect("the server certificate is PEM of a certificate");
	combined_trust(&[&certificate])
}

/// The client's identity: [`CLIENT_CERT`] over [`CLIENT_KEY`].
pub(crate) fn client_identity() -> SigningIdentity {
	let key = CLIENT_KEY.to_provider::<Secp256k1>();
	let key = key.expect("the client key is a secp256k1 scalar");
	SigningIdentity::from_spec(CLIENT_CERT, key).expect("the client key matches its certificate")
}
