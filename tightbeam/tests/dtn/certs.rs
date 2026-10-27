//! X.509 certificates and keys for DTN mutual authentication.
//!
//! This module contains static X.509 certificates and keys:
//! - Mission Control (Earth-based command center)
//! - Earth Relay Satellite
//! - Mars Relay Satellite
//! - Mars Rover
//!
//! Each link authenticates both of its ends over mutual TLS:
//! - Mission Control and the Earth relay
//! - The Earth relay and the Mars relay
//! - The Mars relay and the rover
//!
//! Every certificate is valid for 10 years and carries a secp256k1 key. Each
//! asserts `digitalSignature` in its `keyUsage`, the bit of the signing use a
//! handshake admits it for.

use tightbeam::{
	crypto::{
		key::SigningKeySpec,
		profiles::DefaultCryptoProvider,
		sign::ecdsa::Secp256k1SigningKey,
		x509::{policy::PublicKeyPinning, CertificateSpec, KeyPurposes, PeerCertificate, Signing},
	},
	hex,
	testing::TestCertificate,
};

// These constants hold the certificate and key of Mission Control.

pub const MISSION_CONTROL_CERT: CertificateSpec = CertificateSpec::Pem(
	r#"-----BEGIN CERTIFICATE-----
MIIBgDCCASagAwIBAgIBATAKBggqhkjOPQQDAjAaMRgwFgYDVQQDDA9NaXNzaW9u
IENvbnRyb2wwHhcNMjYxMDE4MDkwMDAwWhcNMzYxMDE1MDkwMDAwWjAaMRgwFgYD
VQQDDA9NaXNzaW9uIENvbnRyb2wwVjAQBgcqhkjOPQIBBgUrgQQACgNCAAT3sZkO
0pQNcl7mQaxoRVG2SZ6lTuVbXExxBfBQh793WZ1YycuQRH5xxeBIiZn/40usOwj/
IoUx4IZGa2zd8V3wo2AwXjAdBgNVHQ4EFgQU+tbs8vNhZUs8R5TjrMHpb8Utfk4w
HwYDVR0jBBgwFoAU+tbs8vNhZUs8R5TjrMHpb8Utfk4wDAYDVR0TAQH/BAIwADAO
BgNVHQ8BAf8EBAMCB4AwCgYIKoZIzj0EAwIDSAAwRQIgPz8mYzP5wG1A/MHAuV0p
jwCLxosOUpu6eAzJs5e9mOECIQDTU3vrWV5bBELrf3LGPi5luJUoHSbInoJzrOF8
2A2Jtw==
-----END CERTIFICATE-----"#,
);

/// The secret scalar of the key that [`MISSION_CONTROL_KEY`] carries.
const MISSION_CONTROL_KEY_BYTES: [u8; 32] = hex!("ce3c6e1d00d4b950963770268e96062a357f8b444e075ec8d35369d325213195");

pub const MISSION_CONTROL_KEY: SigningKeySpec = SigningKeySpec::Bytes(&MISSION_CONTROL_KEY_BYTES);

/// The SubjectPublicKeyInfo DER of the key of Mission Control, the form a pin
/// names it in.
pub const MISSION_CONTROL_SPKI: &[u8] = &hex!("3056301006072a8648ce3d020106052b8104000a03420004f7b1990ed2940d725ee641ac684551b6499ea54ee55b5c4c7105f05087bf77599d58c9cb90447e71c5e0488999ffe34bac3b08ff228531e086466b6cddf15df0");

// These constants hold the certificate and key of the Earth relay satellite.

pub const EARTH_RELAY_CERT: CertificateSpec = CertificateSpec::Pem(
	r#"-----BEGIN CERTIFICATE-----
MIIBdzCCAR6gAwIBAgIBATAKBggqhkjOPQQDAjAWMRQwEgYDVQQDDAtFYXJ0aCBS
ZWxheTAeFw0yNjEwMTgwOTAwMDBaFw0zNjEwMTUwOTAwMDBaMBYxFDASBgNVBAMM
C0VhcnRoIFJlbGF5MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEvoiy39d4kGAG23is
GSxSJGghjYE5NAeHB5A01ZopQwYpo1cLalzQ94jJbYYUVzUQ3UT7+calD9f2YsAy
aIJd/6NgMF4wHQYDVR0OBBYEFPchf217TRdeQVgodWOqXXVdbnoxMB8GA1UdIwQY
MBaAFPchf217TRdeQVgodWOqXXVdbnoxMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/
BAQDAgeAMAoGCCqGSM49BAMCA0cAMEQCIBluZW93RIdFuUJm2FHKNurcKOEI/BfF
MIaSSkx1qlQ2AiBubpuKCrgJXGnY6sbTqw5Uo7mdSuO2i1tLES79c0aEPQ==
-----END CERTIFICATE-----"#,
);

/// The secret scalar of the key that [`EARTH_RELAY_KEY`] carries.
const EARTH_RELAY_KEY_BYTES: [u8; 32] = hex!("5c676e5bbb9d78c6f2e78d67e83052e38bea1858fd67e6e0c12b5e229eaef0ee");

pub const EARTH_RELAY_KEY: SigningKeySpec = SigningKeySpec::Bytes(&EARTH_RELAY_KEY_BYTES);

/// The SubjectPublicKeyInfo DER of the key of Earth Relay, the form a pin
/// names it in.
pub const EARTH_RELAY_SPKI: &[u8] = &hex!("3056301006072a8648ce3d020106052b8104000a03420004be88b2dfd778906006db78ac192c522468218d8139340787079034d59a29430629a3570b6a5cd0f788c96d8614573510dd44fbf9c6a50fd7f662c03268825dff");

// These constants hold the certificate and key of the Mars relay satellite.

pub const MARS_RELAY_CERT: CertificateSpec = CertificateSpec::Pem(
	r#"-----BEGIN CERTIFICATE-----
MIIBdjCCARygAwIBAgIBATAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApNYXJzIFJl
bGF5MB4XDTI2MTAxODA5MDAwMFoXDTM2MTAxNTA5MDAwMFowFTETMBEGA1UEAwwK
TWFycyBSZWxheTBWMBAGByqGSM49AgEGBSuBBAAKA0IABDFKfB8XqXDtXs4ebNp5
UPBGxeQ5ILzkenFm4LaAYzeke+4tsHzFNLI+j6C9rH3qZ3AWNRG3QDiZ/qZkdyqQ
SACjYDBeMB0GA1UdDgQWBBQlHjVAj0IHloHpNKkSS0C1+BNzLzAfBgNVHSMEGDAW
gBQlHjVAj0IHloHpNKkSS0C1+BNzLzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQE
AwIHgDAKBggqhkjOPQQDAgNIADBFAiEAnIoyDt65bP9Mrl7/t5IbJeXO6GXC4OFB
p6J5QRhtLkECIFXkUa/tKCENpNJCYCYfXh+zTxVTEszNX4kWmBeL3G+u
-----END CERTIFICATE-----"#,
);

/// The secret scalar of the key that [`MARS_RELAY_KEY`] carries.
const MARS_RELAY_KEY_BYTES: [u8; 32] = hex!("52c304e563d6bf2f792ddd8b6bcdd8d1a203075ca6ef66119efa7eafa9a5fb6d");

pub const MARS_RELAY_KEY: SigningKeySpec = SigningKeySpec::Bytes(&MARS_RELAY_KEY_BYTES);

/// The SubjectPublicKeyInfo DER of the key of Mars Relay, the form a pin
/// names it in.
pub const MARS_RELAY_SPKI: &[u8] = &hex!("3056301006072a8648ce3d020106052b8104000a03420004314a7c1f17a970ed5ece1e6cda7950f046c5e43920bce47a7166e0b6806337a47bee2db07cc534b23e8fa0bdac7dea6770163511b7403899fea664772a904800");

// These constants hold the certificate and key of the Mars rover.

pub const ROVER_CERT: CertificateSpec = CertificateSpec::Pem(
	r#"-----BEGIN CERTIFICATE-----
MIIBgDCCASagAwIBAgIBATAKBggqhkjOPQQDAjAaMRgwFgYDVQQDDA9NYXJzIFJv
dmVyIENhbkQwHhcNMjYxMDE4MDgxNzU2WhcNMzYxMDE1MDgxNzU2WjAaMRgwFgYD
VQQDDA9NYXJzIFJvdmVyIENhbkQwVjAQBgcqhkjOPQIBBgUrgQQACgNCAASKZIgE
HMtinywvOosfBurxVdtHR5k7F0QbHXsrCbHE2h+7czoIHz0cq3xA4D/dVoETSOIT
SfSIXMG0om7X5bPho2AwXjAdBgNVHQ4EFgQUxgX3K08UFtT2gJXLnXwDHYcm/zYw
HwYDVR0jBBgwFoAUxgX3K08UFtT2gJXLnXwDHYcm/zYwDAYDVR0TAQH/BAIwADAO
BgNVHQ8BAf8EBAMCB4AwCgYIKoZIzj0EAwIDSAAwRQIgYpyof1NyMnkDTh9AHs1c
pYwOxsKjBBL6egK8bevwAUACIQDNQyD5BQI2h5gj+pUSNBz+y1DWXibcGNNYDtHD
VjxCWA==
-----END CERTIFICATE-----"#,
);

/// The secret scalar of the key that [`ROVER_KEY`] carries.
const ROVER_KEY_BYTES: [u8; 32] = hex!("c5d575279e5fc6c691a084db64139f237a18a7044dbd4b5bc7d00e0a21f9eb5b");

pub const ROVER_KEY: SigningKeySpec = SigningKeySpec::Bytes(&ROVER_KEY_BYTES);

/// The SubjectPublicKeyInfo DER of the key of the Rover, the form a pin
/// names it in.
pub const ROVER_SPKI: &[u8] = &hex!("3056301006072a8648ce3d020106052b8104000a034200048a6488041ccb629f2c2f3a8b1f06eaf155db4747993b17441b1d7b2b09b1c4da1fbb733a081f3d1cab7c40e03fdd56811348e21349f4885cc1b4a26ed7e5b3e1");

// Each server checks the certificate of an incoming client with one of these
// pinning policies.

/// The pinning of `pins`, each the SubjectPublicKeyInfo DER of a DTN key.
fn pinning(pins: &[&[u8]]) -> PublicKeyPinning {
	PublicKeyPinning::new(pins).expect("each DTN pin is a SubjectPublicKeyInfo of a point")
}

/// Mission Control's pinning policy accepts only the Earth relay's key.
pub fn mission_control_pinning() -> PublicKeyPinning {
	pinning(&[EARTH_RELAY_SPKI])
}

/// The Earth relay's pinning policy accepts Mission Control and the Mars relay.
pub fn earth_relay_pinning() -> PublicKeyPinning {
	pinning(&[MISSION_CONTROL_SPKI, MARS_RELAY_SPKI])
}

/// The Mars relay's pinning policy accepts the Earth relay and the rover.
pub fn mars_relay_pinning() -> PublicKeyPinning {
	pinning(&[EARTH_RELAY_SPKI, ROVER_SPKI])
}

/// The rover's pinning policy accepts only the Mars relay's key.
pub fn rover_pinning() -> PublicKeyPinning {
	pinning(&[MARS_RELAY_SPKI])
}

// These signer certificates verify the signatures of DTN frames.

/// The certificate a DTN node's frames name as their signer, admitted for
/// signing under the house provider.
pub type FrameSigner = PeerCertificate<Signing<DefaultCryptoProvider>>;

/// The signer certificate of the node whose secret scalar is `key_bytes`:
/// the fixture certificate that `TestIdentity::certified` pairs with the key
/// to sign a frame.
fn frame_signer(key_bytes: &[u8; 32]) -> FrameSigner {
	let key = Secp256k1SigningKey::from_slice(key_bytes).expect("a DTN key is a valid secp256k1 scalar");
	let signer = PeerCertificate::parse(TestCertificate::self_signed(&key), KeyPurposes::HOUSE.signer);
	signer.expect("a fixture certificate asserts digitalSignature")
}

/// Mission Control's signer certificate.
pub fn mission_control_signer() -> FrameSigner {
	frame_signer(&MISSION_CONTROL_KEY_BYTES)
}

/// Earth Relay's signer certificate.
pub fn earth_relay_signer() -> FrameSigner {
	frame_signer(&EARTH_RELAY_KEY_BYTES)
}

/// Mars Relay's signer certificate.
pub fn mars_relay_signer() -> FrameSigner {
	frame_signer(&MARS_RELAY_KEY_BYTES)
}

/// Rover's signer certificate.
pub fn rover_signer() -> FrameSigner {
	frame_signer(&ROVER_KEY_BYTES)
}

// Mission Control and the rover share this encryption key.

/// The key-encryption key Mission Control and the Rover share, which every
/// node of the path holds by reference.
pub type SharedCipher = std::sync::Arc<tightbeam::crypto::key::Aes256GcmKeyProvider>;

/// Generate the key-encryption key that Mission Control and the rover share.
/// Every node of the path holds it, so each relay satellite decrypts the
/// frames it routes.
pub fn generate_shared_cipher() -> SharedCipher {
	use tightbeam::crypto::key::Aes256GcmKeyProvider;
	// The test uses a deterministic key. A production deployment exchanges or
	// derives this key securely.
	let key_bytes = hex!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
	let cipher = Aes256GcmKeyProvider::new(key_bytes.to_vec(), b"tb/test/dtn/kek/v1".to_vec());
	std::sync::Arc::new(cipher.expect("32 octets is the key of AES-256 key wrap"))
}

// These aliases give the Earth relay the prefix `EARTH` and the Mars relay the
// prefix `SATELLITE`.

#[allow(dead_code)]
pub const EARTH_CERT: CertificateSpec = EARTH_RELAY_CERT;
#[allow(dead_code)]
pub const EARTH_KEY: SigningKeySpec = EARTH_RELAY_KEY;
#[allow(dead_code)]
pub const EARTH_SPKI: &[u8] = EARTH_RELAY_SPKI;

#[allow(dead_code)]
pub const SATELLITE_CERT: CertificateSpec = MARS_RELAY_CERT;
#[allow(dead_code)]
pub const SATELLITE_KEY: SigningKeySpec = MARS_RELAY_KEY;
#[allow(dead_code)]
pub const SATELLITE_SPKI: &[u8] = MARS_RELAY_SPKI;
