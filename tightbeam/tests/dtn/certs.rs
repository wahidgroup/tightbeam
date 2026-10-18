//! X.509 Certificates for DTN Mutual Authentication
//!
//! This module contains static X.509 certificates and keys:
//! - Mission Control (Earth-based command center)
//! - Earth Relay Satellite
//! - Mars Relay Satellite
//! - Mars Rover
//!
//! Mutual authentication flows:
//! - Mission Control ↔ Earth Relay (mutual TLS)
//! - Earth Relay ↔ Mars Relay (mutual TLS)
//! - Mars Relay ↔ Rover (mutual TLS)
//!
//! All certificates are configured for 10-year validity and use secp256k1 keys.
//! Each asserts `digitalSignature` in its `keyUsage`, the bit of the signing
//! use a handshake admits it for.

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

// ============================================================================
// Mission Control Certificates
// ============================================================================

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

pub const MISSION_CONTROL_PUB_KEY: &[u8] = &hex!("04f7b1990ed2940d725ee641ac684551b6499ea54ee55b5c4c7105f05087bf77599d58c9cb90447e71c5e0488999ffe34bac3b08ff228531e086466b6cddf15df0");

// ============================================================================
// Earth Relay Satellite Certificates
// ============================================================================

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

pub const EARTH_RELAY_PUB_KEY: &[u8] = &hex!("04be88b2dfd778906006db78ac192c522468218d8139340787079034d59a29430629a3570b6a5cd0f788c96d8614573510dd44fbf9c6a50fd7f662c03268825dff");

// ============================================================================
// Mars Relay Satellite Certificates
// ============================================================================

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

pub const MARS_RELAY_PUB_KEY: &[u8] = &hex!("04314a7c1f17a970ed5ece1e6cda7950f046c5e43920bce47a7166e0b6806337a47bee2db07cc534b23e8fa0bdac7dea6770163511b7403899fea664772a904800");

// ============================================================================
// Mars Rover Certificates
// ============================================================================

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

pub const ROVER_PUB_KEY: &[u8] = &hex!("048a6488041ccb629f2c2f3a8b1f06eaf155db4747993b17441b1d7b2b09b1c4da1fbb733a081f3d1cab7c40e03fdd56811348e21349f4885cc1b4a26ed7e5b3e1");

// ============================================================================
// Public Key Pinning Configurations (Server-Side)
// ============================================================================
// These validators are used by servers to validate incoming client certificates

/// Mission Control's pinning policy: accepts only Earth Relay's public key
pub const MISSION_CONTROL_PINNING: PublicKeyPinning<1> = PublicKeyPinning::new([EARTH_RELAY_PUB_KEY]);

/// Earth Relay's pinning policy: accepts Mission Control and Mars Relay connections
pub const EARTH_RELAY_PINNING: PublicKeyPinning<2> =
	PublicKeyPinning::new([MISSION_CONTROL_PUB_KEY, MARS_RELAY_PUB_KEY]);

/// Mars Relay's pinning policy: accepts Earth Relay and Rover connections
pub const MARS_RELAY_PINNING: PublicKeyPinning<2> = PublicKeyPinning::new([EARTH_RELAY_PUB_KEY, ROVER_PUB_KEY]);

/// Rover's pinning policy: accepts only Mars Relay's public key
pub const ROVER_PINNING: PublicKeyPinning<1> = PublicKeyPinning::new([MARS_RELAY_PUB_KEY]);

// ============================================================================
// Signer Certificates for Signature Verification
// ============================================================================

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

// ============================================================================
// Shared Encryption Key (Mission Control ↔ Rover)
// ============================================================================

/// Generate a shared AES-256-GCM cipher for end-to-end encryption between Mission Control and Rover
/// The relay satellites cannot decrypt messages as they do not possess this key
pub fn generate_shared_cipher() -> tightbeam::crypto::aead::Aes256Gcm {
	use tightbeam::crypto::aead::{Aes256Gcm, Key, KeyInit};
	// For testing: use a deterministic key
	// In production, this would be securely exchanged or derived
	let key_bytes = hex!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
	Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes))
}

// ============================================================================
// Compatibility Aliases (for gradual migration)
// ============================================================================

#[allow(dead_code)]
pub const EARTH_CERT: CertificateSpec = EARTH_RELAY_CERT;
#[allow(dead_code)]
pub const EARTH_KEY: SigningKeySpec = EARTH_RELAY_KEY;
#[allow(dead_code)]
pub const EARTH_PUB_KEY: &[u8] = EARTH_RELAY_PUB_KEY;

#[allow(dead_code)]
pub const SATELLITE_CERT: CertificateSpec = MARS_RELAY_CERT;
#[allow(dead_code)]
pub const SATELLITE_KEY: SigningKeySpec = MARS_RELAY_KEY;
#[allow(dead_code)]
pub const SATELLITE_PUB_KEY: &[u8] = MARS_RELAY_PUB_KEY;
