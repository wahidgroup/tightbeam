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

use tightbeam::{
	crypto::{
		key::KeySpec,
		sign::ecdsa::Secp256k1VerifyingKey,
		x509::{policy::PublicKeyPinning, CertificateSpec},
	},
	hex,
};

// ============================================================================
// Mission Control Certificates
// ============================================================================

pub const MISSION_CONTROL_CERT: CertificateSpec = CertificateSpec::Pem(
	r#"-----BEGIN CERTIFICATE-----
MIIBjDCCATKgAwIBAgIUFidcbRLwUpOIp2U8AloYeNWL8kwwCgYIKoZIzj0EAwIw
HTEbMBkGA1UEAwwSTWlzc2lvbiBDb250cm9sIENBMB4XDTI1MTEyNTA5MTIyNVoX
DTM1MTEyMzA5MTIyNVowHTEbMBkGA1UEAwwSTWlzc2lvbiBDb250cm9sIENBMFYw
EAYHKoZIzj0CAQYFK4EEAAoDQgAE97GZDtKUDXJe5kGsaEVRtkmepU7lW1xMcQXw
UIe/d1mdWMnLkER+ccXgSImZ/+NLrDsI/yKFMeCGRmts3fFd8KNTMFEwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQU+tbs8vNhZUs8R5TjrMHpb8Utfk4wHwYDVR0j
BBgwFoAU+tbs8vNhZUs8R5TjrMHpb8Utfk4wCgYIKoZIzj0EAwIDSAAwRQIgDVAy
+dQhd5TBMSSLrUaB6VvEh+urqHmptaeKidUwYuQCIQDd5K3vbHqpivLfgl2zx4U1
O8ZqbdXnVBULkrLWVzUsXg==
-----END CERTIFICATE-----"#,
);

pub const MISSION_CONTROL_KEY: KeySpec =
	KeySpec::Bytes(&hex!("ce3c6e1d00d4b950963770268e96062a357f8b444e075ec8d35369d325213195"));

pub const MISSION_CONTROL_PUB_KEY: &[u8] = &hex!("04f7b1990ed2940d725ee641ac684551b6499ea54ee55b5c4c7105f05087bf77599d58c9cb90447e71c5e0488999ffe34bac3b08ff228531e086466b6cddf15df0");

// ============================================================================
// Earth Relay Satellite Certificates
// ============================================================================

pub const EARTH_RELAY_CERT: CertificateSpec = CertificateSpec::Pem(
	r#"-----BEGIN CERTIFICATE-----
MIIBhTCCASqgAwIBAgIUGYUgqIrClOdPzsL5cqQVd1vCZUcwCgYIKoZIzj0EAwIw
GTEXMBUGA1UEAwwORWFydGggUmVsYXkgQ0EwHhcNMjUxMTI1MDkyMDA0WhcNMzUx
MTIzMDkyMDA0WjAZMRcwFQYDVQQDDA5FYXJ0aCBSZWxheSBDQTBWMBAGByqGSM49
AgEGBSuBBAAKA0IABL6Ist/XeJBgBtt4rBksUiRoIY2BOTQHhweQNNWaKUMGKaNX
C2pc0PeIyW2GFFc1EN1E+/nGpQ/X9mLAMmiCXf+jUzBRMA8GA1UdEwEB/wQFMAMB
Af8wHQYDVR0OBBYEFPchf217TRdeQVgodWOqXXVdbnoxMB8GA1UdIwQYMBaAFPch
f217TRdeQVgodWOqXXVdbnoxMAoGCCqGSM49BAMCA0kAMEYCIQC1G5i9Czodydsx
waqr2Pf1l3EWyJJB3nqZmb43Hcf3zwIhAKQlds7H4tCOd4FYro+Jgc93GOTzqI77
ihlyt+G86bVx
-----END CERTIFICATE-----"#,
);

pub const EARTH_RELAY_KEY: KeySpec =
	KeySpec::Bytes(&hex!("5c676e5bbb9d78c6f2e78d67e83052e38bea1858fd67e6e0c12b5e229eaef0ee"));

pub const EARTH_RELAY_PUB_KEY: &[u8] = &hex!("04be88b2dfd778906006db78ac192c522468218d8139340787079034d59a29430629a3570b6a5cd0f788c96d8614573510dd44fbf9c6a50fd7f662c03268825dff");

// ============================================================================
// Mars Relay Satellite Certificates
// ============================================================================

pub const MARS_RELAY_CERT: CertificateSpec = CertificateSpec::Pem(
	r#"-----BEGIN CERTIFICATE-----
MIIBgTCCASigAwIBAgIUYhzMEwU9Ahi2treUtZtEsy0ejjYwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNTWFycyBSZWxheSBDQTAeFw0yNTExMjUwOTI5MTRaFw0zNTEx
MjMwOTI5MTRaMBgxFjAUBgNVBAMMDU1hcnMgUmVsYXkgQ0EwVjAQBgcqhkjOPQIB
BgUrgQQACgNCAAQxSnwfF6lw7V7OHmzaeVDwRsXkOSC85HpxZuC2gGM3pHvuLbB8
xTSyPo+gvax96mdwFjURt0A4mf6mZHcqkEgAo1MwUTAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBQlHjVAj0IHloHpNKkSS0C1+BNzLzAfBgNVHSMEGDAWgBQlHjVA
j0IHloHpNKkSS0C1+BNzLzAKBggqhkjOPQQDAgNHADBEAiBeeYGAflFLpQSXFmgi
4r0wH14zddE058QNgSCFFimRaQIgIkuVv7qulrDwZYxZ/alnUrKk38HCHBHtlmc9
gIK96Eg=
-----END CERTIFICATE-----"#,
);

pub const MARS_RELAY_KEY: KeySpec =
	KeySpec::Bytes(&hex!("52c304e563d6bf2f792ddd8b6bcdd8d1a203075ca6ef66119efa7eafa9a5fb6d"));

pub const MARS_RELAY_PUB_KEY: &[u8] = &hex!("04314a7c1f17a970ed5ece1e6cda7950f046c5e43920bce47a7166e0b6806337a47bee2db07cc534b23e8fa0bdac7dea6770163511b7403899fea664772a904800");

// ============================================================================
// Mars Rover Certificates
// ============================================================================

pub const ROVER_CERT: CertificateSpec = CertificateSpec::Pem(
	r#"-----BEGIN CERTIFICATE-----
MIIBhjCCASygAwIBAgIUMiFVQw4ev0pbA5jYstm8UGQY4tswCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPTWFycyBSb3ZlciBDYW5EMB4XDTI1MTEyMzA5MzIxMVoXDTM1
MTEyMTA5MzIxMVowGjEYMBYGA1UEAwwPTWFycyBSb3ZlciBDYW5EMFYwEAYHKoZI
zj0CAQYFK4EEAAoDQgAEimSIBBzLYp8sLzqLHwbq8VXbR0eZOxdEGx17KwmxxNof
u3M6CB89HKt8QOA/3VaBE0jiE0n0iFzBtKJu1+Wz4aNTMFEwHQYDVR0OBBYEFMYF
9ytPFBbU9oCVy518Ax2HJv82MB8GA1UdIwQYMBaAFMYF9ytPFBbU9oCVy518Ax2H
Jv82MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhALer9SsIb8sS
bB+4AM/+tmVuuVIip1L3Z6ewDYD8FHenAiADuFBvAV30Iydk7fevTuA0fvfpP9pe
eXamI/HCiM6bzg==
-----END CERTIFICATE-----"#,
);

pub const ROVER_KEY: KeySpec =
	KeySpec::Bytes(&hex!("c5d575279e5fc6c691a084db64139f237a18a7044dbd4b5bc7d00e0a21f9eb5b"));

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
// Verifying Keys for Signature Verification
// ============================================================================

/// Helper function to create Mission Control's verifying key from its public key
pub fn mission_control_verifying_key() -> Secp256k1VerifyingKey {
	Secp256k1VerifyingKey::from_sec1_bytes(MISSION_CONTROL_PUB_KEY)
		.expect("MISSION_CONTROL_PUB_KEY is a valid secp256k1 public key")
}

/// Helper function to create Earth Relay's verifying key from its public key
#[allow(dead_code)]
pub fn earth_relay_verifying_key() -> Secp256k1VerifyingKey {
	Secp256k1VerifyingKey::from_sec1_bytes(EARTH_RELAY_PUB_KEY)
		.expect("EARTH_RELAY_PUB_KEY is a valid secp256k1 public key")
}

/// Helper function to create Mars Relay's verifying key from its public key
#[allow(dead_code)]
pub fn mars_relay_verifying_key() -> Secp256k1VerifyingKey {
	Secp256k1VerifyingKey::from_sec1_bytes(MARS_RELAY_PUB_KEY)
		.expect("MARS_RELAY_PUB_KEY is a valid secp256k1 public key")
}

/// Helper function to create Rover's verifying key from its public key
pub fn rover_verifying_key() -> Secp256k1VerifyingKey {
	Secp256k1VerifyingKey::from_sec1_bytes(ROVER_PUB_KEY).expect("ROVER_PUB_KEY is a valid secp256k1 public key")
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
pub const EARTH_KEY: KeySpec = EARTH_RELAY_KEY;
#[allow(dead_code)]
pub const EARTH_PUB_KEY: &[u8] = EARTH_RELAY_PUB_KEY;

#[allow(dead_code)]
pub const SATELLITE_CERT: CertificateSpec = MARS_RELAY_CERT;
#[allow(dead_code)]
pub const SATELLITE_KEY: KeySpec = MARS_RELAY_KEY;
#[allow(dead_code)]
pub const SATELLITE_PUB_KEY: &[u8] = MARS_RELAY_PUB_KEY;
