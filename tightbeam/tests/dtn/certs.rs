//! X.509 Certificates for DTN Mutual Authentication
//!
//! This module contains static X.509 certificates and keys for the DTN architecture:
//! - Earth Ground Station
//! - Relay Satellite  
//! - Mars Rover
//!
//! Mutual authentication flows:
//! - Earth ↔ Satellite (mutual TLS)
//! - Satellite ↔ Rover (mutual TLS)
//!
//! All certificates are configured for 10-year validity and use secp256k1 keys.

#![cfg(all(
	feature = "testing-csp",
	feature = "testing-fdr",
	feature = "std",
	feature = "tcp",
	feature = "tokio",
	feature = "x509",
	feature = "secp256k1",
	feature = "signature",
	feature = "sha3"
))]

use tightbeam::{
	crypto::{
		key::KeySpec,
		sign::ecdsa::Secp256k1VerifyingKey,
		x509::{policy::PublicKeyPinning, CertificateSpec},
	},
	hex,
};

// ============================================================================
// Earth Ground Station Certificates
// ============================================================================

pub const EARTH_CERT: CertificateSpec = CertificateSpec::Pem(
	r#"-----BEGIN CERTIFICATE-----
MIIBiTCCATCgAwIBAgIUQICLr8Q2BAkHUeZBD7YJKA5my58wCgYIKoZIzj0EAwIw
HDEaMBgGA1UEAwwRRWFydGggR3JvdW5kIENhbkQwHhcNMjUxMTIzMDkzMTM1WhcN
MzUxMTIxMDkzMTM1WjAcMRowGAYDVQQDDBFFYXJ0aCBHcm91bmQgQ2FuRDBWMBAG
ByqGSM49AgEGBSuBBAAKA0IABLtUWsGHv3+HB9FldYpkTGYT+CFXxOmNtZZlWJUi
25B/gN/DsMc3fJLVT6AHVROmxpe66ccj3EHxV2TAZcFF41yjUzBRMB0GA1UdDgQW
BBRBztA55+UJbqCzP9LRSHUMfJ8S3TAfBgNVHSMEGDAWgBRBztA55+UJbqCzP9LR
SHUMfJ8S3TAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIApq3lxB
m9361ZflyT9r+7og7daQR7CZh8riOfBDFWNdAiASHJB7cIh7o/aJaWEnz0EA7izg
qkpQBgcdW62aAfgSAg==
-----END CERTIFICATE-----"#,
);

pub const EARTH_KEY: KeySpec =
	KeySpec::Bytes(&hex!("fd5e789f827aca85a7f8f9705330affe00cc367d2ac816f27fcbd65d78d2794c"));

pub const EARTH_PUB_KEY: &[u8] = &hex!("04bb545ac187bf7f8707d165758a644c6613f82157c4e98db59665589522db907f80dfc3b0c7377c92d54fa0075513a6c697bae9c723dc41f15764c065c145e35c");

// ============================================================================
// Relay Satellite Certificates
// ============================================================================

pub const SATELLITE_CERT: CertificateSpec = CertificateSpec::Pem(
	r#"-----BEGIN CERTIFICATE-----
MIIBkDCCATagAwIBAgIUWrY/jLzXp8e1HhOLfQ48wKCzXxowCgYIKoZIzj0EAwIw
HzEdMBsGA1UEAwwUUmVsYXkgU2F0ZWxsaXRlIENhbkQwHhcNMjUxMTIzMDkzMTU4
WhcNMzUxMTIxMDkzMTU4WjAfMR0wGwYDVQQDDBRSZWxheSBTYXRlbGxpdGUgQ2Fu
RDBWMBAGByqGSM49AgEGBSuBBAAKA0IABH1zW7qROcQgwCFVbrb/9N2UqUlBNZga
qcZJRhoL23vyazdvlgO6vmcadBuYjzK5Xfhqt+PrdLdR1rdsI8bw77KjUzBRMB0G
A1UdDgQWBBRxiuLpFn9C5WfUfPXFRquhpPjXFDAfBgNVHSMEGDAWgBRxiuLpFn9C
5WfUfPXFRquhpPjXFDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUC
IQDevkc8UvD8QyzOBWHAoUzjm4Lc+XfJYexkXdU+iKYLywIgHoXeOX0xpjB6fcdh
iUZv4zZywor4EeuslfKayvB8WZ0=
-----END CERTIFICATE-----"#,
);

pub const SATELLITE_KEY: KeySpec =
	KeySpec::Bytes(&hex!("50e9a6d72d676bf6dff8d90e2fad367a09607ed8f61127b0547673a72c655ffe"));

pub const SATELLITE_PUB_KEY: &[u8] = &hex!("047d735bba9139c420c021556eb6fff4dd94a9494135981aa9c649461a0bdb7bf26b376f9603babe671a741b988f32b95df86ab7e3eb74b751d6b76c23c6f0efb2");

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
// Public Key Pinning Configurations
// ============================================================================

/// Earth's pinning policy: accepts only Satellite's public key
pub const EARTH_PINNING: PublicKeyPinning<1> = PublicKeyPinning::new([SATELLITE_PUB_KEY]);

/// Satellite's pinning policy for Earth connection
pub const SATELLITE_PINNING_EARTH: PublicKeyPinning<1> = PublicKeyPinning::new([EARTH_PUB_KEY]);

/// Satellite's pinning policy for Rover connection
pub const SATELLITE_PINNING_ROVER: PublicKeyPinning<1> = PublicKeyPinning::new([ROVER_PUB_KEY]);

/// Rover's pinning policy: accepts only Satellite's public key
pub const ROVER_PINNING: PublicKeyPinning<1> = PublicKeyPinning::new([SATELLITE_PUB_KEY]);

// ============================================================================
// Verifying Keys for Signature Verification
// ============================================================================

/// Helper function to create Earth's verifying key from its public key
pub fn earth_verifying_key() -> Secp256k1VerifyingKey {
	Secp256k1VerifyingKey::from_sec1_bytes(EARTH_PUB_KEY)
		.expect("EARTH_PUB_KEY is a valid secp256k1 public key")
}

/// Helper function to create Satellite's verifying key from its public key
pub fn satellite_verifying_key() -> Secp256k1VerifyingKey {
	Secp256k1VerifyingKey::from_sec1_bytes(SATELLITE_PUB_KEY)
		.expect("SATELLITE_PUB_KEY is a valid secp256k1 public key")
}

/// Helper function to create Rover's verifying key from its public key
pub fn rover_verifying_key() -> Secp256k1VerifyingKey {
	Secp256k1VerifyingKey::from_sec1_bytes(ROVER_PUB_KEY)
		.expect("ROVER_PUB_KEY is a valid secp256k1 public key")
}

// ============================================================================
// Shared Encryption Key (Earth ↔ Rover)
// ============================================================================

/// Generate a shared AES-256-GCM cipher for end-to-end encryption between Earth and Rover
/// The Satellite cannot decrypt messages as it does not possess this key
pub fn generate_shared_cipher() -> tightbeam::crypto::aead::Aes256Gcm {
	use tightbeam::crypto::aead::{Aes256Gcm, Key, KeyInit};
	// For testing: use a deterministic key
	// In production, this would be securely exchanged or derived
	let key_bytes = hex!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
	Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes))
}
