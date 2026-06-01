//! Consumer regression test for the `#[derive(Beamable)]` cfg-leak.
//!
//! This crate does not declare any Cargo features, yet enables tightbeam's
//! crypto features transitively.
#![deny(unexpected_cfgs)]

use der::Sequence;
use tightbeam::builder::{CheckAeadOid, CheckDigestOid, CheckSignatureOid};
use tightbeam::crypto::aead::Aes256GcmOid;
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::sign::ecdsa::Secp256k1Signature;
use tightbeam::Beamable;

#[derive(Beamable, Clone, Debug, PartialEq, Eq, Sequence)]
#[beam(profile = 1)]
pub struct Ping {
	pub nonce: u64,
}

/// Compiles only when the derive-generated checker impls are present for the
/// profile's digest, AEAD, and signature OID types.
fn _assert_checker_impls_present()
where
	Ping: CheckDigestOid<Sha3_256> + CheckAeadOid<Aes256GcmOid> + CheckSignatureOid<Secp256k1Signature>,
{
}
