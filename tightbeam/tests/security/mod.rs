#![cfg(all(
	feature = "std",
	feature = "transport",
	feature = "tcp",
	feature = "tokio",
	feature = "x509",
	feature = "secp256k1",
	feature = "signature",
	feature = "sha3",
	feature = "aead",
	feature = "testing",
	feature = "testing-csp"
))]

//! Security-focused transport integration tests.
//!
//! Each module exercises the threat controls documented in the README's
//! transport security table.

pub mod certificate_forgery;
pub mod common;
pub mod confidentiality;
pub mod dos_attack;
pub mod downgrade_attack;
pub mod forward_secrecy;
pub mod mitm_attack;
pub mod nonce_reuse;
pub mod replay_attack;
