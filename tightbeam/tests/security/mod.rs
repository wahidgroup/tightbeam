#![cfg(all(
	feature = "tcp",
	feature = "tokio",
	feature = "testing-csp",
	feature = "transport-hpke",
	feature = "instrument"
))]

//! The transport integration tests that target security.
//!
//! Each module exercises a threat control of the README's transport security
//! table, and `algorithm_confusion` holds the negative control of a primitive
//! that those controls rest on.
//!
//! Two other homes hold the rest of that table:
//! - `tests/transport/multiplex/` holds the rekey ephemerals, stream cap
//!   inflation, reassembly exhaustion, flow-control overrun, and rapid reset.
//! - The crate test `a_client_refuses_an_accept_that_departs_from_its_offer` in
//!   `transport::handshake::negotiation` holds the unsolicited transport
//!   accept, because a server answers an offer alone.

pub mod algorithm_confusion;
pub mod attribute_injection;
pub mod certificate_forgery;
pub mod common;
pub mod confidentiality;
pub mod countersignature_evidence;
pub mod dos_attack;
pub mod downgrade_attack;
pub mod envelope_tamper;
pub mod forward_secrecy;
pub mod live;
pub mod mitm_attack;
pub mod nonce_reuse;
pub mod receipt_activation;
pub mod receipt_confidentiality;
pub mod receipt_integrity;
pub mod record_freshness;
pub mod replay_attack;
pub mod settlement_ordering;
pub mod splice_attack;
pub mod transcript_binding;
