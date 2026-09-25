//! Cause chains of the `Errorizable` derive, observed from outside tightbeam.
//!
//! `#[from]` declares that the payload is the cause, so the derive reports that
//! payload through `Error::source`. A consumer walking the chain is the only
//! place the emitted arm is observable, because the arm is generated code.

use core::error::Error;

use tightbeam::crypto::x509::error::CertificateValidationError;
use tightbeam::transport::TransportError;

#[test]
fn from_variant_reports_its_payload_as_the_cause() {
	let cause = CertificateValidationError::Expired;
	let wrapped = TransportError::from(cause);
	let source = wrapped.source();
	let recovered = source.and_then(|err| err.downcast_ref::<CertificateValidationError>());
	assert!(matches!(recovered, Some(CertificateValidationError::Expired)));
}
