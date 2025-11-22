pub mod error;
pub mod policy;
pub mod utils;

// Re-exports
pub use x509_cert::*;

use crate::der::{Decode, DecodePem};
use crate::TightBeamError;

/// Specification for providing a certificate in various formats.
///
/// This enum allows certificates to be specified in multiple ways for flexible
/// configuration in const contexts (e.g., servlet! macro).
#[derive(Debug, Clone)]
pub enum CertificateSpec {
	/// PEM-encoded certificate string
	Pem(&'static str),

	/// DER-encoded certificate bytes
	Der(&'static [u8]),

	/// Pre-constructed Certificate instance
	Built(Box<Certificate>),
}

impl TryFrom<CertificateSpec> for Certificate {
	type Error = TightBeamError;

	fn try_from(spec: CertificateSpec) -> Result<Self, Self::Error> {
		match spec {
			CertificateSpec::Pem(pem_str) => {
				let cleaned = pem_str.lines().map(|l| l.trim()).collect::<Vec<_>>().join("\n");
				Ok(Certificate::from_pem(cleaned.as_bytes())?)
			}
			CertificateSpec::Der(der_bytes) => Ok(Certificate::from_der(der_bytes)?),
			CertificateSpec::Built(cert) => Ok(*cert),
		}
	}
}
