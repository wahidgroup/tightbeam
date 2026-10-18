pub mod error;
pub mod policy;
pub mod store;
pub mod utils;

mod peer;

pub use peer::{CertificateUse, ErasedSigning, KeyPurposes, PeerCertificate};
pub use x509_cert::{attr, ext, name, serial_number, time, Certificate, TbsCertificate, Version};

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub(crate) use peer::AgreementPoint;
#[cfg(all(feature = "hpke", feature = "signature", feature = "ecdh"))]
pub(crate) use peer::EllipticCurvePoint;
#[cfg(all(feature = "hpke", feature = "signature"))]
pub use peer::KeyAgreement;
#[cfg(feature = "signature")]
pub use peer::Signing;
#[cfg(feature = "transport-cms")]
pub(crate) use peer::SubjectKey;
#[cfg(feature = "builder")]
pub use x509_cert::builder;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

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
