pub mod error;
pub mod policy;
pub mod store;
pub mod utils;

mod key;
mod peer;

pub use key::{CanonicalKey, CurvePoints, KeyCurves, KeyListError, Sec1Curve};
pub use peer::{CertificateUse, ErasedSigning, KeyPurposes, PeerCertificate};
pub use x509_cert::{attr, ext, name, serial_number, time, Certificate, TbsCertificate, Version};

#[cfg(any(
	feature = "transport-cms",
	feature = "transport-hpke",
	all(test, feature = "transport")
))]
pub(crate) use key::KeyIdentity;
#[cfg(feature = "std")]
pub use key::KeyIndex;
pub(crate) use key::KeyList;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub(crate) use key::Sec1Point;
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

/// A certificate given as PEM text, as DER bytes, or as a built
/// [`Certificate`].
///
/// The PEM and DER forms are `'static`, so a const context such as the
/// `servlet!` macro can name a certificate in either form.
#[derive(Debug, Clone)]
pub enum CertificateSpec {
	/// A PEM-encoded certificate string.
	Pem(&'static str),

	/// The DER-encoded bytes of a certificate.
	Der(&'static [u8]),

	/// A certificate value that is already built.
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
