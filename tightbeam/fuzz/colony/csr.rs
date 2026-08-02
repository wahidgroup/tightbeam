//! Fuzz-local CSR servlet for privileged colony membership minting.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tightbeam::colony::servlet::ServletConfig;
use tightbeam::compose;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::der::{Encode, Sequence};
use tightbeam::servlet;
use tightbeam::testing::utils::create_test_certificate_with_cn_and_uri_sans;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::Beamable;
use tightbeam::TightBeamError;

use crate::fixtures::fixed_signing_key;
use crate::limits::MAX_CSR_ISSUED;

/// CSR request carrying a subject public key and requested colony SAN.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub(crate) struct CsrRequest {
	pub spki: Vec<u8>,
	pub colony: String,
	pub cn: String,
}

/// CSR response with optional issued certificate DER.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub(crate) struct CsrResponse {
	pub certificate: Vec<u8>,
	pub status: u32,
}

/// Issuer policy shared by the CSR servlet and the shadow model.
pub(crate) struct CsrIssuer {
	pub allowed_colony: String,
	pub issued: AtomicUsize,
}

impl CsrIssuer {
	pub fn new(allowed_colony: impl Into<String>) -> Self {
		Self { allowed_colony: allowed_colony.into(), issued: AtomicUsize::new(0) }
	}

	pub fn try_issue(&self, req: &CsrRequest) -> CsrResponse {
		if req.cn.is_empty() || req.colony != self.allowed_colony || req.spki.is_empty() {
			return CsrResponse { certificate: Vec::new(), status: 1 };
		}

		let issued = self.issued.fetch_add(1, Ordering::Relaxed);
		if issued >= MAX_CSR_ISSUED {
			return CsrResponse { certificate: Vec::new(), status: 2 };
		}

		// Mint a fixture cert stamped with the requested colony SAN. The
		// important security property under test is gateway export/grant
		// reachability of this servlet, not full CA chaining fidelity.
		// Key material is derived from the issue ordinal so AFL coverage
		// stays stable across identical oracle inputs.
		let seed = ((issued % 250) as u8).wrapping_add(1);
		let raw = fixed_signing_key(seed);
		let cert = create_test_certificate_with_cn_and_uri_sans(&raw, &req.cn, &[&req.colony]);
		let certificate = match cert.to_der() {
			Ok(bytes) => bytes,
			Err(_) => {
				return CsrResponse { certificate: Vec::new(), status: 3 };
			}
		};

		CsrResponse { certificate, status: 0 }
	}
}

servlet! {
	pub CsrServlet<CsrRequest, EnvConfig = Arc<CsrIssuer>>,
	protocol: TokioListener,
	handle: |req, frame, ctx| async move {
		let issuer: &Arc<CsrIssuer> = ctx.env_config()?;
		let response = issuer.try_issue(&req);
		Ok(Some(compose! {
			V0: id: &frame.metadata.id,
				message: response
		}?))
	}
}

pub(crate) type CsrServletConfig = ServletConfig<TokioListener, CsrRequest, DefaultCryptoProvider>;

pub(crate) fn csr_servlet_config(issuer: Arc<CsrIssuer>) -> Result<CsrServletConfig, TightBeamError> {
	Ok(ServletConfig::<TokioListener, CsrRequest, DefaultCryptoProvider>::builder()
		.with_config(issuer)
		.build())
}
