//! Work and stream servlet stubs for the colony fuzz topology.

use std::sync::Arc;

use tightbeam::colony::servlet::ServletConfig;
use tightbeam::compose;
use tightbeam::crypto::key::Secp256k1KeyProvider;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::x509::CertificateSpec;
use tightbeam::der::Sequence;
use tightbeam::servlet;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::Beamable;
use tightbeam::TightBeamError;

use crate::fixtures::ClusterTestCerts;

#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub(crate) struct PingRequest {
	pub value: u32,
}

#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub(crate) struct PingResponse {
	pub doubled: u32,
}

servlet! {
	pub ColonyPingServlet<PingRequest, EnvConfig = ()>,
	protocol: TokioListener,
	handle: |req, frame, _ctx| async move {
		Ok(Some(compose! {
			V0: id: &frame.metadata.id,
				message: PingResponse { doubled: req.value * 2 }
		}?))
	},
	stream: |body, _ctx| async move {
		let bytes = body.into_bytes().await?;
		Ok(Some(compose! {
			V0: id: b"stream-echo-reply",
				message: PingResponse { doubled: bytes.len() as u32 }
		}?))
	},
	duplex: |body, reply, _ctx| async move {
		let mut body = body;
		let mut reply = reply;
		while let Some(chunk) = body.chunk().await? {
			reply.push(&chunk).await?;
		}

		Ok(())
	}
}

pub(crate) type PingServletConfig = ServletConfig<TokioListener, PingRequest, DefaultCryptoProvider>;

/// Servlet TLS identity is the org identity, anchored in the org trust
/// the gateway's forward pool validates against. Without it the
/// gateway-to-servlet hop cannot handshake and every work forward
/// degrades to `Unavailable`.
pub(crate) fn ping_servlet_config(certs: &ClusterTestCerts) -> Result<PingServletConfig, TightBeamError> {
	let transport_offer = TransportOffer::mux(8);
	let key = Arc::new(Secp256k1KeyProvider::from(certs.key.to_owned()));
	let cert = CertificateSpec::Built(Box::new(certs.cert.as_ref().clone()));

	Ok(ServletConfig::<TokioListener, PingRequest, DefaultCryptoProvider>::builder()
		.with_certificate(cert, key, vec![])?
		.with_mux_offer(Some(transport_offer))
		.with_config(Arc::new(()))
		.build())
}
