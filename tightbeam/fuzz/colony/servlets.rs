//! Work and stream servlet stubs for the colony fuzz topology.

use std::sync::Arc;

use tightbeam::colony::servlet::ServletConfig;
use tightbeam::compose;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::der::Sequence;
use tightbeam::servlet;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::Beamable;
use tightbeam::TightBeamError;

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

pub(crate) fn ping_servlet_config() -> Result<PingServletConfig, TightBeamError> {
	Ok(ServletConfig::<TokioListener, PingRequest, DefaultCryptoProvider>::builder()
		.with_mux_offer(Some(TransportOffer::mux(8)))
		.with_config(Arc::new(()))
		.build())
}
