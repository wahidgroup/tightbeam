//! Socket-level CMS handshake integration test.
//!
//! Every other wire test negotiates ECIES; the CMS orchestrators are
//! otherwise only driven through in-memory loopback. This scenario runs
//! the CMS key-transport handshake over a real TCP socket through public
//! interfaces only: the `server!` policy list selects the protocol per
//! accepted connection and [`ClientBuilder`] carries the server chain the
//! client's first flight encrypts to.

#![cfg(all(
	feature = "tcp",
	feature = "testing",
	feature = "instrument",
	feature = "transport-cms"
))]

use std::sync::Arc;

use tightbeam::crypto::key::{Secp256k1KeyProvider, SigningKeyProvider};
use tightbeam::crypto::x509::CertificateSpec;
use tightbeam::exactly;
use tightbeam::instrumentation::events;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::server;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::{create_v0_tightbeam, ClientEnv, SetupEnv};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::HandshakeProtocolKind;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::{ClientBuilder, ConnectionBuilder, X509ClientConfig};
use tightbeam::utils::urn::Urn;
use tightbeam::x509::Certificate;
use tightbeam::{Frame, TightBeamError};
use tokio::task::JoinHandle;

use crate::common::security::{pinning_trust_store, random_signing_key, test_certificate, ServerMaterials};
use crate::transport::support::bind_mutual_listener;

pub(crate) const CMS_WIRE_ECHOED: Urn<'static> = Urn::new("test", "event:cms-socket/cms-wire-echoed");

/// Mutual-auth CMS fixture: server materials plus the client identity the
/// server pins.
struct CmsWireContext {
	materials: ServerMaterials,
	client_certificate: Arc<Certificate>,
	client_provider: Arc<dyn SigningKeyProvider>,
}

impl CmsWireContext {
	fn generate() -> Self {
		let signing_key = random_signing_key();
		let client_certificate = Arc::new(test_certificate(&signing_key));
		let client_provider: Arc<dyn SigningKeyProvider> = Arc::new(Secp256k1KeyProvider::from(signing_key));
		Self { materials: ServerMaterials::generate(), client_certificate, client_provider }
	}
}

/// Echo server that answers CMS handshakes instead of the ECIES default;
/// gate verdicts audit into `trace`.
async fn start_cms_echo_server(
	ctx: &Arc<CmsWireContext>,
	trace: &TraceCollector,
) -> Result<(JoinHandle<()>, TightBeamSocketAddr), TightBeamError> {
	let (listener, addr) = bind_mutual_listener(&ctx.materials, &ctx.client_certificate).await?;
	let addr = TightBeamSocketAddr(addr);
	let trace = trace.share();
	let handle = server! {
		protocol TokioListener: listener,
		policies: {
			with_trace: [ trace.share() ],
			with_handshake_protocol: [ HandshakeProtocolKind::Cms ]
		},
		handle: move |frame: Frame| async move { Ok(Some(frame)) }
	};

	Ok((handle, addr))
}

tb_assert_spec! {
	pub CmsSocketSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::GATE_ACCEPT, exactly!(1)),
			(CMS_WIRE_ECHOED, exactly!(1), equals!(true))
		]
	}
}

// The client encrypts its first flight to the pre-known server chain
// (key transport), the pinning server validates the client certificate,
// and an application frame round-trips over the derived session keys.
tb_scenario! {
	name: cms_handshake_round_trips_over_tcp,
	spec: CmsSocketSpec,
	environment ServiceClient {
		context: CmsWireContext::generate(),
		server: |SetupEnv { context: ctx, trace }| async move {
			start_cms_echo_server(&ctx, &trace).await
		},
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let trust_store = pinning_trust_store(&ctx.materials.certificate)?;
			let client_certificate = ctx.client_certificate.as_ref().to_owned();
			let identity = CertificateSpec::Built(Box::new(client_certificate));
			let server_chain = vec![Certificate::clone(&ctx.materials.certificate)];

			let builder = ClientBuilder::<TokioListener>::builder()
				.with_trust_store(trust_store)
				.with_client_identity(identity, Arc::clone(&ctx.client_provider))?
				.with_server_certificate_chain(server_chain)
				.with_handshake_protocol(HandshakeProtocolKind::Cms)
				.build();
			let mut client = builder.connect(addr).await?;

			let frame = create_v0_tightbeam(Some("cms-wire"), None);
			let reply = client.emit(frame.to_owned(), None).await?;
			trace.event_with(CMS_WIRE_ECHOED, &[], reply == Some(frame))?;
			Ok(())
		}
	}
}
