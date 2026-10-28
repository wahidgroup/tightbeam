//! Peer-list gate integration tests.
//!
//! [`PeerListGate`] keys on the connection's mutually authenticated peer
//! identity: the collector gate on a mux server bars or admits a client
//! by the SPKI DER of its validated certificate, so a refused frame stops
//! ahead of the handler.

#![cfg(all(feature = "tcp", feature = "testing", feature = "instrument"))]

use core::num::NonZeroUsize;
use std::sync::Arc;

use tightbeam::colony::hive::PeerListGate;
use tightbeam::crypto::key::{Secp256k1KeyProvider, SigningKeyProvider};
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::CertificateSpec;
use tightbeam::der::Encode;
use tightbeam::instrumentation::events;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::server;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::fixtures::TestTrace;
use tightbeam::testing::{ClientEnv, ScenarioConfig, SetupEnv, TestFrame};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::policy::CollectorGateConfig;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::{
	ConnectionBuilder, ConnectionPool, PoolConfig, PooledClient, TransportError, TransportFailure,
};
use tightbeam::x509::Certificate;
use tightbeam::{absent, exactly};
use tightbeam::{Frame, TightBeamError};
use tokio::task::JoinHandle;

use crate::common::security::{pinning_trust_store, random_signing_key, test_certificate, ServerMaterials};
use crate::transport::support::bind_mutual_listener;

/// A mutual-auth doorman fixture: the server materials and the client
/// identity the gate lists.
struct DoormanContext {
	materials: ServerMaterials,
	client_certificate: Arc<Certificate>,
	client_provider: Arc<dyn SigningKeyProvider>,
}

impl DoormanContext {
	fn generate() -> Self {
		let signing_key = random_signing_key();
		let client_certificate = Arc::new(test_certificate(&signing_key));
		let client_provider: Arc<dyn SigningKeyProvider> = Arc::new(Secp256k1KeyProvider::from(signing_key));
		Self { materials: ServerMaterials::generate(), client_certificate, client_provider }
	}

	/// The client's account key: the SPKI DER the peer-list gate
	/// matches against.
	fn client_key(&self) -> Result<Vec<u8>, TightBeamError> {
		Ok(self.client_certificate.tbs_certificate.subject_public_key_info.to_der()?)
	}
}

/// An echo server with a peer-list door gate ahead of the handler. The gate
/// verdicts audit into `trace`.
async fn start_doorman_server(
	ctx: &Arc<DoormanContext>,
	gate: PeerListGate,
	trace: &TraceCollector,
) -> Result<(JoinHandle<()>, TightBeamSocketAddr), TightBeamError> {
	let (listener, addr) = bind_mutual_listener(&ctx.materials, &ctx.client_certificate).await?;
	let addr = TightBeamSocketAddr(addr);
	let trace = trace.share();
	let handle = server! {
		protocol TokioListener: listener,
		policies: {
			with_trace: [ trace.share() ],
			with_mux_offer: [ Some(TransportOffer::mux(1)) ],
			// Policy expressions re-evaluate per accepted connection.
			with_collector_gate: [ gate.clone() ]
		},
		handle: move |frame: Frame| async move { Ok(Some(frame)) }
	};

	Ok((handle, addr))
}

/// Builds a pool that dials with the client identity the gate lists.
fn doorman_pool(
	ctx: &DoormanContext,
	trace: &TraceCollector,
) -> Result<Arc<ConnectionPool<TokioListener>>, TightBeamError> {
	let trust_store = pinning_trust_store(&ctx.materials.certificate)?;
	let client_certificate = ctx.client_certificate.as_ref().to_owned();
	let identity = CertificateSpec::Built(Box::new(client_certificate));
	let client_provider = Arc::clone(&ctx.client_provider);
	let config = PoolConfig {
		idle_timeout: None,
		max_connections: NonZeroUsize::MIN,
		mux_offer: Some(Arc::new(TransportOffer::mux(1))),
	};

	let pool = Arc::new(
		ConnectionPool::<TokioListener>::builder()
			.with_config(config)
			.with_trust_store(trust_store)
			.with_client_identity(SigningIdentity::from_spec(identity, client_provider)?)
			.with_trace(trace.share())
			.build(),
	);
	Ok(pool)
}

/// Knocks once on the door: emits a frame and reports whether it echoed.
async fn knock(lease: &mut PooledClient<TokioListener>) -> Result<bool, TightBeamError> {
	let frame = TestFrame::v0(Some("door-knock"), None);
	let reply = lease.emit(frame.to_owned(), None).await?;
	Ok(reply == Some(frame))
}

// The trace sets the detail flag, so the one policy step of the gate shows
// that the server records on the trace, and `absent!()` on the handler span
// reads the refusal of the gate.
tb_assert_spec! {
	pub PeerDenyListSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::GATE_REJECT, exactly!(1)),
			(events::POLICY_EVAL, exactly!(1)),
			(events::HANDLER_ENTER, absent!())
		]
	}
}

// A deny-listed public key completes the mutual handshake, but the door
// gate matches the session's peer identity and refuses every frame
// before the handler sees one.
tb_scenario! {
	name: peer_deny_listed_client_is_barred,
	config: ScenarioConfig::builder()
		.with_spec(PeerDenyListSpec::latest())
		.with_trace(TestTrace::with_detail(true))
		.build(),
	environment ServiceClient {
		context: DoormanContext::generate(),
		server: |SetupEnv { context: ctx, trace }| async move {
			let gate = PeerListGate::deny([ctx.client_key()?])?;
			start_doorman_server(&ctx, gate, &trace).await
		},
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let pool = doorman_pool(&ctx, &trace)?;
			let mut lease = pool.connect(addr).await?;

			let outcome = lease.emit(TestFrame::v0(Some("door-knock"), None), None).await;
			let barred = matches!(outcome, Err(TransportError::OperationFailed(TransportFailure::PermissionDenied)));
			assert!(barred, "the deny list bars the client");
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub PeerAllowListSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POOL_DIAL, exactly!(1)),
			(events::GATE_ACCEPT, exactly!(1))
		]
	}
}

// The same gate in allow mode admits the listed key: the allow list
// proves the gate keys on the session identity, not on frames.
tb_scenario! {
	name: peer_allow_listed_client_is_admitted,
	spec: PeerAllowListSpec,
	environment ServiceClient {
		context: DoormanContext::generate(),
		server: |SetupEnv { context: ctx, trace }| async move {
			let gate = PeerListGate::allow([ctx.client_key()?])?;
			start_doorman_server(&ctx, gate, &trace).await
		},
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let pool = doorman_pool(&ctx, &trace)?;
			let mut lease = pool.connect(addr).await?;

			let echoed = knock(&mut lease).await?;
			assert!(echoed, "the allow-listed client's knock echoes");
			Ok(())
		}
	}
}
