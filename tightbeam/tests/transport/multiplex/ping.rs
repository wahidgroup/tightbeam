//! Mux scenarios for the ping and ack control plane.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use tightbeam::exactly;
use tightbeam::instrumentation::events;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::fixtures::TestTrace;
use tightbeam::testing::{ClientEnv, ScenarioConfig, SetupEnv};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::envelopes::{MuxEnvelope, MuxPingPackage};
use tightbeam::transport::{EnvelopeSink, EnvelopeSource, TransportEnvelope, TransportError};
use tightbeam::{Frame, TightBeamError};

use crate::common::security::expectation_failure;
use crate::transport::support::{await_ok, bind_encrypted_listener, mux_frame, mux_offer};

use super::common::*;

tb_assert_spec! {
	pub MuxPingRoundtripSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::ROUTE_STEP, exactly!(1))
		]
	}
}

// A ping resolves in both directions and never invokes the handler, so the
// trace holds one route step, the emit's. The client acks the server's probe
// with no responder on its side, which proves that the reader driver acks.
tb_scenario! {
	name: mux_ping_roundtrip,
	config: ScenarioConfig::builder()
		.with_spec(MuxPingRoundtripSpec::latest())
		.with_trace(TestTrace::with_detail(true))
		.build(),
	environment ServiceClient {
		context: PingContext::generate(),
		server: |SetupEnv { trace, context: ping }| async move {
			let (listener, addr) = bind_encrypted_listener(&ping.materials).await?;
			let task = tokio::spawn(async move {
				let Ok((server, responder)) = accept_mux_server(listener, mux_offer(4), trace.share()).await else {
					return;
				};

				let handler = |frame: Arc<Frame>| core::future::ready(echo_response(&frame));
				let serving = tokio::spawn(responder.serve(handler));
				let acked = server.handle.ping().await.is_ok();

				ping.server_ping_acked.store(acked, Ordering::SeqCst);
				ping.server_ping_done.raise();

				// The endpoint holds the drivers of the connection, so the task
				// holds the endpoint until the serve ends with the connection.
				let _served = serving.await;
			});
			Ok((task, addr))
		},
		client: |ClientEnv { trace, context: ping, addr }| async move {
			let client = connect_mux_client(addr, &ping.materials, 4, trace.share()).await?;
			assert!(client.handle().ping().await.is_ok(), "the client ping must resolve with the server's ack");

			ping.server_ping_done.wait("the server ping must finish").await?;

			assert!(
				ping.server_ping_acked.load(Ordering::SeqCst),
				"the server ping must resolve with the client reader's ack"
			);

			let frame = mux_frame("mux-ping-alive");
			let echoed = client.handle().emit_on_stream(&frame).await?;
			assert!(is_echo(echoed, &frame), "a stream must still echo after the pings");

			Ok(())
		}
	}
}

/// Read the next envelope, and require it to be the ack of the probe that
/// carries `opaque`.
///
/// # Errors
///
/// - [`TightBeamError`] -- the read fails.
/// - An expectation failure -- the envelope is another record.
async fn expect_ping_ack(link: &mut ClientMuxServerRaw, opaque: u64) -> Result<(), TightBeamError> {
	let ack = link.server_reader.read_envelope().await?;
	match ack {
		TransportEnvelope::Mux(MuxEnvelope::Ping(package)) if package.ack() && package.opaque() == opaque => Ok(()),
		_ => Err(expectation_failure(
			"the client reader must answer the probe with a matching ack",
		)),
	}
}

/// The mux client answers a probe written on raw halves with its ack, and it
/// discards an unsolicited ack and keeps the connection up.
#[tokio::test]
async fn mux_ping_wire_ack() -> Result<(), TightBeamError> {
	let mut link = establish_client_mux_server_raw(4, TraceCollector::new()).await?;

	let probe = MuxPingPackage::new(false, 42);
	link.server_writer.write_envelope(probe.into()).await?;
	expect_ping_ack(&mut link, 42).await?;

	let stray_ack = MuxPingPackage::new(true, 999);
	link.server_writer.write_envelope(stray_ack.into()).await?;

	let followup_echoed = raw_echo_roundtrip(&mut link, &mux_frame("mux-ping-follow-up")).await?;
	assert!(followup_echoed, "the connection must stay up after a stray ack");
	Ok(())
}

tb_assert_spec! {
	pub MuxPingDrainingSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::MUX_GOAWAY_SENT, exactly!(1)),
			(events::MUX_EMIT_DRAINING, exactly!(1)),
			(events::MUX_GOAWAY_RECV, exactly!(1))
		]
	}
}

// Once the client sends GoAway, it refuses new pings as `Draining`, and the
// in-flight stream drains to completion.
tb_scenario! {
	name: mux_ping_draining,
	spec: MuxPingDrainingSpec,
	environment ServiceClient {
		context: GatedMuxContext::generate(),
		server: |env| async move {
			start_mux_server(&env.context.materials, 4, gated_echo(Arc::clone(&env.context)), env.trace).await
		},
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let client = connect_mux_client(addr, &ctx.materials, 4, trace.share()).await?;

			let frame_inflight = mux_frame("mux-ping-inflight");
			let inflight_task = spawn_emit(client.handle(), frame_inflight.to_owned());
			ctx.started.wait("the in-flight emit must start the gated handler").await?;

			let shutdown_future = kick_shutdown(client.handle()).await;
			let refused = client.handle().ping().await;
			assert!(matches!(refused, Err(TransportError::Draining)), "a ping after the GoAway must fail as draining");

			ctx.release.notify_one();

			let echoed = await_ok(inflight_task, "in-flight emit task must not panic").await?;
			assert!(is_echo(echoed, &frame_inflight), "the in-flight stream must drain to its echo");

			shutdown_future.await?;
			Ok(())
		}
	}
}
