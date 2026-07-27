//! Mux ping / ack control-plane scenarios.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use tightbeam::exactly;
use tightbeam::instrumentation::events;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::{ClientEnv, SetupEnv};
use tightbeam::transport::envelopes::{MuxEnvelope, MuxPingPackage};
use tightbeam::transport::{EnvelopeSink, EnvelopeSource, TransportEnvelope, TransportError};
use tightbeam::utils::urn::Urn;
use tightbeam::Frame;

use crate::transport::support::{await_ok, bind_encrypted_listener, mux_frame, mux_offer, record_spawned_event};

use super::common::*;

pub(crate) const CLIENT_PING_ACKED: Urn<'static> = Urn::new("test", "event:ping/client-ping-acked");
pub(crate) const FOLLOWUP_ECHOES_AFTER_STRAY_ACK: Urn<'static> =
	Urn::new("test", "event:ping/followup-echoes-after-stray-ack");
pub(crate) const HANDLER_SAW_ONLY_STREAM: Urn<'static> = Urn::new("test", "event:ping/handler-saw-only-stream");
pub(crate) const INFLIGHT_DRAINS_TO_ECHO: Urn<'static> = Urn::new("test", "event:ping/inflight-drains-to-echo");
pub(crate) const PING_REFUSED_DRAINING: Urn<'static> = Urn::new("test", "event:ping/ping-refused-draining");
pub(crate) const PROBE_ANSWERED_WITH_MATCHING_ACK: Urn<'static> =
	Urn::new("test", "event:ping/probe-answered-with-matching-ack");
pub(crate) const SERVER_PING_ACKED: Urn<'static> = Urn::new("test", "event:ping/server-ping-acked");
pub(crate) const STREAM_ECHOES_AFTER_PINGS: Urn<'static> = Urn::new("test", "event:ping/stream-echoes-after-pings");

tb_assert_spec! {
	pub MuxPingRoundtripSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(CLIENT_PING_ACKED, exactly!(1), equals!(true)),
			(SERVER_PING_ACKED, exactly!(1), equals!(true)),
			(STREAM_ECHOES_AFTER_PINGS, exactly!(1), equals!(true)),
			(HANDLER_SAW_ONLY_STREAM, exactly!(1), equals!(true))
		]
	}
}

// Ping resolves in both directions and never invokes the handler.
// The server-to-client probe is acked with no responder serving the
// client side, proving the ack terminates in the reader driver.
tb_scenario! {
	name: mux_ping_roundtrip,
	spec: MuxPingRoundtripSpec,
	environment ServiceClient {
		context: PingContext::generate(),
		server: |SetupEnv { trace, context: ping }| async move {
			let (listener, addr) = bind_encrypted_listener(&ping.materials).await?;
			let task = tokio::spawn(async move {
				let Ok((server, responder)) = accept_mux_server(listener, mux_offer(4), trace.share()).await else {
					return;
				};

				let ping_ctx = Arc::clone(&ping);
				let handler = move |frame: Arc<Frame>| {
					ping_ctx.handler_calls.fetch_add(1, Ordering::SeqCst);
					core::future::ready(echo_response(&frame))
				};

				let _serve = tokio::spawn(responder.serve(handler));

				let acked = server.handle.ping().await.is_ok();
				record_spawned_event(&trace, SERVER_PING_ACKED, acked);

				ping.server_ping_done.notify_one();
			});
			Ok((task, addr))
		},
		client: |ClientEnv { trace, context: ping, addr }| async move {
			let client = connect_mux_client(addr, &ping.materials, 4, trace.share()).await?;
			trace.event_with(CLIENT_PING_ACKED, &[], client.handle().ping().await.is_ok())?;

			ping.server_ping_done.notified().await;

			let frame = mux_frame("mux-ping-alive");
			let echoed = client.handle().emit_on_stream(&frame).await?;
			trace.event_with(STREAM_ECHOES_AFTER_PINGS, &[], is_echo(echoed, &frame))?;

			trace.event_with(
				HANDLER_SAW_ONLY_STREAM,
				&[],
				ping.handler_calls.load(Ordering::SeqCst) == 1,
			)?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxPingWireAckSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PROBE_ANSWERED_WITH_MATCHING_ACK, exactly!(1), equals!(true)),
			(FOLLOWUP_ECHOES_AFTER_STRAY_ACK, exactly!(1), equals!(true))
		]
	}
}

// A probe written on raw halves is answered with its ack, and an
// unsolicited ack is discarded without tearing down the connection.
tb_scenario! {
	name: mux_ping_wire_ack,
	spec: MuxPingWireAckSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let mut link = establish_client_mux_server_raw(4, trace.share()).await?;

			let probe = MuxPingPackage::new(false, 42);
			link.server_writer.write_envelope(probe.into()).await?;

			let ack = link.server_reader.read_envelope().await?;
			let ack_ok = matches!(
				&ack,
				TransportEnvelope::Mux(MuxEnvelope::Ping(package)) if package.ack() && package.opaque() == 42
			);

			trace.event_with(PROBE_ANSWERED_WITH_MATCHING_ACK, &[], ack_ok)?;

			let stray_ack = MuxPingPackage::new(true, 999);
			link.server_writer.write_envelope(stray_ack.into()).await?;

			let followup_echoed = raw_echo_roundtrip(&mut link, &mux_frame("mux-ping-follow-up")).await?;
			trace.event_with(FOLLOWUP_ECHOES_AFTER_STRAY_ACK, &[], followup_echoed)?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxPingDrainingSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::MUX_GOAWAY_SENT, exactly!(1)),
			(events::MUX_EMIT_DRAINING, exactly!(1)),
			(events::MUX_GOAWAY_RECV, exactly!(1)),
			(PING_REFUSED_DRAINING, exactly!(1), equals!(true)),
			(INFLIGHT_DRAINS_TO_ECHO, exactly!(1), equals!(true))
		]
	}
}

// Once GoAway is sent, new pings are refused as `Draining` while the
// in-flight stream still drains to completion.
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
			ctx.started.notified().await;

			let shutdown_future = kick_shutdown(client.handle()).await;
			let refused = client.handle().ping().await;
			trace.event_with(
				PING_REFUSED_DRAINING,
				&[],
				matches!(refused, Err(TransportError::Draining)),
			)?;

			ctx.release.notify_one();

			let echoed = await_ok(inflight_task, "in-flight emit task must not panic").await?;
			trace.event_with(INFLIGHT_DRAINS_TO_ECHO, &[], is_echo(echoed, &frame_inflight))?;

			shutdown_future.await?;
			Ok(())
		}
	}
}
