//! Mux ping / ack control-plane scenarios.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use tightbeam::exactly;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::{ClientEnv, SetupEnv};
use tightbeam::transport::envelopes::{MuxEnvelope, MuxPingPackage};
use tightbeam::transport::{EnvelopeSink, EnvelopeSource, TransportEnvelope, TransportError};
use tightbeam::Frame;

use crate::transport::support::{await_ok, bind_encrypted_listener};

use super::common::*;

tb_assert_spec! {
	pub MuxPingRoundtripSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(client_ping_acked, exactly!(1), equals!(true)),
			(server_ping_acked, exactly!(1), equals!(true)),
			(stream_echoes_after_pings, exactly!(1), equals!(true)),
			(handler_saw_only_stream, exactly!(1), equals!(true))
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
				let Ok((server, responder)) = accept_mux_server(listener, mux_offer(4)).await else {
					return;
				};

				let ping_ctx = Arc::clone(&ping);
				let handler = move |frame: Arc<Frame>| {
					ping_ctx.handler_calls.fetch_add(1, Ordering::SeqCst);
					core::future::ready(echo_response(&frame))
				};
				let _serve = tokio::spawn(responder.serve(handler));

				let acked = server.handle.ping().await.is_ok();
				trace
					.event_with(MuxPingRoundtripSpec::server_ping_acked, &[], acked)
					.expect("server_ping_acked must record");
				ping.server_ping_done.notify_one();
			});
			Ok((task, addr))
		},
		client: |ClientEnv { trace, context: ping, addr }| async move {
			let client = connect_mux_client(addr, &ping.materials, 4).await?;
			trace.event_with(MuxPingRoundtripSpec::client_ping_acked, &[], client.handle().ping().await.is_ok())?;

			ping.server_ping_done.notified().await;

			let frame = mux_frame("mux-ping-alive");
			let echoed = client.handle().emit_on_stream(&frame).await?;
			trace.event_with(MuxPingRoundtripSpec::stream_echoes_after_pings, &[], is_echo(echoed, &frame))?;

			trace.event_with(
				MuxPingRoundtripSpec::handler_saw_only_stream,
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
			(probe_answered_with_matching_ack, exactly!(1), equals!(true)),
			(followup_echoes_after_stray_ack, exactly!(1), equals!(true))
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
			let mut link = establish_client_mux_server_raw(4).await?;

			let probe = MuxPingPackage::new(false, 42);
			link.server_writer.write_envelope(probe.into()).await?;

			let ack = link.server_reader.read_envelope().await?;
			let ack_ok = matches!(
				&ack,
				TransportEnvelope::Mux(MuxEnvelope::Ping(package)) if package.ack() && package.opaque() == 42
			);

			trace.event_with(MuxPingWireAckSpec::probe_answered_with_matching_ack, &[], ack_ok)?;

			let stray_ack = MuxPingPackage::new(true, 999);
			link.server_writer.write_envelope(stray_ack.into()).await?;

			let followup_echoed = raw_echo_roundtrip(&mut link, &mux_frame("mux-ping-follow-up")).await?;
			trace.event_with(MuxPingWireAckSpec::followup_echoes_after_stray_ack, &[], followup_echoed)?;

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
			(ping_refused_draining, exactly!(1), equals!(true)),
			(inflight_drains_to_echo, exactly!(1), equals!(true))
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
			start_mux_server(&env.context.materials, 4, gated_echo(Arc::clone(&env.context))).await
		},
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let client = connect_mux_client(addr, &ctx.materials, 4).await?;

			let frame_inflight = mux_frame("mux-ping-inflight");
			let inflight_task = spawn_emit(client.handle(), frame_inflight.to_owned());
			ctx.started.notified().await;

			let shutdown_future = kick_shutdown(client.handle()).await;
			let refused = client.handle().ping().await;
			trace.event_with(
				MuxPingDrainingSpec::ping_refused_draining,
				&[],
				matches!(refused, Err(TransportError::Draining)),
			)?;

			ctx.release.notify_one();

			let echoed = await_ok(inflight_task, "in-flight emit task must not panic").await?;
			trace.event_with(MuxPingDrainingSpec::inflight_drains_to_echo, &[], is_echo(echoed, &frame_inflight))?;

			shutdown_future.await?;
			Ok(())
		}
	}
}
