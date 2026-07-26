//! GoAway drain, rekey headroom, cancel budget, and connection teardown.

use std::sync::Arc;

use tightbeam::asn1::{MessagePriority, Metadata, Version};
use tightbeam::der::Encode;
use tightbeam::exactly;
use tightbeam::tb_assert_spec;
use tightbeam::tb_process_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::{ClientEnv, ScenarioConf, SetupEnv};
use tightbeam::transport::envelopes::{GoAwayReason, MuxDataPackage, MuxOpenPackage};
use tightbeam::transport::{EnvelopeSink, EnvelopeSource, TransportEnvelope};
use tightbeam::{Frame, TightBeamError};

use crate::transport::support::{await_ok, join_task};

use super::common::*;

tb_assert_spec! {
	pub MuxGoAwayDrainSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(late_emit_refused_draining, exactly!(1), equals!(true)),
			(inflight_drains_to_echo, exactly!(1), equals!(true))
		]
	}
}

tb_process_spec! {
	pub MuxGoAwayDrainProcess,
	events {
		observable {
			MuxGoAwayDrainSpec::late_emit_refused_draining,
			MuxGoAwayDrainSpec::inflight_drains_to_echo
		}
		hidden { }
	}
	states {
		Idle => { MuxGoAwayDrainSpec::late_emit_refused_draining => LateRefused },
		LateRefused => { MuxGoAwayDrainSpec::inflight_drains_to_echo => Done },
		Done => { }
	}
	terminal { Done }
}

// Shutdown GoAway drains in-flight work and rejects new streams as Draining.
tb_scenario! {
	name: mux_goaway_drains_and_rejects_new,
	config: ScenarioConf::builder()
		.with_spec(MuxGoAwayDrainSpec::latest())
		.with_csp(MuxGoAwayDrainProcess)
		.build(),
	environment ServiceClient {
		context: GatedMuxContext::generate(),
		server: |env| async move {
			start_mux_server(&env.context.materials, 4, gated_echo(Arc::clone(&env.context))).await
		},
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let client = connect_mux_client(addr, &ctx.materials, 4).await?;

			let frame_inflight = mux_frame("mux-inflight");
			let inflight_task = spawn_emit(client.handle(), frame_inflight.to_owned());

			ctx.started.notified().await;

			let shutdown_future = kick_shutdown(client.handle()).await;
			let late = client.handle().emit_on_stream(&mux_frame("mux-late")).await;

			trace.event_with(MuxGoAwayDrainSpec::late_emit_refused_draining, &[], is_draining(&late))?;

			ctx.release.notify_one();

			let echoed = await_ok(inflight_task, "in-flight emit task must not panic").await?;
			trace.event_with(MuxGoAwayDrainSpec::inflight_drains_to_echo, &[], is_echo(echoed, &frame_inflight))?;

			shutdown_future.await?;
			Ok(())
		}
	}
}

/// Drain a fresh link via `shutdown_with(reason)` and observe the
/// GoAway on the raw server half.
async fn run_shutdown_with_case(reason: GoAwayReason) -> Result<bool, TightBeamError> {
	let mut link = establish_client_mux_server_raw(4).await?;

	link.client.handle.shutdown_with(reason).await?;

	let envelope = link.server_reader.read_envelope().await?;
	Ok(is_goaway(&envelope, reason, Some(0)))
}

tb_assert_spec! {
	pub MuxShutdownReasonSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(shutdown_with_advertises_reason, exactly!(2), equals!(true))
		]
	}
}

// `shutdown_with` advertises the caller's reason in the GoAway,
// including application-defined codes.
tb_scenario! {
	name: mux_shutdown_with_advertises_reason,
	spec: MuxShutdownReasonSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			for reason in [GoAwayReason::EnhanceYourCalm, GoAwayReason::Application(0x1000)] {
				let advertised = run_shutdown_with_case(reason).await?;
				trace.event_with(MuxShutdownReasonSpec::shutdown_with_advertises_reason, &[], advertised)?;
			}

			Ok(())
		}
	}
}

/// Answer an in-flight emit with GoAway(reason) from the raw server
/// half. The failed emit sequences the read: once it resolves, the
/// handle has recorded the peer's reason.
async fn run_peer_reason_case(reason: GoAwayReason) -> Result<bool, TightBeamError> {
	let mut link = establish_client_mux_server_raw(4).await?;

	let emit_task = spawn_emit(&link.client.handle, mux_frame("mux-peer-reason"));
	let _stream_id = read_muxed_request_id(&mut link.server_reader).await?;

	write_goaway(&mut link.server_writer, 0, reason).await?;

	let outcome = join_task(emit_task, "drained emit task must not panic").await?;
	let drained = is_draining(&outcome);
	let surfaced = link.client.handle.goaway_reason() == Some(reason);

	Ok(drained && surfaced)
}

tb_assert_spec! {
	pub MuxPeerReasonSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(peer_reason_surfaces_on_handle, exactly!(2), equals!(true))
		]
	}
}

// A peer GoAway drains pending streams and its reason surfaces through
// `goaway_reason` for reconnect policy.
tb_scenario! {
	name: mux_peer_goaway_reason_surfaces_on_handle,
	spec: MuxPeerReasonSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			for reason in [GoAwayReason::EnhanceYourCalm, GoAwayReason::Application(0x2000)] {
				let surfaced = run_peer_reason_case(reason).await?;
				trace.event_with(MuxPeerReasonSpec::peer_reason_surfaces_on_handle, &[], surfaced)?;
			}

			Ok(())
		}
	}
}

/// Drive one rekey case over raw client halves against a muxed server.
async fn run_rekey_case(case: RekeyCase) -> Result<bool, TightBeamError> {
	let responses_before_goaway = case.responses_before_goaway();
	let mut link = establish_server_mux_client_raw(
		case.server_local_cap,
		case.server_peer_cap,
		MuxEndpointConfig { rekey_limit: Some(case.rekey_limit), cancel_budget: None, grantor: None },
	)
	.await?;
	let _server_serve = spawn_immediate_echo(link.responder);

	let mut last_stream_id = 0u32;
	let mut responses_ok = true;
	for index in 0..responses_before_goaway {
		let stream_id = client_stream_id(index);
		last_stream_id = stream_id;
		write_muxed_request(&mut link.client_writer, stream_id, mux_frame("mux-rekey")).await?;

		let response = link.client_reader.read_envelope().await?;
		responses_ok &= is_muxed_response(&response, stream_id);
	}

	let goaway = link.client_reader.read_envelope().await?;
	let goaway_ok = is_goaway(&goaway, GoAwayReason::Shutdown, Some(last_stream_id));
	let late = link.server.handle.emit_on_stream(&mux_frame("mux-rekey-late")).await;
	let draining_ok = is_draining(&late);

	Ok(responses_ok && goaway_ok && draining_ok)
}

tb_assert_spec! {
	pub MuxRekeyHeadroomSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(rekey_case_holds, exactly!(4), equals!(true))
		]
	}
}

// Table of rekey drain headroom points:
// `2 * (local_cap + peer_cap) + 1` vs record limit.
tb_scenario! {
	name: mux_rekey_headroom_table,
	spec: MuxRekeyHeadroomSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			for case in [
				RekeyCase { server_local_cap: 2, server_peer_cap: 1, rekey_limit: 8 },
				RekeyCase { server_local_cap: 2, server_peer_cap: 1, rekey_limit: 9 },
				RekeyCase { server_local_cap: 4, server_peer_cap: 2, rekey_limit: 14 },
				RekeyCase { server_local_cap: 4, server_peer_cap: 2, rekey_limit: 15 },
			] {
				let holds = run_rekey_case(case).await?;
				trace.event_with(MuxRekeyHeadroomSpec::rekey_case_holds, &[], holds)?;
			}

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxCancelBudgetSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(goaway_enhance_your_calm, exactly!(1), equals!(true)),
			(responder_policy_rejection, exactly!(1), equals!(true))
		]
	}
}

tb_process_spec! {
	pub MuxCancelBudgetProcess,
	events {
		observable {
			MuxCancelBudgetSpec::goaway_enhance_your_calm,
			MuxCancelBudgetSpec::responder_policy_rejection
		}
		hidden { }
	}
	states {
		Idle => { MuxCancelBudgetSpec::goaway_enhance_your_calm => GoAwaySeen },
		GoAwaySeen => { MuxCancelBudgetSpec::responder_policy_rejection => Done },
		Done => { }
	}
	terminal { Done }
}

// Budget N: N aborting cancels OK. N+1 yields GoAway(EnhanceYourCalm) and PolicyRejection.
tb_scenario! {
	name: mux_cancel_budget_boundary,
	config: ScenarioConf::builder()
		.with_spec(MuxCancelBudgetSpec::latest())
		.with_csp(MuxCancelBudgetProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let cancel_budget = 2;
			let link = establish_server_mux_client_raw(
				8,
				8,
				MuxEndpointConfig { rekey_limit: None, cancel_budget: Some(cancel_budget), grantor: None },
			)
			.await?;

			let outcome =
				run_cancel_abuse(link.client_reader, link.client_writer, link.responder, cancel_budget).await?;

			record_cancel_abuse(
				&trace,
				&outcome,
				MuxCancelBudgetSpec::goaway_enhance_your_calm,
				MuxCancelBudgetSpec::responder_policy_rejection,
			)?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxPeerGoAwaySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(stream_above_watermark_draining, exactly!(1), equals!(true)),
			(stream_at_watermark_echoed, exactly!(1), equals!(true)),
			(late_emit_refused_draining, exactly!(1), equals!(true))
		]
	}
}

// Peer GoAway: keep ≤ watermark, fail pending above as Draining.
tb_scenario! {
	name: mux_peer_goaway_fails_pending_above,
	spec: MuxPeerGoAwaySpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let mut link = establish_client_mux_server_raw(4).await?;

			let frame_kept = mux_frame("mux-kept");
			let kept_id = client_stream_id(0);
			let kept_task = spawn_emit(&link.client.handle, frame_kept.to_owned());
			let kept_message = expect_muxed_request(
				&mut link.server_reader,
				kept_id,
				"first client-initiated stream must be id 1",
			)
			.await?;

			let dropped_id = client_stream_id(1);
			let dropped_task = spawn_emit(&link.client.handle, mux_frame("mux-dropped"));
			let _ = expect_muxed_request(
				&mut link.server_reader,
				dropped_id,
				"second client-initiated stream must be id 3",
			)
			.await?;

			write_goaway(&mut link.server_writer, kept_id, GoAwayReason::Shutdown).await?;

			let dropped = join_task(dropped_task, "dropped emit task must not panic").await?;
			trace.event_with(MuxPeerGoAwaySpec::stream_above_watermark_draining, &[], is_draining(&dropped))?;

			write_muxed_echo(&mut link.server_writer, kept_id, &kept_message).await?;

			let kept = await_ok(kept_task, "kept emit task must not panic").await?;
			trace.event_with(MuxPeerGoAwaySpec::stream_at_watermark_echoed, &[], is_echo(kept, &frame_kept))?;

			let late = link.client.handle.emit_on_stream(&mux_frame("mux-after-peer-goaway")).await;
			trace.event_with(MuxPeerGoAwaySpec::late_emit_refused_draining, &[], is_draining(&late))?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxProtocolViolationSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(goaway_protocol_error, exactly!(1), equals!(true)),
			(pending_fails_connection_closed, exactly!(1), equals!(true))
		]
	}
}

// Non-mux envelope on mux peer: GoAway(ProtocolError) + pending ConnectionClosed.
tb_scenario! {
	name: mux_protocol_violation_goaway_and_pending_fail,
	spec: MuxProtocolViolationSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let mut link = establish_client_mux_server_raw(4).await?;

			let inflight_task = spawn_emit(&link.client.handle, mux_frame("mux-proto-down"));
			let _ = expect_muxed_request(
				&mut link.server_reader,
				client_stream_id(0),
				"in-flight stream must be the first client id",
			)
			.await?;

			link.server_writer
				.write_envelope(TransportEnvelope::new_request(mux_frame("mux-proto-rogue")))
				.await?;

			let goaway = link.server_reader.read_envelope().await?;
			trace.event_with(
				MuxProtocolViolationSpec::goaway_protocol_error,
				&[],
				is_goaway(&goaway, GoAwayReason::ProtocolError, Some(0)),
			)?;

			let failed = join_task(inflight_task, "in-flight emit task must not panic").await?;
			trace.event_with(
				MuxProtocolViolationSpec::pending_fails_connection_closed,
				&[],
				is_connection_closed(&failed),
			)?;

			Ok(())
		}
	}
}

/// Frame claiming a V2+ field (priority) on a V0 frame: decodes fine
/// but must fail version validation at the mux router.
fn version_incompatible_frame_der() -> Result<Vec<u8>, TightBeamError> {
	let mut metadata = Metadata::default();
	metadata.priority = Some(MessagePriority::Standard);

	let frame = Frame {
		version: Version::V0,
		metadata,
		message: Vec::new(),
		integrity: None,
		nonrepudiation: None,
	};

	let der = frame.to_der()?;
	Ok(der)
}

/// Each offender gets a fresh mux server so one violation cannot mask
/// the next.
async fn violation_answered_with_goaway(offender: TransportEnvelope) -> Result<bool, TightBeamError> {
	let mut link = establish_server_mux_client_raw(4, 4, MuxEndpointConfig::default()).await?;
	let _server_serve = spawn_immediate_echo(link.responder);

	link.client_writer.write_envelope(offender).await?;

	let goaway = link.client_reader.read_envelope().await?;
	let rejected = is_goaway(&goaway, GoAwayReason::ProtocolError, None);
	Ok(rejected)
}

tb_assert_spec! {
	pub MuxGrammarViolationSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(offender_answered_with_goaway, exactly!(4), equals!(true))
		]
	}
}

// Every encodable stream-grammar violation must be answered with
// GoAway(ProtocolError).
tb_scenario! {
	name: mux_stream_grammar_violations_rejected,
	spec: MuxGrammarViolationSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let chunk = mux_frame("mux-violation").to_der()?;
			let offenders: Vec<TransportEnvelope> = vec![
				// Continuation chunk for a stream that was never opened
				MuxDataPackage::new(1, true, chunk)?.into(),
				// Open whose payload is not a frame
				MuxOpenPackage::new(1, true, vec![0xDE, 0xAD])?.into(),
				// Open without a message (requests must carry one)
				MuxOpenPackage::new(1, true, Vec::new())?.into(),
				// Open whose frame claims fields its version forbids
				MuxOpenPackage::new(1, true, version_incompatible_frame_der()?)?.into(),
			];

			for offender in offenders {
				let rejected = violation_answered_with_goaway(offender).await?;
				trace.event_with(MuxGrammarViolationSpec::offender_answered_with_goaway, &[], rejected)?;
			}

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxConnectionDropSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(emit_fails_connection_closed, exactly!(1), equals!(true))
		]
	}
}

// Peer close mid-emit surfaces ConnectionClosed after reader EOF.
tb_scenario! {
	name: mux_connection_drop_mid_emit,
	spec: MuxConnectionDropSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let mut link = establish_client_mux_server_raw(4).await?;

			let emit_task = spawn_emit(&link.client.handle, mux_frame("mux-drop"));
			let _ = expect_muxed_request(
				&mut link.server_reader,
				client_stream_id(0),
				"dropped stream must be the first client id",
			)
			.await?;

			drop(link.server_reader);
			drop(link.server_writer);

			let failed = join_task(emit_task, "emit task must not panic").await?;
			trace.event_with(
				MuxConnectionDropSpec::emit_fails_connection_closed,
				&[],
				is_connection_closed(&failed),
			)?;

			Ok(())
		}
	}
}
