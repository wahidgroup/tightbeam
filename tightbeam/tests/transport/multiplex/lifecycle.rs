//! Mux lifecycle: GoAway, rekey headroom, cancel budget, teardown.

use std::sync::Arc;

use tightbeam::asn1::{MessagePriority, Metadata, Version};
use tightbeam::der::Encode;
use tightbeam::exactly;
use tightbeam::tb_assert_spec;
use tightbeam::tb_process_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::{ClientEnv, ScenarioConfig, SetupEnv};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::envelopes::{GoAwayReason, MuxDataPackage, MuxOpenPackage, MuxStreamKind};
use tightbeam::transport::{EnvelopeSink, EnvelopeSource, TransportEnvelope};
use tightbeam::{Frame, TightBeamError};

use crate::common::security::expectation_failure;
use crate::transport::support::{await_ok, join_task, mux_frame};

use super::common::*;

use tightbeam::instrumentation::events;
use tightbeam::utils::urn::Urn;

pub(crate) const EMIT_FAILS_CONNECTION_CLOSED: Urn<'static> =
	Urn::new("test", "event:lifecycle/emit-fails-connection-closed");
pub(crate) const INFLIGHT_DRAINS_TO_ECHO: Urn<'static> = Urn::new("test", "event:lifecycle/inflight-drains-to-echo");
pub(crate) const LATE_EMIT_REFUSED_DRAINING: Urn<'static> =
	Urn::new("test", "event:lifecycle/late-emit-refused-draining");
pub(crate) const OFFENDER_ANSWERED_WITH_GOAWAY: Urn<'static> =
	Urn::new("test", "event:lifecycle/offender-answered-with-goaway");
pub(crate) const PEER_REASON_SURFACES_ON_HANDLE: Urn<'static> =
	Urn::new("test", "event:lifecycle/peer-reason-surfaces-on-handle");
pub(crate) const PENDING_FAILS_CONNECTION_CLOSED: Urn<'static> =
	Urn::new("test", "event:lifecycle/pending-fails-connection-closed");
pub(crate) const REKEY_CASE_HOLDS: Urn<'static> = Urn::new("test", "event:lifecycle/rekey-case-holds");
pub(crate) const RESPONDER_POLICY_REJECTION: Urn<'static> =
	Urn::new("test", "event:lifecycle/responder-policy-rejection");
pub(crate) const SHUTDOWN_WITH_ADVERTISES_REASON: Urn<'static> =
	Urn::new("test", "event:lifecycle/shutdown-with-advertises-reason");
pub(crate) const STREAM_ABOVE_WATERMARK_DRAINING: Urn<'static> =
	Urn::new("test", "event:lifecycle/stream-above-watermark-draining");
pub(crate) const STREAM_AT_WATERMARK_ECHOED: Urn<'static> =
	Urn::new("test", "event:lifecycle/stream-at-watermark-echoed");

tb_assert_spec! {
	pub MuxGoAwayDrainSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::MUX_GOAWAY_SENT, exactly!(1)),
			(events::MUX_EMIT_DRAINING, exactly!(1)),
			(events::MUX_GOAWAY_RECV, exactly!(1)),
			(INFLIGHT_DRAINS_TO_ECHO, exactly!(1), equals!(true))
		],
		events: [events::MUX_GOAWAY_SENT, events::MUX_EMIT_DRAINING]
	}
}

tb_process_spec! {
	pub MuxGoAwayDrainProcess,
	events {
		observable {
			events::MUX_GOAWAY_SENT,
			events::MUX_EMIT_DRAINING,
			INFLIGHT_DRAINS_TO_ECHO
		}
		hidden { }
	}
	states {
		Idle => { events::MUX_GOAWAY_SENT => GoAwaySent },
		GoAwaySent => { events::MUX_EMIT_DRAINING => LateRefused },
		LateRefused => { INFLIGHT_DRAINS_TO_ECHO => Done },
		Done => { }
	}
	terminal { Done }
}

tb_scenario! {
	name: mux_goaway_drains_and_rejects_new,
	config: ScenarioConfig::builder()
		.with_spec(MuxGoAwayDrainSpec::latest())
		.with_csp(MuxGoAwayDrainProcess)
		.build(),
	environment ServiceClient {
		context: GatedMuxContext::generate(),
		server: |env| async move {
			start_mux_server(&env.context.materials, 4, gated_echo(Arc::clone(&env.context)), env.trace).await
		},
		client: |ClientEnv { trace, context: ctx, addr }| async move {
			let client = connect_mux_client(addr, &ctx.materials, 4, trace.share()).await?;

			let frame_inflight = mux_frame("mux-inflight");
			let inflight_task = spawn_emit(client.handle(), frame_inflight.to_owned());

			ctx.started.notified().await;

			let shutdown_future = kick_shutdown(client.handle()).await;
			let late = client.handle().emit_on_stream(&mux_frame("mux-late")).await;
			if !is_draining(&late) {
				return Err(expectation_failure("late emit must refuse while draining"));
			}

			ctx.release.notify_one();

			let echoed = await_ok(inflight_task, "in-flight emit task must not panic").await?;
			trace.event_with(INFLIGHT_DRAINS_TO_ECHO, &[], is_echo(echoed, &frame_inflight))?;

			shutdown_future.await?;
			Ok(())
		}
	}
}

async fn run_shutdown_with_case(reason: GoAwayReason, trace: TraceCollector) -> Result<bool, TightBeamError> {
	let mut link = establish_client_mux_server_raw(4, trace).await?;

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
			(events::MUX_GOAWAY_SENT, exactly!(2)),
			(SHUTDOWN_WITH_ADVERTISES_REASON, exactly!(2), equals!(true))
		]
	}
}

tb_scenario! {
	name: mux_shutdown_with_advertises_reason,
	spec: MuxShutdownReasonSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			for reason in [GoAwayReason::EnhanceYourCalm, GoAwayReason::Application(0x1000)] {
				let advertised = run_shutdown_with_case(reason, trace.share()).await?;
				trace.event_with(SHUTDOWN_WITH_ADVERTISES_REASON, &[], advertised)?;
			}

			Ok(())
		}
	}
}

async fn run_peer_reason_case(reason: GoAwayReason, trace: TraceCollector) -> Result<bool, TightBeamError> {
	let mut link = establish_client_mux_server_raw(4, trace).await?;

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
			(events::MUX_GOAWAY_RECV, exactly!(2)),
			(PEER_REASON_SURFACES_ON_HANDLE, exactly!(2), equals!(true))
		]
	}
}

tb_scenario! {
	name: mux_peer_goaway_reason_surfaces_on_handle,
	spec: MuxPeerReasonSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			for reason in [GoAwayReason::EnhanceYourCalm, GoAwayReason::Application(0x2000)] {
				let surfaced = run_peer_reason_case(reason, trace.share()).await?;
				trace.event_with(PEER_REASON_SURFACES_ON_HANDLE, &[], surfaced)?;
			}

			Ok(())
		}
	}
}

async fn run_rekey_case(case: RekeyCase, trace: TraceCollector) -> Result<bool, TightBeamError> {
	let responses_before_goaway = case.responses_before_goaway();
	let mut link = establish_server_mux_client_raw(
		case.server_local_cap,
		case.server_peer_cap,
		MuxEndpointConfig { rekey_limit: Some(case.rekey_limit), ..MuxEndpointConfig::default() },
		trace,
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
			(events::MUX_GOAWAY_SENT, exactly!(4)),
			(events::MUX_EMIT_DRAINING, exactly!(4)),
			(REKEY_CASE_HOLDS, exactly!(4), equals!(true))
		]
	}
}

// Headroom: `2 * (local_cap + peer_cap) + 1` vs record limit.
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
				let holds = run_rekey_case(case, trace.share()).await?;
				trace.event_with(REKEY_CASE_HOLDS, &[], holds)?;
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
			(events::MUX_CANCEL_BUDGET, exactly!(1)),
			(events::MUX_GOAWAY_SENT, exactly!(1), equals!(u32::from(GoAwayReason::EnhanceYourCalm))),
			(RESPONDER_POLICY_REJECTION, exactly!(1), equals!(true))
		]
	}
}

tb_process_spec! {
	pub MuxCancelBudgetProcess,
	events {
		observable {
			events::MUX_CANCEL_BUDGET,
			events::MUX_GOAWAY_SENT,
			RESPONDER_POLICY_REJECTION
		}
		hidden { }
	}
	states {
		Idle => { events::MUX_CANCEL_BUDGET => Tripped },
		Tripped => { events::MUX_GOAWAY_SENT => GoAwaySeen },
		GoAwaySeen => { RESPONDER_POLICY_REJECTION => Done },
		Done => { }
	}
	terminal { Done }
}

tb_scenario! {
	name: mux_cancel_budget_boundary,
	config: ScenarioConfig::builder()
		.with_spec(MuxCancelBudgetSpec::latest())
		.with_csp(MuxCancelBudgetProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let cancel_budget = 2;
			let link = establish_server_mux_client_raw(
				8,
				8,
				MuxEndpointConfig { cancel_budget: Some(cancel_budget), ..MuxEndpointConfig::default() },
				trace.share(),
			)
			.await?;

			let rejected =
				run_cancel_abuse(link.client_reader, link.client_writer, link.responder, cancel_budget).await?;
			trace.event_with(RESPONDER_POLICY_REJECTION, &[], rejected)?;

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
			(events::MUX_GOAWAY_RECV, exactly!(1), equals!(u32::from(GoAwayReason::Shutdown))),
			(events::MUX_EMIT_DRAINING, exactly!(1)),
			(STREAM_ABOVE_WATERMARK_DRAINING, exactly!(1), equals!(true)),
			(STREAM_AT_WATERMARK_ECHOED, exactly!(1), equals!(true)),
			(LATE_EMIT_REFUSED_DRAINING, exactly!(1), equals!(true))
		]
	}
}

tb_scenario! {
	name: mux_peer_goaway_fails_pending_above,
	spec: MuxPeerGoAwaySpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let mut link = establish_client_mux_server_raw(4, trace.share()).await?;

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
			trace.event_with(STREAM_ABOVE_WATERMARK_DRAINING, &[], is_draining(&dropped))?;

			write_muxed_echo(&mut link.server_writer, kept_id, &kept_message).await?;

			let kept = await_ok(kept_task, "kept emit task must not panic").await?;
			trace.event_with(STREAM_AT_WATERMARK_ECHOED, &[], is_echo(kept, &frame_kept))?;

			let late = link.client.handle.emit_on_stream(&mux_frame("mux-after-peer-goaway")).await;
			trace.event_with(LATE_EMIT_REFUSED_DRAINING, &[], is_draining(&late))?;

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
			(events::MUX_PROTOCOL_ERROR, exactly!(1)),
			(events::MUX_GOAWAY_SENT, exactly!(1), equals!(u32::from(GoAwayReason::ProtocolError))),
			(PENDING_FAILS_CONNECTION_CLOSED, exactly!(1), equals!(true))
		]
	}
}

tb_scenario! {
	name: mux_protocol_violation_goaway_and_pending_fail,
	spec: MuxProtocolViolationSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let mut link = establish_client_mux_server_raw(4, trace.share()).await?;

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
			assert!(
				is_goaway(&goaway, GoAwayReason::ProtocolError, Some(0)),
				"protocol violation must answer GoAway(ProtocolError) at watermark 0"
			);

			let failed = join_task(inflight_task, "in-flight emit task must not panic").await?;
			trace.event_with(
				PENDING_FAILS_CONNECTION_CLOSED,
				&[],
				is_connection_closed(&failed),
			)?;

			Ok(())
		}
	}
}

/// V0 frame with V2-only field: mux router must reject.
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

async fn violation_answered_with_goaway(
	offender: TransportEnvelope,
	trace: TraceCollector,
) -> Result<bool, TightBeamError> {
	let mut link = establish_server_mux_client_raw(4, 4, MuxEndpointConfig::default(), trace).await?;
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
			(events::MUX_PROTOCOL_ERROR, exactly!(4)),
			(OFFENDER_ANSWERED_WITH_GOAWAY, exactly!(4), equals!(true))
		]
	}
}

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
				MuxOpenPackage::new(1, true, MuxStreamKind::Unary, vec![0xDE, 0xAD])?.into(),
				// Open without a message (requests must carry one)
				MuxOpenPackage::new(1, true, MuxStreamKind::Unary, Vec::new())?.into(),
				// Open whose frame claims fields its version forbids
				MuxOpenPackage::new(1, true, MuxStreamKind::Unary, version_incompatible_frame_der()?)?.into(),
			];

			for offender in offenders {
				let rejected = violation_answered_with_goaway(offender, trace.share()).await?;
				trace.event_with(OFFENDER_ANSWERED_WITH_GOAWAY, &[], rejected)?;
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
			(EMIT_FAILS_CONNECTION_CLOSED, exactly!(1), equals!(true))
		]
	}
}

tb_scenario! {
	name: mux_connection_drop_mid_emit,
	spec: MuxConnectionDropSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let mut link = establish_client_mux_server_raw(4, trace.share()).await?;

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
				EMIT_FAILS_CONNECTION_CLOSED,
				&[],
				is_connection_closed(&failed),
			)?;

			Ok(())
		}
	}
}
