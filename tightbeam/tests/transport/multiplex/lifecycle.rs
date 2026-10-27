//! The mux lifecycle scenarios of GoAway, rekey headroom, the cancel budget,
//! and teardown.

use core::error::Error;
use std::sync::Arc;

use tightbeam::asn1::Version;
use tightbeam::der::Encode;
use tightbeam::exactly;
use tightbeam::tb_assert_spec;
use tightbeam::tb_cases;
use tightbeam::tb_process_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::{ClientEnv, ScenarioConfig, SetupEnv, TestFrame};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::envelopes::{GoAwayReason, MuxDataPackage, MuxOpenPackage, MuxStreamKind};
use tightbeam::transport::multiplex::MuxAcceptor;
use tightbeam::transport::{EnvelopeSink, EnvelopeSource, TransportEnvelope};
use tightbeam::TightBeamError;

use crate::common::security::expectation_failure;
use crate::transport::support::{await_ok, join_task, mux_frame, mux_offer};

use super::common::*;

use tightbeam::instrumentation::events;
use tightbeam::urn::Urn;

/// The event that records whether an in-flight emit drains to its echo after a
/// local shutdown.
pub(crate) const INFLIGHT_DRAINS_TO_ECHO: Urn<'static> =
	tightbeam::urn!("test", "event:lifecycle/inflight-drains-to-echo");
/// The event that records whether cancel abuse ends the responder with a
/// policy rejection.
pub(crate) const RESPONDER_POLICY_REJECTION: Urn<'static> =
	tightbeam::urn!("test", "event:lifecycle/responder-policy-rejection");

tb_assert_spec! {
	pub MuxGoAwayDrainSpec,
	V(1,0,0): {
		mode: Accept,
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

			ctx.started.wait("the in-flight emit must start the gated handler").await?;

			let shutdown_future = kick_shutdown(client.handle()).await;
			let late = client.handle().emit_on_stream(&mux_frame("mux-late")).await;
			assert!(is_draining(&late), "late emit must refuse while draining");

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
		assertions: [
			(events::MUX_GOAWAY_SENT, exactly!(1))
		]
	}
}

// `shutdown_with` advertises its reason in the GoAway it sends, at watermark
// 0, whatever the reason.
tb_cases! {
	fn mux_shutdown_with_advertises_reason(reason: GoAwayReason) -> Result<(), Box<dyn Error>> {
		grade_case(MuxShutdownReasonSpec::latest(), |trace| async move {
			let advertised = run_shutdown_with_case(reason, trace).await?;
			assert!(advertised, "shutdown_with must advertise its reason at watermark 0");
			Ok(())
		})
	}
	cases {
		enhance_your_calm => GoAwayReason::EnhanceYourCalm,
		application => GoAwayReason::Application(0x1000),
	}
}

/// A shutdown with no stream in flight ends on the poll that sends its
/// GoAway, so the future that `kick_shutdown` returns yields the output of
/// that poll.
#[tokio::test]
async fn a_shutdown_that_ends_on_its_first_poll_yields_its_output() -> Result<(), TightBeamError> {
	let link = establish_client_mux_server_raw(4, TraceCollector::new()).await?;
	let shutdown = kick_shutdown(&link.client.handle).await;
	shutdown.await?;
	Ok(())
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
		assertions: [
			(events::MUX_GOAWAY_RECV, exactly!(1))
		]
	}
}

// The reason of a peer GoAway surfaces on the handle and drains the emit,
// whatever the reason.
tb_cases! {
	fn mux_peer_goaway_reason_surfaces_on_handle(reason: GoAwayReason) -> Result<(), Box<dyn Error>> {
		grade_case(MuxPeerReasonSpec::latest(), |trace| async move {
			let surfaced = run_peer_reason_case(reason, trace).await?;
			assert!(surfaced, "the peer GoAway reason must surface on the handle and drain the emit");
			Ok(())
		})
	}
	cases {
		enhance_your_calm => GoAwayReason::EnhanceYourCalm,
		application => GoAwayReason::Application(0x2000),
	}
}

/// Writes `count` requests from the raw client, one per stream, and reports
/// whether each draws its own response, beside the ID of the last stream.
///
/// # Errors
///
/// - [`TightBeamError`] -- the write or read failure of the raw client.
async fn responses_before_drain(
	reader: &mut SplitReader,
	writer: &mut SplitWriter,
	count: u32,
) -> Result<(bool, u32), TightBeamError> {
	let mut last_stream_id = 0u32;
	let mut responses_ok = true;
	for index in 0..count {
		let stream_id = client_stream_id(index);
		last_stream_id = stream_id;
		write_muxed_request(writer, stream_id, mux_frame("mux-rekey")).await?;

		let response = reader.read_envelope().await?;
		responses_ok &= is_muxed_response(&response, stream_id);
	}

	Ok((responses_ok, last_stream_id))
}

async fn run_rekey_case(case: RekeyCase, trace: TraceCollector) -> Result<bool, TightBeamError> {
	let mut link = establish_server_mux_client_raw(
		case.server_local_cap,
		case.server_peer_cap,
		MuxEndpointConfig { rekey_limit: Some(case.rekey_limit), ..MuxEndpointConfig::default() },
		trace,
	)
	.await?;
	let _server_serve = spawn_immediate_echo(link.responder);

	let responses = case.responses_before_goaway();
	let (responses_ok, last_stream_id) =
		responses_before_drain(&mut link.client_reader, &mut link.client_writer, responses).await?;

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
		assertions: [
			(events::MUX_GOAWAY_SENT, exactly!(1), equals!(u32::from(GoAwayReason::Shutdown))),
			(events::MUX_EMIT_DRAINING, exactly!(1))
		]
	}
}

// Each case sets the drain headroom `2 * (local_cap + peer_cap) + 1`
// against the record limit.
tb_cases! {
	fn mux_rekey_headroom(case: RekeyCase) -> Result<(), Box<dyn Error>> {
		grade_case(MuxRekeyHeadroomSpec::latest(), |trace| async move {
			let holds = run_rekey_case(case, trace).await?;
			assert!(holds, "the server must answer N responses, then GoAway(Shutdown) at the watermark, then refuse");
			Ok(())
		})
	}
	cases {
		caps_2_1_limit_8 => RekeyCase { server_local_cap: 2, server_peer_cap: 1, rekey_limit: 8 },
		caps_2_1_limit_9 => RekeyCase { server_local_cap: 2, server_peer_cap: 1, rekey_limit: 9 },
		caps_4_2_limit_14 => RekeyCase { server_local_cap: 4, server_peer_cap: 2, rekey_limit: 14 },
		caps_4_2_limit_15 => RekeyCase { server_local_cap: 4, server_peer_cap: 2, rekey_limit: 15 },
	}
}

tb_assert_spec! {
	pub MuxCancelBudgetSpec,
	V(1,0,0): {
		mode: Accept,
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
	pub MuxServeCancelBudgetSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::MUX_CANCEL_BUDGET, exactly!(1)),
			(events::MUX_GOAWAY_SENT, exactly!(1), equals!(u32::from(GoAwayReason::EnhanceYourCalm)))
		]
	}
}

// The cancel budget must also reach the responder on the `MuxAcceptor::serve`
// path the servlet macro runs, because `mux_cancel_budget_boundary` covers only
// the hand-assembled spawn path.
tb_scenario! {
	name: mux_serve_applies_cancel_budget,
	spec: MuxServeCancelBudgetSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let cancel_budget = 2;
			let (client, server) = establish_transports(Some(mux_offer(8)), Some(mux_offer(8))).await?;
			let server = server.with_trace(trace.share());
			let settings = server
				.negotiated_mux()
				.ok_or_else(|| expectation_failure("handshake must negotiate multiplexing"))?;

			let serve_task = tokio::spawn(server.serve(settings, parked_unary_service(), Some(cancel_budget)));
			let (client_reader, client_writer) = client.into_split()?;

			let rejected = run_cancel_abuse_against(client_reader, client_writer, serve_task, cancel_budget).await?;
			assert!(rejected, "MuxAcceptor::serve must end with a policy rejection");

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxPeerGoAwaySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::MUX_GOAWAY_RECV, exactly!(1), equals!(u32::from(GoAwayReason::Shutdown))),
			(events::MUX_EMIT_DRAINING, exactly!(1))
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
			assert!(is_draining(&dropped), "the stream above the peer watermark must fail as draining");

			write_muxed_echo(&mut link.server_writer, kept_id, &kept_message).await?;

			let kept = await_ok(kept_task, "kept emit task must not panic").await?;
			assert!(is_echo(kept, &frame_kept), "the stream at the peer watermark must still echo");

			let late = link.client.handle.emit_on_stream(&mux_frame("mux-after-peer-goaway")).await;
			assert!(is_draining(&late), "an emit after the peer GoAway must fail as draining");

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxProtocolViolationSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::MUX_PROTOCOL_ERROR, exactly!(1)),
			(events::MUX_GOAWAY_SENT, exactly!(1), equals!(u32::from(GoAwayReason::ProtocolError)))
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
			assert!(
				is_connection_closed(&failed),
				"the in-flight emit must fail as a closed connection after the violation"
			);

			Ok(())
		}
	}
}

/// A V0 frame that carries a V2-only field, which the mux router must reject.
fn version_incompatible_frame_der() -> Vec<u8> {
	let frame = TestFrame::prioritized();
	TestFrame::forge_version(&frame, &frame, Version::V0)
}

/// An offender of the stream grammar, as the raw client writes it.
///
/// # Panics
///
/// The call panics when a fixture record does not encode.
fn offender(offence: Offence) -> TransportEnvelope {
	let chunk = mux_frame("mux-violation").to_der().expect("the fixture frame encodes");
	match offence {
		Offence::DataWithoutOpen => MuxDataPackage::new(1, true, chunk).map(Into::into),
		Offence::OpenWithoutFrame => {
			MuxOpenPackage::new(1, true, MuxStreamKind::Unary, vec![0xDE, 0xAD]).map(Into::into)
		}
		Offence::OpenWithoutMessage => MuxOpenPackage::new(1, true, MuxStreamKind::Unary, Vec::new()).map(Into::into),
		Offence::OpenOfForbiddenFields => {
			MuxOpenPackage::new(1, true, MuxStreamKind::Unary, version_incompatible_frame_der()).map(Into::into)
		}
	}
	.expect("the fixture record encodes")
}

/// The breaks of the stream grammar that the server must answer with a
/// `ProtocolError` GoAway.
enum Offence {
	/// A continuation chunk for a stream with no open.
	DataWithoutOpen,
	/// An open whose payload is not a frame.
	OpenWithoutFrame,
	/// An open without a message, although requests must carry one.
	OpenWithoutMessage,
	/// An open whose frame claims fields its version forbids.
	OpenOfForbiddenFields,
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
		assertions: [
			(events::MUX_PROTOCOL_ERROR, exactly!(1)),
			(events::MUX_GOAWAY_SENT, exactly!(1), equals!(u32::from(GoAwayReason::ProtocolError)))
		]
	}
}

// Each break of the stream grammar draws a `ProtocolError` GoAway from the
// server that reads it.
tb_cases! {
	fn mux_stream_grammar_violation_rejected(offence: Offence) -> Result<(), Box<dyn Error>> {
		grade_case(MuxGrammarViolationSpec::latest(), |trace| async move {
			let rejected = violation_answered_with_goaway(offender(offence), trace).await?;
			assert!(rejected, "the grammar violation must draw a ProtocolError GoAway");
			Ok(())
		})
	}
	cases {
		data_without_open => Offence::DataWithoutOpen,
		open_without_frame => Offence::OpenWithoutFrame,
		open_without_message => Offence::OpenWithoutMessage,
		open_of_forbidden_fields => Offence::OpenOfForbiddenFields,
	}
}

tb_assert_spec! {
	pub MuxConnectionDropSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CONNECTION_CLOSED, exactly!(1))
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
			assert!(is_connection_closed(&failed), "the pending emit must fail as a closed connection");

			Ok(())
		}
	}
}
