//! The mux lifecycle tests of GoAway, rekey headroom, the cancel budget, and
//! teardown.

use core::future::{poll_fn, Future};
use core::pin::pin;
use core::task::Poll;
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
use tightbeam::transport::envelopes::{
	GoAwayPackage, GoAwayReason, MuxDataPackage, MuxEnvelope, MuxOpenPackage, MuxStreamKind,
};
use tightbeam::transport::multiplex::MuxAcceptor;
use tightbeam::transport::{EnvelopeSink, EnvelopeSource, TransportEnvelope, TransportError};
use tightbeam::Frame;

use crate::common::poll::joined;
use crate::common::result::TestResult;
use crate::common::security::expectation_failure;
use crate::transport::fixtures::{await_ok, join_task, mux_frame, mux_offer};

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

/// Shuts the muxed client of a raw link on `trace` down with `reason`, and
/// returns the envelope that the raw server reads next.
async fn run_shutdown_with_case(reason: GoAwayReason, trace: TraceCollector) -> TransportEnvelope {
	let link = establish_client_mux_server_raw(4, trace).await;
	let mut link = link.expect("the raw link establishes");
	link.client.handle.shutdown_with(reason).await.expect("the shutdown drains");

	let envelope = link.server_reader.read_envelope().await;
	envelope.expect("the raw server reads the GoAway")
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
	async fn shutdown_with_advertises_its_reason_at_watermark_zero(reason: GoAwayReason) -> TestResult {
		grade_case(MuxShutdownReasonSpec::latest(), |trace| async move {
			let advertised = run_shutdown_with_case(reason, trace).await;
			assert_eq!(advertised, TransportEnvelope::from(GoAwayPackage::new(0, reason)));
		})
		.await
	}
	cases {
		enhance_your_calm => GoAwayReason::EnhanceYourCalm,
		application => GoAwayReason::Application(0x1000),
	}
}

/// A shutdown with no stream in flight ends on the poll that sends its
/// GoAway.
#[tokio::test]
async fn a_shutdown_with_no_stream_in_flight_ends_on_its_first_poll() -> TestResult {
	let link = establish_client_mux_server_raw(4, TraceCollector::new()).await?;
	let mut shutdown = pin!(link.client.handle.shutdown());

	let first = poll_fn(|context| Poll::Ready(shutdown.as_mut().poll(context))).await;
	assert!(matches!(first, Poll::Ready(Ok(()))));
	Ok(())
}

/// What a muxed client showed after the raw server answered its in-flight
/// emit with a GoAway at watermark 0.
struct PeerGoAway {
	/// The outcome of the in-flight emit.
	emit: Result<Option<Frame>, TransportError>,
	/// The reason that the handle of the client surfaces.
	surfaced: Option<GoAwayReason>,
}

/// Answers an in-flight emit of the muxed client of a raw link on `trace`
/// with a GoAway of `reason` at watermark 0, and returns what the client
/// showed.
async fn run_peer_reason_case(reason: GoAwayReason, trace: TraceCollector) -> PeerGoAway {
	let link = establish_client_mux_server_raw(4, trace).await;
	let mut link = link.expect("the raw link establishes");

	let emit_task = spawn_emit(&link.client.handle, mux_frame("mux-peer-reason"));
	let request = read_muxed_request_id(&mut link.server_reader).await;
	request.expect("the raw server reads the request");

	let goaway = write_goaway(&mut link.server_writer, 0, reason).await;
	goaway.expect("the raw server writes the GoAway");

	let emit = joined(emit_task).await;
	PeerGoAway { emit, surfaced: link.client.handle.goaway_reason() }
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
	async fn a_peer_goaway_reason_surfaces_on_the_handle(reason: GoAwayReason) -> TestResult {
		grade_case(MuxPeerReasonSpec::latest(), |trace| async move {
			let peer_goaway = run_peer_reason_case(reason, trace).await;
			assert!(matches!(peer_goaway.emit, Err(TransportError::Draining)));
			assert_eq!(peer_goaway.surfaced, Some(reason));
		})
		.await
	}
	cases {
		enhance_your_calm => GoAwayReason::EnhanceYourCalm,
		application => GoAwayReason::Application(0x2000),
	}
}

/// Writes one request from the raw client on each of `streams`, and returns
/// the streams whose own `End` answers it, in order.
async fn responses_before_drain(reader: &mut SplitReader, writer: &mut SplitWriter, streams: &[u32]) -> Vec<u32> {
	let mut answered = Vec::new();
	for &stream_id in streams {
		let request = write_muxed_request(writer, stream_id, mux_frame("mux-rekey")).await;
		request.expect("the raw client writes its request");

		let response = reader.read_envelope().await.expect("the raw client reads the next envelope");
		if is_muxed_response(&response, stream_id) {
			answered.push(stream_id);
		}
	}

	answered
}

/// What a server under the rekey limit of a [`RekeyCase`] showed as it
/// drained.
struct RekeyDrain {
	/// The streams whose request drew its own `End` before the drain.
	answered: Vec<u32>,
	/// The envelope that followed the last answer.
	goaway: TransportEnvelope,
	/// The outcome of an emit of the server after its GoAway.
	late: Result<Option<Frame>, TransportError>,
}

/// Drives the server of `case` on `trace` up to its drain, and returns what
/// it showed.
async fn run_rekey_case(case: &RekeyCase, trace: TraceCollector) -> RekeyDrain {
	let config = MuxEndpointConfig { rekey_limit: Some(case.rekey_limit), ..MuxEndpointConfig::default() };
	let link = establish_server_mux_client_raw(case.server_local_cap, case.server_peer_cap, config, trace).await;
	let mut link = link.expect("the raw link establishes");
	let _server_serve = spawn_immediate_echo(link.responder);

	let answered = responses_before_drain(&mut link.client_reader, &mut link.client_writer, case.answered).await;

	let goaway = link.client_reader.read_envelope().await;
	let goaway = goaway.expect("the raw client reads the GoAway");
	let late = link.server.handle.emit_on_stream(&mux_frame("mux-rekey-late")).await;
	RekeyDrain { answered, goaway, late }
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

// Each case sets the drain headroom `2 * (local_cap + peer_cap) + 1` against
// the record limit, so the server answers the requests that the rest of the
// limit carries, sends GoAway(Shutdown) at the last of them, and then refuses
// its own emit as draining.
tb_cases! {
	async fn the_server_drains_at_its_rekey_headroom(case: RekeyCase) -> TestResult {
		grade_case(MuxRekeyHeadroomSpec::latest(), |trace| async move {
			let goaway = GoAwayPackage::new(case.watermark(), GoAwayReason::Shutdown);

			let drain = run_rekey_case(&case, trace).await;
			assert_eq!(drain.answered, case.answered);
			assert_eq!(drain.goaway, TransportEnvelope::from(goaway));
			assert!(matches!(drain.late, Err(TransportError::Draining)));
		})
		.await
	}
	cases {
		caps_2_1_limit_8 => RekeyCase { server_local_cap: 2, server_peer_cap: 1, rekey_limit: 8, answered: &[1] },
		caps_2_1_limit_9 => RekeyCase { server_local_cap: 2, server_peer_cap: 1, rekey_limit: 9, answered: &[1, 3] },
		caps_4_2_limit_14 => RekeyCase { server_local_cap: 4, server_peer_cap: 2, rekey_limit: 14, answered: &[1] },
		caps_4_2_limit_15 => RekeyCase { server_local_cap: 4, server_peer_cap: 2, rekey_limit: 15, answered: &[1, 3] },
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
	let unary_open = |payload| MuxOpenPackage::new(1, true, MuxStreamKind::Unary, payload);
	let record = match offence {
		Offence::DataWithoutOpen => MuxDataPackage::new(1, true, chunk).map(Into::into),
		Offence::OpenWithoutFrame => unary_open(vec![0xDE, 0xAD]).map(Into::into),
		Offence::OpenWithoutMessage => unary_open(Vec::new()).map(Into::into),
		Offence::OpenOfForbiddenFields => unary_open(version_incompatible_frame_der()).map(Into::into),
	};
	record.expect("the fixture record encodes")
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

/// Writes `offender` from the raw client of a muxed server on `trace`, and
/// returns the envelope that the raw client reads back.
async fn violation_answered_with_goaway(offender: TransportEnvelope, trace: TraceCollector) -> TransportEnvelope {
	let link = establish_server_mux_client_raw(4, 4, MuxEndpointConfig::default(), trace).await;
	let mut link = link.expect("the raw link establishes");
	let _server_serve = spawn_immediate_echo(link.responder);

	let written = link.client_writer.write_envelope(offender).await;
	written.expect("the raw client writes the offender");

	let answer = link.client_reader.read_envelope().await;
	answer.expect("the raw client reads the answer of the server")
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
	async fn a_stream_grammar_violation_draws_a_protocol_error_goaway(offence: Offence) -> TestResult {
		grade_case(MuxGrammarViolationSpec::latest(), |trace| async move {
			let answer = violation_answered_with_goaway(offender(offence), trace).await;
			assert!(matches!(
				answer,
				TransportEnvelope::Mux(MuxEnvelope::GoAway(package)) if package.reason() == GoAwayReason::ProtocolError
			));
		})
		.await
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
