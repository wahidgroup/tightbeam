//! The mux tests on a cleartext link, which hold it to the behavior of an
//! encrypted link for interleaved echo, the cancel budget, and chunked credit.

use core::sync::atomic::AtomicUsize;
use std::sync::Arc;

use tokio::sync::Notify;

use tightbeam::der::Encode;
use tightbeam::exactly;
use tightbeam::instrumentation::events;
use tightbeam::tb_assert_spec;
use tightbeam::tb_process_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::{ScenarioConfig, SetupEnv};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::envelopes::GoAwayReason;
use tightbeam::transport::handshake::negotiation::MuxSettings;
use tightbeam::transport::multiplex::MuxRole;
use tightbeam::urn::Urn;
use tightbeam::TightBeamError;

use super::common::*;
use crate::transport::support::mux_frame;

pub(crate) const RESPONDER_POLICY_REJECTION: Urn<'static> =
	tightbeam::urn!("test", "event:cleartext/responder-policy-rejection");

/// The mux runs over raw TCP with no handshake and symmetric out-of-band
/// settings, and it answers two interleaved streams out of order.
#[tokio::test]
async fn mux_cleartext_interleaved_echo() -> Result<(), TightBeamError> {
	let (client, server) = establish_cleartext_transports().await?;
	let settings = MuxSettings::symmetric(4);
	let (client_end, _client_responder) =
		spawn_cleartext_mux_endpoint(client, MuxRole::Client, settings, None, TraceCollector::new())?;
	let (_server_end, server_responder) =
		spawn_cleartext_mux_endpoint(server, MuxRole::Server, settings, None, TraceCollector::new())?;

	let frame_first = mux_frame("clear-first");
	let frame_second = mux_frame("clear-second");
	let gate = Arc::new(Notify::new());
	let handler = order_forcing_echo(frame_first.to_owned(), gate);
	let _server_serve = tokio::spawn(server_responder.serve(handler));

	let (first, second) = tokio::join!(
		client_end.handle.emit_on_stream(&frame_first),
		client_end.handle.emit_on_stream(&frame_second),
	);

	assert!(is_echo(first?, &frame_first), "the held first stream must echo its own frame");
	assert!(is_echo(second?, &frame_second), "the second stream must echo its own frame");
	Ok(())
}

tb_assert_spec! {
	pub MuxCleartextCancelBudgetSpec,
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
	pub MuxCleartextCancelBudgetProcess,
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

// The cancel budget holds on a cleartext link too, so budget + 1 open and
// cancel pairs draw a GoAway(EnhanceYourCalm).
tb_scenario! {
	name: mux_cleartext_cancel_budget,
	config: ScenarioConfig::builder()
		.with_spec(MuxCleartextCancelBudgetSpec::latest())
		.with_csp(MuxCleartextCancelBudgetProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (client, server) = establish_cleartext_transports().await?;
			let cancel_budget = 2;
			let settings = MuxSettings::symmetric(8);
			let (_server_end, responder) =
				spawn_cleartext_mux_endpoint(server, MuxRole::Server, settings, Some(cancel_budget), trace.share())?;
			let (client_reader, client_writer) = client.into_split()?;

			let rejected = run_cancel_abuse(client_reader, client_writer, responder, cancel_budget).await?;
			trace.event_with(RESPONDER_POLICY_REJECTION, &[], rejected)?;

			Ok(())
		}
	}
}

/// The mux settings of the cleartext tests: a cap of 4 and 1 KiB chunks, with
/// the budgets the symmetric settings leave unmetered.
fn chunked_cleartext_settings() -> MuxSettings {
	MuxSettings::symmetric(4).with_chunk_size(1024)
}

/// Symmetric cleartext settings leave both budgets unmetered, because the link
/// has no epoch to renew.
#[test]
fn mux_cleartext_budgets_unmetered() {
	let settings = chunked_cleartext_settings();
	let unmetered = settings.send_budget().is_none() && settings.recv_budget().is_none();
	assert!(unmetered, "symmetric cleartext settings must leave both budgets unmetered");
}

/// On a cleartext link, chunking and stream credit run over symmetric
/// out-of-band settings while the budget machinery stays inert.
#[tokio::test]
async fn mux_cleartext_chunked_parity() -> Result<(), TightBeamError> {
	let (client, server) = establish_cleartext_transports().await?;
	let settings = chunked_cleartext_settings();
	let (client_end, _client_responder) =
		spawn_cleartext_mux_endpoint(client, MuxRole::Client, settings, None, TraceCollector::new())?;
	let (_server_end, server_responder) =
		spawn_cleartext_mux_endpoint(server, MuxRole::Server, settings, None, TraceCollector::new())?;
	let _serve = spawn_immediate_echo(server_responder);

	let frame = large_mux_frame("mux-cleartext-chunked");
	let echoed = client_end.handle.emit_on_stream(&frame).await?;
	assert!(is_echo(echoed, &frame), "a chunked frame must echo over cleartext");
	Ok(())
}

/// A cleartext link carries a stream, as the ws-style embedding does:
/// `open_stream` pushes against `serve_streaming` with only chunking and
/// stream credit in play.
#[tokio::test]
async fn mux_cleartext_streaming_echo() -> Result<(), TightBeamError> {
	let (client, server) = establish_cleartext_transports().await?;
	let settings = chunked_cleartext_settings();
	let (client_end, _client_responder) =
		spawn_cleartext_mux_endpoint(client, MuxRole::Client, settings, None, TraceCollector::new())?;
	let (_server_end, server_responder) =
		spawn_cleartext_mux_endpoint(server, MuxRole::Server, settings, None, TraceCollector::new())?;

	let chunks_seen = Arc::new(AtomicUsize::new(0));
	let _serve = tokio::spawn(server_responder.serve_streaming(streaming_echo_handler(Arc::clone(&chunks_seen))));

	let frame = large_mux_frame("mux-cleartext-streaming");
	let payload = frame.to_der()?;
	let (sink, response) = client_end.handle.open_stream()?;
	push_split(sink, &payload).await?;

	let echoed = response.await?;
	let chunked = saw_multiple_chunks(&chunks_seen);
	assert!(is_echo(echoed, &frame), "a streamed request must echo over cleartext");
	assert!(chunked, "the streaming handler must see more than one chunk");
	Ok(())
}
