//! The mux tests on a cleartext link, which hold it to the behavior of an
//! encrypted link for the cancel budget and chunked credit. The parity tables
//! of `streams` and `streaming` run interleaved and streamed echo on both
//! links.

use tightbeam::exactly;
use tightbeam::instrumentation::events;
use tightbeam::tb_assert_spec;
use tightbeam::tb_process_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::{ScenarioConfig, SetupEnv};
use tightbeam::transport::envelopes::GoAwayReason;
use tightbeam::transport::handshake::negotiation::MuxSettings;
use tightbeam::transport::multiplex::MuxRole;
use tightbeam::urn::Urn;

use super::common::*;
use crate::common::result::TestResult;

pub(crate) const RESPONDER_POLICY_REJECTION: Urn<'static> =
	tightbeam::urn!("test", "event:cleartext/responder-policy-rejection");

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

/// On a cleartext link, chunking and stream credit run over symmetric
/// out-of-band settings while the budget machinery stays inert, so a frame
/// that spans many chunks echoes.
#[tokio::test]
async fn a_chunked_frame_echoes_over_a_cleartext_link() -> TestResult {
	let mux = Link::Cleartext.endpoints().await;
	let _serve = spawn_immediate_echo(mux.responder);
	let frame = large_mux_frame("mux-cleartext-chunked");

	let echoed = mux.client.handle.emit_on_stream(&frame).await?;
	assert_eq!(echoed, Some(frame));
	Ok(())
}
