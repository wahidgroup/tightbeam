//! Cleartext mux parity: interleaved echo, cancel budget, chunked credit.

use std::sync::Arc;

use tightbeam::exactly;
use tightbeam::tb_assert_spec;
use tightbeam::tb_process_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::{ScenarioConf, SetupEnv};
use tightbeam::transport::handshake::negotiation::MuxSettings;
use tightbeam::transport::multiplex::MuxRole;
use tokio::sync::Notify;

use super::common::*;

tb_assert_spec! {
	pub MuxCleartextInterleavedSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(first_stream_echoed, exactly!(1), equals!(true)),
			(second_stream_echoed, exactly!(1), equals!(true))
		]
	}
}

// Cleartext mux over raw TCP: no handshake, symmetric out-of-band
// settings, two interleaved streams answered out of order.
tb_scenario! {
	name: mux_cleartext_interleaved_echo,
	spec: MuxCleartextInterleavedSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (client, server) = establish_cleartext_transports().await?;
			let settings = MuxSettings::symmetric(4);
			let (client_end, _client_responder) =
				spawn_cleartext_mux_endpoint(client, MuxRole::Client, settings, None)?;
			let (_server_end, server_responder) =
				spawn_cleartext_mux_endpoint(server, MuxRole::Server, settings, None)?;

			let frame_first = mux_frame("clear-first");
			let frame_second = mux_frame("clear-second");
			let gate = Arc::new(Notify::new());
			let handler = order_forcing_echo(frame_first.to_owned(), gate);
			let _server_serve = tokio::spawn(server_responder.serve(handler));

			let (first, second) = tokio::join!(
				client_end.handle.emit_on_stream(&frame_first),
				client_end.handle.emit_on_stream(&frame_second),
			);

			trace.event_with(
				MuxCleartextInterleavedSpec::first_stream_echoed,
				&[],
				is_echo(first?, &frame_first),
			)?;
			trace.event_with(
				MuxCleartextInterleavedSpec::second_stream_echoed,
				&[],
				is_echo(second?, &frame_second),
			)?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxCleartextCancelBudgetSpec,
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
	pub MuxCleartextCancelBudgetProcess,
	events {
		observable {
			MuxCleartextCancelBudgetSpec::goaway_enhance_your_calm,
			MuxCleartextCancelBudgetSpec::responder_policy_rejection
		}
		hidden { }
	}
	states {
		Idle => { MuxCleartextCancelBudgetSpec::goaway_enhance_your_calm => GoAwaySeen },
		GoAwaySeen => { MuxCleartextCancelBudgetSpec::responder_policy_rejection => Done },
		Done => { }
	}
	terminal { Done }
}

// Cancel-budget hardening holds on cleartext links too: budget + 1
// open/cancel pairs answered with GoAway(EnhanceYourCalm).
tb_scenario! {
	name: mux_cleartext_cancel_budget,
	config: ScenarioConf::builder()
		.with_spec(MuxCleartextCancelBudgetSpec::latest())
		.with_csp(MuxCleartextCancelBudgetProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (client, server) = establish_cleartext_transports().await?;
			let cancel_budget = 2;
			let settings = MuxSettings::symmetric(8);
			let (_server_end, responder) =
				spawn_cleartext_mux_endpoint(server, MuxRole::Server, settings, Some(cancel_budget))?;
			let (client_reader, client_writer) = client.into_split_cleartext()?;

			let outcome = run_cancel_abuse(client_reader, client_writer, responder, cancel_budget).await?;
			record_cancel_abuse(
				&trace,
				&outcome,
				MuxCleartextCancelBudgetSpec::goaway_enhance_your_calm,
				MuxCleartextCancelBudgetSpec::responder_policy_rejection,
			)?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub MuxCleartextChunkedSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(cleartext_budgets_unmetered, exactly!(1), equals!(true)),
			(cleartext_chunked_echo, exactly!(1), equals!(true))
		]
	}
}

// Cleartext parity: chunking and stream credit run over symmetric
// out-of-band settings while the budget machinery stays inert
// (unmetered by construction, no epoch to renew).
tb_scenario! {
	name: mux_cleartext_chunked_parity,
	spec: MuxCleartextChunkedSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let (client, server) = establish_cleartext_transports().await?;
			let mut settings = MuxSettings::symmetric(4);
			settings.send_chunk_size = 1024;
			settings.recv_chunk_size = 1024;

			trace.event_with(
				MuxCleartextChunkedSpec::cleartext_budgets_unmetered,
				&[],
				settings.send_budget.is_none() && settings.recv_budget.is_none(),
			)?;

			let (client_end, _client_responder) =
				spawn_cleartext_mux_endpoint(client, MuxRole::Client, settings, None)?;
			let (_server_end, server_responder) =
				spawn_cleartext_mux_endpoint(server, MuxRole::Server, settings, None)?;
			let _serve = spawn_immediate_echo(server_responder);

			let frame = large_mux_frame("mux-cleartext-chunked");
			let echoed = client_end.handle.emit_on_stream(&frame).await?;
			trace.event_with(MuxCleartextChunkedSpec::cleartext_chunked_echo, &[], is_echo(echoed, &frame))?;

			Ok(())
		}
	}
}
