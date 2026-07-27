//! Integration tests for automatic instrumentation in testing framework
//!
//! Demonstrates Phase 2: tb_scenario! automatic instrumentation capture

#![cfg(all(feature = "instrument", feature = "tokio", feature = "tcp", feature = "testing"))]

use tightbeam::testing::{create_test_message, ClientEnv, ScenarioConf, SetupEnv};
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::tcp::TightBeamSocketAddr;
use tightbeam::transport::{MessageEmitter, Protocol};
use tightbeam::utils::urn::Urn;
use tightbeam::{compose, server, tb_assert_spec, tb_process_spec, tb_scenario};

pub(crate) const MESSAGE_COLLECT: Urn<'static> = Urn::new("test", "event:instrumentation-tests/message-collect");
pub(crate) const MESSAGE_EMIT: Urn<'static> = Urn::new("test", "event:instrumentation-tests/message-emit");

tb_assert_spec! {
	pub AutoInstrSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: []
	}
}

// CSP process spec for automatic message flow verification
tb_process_spec! {
	pub MessageFlowProc,
	events {
		observable { MESSAGE_EMIT, MESSAGE_COLLECT }
		hidden { }
	}
	states {
		S0 => { MESSAGE_EMIT => S1 },
		S1 => { MESSAGE_COLLECT => S2 }
	}
	terminal { S2 }
	annotations { description: "Automatic message emit -> collect flow" }
}

mod sink {
	use std::sync::{Arc, Mutex};

	use tightbeam::instrumentation::{events, EventSink, TbEvent, TbInstrumentationConfig};
	use tightbeam::trace::{TraceCollector, TraceConfig};

	/// Mission-critical sink: retains every event, never drops.
	#[derive(Default)]
	struct LossFreeSink {
		events: Mutex<Vec<TbEvent>>,
	}

	impl EventSink for LossFreeSink {
		fn emit(&self, event: TbEvent) {
			if let Ok(mut events) = self.events.lock() {
				events.push(event);
			}
		}

		fn drain(&self) -> Vec<TbEvent> {
			if let Ok(mut events) = self.events.lock() {
				events.drain(..).collect()
			} else {
				Vec::new()
			}
		}

		fn overflowed(&self) -> bool {
			false
		}
	}

	fn count_urn(drained: &[TbEvent], urn: tightbeam::utils::urn::Urn<'static>) -> usize {
		drained.iter().filter(|e| e.urn == urn).count()
	}

	#[test]
	fn consumer_sink_keeps_every_event_past_default_bound() {
		let config = TbInstrumentationConfig { max_events: 1, ..Default::default() };
		let collector = TraceCollector::from(
			TraceConfig::builder()
				.with_instrumentation(config)
				.with_sink(Arc::new(LossFreeSink::default()))
				.build(),
		);

		collector.emit_event(events::MUX_GOAWAY_SENT);
		collector.emit_event(events::MUX_EMIT_DRAINING);
		collector.emit_event(events::MUX_GOAWAY_RECV);

		assert!(!collector.overflowed(), "loss-free sink must never report overflow");

		let drained = collector.drain_events();
		assert_eq!(count_urn(&drained, events::MUX_GOAWAY_SENT), 1, "sink must retain goaway-sent");
		assert_eq!(
			count_urn(&drained, events::MUX_EMIT_DRAINING),
			1,
			"sink must retain emit-draining"
		);
		assert_eq!(count_urn(&drained, events::MUX_GOAWAY_RECV), 1, "sink must retain goaway-recv");
	}

	#[test]
	fn default_bounded_sink_truncates_and_reports_overflow() {
		let config = TbInstrumentationConfig { max_events: 1, ..Default::default() };
		let collector = TraceCollector::from(TraceConfig::with_instrumentation(config));

		collector.emit_event(events::MUX_GOAWAY_SENT);
		collector.emit_event(events::MUX_EMIT_DRAINING);

		assert!(collector.overflowed(), "bounded sink past cap must latch overflow");
		assert_eq!(collector.drain_events().len(), 1, "bounded sink must retain only up to cap");
	}
}

tb_scenario! {
	name: test_auto_instrumentation_capture,
	config: ScenarioConf::builder()
		.with_spec(AutoInstrSpec::latest())
		.with_csp(MessageFlowProc)
		.build(),
	environment ServiceClient {
		worker_threads: 1,
		server: |SetupEnv { trace, .. }| async move {
			let bind_addr = TightBeamSocketAddr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
			let (listener, addr) = <TokioListener as Protocol>::bind(bind_addr).await?;
			let handle = server! {
				protocol TokioListener: listener,
				assertions: trace.share(),
				handle: |frame, _trace| async move {
					Ok(Some(frame))
				}
			};
			Ok((handle, addr))
		},
		client: |ClientEnv { addr, .. }| async move {
			let stream = <TokioListener as Protocol>::connect(addr).await?;
			let mut client = <TokioListener as Protocol>::create_transport(stream);

			let test_message = create_test_message(None);
			let test_frame = compose! {
				V0: id: "test", order: 1u64, message: test_message
			}?;

			let _response = client.emit(test_frame, None).await?;
			Ok(())
		}
	}
}
