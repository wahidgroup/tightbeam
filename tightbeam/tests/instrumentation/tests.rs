//! The integration tests of automatic instrumentation in the testing framework.
//!
//! The scenario shows that `tb_scenario!` captures the production events of a
//! server that records into the scenario trace: the gate verdict and the
//! handler span of the request that the server serves.

#![cfg(all(feature = "instrument", feature = "tokio", feature = "tcp", feature = "testing"))]

use tightbeam::instrumentation::{events, TbInstrumentationConfig};
use tightbeam::testing::{ClientEnv, ScenarioConfig, SetupEnv, TestMessage};
use tightbeam::trace::TraceConfig;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::tcp::TightBeamSocketAddr;
use tightbeam::transport::{EndpointConfig, MessageEmitter, Protocol};
use tightbeam::{compose, exactly, server, tb_assert_spec, tb_process_spec, tb_scenario};

tb_assert_spec! {
	pub AutoInstrSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::POLICY_EVAL, exactly!(1)),
			(events::GATE_ACCEPT, exactly!(1)),
			(events::HANDLER_ENTER, exactly!(1)),
			(events::HANDLER_EXIT, exactly!(1))
		]
	}
}

// The CSP process spec of the request flow on the server: the gate evaluates
// the request and admits it, and then the handler runs.
tb_process_spec! {
	pub MessageFlowProc,
	events {
		observable { events::POLICY_EVAL, events::GATE_ACCEPT, events::HANDLER_ENTER, events::HANDLER_EXIT }
		hidden { }
	}
	states {
		S0 => { events::POLICY_EVAL => S1 },
		S1 => { events::GATE_ACCEPT => S2 },
		S2 => { events::HANDLER_ENTER => S3 },
		S3 => { events::HANDLER_EXIT => S4 }
	}
	terminal { S4 }
	annotations { description: "The server gates the request and then runs its handler" }
}

mod sink {
	use core::sync::atomic::{AtomicBool, Ordering};
	use std::borrow::Cow;
	use std::sync::Mutex;

	use tightbeam::instrumentation::{events, EventSink, TbEvent, TbInstrumentationConfig};
	use tightbeam::trace::{TraceCollector, TraceConfig};

	/// A loss-free sink, which holds every event in an unbounded list.
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

	fn count_urn(drained: impl AsRef<[TbEvent]>, urn: tightbeam::urn::Urn<'static>) -> usize {
		let drained = drained.as_ref();
		drained.iter().filter(|e| e.urn == urn).count()
	}

	#[test]
	fn consumer_sink_keeps_every_event_past_default_bound() -> Result<(), tightbeam::TightBeamError> {
		let config = TbInstrumentationConfig { max_events: 1, ..Default::default() };
		let collector =
			TraceCollector::from(TraceConfig::with_instrumentation(config).with_sink(LossFreeSink::default()));

		collector.emit_event(events::MUX_GOAWAY_SENT)?;
		collector.emit_event(events::MUX_EMIT_DRAINING)?;
		collector.emit_event(events::MUX_GOAWAY_RECV)?;

		assert!(!collector.overflowed(), "loss-free sink must never report overflow");

		let drained = collector.drain_events();
		assert_eq!(count_urn(&drained, events::MUX_GOAWAY_SENT), 1, "sink must retain goaway-sent");
		assert_eq!(
			count_urn(&drained, events::MUX_EMIT_DRAINING),
			1,
			"sink must retain emit-draining"
		);
		assert_eq!(count_urn(&drained, events::MUX_GOAWAY_RECV), 1, "sink must retain goaway-recv");
		Ok(())
	}

	#[test]
	fn default_bounded_sink_truncates_and_reports_overflow() -> Result<(), tightbeam::TightBeamError> {
		let config = TbInstrumentationConfig { max_events: 1, ..Default::default() };
		let collector = TraceCollector::from(TraceConfig::with_instrumentation(config));

		collector.emit_event(events::MUX_GOAWAY_SENT)?;
		collector.emit_event(events::MUX_EMIT_DRAINING)?;

		assert!(collector.overflowed(), "bounded sink past cap must latch overflow");
		assert_eq!(
			collector.drain_events().len(),
			2,
			"bounded sink must retain up to cap and one warning"
		);
		Ok(())
	}

	/// A sink that holds one event, and keeps the overflow warning of the first
	/// event past it, as [`EventSink`] asks of a sink that drops events.
	#[derive(Default)]
	struct OneEventSink {
		events: Mutex<Vec<TbEvent>>,
		overflow: AtomicBool,
	}

	impl EventSink for OneEventSink {
		fn emit(&self, event: TbEvent) {
			let Ok(mut events) = self.events.lock() else {
				return;
			};
			if events.is_empty() {
				events.push(event);
				return;
			}

			let first_drop = !self.overflow.swap(true, Ordering::Relaxed);
			if first_drop {
				events.push(event.into_overflow_warning());
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
			self.overflow.load(Ordering::Relaxed)
		}
	}

	/// A sink of an outside crate keeps the warning of the first event it
	/// drops, under the sequence number of that event and named by its URN.
	#[test]
	fn an_outside_sink_keeps_the_warning_of_the_first_event_it_drops() {
		let collector = TraceCollector::from(TraceConfig::default().with_sink(OneEventSink::default()));
		collector.emit(events::MUX_GOAWAY_SENT, "kept");
		collector.emit(events::MUX_EMIT_DRAINING, "replaced");
		collector.emit(events::MUX_GOAWAY_RECV, "dropped");

		let drained = collector.drain_events();

		let records: Vec<_> = drained.into_iter().map(|event| (event.seq, event.urn, event.label)).collect();
		let warning_label = Some(Cow::Borrowed("urn:tightbeam:event:mux/emit-draining"));
		let expected = [
			(0, events::MUX_GOAWAY_SENT, Some(Cow::Borrowed("kept"))),
			(1, events::WARN, warning_label),
		];
		assert_eq!(records, expected);
	}
}

tb_scenario! {
	name: test_auto_instrumentation_capture,
	config: ScenarioConfig::builder()
		.with_spec(AutoInstrSpec::latest())
		.with_csp(MessageFlowProc)
		.with_trace(TraceConfig::with_instrumentation(TbInstrumentationConfig {
			enable_internal_detail: true,
			..Default::default()
		}).into())
		.build(),
	environment ServiceClient {
		worker_threads: 1,
		server: |SetupEnv { trace, .. }| async move {
			let bind_addr = TightBeamSocketAddr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
			let (listener, addr) = <TokioListener as Protocol>::bind_cleartext(bind_addr).await?;
			let handle = server! {
				protocol TokioListener: listener,
				policies: { with_trace: [ trace.share() ] },
				handle: |frame: tightbeam::Frame| async move {
					Ok(Some(frame))
				}
			};
			Ok((handle, addr))
		},
		client: |ClientEnv { addr, .. }| async move {
			let stream = <TokioListener as Protocol>::connect(addr).await?;
			let mut client = <TokioListener as Protocol>::create_transport(stream, EndpointConfig::cleartext());

			let test_message = TestMessage::sample(None);
			let test_frame = compose! {
				V0: id: "test", order: 1u64, message: test_message
			}?;

			let response = client.emit(test_frame, None).await?;

			assert!(response.is_some(), "the echo handler must return the frame it received");
			Ok(())
		}
	}
}
