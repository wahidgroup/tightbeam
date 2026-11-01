//! Delay simulation for the DTN tests.
//!
//! The simulator is test code over `HashMap` and the tokio clock, so the tests
//! of this file are self-checks of the harness, and no tightbeam code runs in
//! them.

use std::collections::HashMap;
use std::time::Duration;

/// A simulator of the network delays between the nodes of a DTN network.
///
/// Each hop takes a delay of its own, so a test can model long-distance
/// links such as Earth to Mars.
pub struct DelaySimulator {
	delays: HashMap<String, Duration>,
}

impl DelaySimulator {
	/// Creates a simulator with an empty delay table.
	pub fn new() -> Self {
		Self { delays: HashMap::new() }
	}

	/// Sets the delay of `hop`.
	///
	/// The hop name has the form `source->destination`, such as `Earth->Relay`.
	pub fn configure_delay(&mut self, hop: impl Into<String>, delay: Duration) {
		self.delays.insert(hop.into(), delay);
	}

	/// Sleeps for the delay of the hop from `from` to `to`, and returns at
	/// once for a hop with no configured delay.
	///
	/// The sleep stands for the signal propagation time of a real DTN path,
	/// plus any store-and-forward delay.
	pub async fn simulate_hop(&self, from: impl AsRef<str>, to: impl AsRef<str>) {
		let from = from.as_ref();
		let to = to.as_ref();
		let hop_key = format!("{}->{}", from, to);

		if let Some(delay) = self.delays.get(&hop_key) {
			tokio::time::sleep(*delay).await;
		}
	}

	/// The delay configured for the hop from `from` to `to`, if any.
	pub fn delay_for(&self, from: impl AsRef<str>, to: impl AsRef<str>) -> Option<Duration> {
		let from = from.as_ref();
		let to = to.as_ref();
		let hop_key = format!("{}->{}", from, to);
		self.delays.get(&hop_key).copied()
	}
}

impl Default for DelaySimulator {
	fn default() -> Self {
		Self::new()
	}
}

mod tests {
	use tightbeam::tb_cases;

	use super::*;

	// A hop sleeps for its configured delay, which the paused clock reads
	// exactly, and a hop with no configured delay returns at once.
	tb_cases! {
		#[tokio::test(start_paused = true)]
		async fn a_hop_sleeps_for_its_configured_delay((from, to, slept): (&str, &str, Duration)) {
			let mut sim = DelaySimulator::new();
			sim.configure_delay("Earth->Relay", Duration::from_millis(100));

			let start = tokio::time::Instant::now();
			sim.simulate_hop(from, to).await;
			assert_eq!(start.elapsed(), slept);
		}
		cases {
			configured_hop => ("Earth", "Relay", Duration::from_millis(100)),
			unconfigured_hop => ("Node1", "Node2", Duration::ZERO),
		}
	}

	// A configured delay belongs to its own direction of a hop.
	tb_cases! {
		fn a_delay_belongs_to_its_own_direction((from, to, delay): (&str, &str, Option<Duration>)) {
			let mut sim = DelaySimulator::new();
			sim.configure_delay("Earth->Mars", Duration::from_secs(1200));

			let configured = sim.delay_for(from, to);
			assert_eq!(configured, delay);
		}
		cases {
			configured => ("Earth", "Mars", Some(Duration::from_secs(1200))),
			reverse => ("Mars", "Earth", None),
		}
	}
}
