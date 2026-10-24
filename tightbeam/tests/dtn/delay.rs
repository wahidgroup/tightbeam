//! Delay simulation for the DTN tests.

use std::collections::HashMap;
use std::time::Duration;
use tightbeam::TightBeamError;

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
	pub async fn simulate_hop(&self, from: impl AsRef<str>, to: impl AsRef<str>) -> Result<(), TightBeamError> {
		let from = from.as_ref();
		let to = to.as_ref();
		let hop_key = format!("{}->{}", from, to);

		if let Some(delay) = self.delays.get(&hop_key) {
			tokio::time::sleep(*delay).await;
		}

		Ok(())
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

#[cfg(test)]
mod tests {
	use super::*;

	/// A configured hop sleeps for its delay, which the paused clock reads
	/// exactly.
	#[tokio::test(start_paused = true)]
	async fn delay_simulator_basic() -> Result<(), TightBeamError> {
		let mut sim = DelaySimulator::new();

		sim.configure_delay("Earth->Relay", Duration::from_millis(100));

		let start = tokio::time::Instant::now();
		sim.simulate_hop("Earth", "Relay").await?;
		let elapsed = start.elapsed();

		assert_eq!(elapsed, Duration::from_millis(100));

		Ok(())
	}

	/// A hop with no configured delay returns at once.
	#[tokio::test(start_paused = true)]
	async fn delay_simulator_unconfigured_hop() -> Result<(), TightBeamError> {
		let sim = DelaySimulator::new();

		let start = tokio::time::Instant::now();
		sim.simulate_hop("Node1", "Node2").await?;
		let elapsed = start.elapsed();

		assert_eq!(elapsed, Duration::ZERO);

		Ok(())
	}

	#[test]
	fn delay_simulator_query() {
		let mut sim = DelaySimulator::new();

		sim.configure_delay("Earth->Mars", Duration::from_secs(1200)); // 20 minutes

		assert_eq!(sim.delay_for("Earth", "Mars"), Some(Duration::from_secs(1200)));
		assert_eq!(sim.delay_for("Mars", "Earth"), None);
	}
}
