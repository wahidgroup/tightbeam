//! Delay simulation utilities for DTN testing

use std::collections::HashMap;
use std::time::Duration;
use tightbeam::TightBeamError;

/// Simulates network delays between nodes in a DTN network
///
/// Provides configurable delays for different hops to simulate
/// realistic long-distance communication scenarios (e.g., Earth-Mars).
pub struct DelaySimulator {
	delays: HashMap<String, Duration>,
}

impl DelaySimulator {
	/// Create a new delay simulator
	pub fn new() -> Self {
		Self { delays: HashMap::new() }
	}

	/// Configure delay for a specific hop
	///
	/// Hop identifier should be in format "source->destination" (e.g., "Earth->Relay")
	pub fn configure_delay(&mut self, hop: impl Into<String>, delay: Duration) {
		self.delays.insert(hop.into(), delay);
	}

	/// Simulate delay for a hop
	///
	/// This is an async function that sleeps for the configured duration.
	/// In a real DTN scenario, this represents the time for signal propagation
	/// plus any store-and-forward delays.
	pub async fn simulate_hop(&self, from: &str, to: &str) -> Result<(), TightBeamError> {
		let hop_key = format!("{}->{}",from, to);

		if let Some(delay) = self.delays.get(&hop_key) {
			tokio::time::sleep(*delay).await;
		}

		Ok(())
	}

	/// Get configured delay for a hop
	pub fn delay_for(&self, from: &str, to: &str) -> Option<Duration> {
		let hop_key = format!("{}->{}",from, to);
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

	#[tokio::test]
	async fn delay_simulator_basic() -> Result<(), TightBeamError> {
		let mut sim = DelaySimulator::new();

		// Configure 100ms delay
		sim.configure_delay("Earth->Relay", Duration::from_millis(100));

		// Simulate should take at least 100ms
		let start = std::time::Instant::now();
		sim.simulate_hop("Earth", "Relay").await?;
		let elapsed = start.elapsed();

		assert!(elapsed >= Duration::from_millis(100));
		assert!(elapsed < Duration::from_millis(150)); // Some tolerance for scheduling

		Ok(())
	}

	#[tokio::test]
	async fn delay_simulator_unconfigured_hop() -> Result<(), TightBeamError> {
		let sim = DelaySimulator::new();

		// Unconfigured hop should return immediately
		let start = std::time::Instant::now();
		sim.simulate_hop("Node1", "Node2").await?;
		let elapsed = start.elapsed();

		assert!(elapsed < Duration::from_millis(10));

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

