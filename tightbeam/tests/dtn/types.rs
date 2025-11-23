//! DTN message types and custom errors for delay-tolerant network testing

use tightbeam::Beamable;
use tightbeam::der::Sequence;
use tightbeam::TightBeamError;

/// DTN payload for multi-hop communication
///
/// This message type demonstrates tightbeam's self-contained nature:
/// - No custody transfer protocol needed
/// - No trusted intermediaries required
/// - Cryptographic chain in metadata provides verification
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct DtnPayload {
	/// Payload content
	pub content: Vec<u8>,
	/// Source node identifier
	pub source_node: String,
	/// Destination node identifier
	pub dest_node: String,
	/// Hop count for tracking message path
	pub hop_count: u32,
}

/// Network partition error (custom fault type)
///
/// This demonstrates tightbeam's ability to inject arbitrary error types
/// during testing via the InjectedError trait.
#[derive(Debug, Clone)]
pub struct NetworkPartition {
	pub from_node: String,
	pub to_node: String,
	pub duration_ms: u64,
}

impl core::fmt::Display for NetworkPartition {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(f, "Network partition {} → {} ({}ms)", self.from_node, self.to_node, self.duration_ms)
	}
}

/// Data corruption error (custom fault type)
#[derive(Debug, Clone)]
pub struct DataCorruption {
	pub bytes_affected: usize,
}

impl core::fmt::Display for DataCorruption {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(f, "Data corruption ({} bytes affected)", self.bytes_affected)
	}
}

/// Link delay error (custom fault type)
#[derive(Debug, Clone)]
pub struct LinkDelay {
	pub delay_ms: u64,
}

impl core::fmt::Display for LinkDelay {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(f, "Link delay ({}ms)", self.delay_ms)
	}
}

/// Communications fault - transient, resolves after 1-3 retries
#[derive(Debug, Clone)]
pub struct CommsFault {
	pub duration_ms: u64,
	pub retry_count: u8,
}

impl core::fmt::Display for CommsFault {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(f, "Communications fault: {}ms (retry {})", self.duration_ms, self.retry_count)
	}
}

impl From<CommsFault> for TightBeamError {
	fn from(e: CommsFault) -> Self {
		TightBeamError::InjectedFault(Box::new(e))
	}
}

/// Thermal fault - transient, resolves after cooldown cycles
#[derive(Debug, Clone)]
pub struct ThermalFault {
	pub temp_c: i8,
	pub cycle_count: u8,
}

impl core::fmt::Display for ThermalFault {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(f, "Thermal fault: {}°C (cycle {})", self.temp_c, self.cycle_count)
	}
}

impl From<ThermalFault> for TightBeamError {
	fn from(e: ThermalFault) -> Self {
		TightBeamError::InjectedFault(Box::new(e))
	}
}

