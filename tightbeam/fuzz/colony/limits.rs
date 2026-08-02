//! Harness clamps that bound oracle-decoded sizes.
//!
//! These are local AFL safety limits. They do not redefine production
//! `MAX_*` constants on the cluster runtime. Caps stay tight so one
//! iteration finishes under the AFL hang timeout.

/// Maximum opcodes executed in one AFL iteration.
pub(crate) const MAX_ACTIONS: u64 = 24;

/// Concurrent work/stream tasks inside one stress burst.
#[allow(dead_code)]
pub(crate) const MAX_IN_FLIGHT: usize = 8;

/// Live servlet instances per hive type.
pub(crate) const MAX_SERVLET_INSTANCES: usize = 4;

/// CSR certificates retained per iteration.
pub(crate) const MAX_CSR_ISSUED: usize = 8;

/// Upper bound for oracle-decoded stress batch size.
pub(crate) const MAX_STRESS_BATCH: usize = 3;

/// Dead dial target used to force Unavailable before trail failover.
pub(crate) const DEAD_PEER_ADDR: &[u8] = b"127.0.0.1:9";

/// Clamp an oracle byte into `1..=max` when non-zero.
pub(crate) fn clamp_nonzero(raw: u8, max: usize) -> usize {
	if max == 0 {
		return 0;
	}
	let n = (raw as usize) % (max + 1);
	if n == 0 {
		return 1;
	}
	n
}
