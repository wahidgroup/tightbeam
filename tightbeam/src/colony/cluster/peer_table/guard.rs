//! Guarded ownership of the peer table's mutable state.
//!
//! [`GuardedTable`] owns the one `Mutex` over the table, so every mutation
//! reaches the state through [`GuardedTable::change`]. Each mutation
//! therefore takes its generation inside the guard that applied it, which
//! lets the driver drop a snapshot that a newer one superseded (CWE-362).

use core::time::Duration;
use std::collections::HashMap;
use std::sync::Mutex;

use super::{AddressGroup, AdmittedDial, ClusterError, PeerAddress, PeerRecord};
use crate::constants::{PEER_PROBE_BACKOFF_MAX_MS, PEER_PROBE_BACKOFF_MS};
use crate::utils::time::UnixMillis;

/// What the table knows about one peer address.
#[derive(Debug, Clone)]
pub struct PeerEntry {
	/// Peer certificate fingerprint, advisory until a probe verifies the peer.
	pub peer_id: Option<Vec<u8>>,
	/// Time of the last probe attempt, which orders the probe backlog.
	pub last_probe: UnixMillis,
	/// Consecutive failed rounds since the last verified probe: beat dials for
	/// a tried peer, and feeler probes for a `new` candidate.
	///
	/// The count lives in memory only. A restart sets the count to zero
	/// because the following beats re-verify every resident.
	pub failures: usize,
}

impl PeerEntry {
	/// Whether a feeler probe of this candidate is due at `now`.
	///
	/// - A candidate that never failed a probe is always due.
	/// - A failed one waits [`PEER_PROBE_BACKOFF_MS`] after its last probe, and
	///   each further failure doubles that wait.
	/// - The wait stops growing at [`PEER_PROBE_BACKOFF_MAX_MS`].
	/// - The distance to the last probe is taken in either clock direction, so
	///   a stamp from before a backward clock step holds no candidate out for
	///   good.
	pub fn probe_due(&self, now: UnixMillis) -> bool {
		now.abs_diff(self.last_probe) >= self.probe_wait()
	}

	/// The wait the failed probes of this candidate have earned.
	fn probe_wait(&self) -> Duration {
		let Some(doublings) = self.failures.checked_sub(1) else {
			return Duration::ZERO;
		};

		let doublings = u32::try_from(doublings).unwrap_or(u32::MAX);
		let factor = 1u64.checked_shl(doublings).unwrap_or(u64::MAX);

		let wait_ms = PEER_PROBE_BACKOFF_MS.saturating_mul(factor);
		Duration::from_millis(wait_ms.min(PEER_PROBE_BACKOFF_MAX_MS))
	}
}

/// The peer table's mutable state, reachable only through [`GuardedTable`].
#[derive(Debug, Default)]
pub struct TableState {
	/// Learned peers that no probe has verified yet.
	pub new: HashMap<AdmittedDial, PeerEntry>,
	/// Learned peers that a probe has verified.
	pub tried: HashMap<AdmittedDial, PeerEntry>,
	/// Anchors whose beat dial proved flood membership.
	///
	/// A seed shares its verified anchors over PEX, which is how a
	/// bootstrapping peer learns its first dial targets. An anchor that later
	/// answers from outside the flood leaves this map.
	pub anchors_verified: HashMap<AdmittedDial, PeerEntry>,
	/// This gateway's own advertised address, held out of peer admission.
	pub local: Option<PeerAddress>,
	/// The prefix the last feeler draw ended on, so the next draw starts at
	/// the prefix after it. The cursor lives in memory only.
	pub probe_cursor: Option<AddressGroup>,
	/// The prefix the last peer-exchange draw ended on. It is kept apart from
	/// the feeler cursor, so each walk is fair on its own.
	pub pex_cursor: Option<AddressGroup>,
	/// Count of durable mutations applied so far, each one taken inside the
	/// guard that applied it.
	///
	/// A snapshot taken at generation N holds every change below N, so the
	/// newest snapshot to reach the driver is always the complete one.
	pub generation: u64,
}

/// One durable change, and the generation it applied at.
pub struct PendingWrite {
	/// Generation taken inside the guard that produced `records`.
	pub generation: u64,
	/// Table contents as of that generation.
	pub records: Vec<PeerRecord>,
}

/// Sole owner of the table state.
#[derive(Debug, Default)]
pub struct GuardedTable {
	state: Mutex<TableState>,
}

impl GuardedTable {
	/// Puts a table built before any caller could reach it behind the guard.
	pub fn new(state: TableState) -> Self {
		Self { state: Mutex::new(state) }
	}

	/// Reads the table under the guard.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the table lock is poisoned.
	pub fn read<T>(&self, view: impl FnOnce(&TableState) -> T) -> Result<T, ClusterError> {
		let state = self.state.lock()?;
		Ok(view(&state))
	}

	/// Applies `change` under the guard.
	///
	/// A `change` reporting a durable edit bumps the generation and returns
	/// the snapshot at that generation. The caller hands it to the driver
	/// after the guard is released, so a slow driver delays no reader
	/// (CWE-667).
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the table lock is poisoned.
	pub fn change<T>(
		&self,
		change: impl FnOnce(&mut TableState) -> (T, bool),
	) -> Result<(T, Option<PendingWrite>), ClusterError> {
		let mut state = self.state.lock()?;
		let (outcome, durable) = change(&mut state);
		let write = durable.then(|| {
			state.generation = state.generation.saturating_add(1);

			PendingWrite { generation: state.generation, records: Self::snapshot(&state) }
		});

		Ok((outcome, write))
	}

	/// Every learned peer as a durable record.
	fn snapshot(state: &TableState) -> Vec<PeerRecord> {
		state
			.new
			.iter()
			.map(|(addr, entry)| (addr, entry, false))
			.chain(state.tried.iter().map(|(addr, entry)| (addr, entry, true)))
			.map(|(addr, entry, tried)| PeerRecord {
				gateway_addr: addr.address(),
				peer_id: entry.peer_id.clone(),
				tried,
				last_probe: entry.last_probe,
			})
			.collect()
	}
}
