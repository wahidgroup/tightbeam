//! Guarded ownership of the peer table's mutable state.
//!
//! [`GuardedTable`] owns the one `Mutex` over the table, so every mutation
//! reaches the state through [`GuardedTable::change`]. Each mutation
//! therefore takes its generation inside the guard that applied it, which
//! lets the driver drop a snapshot that a newer one superseded (CWE-362).

use std::collections::HashMap;
use std::sync::Mutex;

use super::{AdmittedDial, ClusterError, PeerAddress, PeerRecord};
use crate::utils::time::UnixMillis;

/// What the table knows about one peer address.
#[derive(Debug, Clone)]
pub struct PeerEntry {
	/// Peer certificate fingerprint, advisory until a probe verifies the peer.
	pub peer_id: Option<Vec<u8>>,
	/// Time of the last probe attempt, which orders the probe backlog.
	pub last_probe: UnixMillis,
	/// Consecutive failed beat dials since the last verified probe.
	///
	/// The count lives in memory only. A restart sets the count to zero
	/// because the following beats re-verify every resident.
	pub failures: usize,
}

/// The peer table's mutable state, reachable only through [`GuardedTable`].
#[derive(Debug, Default)]
pub struct TableState {
	/// Learned peers that no probe has verified yet.
	pub new: HashMap<AdmittedDial, PeerEntry>,
	/// Learned peers that a probe has verified.
	pub tried: HashMap<AdmittedDial, PeerEntry>,
	/// Anchors whose beat dial passed the colony gate.
	///
	/// A seed shares its verified anchors over PEX, which is how a
	/// bootstrapping peer learns its first dial targets.
	pub anchors_verified: HashMap<AdmittedDial, PeerEntry>,
	/// This gateway's own advertised address, held out of peer admission.
	pub local: Option<PeerAddress>,
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
