//! Guarded ownership of the peer table's mutable state.
//!
//! The `Mutex` lives here and nowhere else, so a mutation reaches the
//! state through [`GuardedTable::change`] alone. Every mutation therefore
//! mints its generation inside the guard that applied it, which is what
//! lets the driver drop a snapshot a newer one superseded (CWE-362).

use std::collections::HashMap;
use std::sync::Mutex;

use super::{ClusterError, PeerRecord};

#[derive(Debug, Clone)]
pub struct PeerEntry {
	pub peer_id: Option<Vec<u8>>,
	pub last_probe_ms: u64,
	/// Consecutive failed beat dials since the last verified probe.
	///
	/// The count lives in memory only. A restart starts the count at
	/// zero because the following beats re-verify every resident.
	pub failures: usize,
}

#[derive(Debug, Default)]
pub struct TableState {
	pub new: HashMap<String, PeerEntry>,
	pub tried: HashMap<String, PeerEntry>,
	/// Anchors whose beat dial passed the colony gate.
	///
	/// A seed shares its verified anchors over PEX, which is how a
	/// bootstrapping peer learns its first dial targets.
	pub anchors_verified: HashMap<String, PeerEntry>,
	/// This gateway's own advertised address, held out of peer admission.
	pub local: Option<String>,
	/// Mutations applied so far, minted inside the guard that applies them.
	///
	/// A snapshot taken at generation N holds every change below N, so the
	/// newest snapshot to reach the driver is always the complete one.
	pub generation: u64,
}

/// One durable change, and the generation it applied at.
pub struct PendingWrite {
	/// Generation minted inside the guard that produced `records`.
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
	/// Reads the table under the guard.
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
				gateway_addr: addr.clone(),
				peer_id: entry.peer_id.clone(),
				tried,
				last_probe_ms: entry.last_probe_ms,
			})
			.collect()
	}
}
