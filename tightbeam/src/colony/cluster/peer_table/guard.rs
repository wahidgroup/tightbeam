//! Guarded ownership of the peer table's mutable state.
//!
//! [`GuardedTable`] owns the one `Mutex` over the table, so every mutation
//! reaches the state through [`GuardedTable::change`]. Each mutation
//! therefore takes its generation inside the guard that applied it, which
//! lets the driver drop a snapshot that a newer one superseded (CWE-362).
//!
//! [`TableState`] keeps its tables private and holds the bounds it was built
//! with. [`TableState::admit`] is therefore the only insert into either
//! learned table, and no code outside this file can skip a bound (CWE-770).

use core::cmp::Reverse;
use core::num::NonZeroUsize;
use core::time::Duration;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use super::{AddressGroup, AdmittedDial, ClusterError, PeerAddress, PeerHint, PeerRecord};
use crate::clock::UnixMillis;
use crate::constants::{
	MAX_PEER_BUCKET, MAX_PEER_TABLE_NEW, MAX_PEER_TABLE_TRIED, MAX_PEER_TRIED_FAILURES, PEER_PROBE_BACKOFF_MAX_MS,
	PEER_PROBE_BACKOFF_MS, PEER_PROBE_PER_BEAT,
};

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
	/// - The check takes the distance to the last probe in either clock
	///   direction, so a stamp from before a backward clock step holds no
	///   candidate out for good.
	pub fn probe_due(&self, now: UnixMillis) -> bool {
		now.abs_diff(self.last_probe) >= self.probe_wait()
	}

	/// The durable record of this entry for the peer at `addr`, which `tried`
	/// places in the tried table or the new one.
	///
	/// Peer exchange and the persisted snapshot both read an entry through
	/// this one mapping, so the two agree on what a record holds.
	pub fn record(&self, addr: AdmittedDial, tried: bool) -> PeerRecord {
		let peer_id = self.peer_id.clone();
		PeerRecord { gateway_addr: addr.address(), peer_id, tried, last_probe: self.last_probe }
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

/// The bounds that every admission into the table meets.
///
/// [`GuardedTable::new`] gives a table its bounds, and the table keeps them,
/// so every later admission meets those same bounds.
#[derive(Debug, Default)]
pub struct Bounds {
	/// The configured anchors, which admission keeps out of both learned
	/// tables.
	pub anchors: HashSet<AdmittedDial>,
	/// Cap on the tried entries one signer holds, where `None` sets no cap.
	pub tried_per_signer: Option<NonZeroUsize>,
}

/// The peer table's mutable state, reachable only through [`GuardedTable`].
///
/// The fields are private, so every transition is a method here and
/// [`Self::admit`] is the only insert into either learned table. Only
/// [`GuardedTable::new`] builds a state, so no caller can put a fresh one,
/// with other bounds, in its place.
#[derive(Debug)]
pub struct TableState {
	/// The bounds that every admission meets, fixed for the life of the table.
	bounds: Bounds,
	/// Learned peers that wait for their first verified probe.
	new: HashMap<AdmittedDial, PeerEntry>,
	/// Learned peers that a probe has verified.
	tried: HashMap<AdmittedDial, PeerEntry>,
	/// Anchors whose beat dial proved flood membership.
	///
	/// A seed shares its verified anchors over PEX, which is how a peer at
	/// bootstrap learns its first dial targets. An anchor that later
	/// answers from outside the flood leaves this map.
	anchors_verified: HashMap<AdmittedDial, PeerEntry>,
	/// This gateway's own advertised address, held out of peer admission.
	local: Option<PeerAddress>,
	/// The prefix the last feeler draw ended on, so the next draw starts at
	/// the prefix after it. The cursor lives in memory only.
	probe_cursor: Option<AddressGroup>,
	/// The prefix the last peer-exchange draw ended on. It stays apart from
	/// the feeler cursor, so each walk is fair on its own.
	pex_cursor: Option<AddressGroup>,
	/// Count of durable mutations applied so far, each one taken inside the
	/// guard that applied it.
	///
	/// A snapshot taken at generation N holds every change below N, so the
	/// newest snapshot to reach the driver is always the complete one.
	generation: u64,
}

impl TableState {
	/// An empty state held to `bounds` for as long as it lives.
	fn new(bounds: Bounds) -> Self {
		Self {
			bounds,
			new: HashMap::new(),
			tried: HashMap::new(),
			anchors_verified: HashMap::new(),
			local: None,
			probe_cursor: None,
			pex_cursor: None,
			generation: 0,
		}
	}

	/// Admits one candidate into its table, or refuses it.
	///
	/// This is the only insert into either learned table. A hint, a verified
	/// probe, and a hydrated record therefore all meet anchor exclusion, the
	/// table and prefix bounds, and the signer cap here (CWE-770).
	pub fn admit(&mut self, candidate: Candidate) -> bool {
		let Candidate { dial: key, tried, entry } = candidate;
		let group = key.address().group();
		if self.bounds.anchors.contains(&key) || self.tried.contains_key(&key) {
			return false;
		}
		if self.local == Some(key.address()) {
			return false;
		}

		if tried {
			let within_table = self.tried.len() < MAX_PEER_TABLE_TRIED;
			let within_bucket = bucket_len(&self.tried, group) < MAX_PEER_BUCKET;
			let within_signer = !signer_at_cap(&self.tried, self.bounds.tried_per_signer, entry.peer_id.as_deref());
			if !(within_table && within_bucket && within_signer) {
				return false;
			}

			self.new.remove(&key);
			self.tried.insert(key, entry);

			return true;
		}

		if self.new.contains_key(&key) {
			return false;
		}

		let within_table = self.new.len() < MAX_PEER_TABLE_NEW;
		let within_bucket = bucket_len(&self.new, group) < MAX_PEER_BUCKET;
		if !(within_table && within_bucket) {
			// A full bucket yields the slot of a candidate that failed a probe
			// and of no other, so a dead address never blocks a newcomer and a
			// flood of hints never displaces an untested one (CWE-770).
			let reach = (!within_bucket).then_some(group);
			let Some(failed) = most_failed(&self.new, reach) else {
				return false;
			};

			self.new.remove(&failed);
		}

		self.new.insert(key, entry);
		true
	}

	/// Admits `hints` as unverified candidates stamped at `now`, and returns
	/// how many it took.
	pub fn learn(&mut self, hints: impl IntoIterator<Item = PeerHint>, now: UnixMillis) -> usize {
		let mut admitted: usize = 0;
		for hint in hints {
			let entry = PeerEntry { peer_id: hint.peer_id, last_probe: now, failures: 0 };
			let candidate = Candidate { dial: hint.dial, tried: false, entry };
			if self.admit(candidate) {
				admitted = admitted.saturating_add(1);
			}
		}

		admitted
	}

	/// Records a verified probe of `addr` under the signer that answered.
	///
	/// It returns whether it promoted the address into tried, and whether a
	/// learned table moved.
	pub fn promote(&mut self, addr: AdmittedDial, peer_id: Option<&[u8]>, now: UnixMillis) -> (bool, bool) {
		// Anchors are configured rather than learned, so a verified anchor
		// lands in its own map and leaves both learned tables as they are.
		if self.bounds.anchors.contains(&addr) {
			let entry = PeerEntry { peer_id: peer_id.map(<[u8]>::to_vec), last_probe: now, failures: 0 };
			self.anchors_verified.insert(addr, entry);

			return (false, false);
		}

		// A resident leaves its slot for the length of this call, so the one
		// admission path decides whether the signer that answered may hold
		// it. A resident that keeps its signer always wins the slot back.
		let resident = self.tried.remove(&addr);
		let recorded = resident.as_ref().and_then(|held| held.peer_id.clone());
		let signer = peer_id.map(<[u8]>::to_vec).or(recorded);
		let entry = PeerEntry { peer_id: signer, last_probe: now, failures: 0 };

		let admitted = self.admit(Candidate { dial: addr, tried: true, entry: entry.clone() });
		let was_resident = resident.is_some();
		if was_resident && !admitted {
			// The signer that answered is at its cap, so the address waits
			// in `new` the way a capped candidate does. A full `new` table
			// drops it, so a later hint can teach it again.
			self.admit(Candidate { dial: addr, tried: false, entry });
		}

		(admitted && !was_resident, admitted || was_resident)
	}

	/// Counts a failed probe on the candidate at `addr`, which keeps its slot.
	pub fn record_probe_failure(&mut self, addr: AdmittedDial, now: UnixMillis) {
		if let Some(entry) = self.new.get_mut(&addr) {
			entry.failures = entry.failures.saturating_add(1);
			entry.last_probe = now;
		}
	}

	/// Drops the candidate at `addr`, and returns whether one was there.
	pub fn discard(&mut self, addr: AdmittedDial) -> bool {
		self.new.remove(&addr).is_some()
	}

	/// Counts a failed beat dial on the tried peer at `addr`, and evicts the
	/// peer at the failure threshold. It returns whether it evicted the peer.
	pub fn record_failure(&mut self, addr: AdmittedDial) -> bool {
		let Some(entry) = self.tried.get_mut(&addr) else {
			return false;
		};

		entry.failures = entry.failures.saturating_add(1);

		if entry.failures < MAX_PEER_TRIED_FAILURES {
			return false;
		}

		self.tried.remove(&addr);

		true
	}

	/// Removes `addr` from both learned tables and from the verified anchors.
	/// It returns whether a learned table moved.
	pub fn expel(&mut self, addr: AdmittedDial) -> bool {
		let from_new = self.new.remove(&addr).is_some();
		let from_tried = self.tried.remove(&addr).is_some();
		self.anchors_verified.remove(&addr);

		from_new || from_tried
	}

	/// Holds this gateway's own address out of admission, and evicts it from
	/// both learned tables.
	pub fn exclude(&mut self, addr: PeerAddress) {
		self.new.retain(|dial, _| dial.address() != addr);
		self.tried.retain(|dial, _| dial.address() != addr);
		self.local = Some(addr);
	}

	/// The address of every tried peer.
	pub fn tried_dials(&self) -> Vec<AdmittedDial> {
		self.tried.keys().copied().collect()
	}

	/// Draws this beat's feeler sample from the candidates that are due, and
	/// stamps each one drawn with `now`.
	pub fn probe_sample(&mut self, now: UnixMillis) -> Vec<AdmittedDial> {
		let due = self.new.iter().filter(|(_, entry)| entry.probe_due(now));
		let draw = diversity_sample(due, PEER_PROBE_PER_BEAT, self.probe_cursor);
		self.probe_cursor = draw.served_last.or(self.probe_cursor);

		for addr in &draw.sample {
			if let Some(entry) = self.new.get_mut(addr) {
				entry.last_probe = now;
			}
		}

		draw.sample
	}

	/// Draws up to `cap` verified peers to share over peer exchange.
	pub fn pex_sample(&mut self, cap: usize) -> Vec<PeerRecord> {
		// Anchors and tried are disjoint maps, so a chain of the two borrows a
		// disjoint shareable view and builds no merged copy. Only the
		// sampled records own their data, because they outlive the guard.
		let shareable = self.tried.iter().chain(self.anchors_verified.iter());
		let draw = diversity_sample(shareable, cap, self.pex_cursor);
		self.pex_cursor = draw.served_last.or(self.pex_cursor);

		let shared = draw.sample.into_iter();
		shared.filter_map(|addr| self.shared_record(addr)).collect()
	}

	/// The record peer exchange shares for the verified peer at `addr`.
	fn shared_record(&self, addr: AdmittedDial) -> Option<PeerRecord> {
		let entry = self.tried.get(&addr).or_else(|| self.anchors_verified.get(&addr))?;
		let record = entry.record(addr, true);

		Some(record)
	}

	/// The sockets among `advertised` that this state still holds as a
	/// candidate, a tried peer, or a verified anchor.
	pub fn held_among(&self, advertised: impl IntoIterator<Item = PeerAddress>) -> HashSet<PeerAddress> {
		let entries = self.new.keys().chain(self.tried.keys()).chain(self.anchors_verified.keys());
		let held: HashSet<PeerAddress> = entries.map(AdmittedDial::address).collect();

		advertised.into_iter().filter(|socket| held.contains(socket)).collect()
	}

	/// The learned sizes as `(new, tried)`.
	pub fn learned(&self) -> (usize, usize) {
		(self.new.len(), self.tried.len())
	}

	/// Whether any tried peer exists.
	pub fn has_tried(&self) -> bool {
		!self.tried.is_empty()
	}
}

/// Counts the entries in `map` that share the prefix bucket of `group`.
fn bucket_len(map: &HashMap<AdmittedDial, PeerEntry>, group: AddressGroup) -> usize {
	map.keys().filter(|addr| addr.address().group() == group).count()
}

/// Whether the signer `peer_id` already holds as many entries of `tried` as
/// `cap` allows. A table with no cap, or an entry with no signer to count, is
/// never at one.
fn signer_at_cap(tried: &HashMap<AdmittedDial, PeerEntry>, cap: Option<NonZeroUsize>, peer_id: Option<&[u8]>) -> bool {
	let (Some(cap), Some(peer_id)) = (cap, peer_id) else {
		return false;
	};

	let held = tried.values().filter(|entry| entry.peer_id.as_deref() == Some(peer_id));
	held.count() >= cap.get()
}

/// The entry of `map` that owes its slot to a newcomer: the one with the most
/// failed probes, and among equals the one probed longest ago.
///
/// `group` narrows the search to one prefix bucket. It returns `None` when no
/// entry in reach has failed a probe, so a candidate that never failed keeps
/// its slot.
fn most_failed(map: &HashMap<AdmittedDial, PeerEntry>, group: Option<AddressGroup>) -> Option<AdmittedDial> {
	map.iter()
		.filter(|(addr, _)| group.is_none_or(|group| addr.address().group() == group))
		.filter(|(_, entry)| entry.failures > 0)
		.max_by_key(|(addr, entry)| (entry.failures, Reverse(entry.last_probe), **addr))
		.map(|(addr, _)| *addr)
}

/// One round-robin draw across prefix buckets.
struct Draw {
	/// The drawn addresses, at most the cap of the draw.
	sample: Vec<AdmittedDial>,
	/// The prefix the first pass ended on, or `None` for an empty draw.
	served_last: Option<AddressGroup>,
}

/// Round-robin sample across prefix buckets.
///
/// - The walk visits buckets in prefix order from the prefix after `after`, so the draw is deterministic.
/// - Each bucket prefers the peer with the fewest failed probes, then its least recently probed one.
/// - One prefix therefore draws at most its own share of a bounded sample.
/// - The walk draws a peer that failed a probe after every fresher one in its bucket.
///
/// # Starting prefix
///
/// A walk that started at the lowest prefix every time would serve the same
/// `cap` prefixes for as long as each held one entry, and starve every
/// other prefix (CWE-770). The caller therefore passes the prefix its last
/// draw ended on as `after`, and keeps [`Draw::served_last`] for the next.
///
/// The walk holds borrowed pairs only. It copies out the drawn addresses,
/// at most `cap` of them, because they outlive the table lock.
fn diversity_sample<'t, I>(entries: I, cap: usize, after: Option<AddressGroup>) -> Draw
where
	I: Iterator<Item = (&'t AdmittedDial, &'t PeerEntry)>,
{
	let mut buckets: HashMap<AddressGroup, Vec<(&AdmittedDial, &PeerEntry)>> = HashMap::new();
	for (addr, entry) in entries {
		buckets.entry(addr.address().group()).or_default().push((addr, entry));
	}

	let mut lanes: Vec<(AddressGroup, Vec<(&AdmittedDial, &PeerEntry)>)> = buckets.into_iter().collect();
	for (_, lane) in &mut lanes {
		lane.sort_by_key(|(_, entry)| (entry.failures, entry.last_probe));
	}

	lanes.sort_by_key(|(group, _)| *group);

	let start = after.map_or(0, |served| lanes.partition_point(|(group, _)| *group <= served));
	lanes.rotate_left(start);

	// Every lane holds an entry, so the first pass serves the leading lanes
	// one each, up to the cap.
	let first_pass = cap.min(lanes.len());
	let last_lane = first_pass.checked_sub(1).and_then(|last| lanes.get(last));
	let served_last = last_lane.map(|(group, _)| *group);

	let mut sample = Vec::new();
	let mut depth: usize = 0;
	while sample.len() < cap {
		let mut drew = false;
		for (_, lane) in &lanes {
			if sample.len() == cap {
				break;
			}
			if let Some((addr, _)) = lane.get(depth) {
				sample.push(**addr);
				drew = true;
			}
		}

		if !drew {
			break;
		}

		depth = depth.saturating_add(1);
	}

	Draw { sample, served_last }
}

/// One peer on its way into a table, with the proof that the dial policy
/// admitted its address.
///
/// Learned hints, verified probes, and hydrated records all enter through
/// this one shape, so every path applies the anchor exclusion and the
/// prefix bounds to an address the dial policy already admitted.
pub struct Candidate {
	/// The admitted gateway address, which keys the table.
	pub dial: AdmittedDial,
	/// Whether a probe has verified the peer, which picks the table.
	pub tried: bool,
	/// What the table records about the peer.
	pub entry: PeerEntry,
}

/// One durable change, and the generation it applied at.
pub struct PendingWrite {
	/// Generation taken inside the guard that produced `records`.
	pub generation: u64,
	/// Table contents as of that generation.
	pub records: Vec<PeerRecord>,
}

/// Sole owner of the table state.
#[derive(Debug)]
pub struct GuardedTable {
	state: Mutex<TableState>,
}

impl GuardedTable {
	/// A guarded table held to `bounds`.
	///
	/// It replays `candidates` through admission before any caller can reach
	/// the table, which is how persisted records come back.
	pub fn new(bounds: Bounds, candidates: impl IntoIterator<Item = Candidate>) -> Self {
		let mut state = TableState::new(bounds);
		for candidate in candidates {
			state.admit(candidate);
		}

		Self { state: Mutex::new(state) }
	}

	/// Poisons the table lock, as a thread that panicked under the guard
	/// leaves it.
	#[cfg(test)]
	pub fn poison(&self) {
		let poisoner = || {
			let _guard = self.state.lock();
			panic!("a thread panicked under the table guard");
		};

		// The panic is the point, so the joined result carries nothing to read.
		let _panicked = std::thread::scope(|scope| scope.spawn(poisoner).join());
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
	/// A `change` that reports a durable edit bumps the generation and returns
	/// the snapshot at that generation. The caller hands it to the driver
	/// after it releases the guard, so a slow driver delays no reader
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
			.map(|(addr, entry, tried)| entry.record(*addr, tried))
			.collect()
	}
}
