//! Anchored bounded peer table with pluggable persistence.
//!
//! This module holds discovery state for the peer beat. The design follows
//! Bitcoin's address manager as analyzed against eclipse attacks.
//!
//! - Configured anchors cannot be evicted and are always dialed.
//! - Learned peers are bucketed by address prefix with per-bucket caps.
//!   One network position therefore cannot dominate the table (CWE-770).
//! - An unverified hint enters the `new` table only. A probe dial whose
//!   handshake certificate proves the local colony promotes the peer to
//!   `tried`. Only anchors and `tried` peers receive traffic.
//! - A `tried` resident that fails consecutive beats is evicted, so a
//!   dead peer cannot hold a bucket slot. Discovery refills the table.
//!
//! [`PeerStore`] is the persistence seam. The table owns every eclipse
//! invariant. A driver only loads and saves learned records. A hydrated
//! record re-enters through the same capped admission path.
//!
//! # Sources
//!
//! - Heilman, Kendler, Zohar & Goldberg (2015), eclipse attacks on
//!   Bitcoin's peer-to-peer network (new/tried tables, feeler probes,
//!   and per-group capacity):
//!   [USENIX Security '15](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/heilman),
//!   [ePrint 2015/263](https://eprint.iacr.org/2015/263)
//! - CWE-770, allocation of resources without limits or throttling:
//!   <https://cwe.mitre.org/data/definitions/770.html>

use core::net::{IpAddr, SocketAddr};
use core::str::FromStr;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use super::ClusterError;
use crate::colony::common::PeerGossip;
use crate::constants::{
	MAX_PEER_BUCKET, MAX_PEER_TABLE_NEW, MAX_PEER_TABLE_TRIED, MAX_PEER_TRIED_FAILURES, PEER_PROBE_PER_BEAT,
};

/// Network locality bucket of one peer address.
///
/// IPv4 groups by a /16 prefix. IPv6 groups by a /32 prefix. Table capacity
/// is spent per prefix, so an attacker inside one prefix is bounded by one
/// bucket. See the module-level sources for the eclipse analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressGroup {
	/// IPv4 /16 prefix formed from the first two octets.
	V4([u8; 2]),
	/// IPv6 /32 prefix formed from the first four octets.
	V6([u8; 4]),
}

impl From<IpAddr> for AddressGroup {
	fn from(ip: IpAddr) -> Self {
		match ip {
			IpAddr::V4(v4) => {
				let octets = v4.octets();
				Self::V4([octets[0], octets[1]])
			}
			IpAddr::V6(v6) => {
				let octets = v6.octets();
				Self::V6([octets[0], octets[1], octets[2], octets[3]])
			}
		}
	}
}

impl FromStr for AddressGroup {
	type Err = core::net::AddrParseError;

	fn from_str(addr: &str) -> Result<Self, Self::Err> {
		let socket: SocketAddr = addr.parse()?;
		Ok(Self::from(socket.ip()))
	}
}

/// One unverified discovery hint from peer exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHint {
	/// Dialable gateway address claimed by the sharer.
	pub gateway_addr: String,
	/// Peer certificate fingerprint last seen with this address, when known.
	///
	/// The value is advisory until a probe verifies the peer.
	pub peer_id: Option<Vec<u8>>,
}

impl TryFrom<PeerGossip> for PeerHint {
	type Error = ClusterError;

	/// Convert one peer-exchange wire entry into a discovery hint.
	///
	/// The entry is untrusted wire input. A dial address that is not UTF-8
	/// can never parse as a socket, so admission refuses it first. An empty
	/// fingerprint means the sharer sent no identity.
	///
	/// The conversion moves both buffers, and a refused address travels
	/// back inside the error, so neither outcome copies wire bytes.
	fn try_from(entry: PeerGossip) -> Result<Self, Self::Error> {
		let gateway_addr =
			String::from_utf8(entry.gateway_addr).map_err(|error| ClusterError::InvalidAddress(error.into_bytes()))?;

		let mut peer_id = None;
		if !entry.peer_id.is_empty() {
			peer_id = Some(entry.peer_id);
		}

		Ok(Self { gateway_addr, peer_id })
	}
}

/// One learned peer as stored by a [`PeerStore`] driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
	/// Dialable gateway address for this peer.
	pub gateway_addr: String,
	/// Peer certificate fingerprint from the last verified probe.
	pub peer_id: Option<Vec<u8>>,
	/// Whether a colony-gated probe has verified this peer.
	pub tried: bool,
	/// Unix time in milliseconds of the last probe attempt.
	pub last_probe_ms: u64,
}

/// Persistence driver beneath [`PeerTable`].
///
/// The table owns every eclipse invariant. Those invariants include prefix
/// bucketing, table and bucket caps, and anchor permanence. A full tried
/// bucket also keeps its residents instead of displacing them.
///
/// A driver only loads and saves learned records. Hydrated records re-enter
/// through the same capped admission path, so a driver cannot bypass the
/// bounds.
///
/// Persistence is advisory. A driver fault never interrupts routing.
/// Hydration failure degrades to an anchors-only start. That direction is
/// safe because discovery refills the table.
pub trait PeerStore: Send + Sync {
	/// Load previously persisted learned peers.
	fn hydrate(&self) -> Result<Vec<PeerRecord>, ClusterError>;

	/// Replace the persisted snapshot of learned peers.
	fn persist(&self, records: &[PeerRecord]) -> Result<(), ClusterError>;
}

/// No-op driver. Discovery state lives for the process lifetime only.
#[derive(Debug, Default, Clone, Copy)]
pub struct MemoryPeerStore;

impl PeerStore for MemoryPeerStore {
	fn hydrate(&self) -> Result<Vec<PeerRecord>, ClusterError> {
		Ok(Vec::new())
	}

	fn persist(&self, _records: &[PeerRecord]) -> Result<(), ClusterError> {
		Ok(())
	}
}

#[derive(Debug, Clone)]
struct PeerEntry {
	peer_id: Option<Vec<u8>>,
	last_probe_ms: u64,
	/// Consecutive failed beat dials since the last verified probe.
	///
	/// The count lives in memory only. A restart starts the count at
	/// zero because the following beats re-verify every resident.
	failures: usize,
}

#[derive(Debug, Default)]
struct TableState {
	new: HashMap<String, PeerEntry>,
	tried: HashMap<String, PeerEntry>,
	/// Anchors whose beat dial passed the colony gate.
	///
	/// Anchors never enter `tried`. A seed MUST still share its verified
	/// anchors over PEX, or a bootstrapping peer could learn nothing.
	anchors_verified: HashMap<String, PeerEntry>,
	/// This gateway's own advertised address. It is never admitted as a peer.
	local: Option<String>,
}

/// Anchored bounded peer discovery table.
///
/// Interior mutability lets the advertise beat, reconcile rounds, and
/// detached reflood tasks share one instance through configuration.
pub struct PeerTable {
	anchors: Vec<String>,
	anchor_keys: HashSet<String>,
	state: Mutex<TableState>,
	store: Arc<dyn PeerStore>,
}

impl Default for PeerTable {
	fn default() -> Self {
		Self::new(Vec::new(), Arc::new(MemoryPeerStore))
	}
}

impl core::fmt::Debug for PeerTable {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("PeerTable")
			.field("anchors", &self.anchors)
			.field("state", &self.state)
			.field("store", &"<dyn PeerStore>")
			.finish()
	}
}

/// Canonical map key for an address.
///
/// The key is the parsed socket rendering so textual variants of one socket
/// collapse to one entry.
fn address_key(addr: &str) -> Option<String> {
	let socket: SocketAddr = addr.parse().ok()?;
	Some(socket.to_string())
}

/// Count entries in `map` that share the prefix bucket of `group`.
fn bucket_len(map: &HashMap<String, PeerEntry>, group: AddressGroup) -> usize {
	map.keys()
		.filter_map(|addr| addr.parse::<AddressGroup>().ok())
		.filter(|candidate| *candidate == group)
		.count()
}

/// Round-robin sample across prefix buckets.
///
/// One prefix therefore cannot monopolize a bounded sample. Buckets are
/// visited in sorted-key order so the draw is deterministic. Each bucket
/// prefers its least recently probed peer.
///
/// The walk holds borrowed pairs only. Solely the up-to-`cap` drawn
/// addresses are cloned, because they outlive the table lock.
fn diversity_sample<'t, I>(entries: I, cap: usize) -> Vec<String>
where
	I: Iterator<Item = (&'t String, &'t PeerEntry)>,
{
	let mut buckets: HashMap<AddressGroup, Vec<(&String, &PeerEntry)>> = HashMap::new();
	for (addr, entry) in entries {
		if let Ok(group) = addr.parse::<AddressGroup>() {
			buckets.entry(group).or_default().push((addr, entry));
		}
	}

	let mut lanes: Vec<Vec<(&String, &PeerEntry)>> = buckets.into_values().collect();
	for lane in &mut lanes {
		lane.sort_by_key(|(_, entry)| entry.last_probe_ms);
	}

	lanes.sort_by(|left, right| lane_key(left).cmp(&lane_key(right)));

	let mut sample = Vec::new();
	let mut depth = 0;
	while sample.len() < cap {
		let mut drew = false;
		for lane in &lanes {
			if sample.len() == cap {
				break;
			}
			if let Some((addr, _)) = lane.get(depth) {
				sample.push((*addr).clone());
				drew = true;
			}
		}

		if !drew {
			break;
		}

		depth += 1;
	}

	sample
}

/// Deterministic lane order key: the lane's front address, borrowed.
fn lane_key<'t>(lane: &[(&'t String, &'t PeerEntry)]) -> Option<&'t String> {
	lane.first().map(|(addr, _)| *addr)
}

impl PeerTable {
	/// Build a table around the given anchors and persistence driver.
	///
	/// Hydration replays persisted records through the capped admission path.
	/// A driver fault degrades to an anchors-only start. An empty table is
	/// safe because discovery refills it. A faulty driver must never seed
	/// unchecked entries.
	#[must_use]
	pub fn new(anchors: Vec<String>, store: Arc<dyn PeerStore>) -> Self {
		let anchor_keys = anchors
			.iter()
			.map(|anchor| address_key(anchor).unwrap_or_else(|| anchor.clone()))
			.collect();
		let table = Self { anchors, anchor_keys, state: Mutex::new(TableState::default()), store };

		let records = table.store.hydrate().unwrap_or_default();
		if let Ok(mut state) = table.state.lock() {
			for record in records {
				table.admit_record(&mut state, record);
			}
		}

		table
	}

	/// Admit unverified peer hints into the new table.
	///
	/// Anchors, known addresses, unparsable addresses, and hints beyond the
	/// per-prefix or table caps are dropped. Cap overflow is the eclipse
	/// bound: one address prefix cannot flood discovery (CWE-770).
	///
	/// Returns how many hints were admitted.
	pub fn learn<I>(&self, hints: I) -> Result<usize, ClusterError>
	where
		I: IntoIterator<Item = PeerHint>,
	{
		let mut state = self.state.lock()?;
		let mut admitted = 0;
		for hint in hints {
			let record = PeerRecord {
				gateway_addr: hint.gateway_addr,
				peer_id: hint.peer_id,
				tried: false,
				last_probe_ms: 0,
			};
			if self.admit_record(&mut state, record) {
				admitted += 1;
			}
		}

		if admitted > 0 {
			self.persist_snapshot(&state);
		}

		Ok(admitted)
	}

	/// Record a verified probe of `addr` and promote it into tried.
	///
	/// Verification is the caller's colony-certificate gate on the probe
	/// dial handshake. Returns `true` only on a promotion into tried so the
	/// caller can emit one discovery event per peer.
	///
	/// A full tried prefix bucket keeps its residents and leaves the
	/// candidate in new. That is the test-before-evict discipline. Residents
	/// re-verify on every beat, so a candidate waits for a freed slot
	/// instead of displacing a verified peer.
	///
	/// A verified anchor never moves into tried because it is already a
	/// permanent target. The probe is still recorded so the anchor becomes
	/// shareable over PEX. Without that record, a seed whose only peers are
	/// anchors would have nothing to share, and a bootstrapping node could
	/// never discover the graph.
	///
	/// The table copies `peer_id` into the stored entry. The borrowed
	/// fingerprint lives only as long as the caller's handshake.
	pub fn promote(&self, addr: &str, peer_id: Option<&[u8]>, now_ms: u64) -> Result<bool, ClusterError> {
		let Some(key) = address_key(addr) else {
			return Ok(false);
		};

		if self.anchor_keys.contains(&key) {
			let mut state = self.state.lock()?;
			let entry = PeerEntry { peer_id: peer_id.map(<[u8]>::to_vec), last_probe_ms: now_ms, failures: 0 };
			state.anchors_verified.insert(key, entry);

			return Ok(false);
		}

		let mut state = self.state.lock()?;
		if let Some(entry) = state.tried.get_mut(&key) {
			entry.last_probe_ms = now_ms;
			entry.failures = 0;

			if let Some(peer_id) = peer_id {
				entry.peer_id = Some(peer_id.to_vec());
			}

			self.persist_snapshot(&state);

			return Ok(false);
		}

		let record = PeerRecord {
			gateway_addr: key,
			peer_id: peer_id.map(<[u8]>::to_vec),
			tried: true,
			last_probe_ms: now_ms,
		};

		let promoted = self.admit_record(&mut state, record);
		if promoted {
			self.persist_snapshot(&state);
		}

		Ok(promoted)
	}

	/// Drop a candidate whose probe failed.
	///
	/// Only the new table is pruned here, so dead or foreign addresses cannot
	/// clog a prefix bucket. Tried residents are never evicted by a transient
	/// failure; repeated beat failures go through [`Self::record_failure`].
	/// Misbehavior is handled by relay scoring.
	pub fn discard(&self, addr: &str) -> Result<(), ClusterError> {
		let Some(key) = address_key(addr) else {
			return Ok(());
		};

		let mut state = self.state.lock()?;
		if state.new.remove(&key).is_some() {
			self.persist_snapshot(&state);
		}

		Ok(())
	}

	/// Record a failed beat dial of a tried peer.
	///
	/// Residents re-verify on every beat, so consecutive failures measure
	/// liveness. Returns `true` only on an eviction so the caller can emit
	/// one event per reclaimed peer.
	///
	/// - Failures beyond [`MAX_PEER_TRIED_FAILURES`] evict the entry.
	/// - Eviction frees the prefix bucket slot for a live candidate.
	/// - The threshold tolerates a transient partition.
	/// - A verified probe resets the count.
	/// - Eviction fails closed: the table shrinks toward its anchors, and
	///   discovery refills it.
	/// - Anchors never live in tried, so this method ignores an anchor address.
	///
	/// # Sources
	///
	/// - Heilman, Kendler, Zohar & Goldberg (2015), eclipse attacks on
	///   Bitcoin's peer-to-peer network (feeler probes / tried eviction):
	///   [USENIX Security '15](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/heilman),
	///   [ePrint 2015/263](https://eprint.iacr.org/2015/263)
	pub fn record_failure(&self, addr: &str) -> Result<bool, ClusterError> {
		let Some(key) = address_key(addr) else {
			return Ok(false);
		};

		let mut state = self.state.lock()?;
		let Some(entry) = state.tried.get_mut(&key) else {
			return Ok(false);
		};

		entry.failures = entry.failures.saturating_add(1);
		if entry.failures < MAX_PEER_TRIED_FAILURES {
			return Ok(false);
		}

		state.tried.remove(&key);
		self.persist_snapshot(&state);

		Ok(true)
	}

	/// Remove an address from both learned tables.
	///
	/// A probe that answers with a foreign-colony certificate is a
	/// definitive identity mismatch, not a transient fault.
	///
	/// - The address leaves discovery at once.
	/// - It does not wait out the failure threshold.
	/// - A re-keyed peer therefore stops receiving advertisements.
	pub fn expel(&self, addr: &str) -> Result<(), ClusterError> {
		let Some(key) = address_key(addr) else {
			return Ok(());
		};

		let mut state = self.state.lock()?;
		let from_new = state.new.remove(&key).is_some();
		let from_tried = state.tried.remove(&key).is_some();
		if from_new || from_tried {
			self.persist_snapshot(&state);
		}

		Ok(())
	}

	/// Dial targets for the advertise/reconcile beat and gossip reflood.
	///
	/// Anchors always lead the set and cannot be displaced by learned peers.
	/// Verified tried peers follow. New entries never appear. An unverified
	/// hint MUST NOT receive advertisements or rumor bytes.
	///
	/// The returned targets outlive the table lock, so each beat draws
	/// owned copies. The set is bounded by the anchor and tried caps.
	pub fn target_set(&self) -> Result<Vec<String>, ClusterError> {
		let state = self.state.lock()?;
		let mut targets = self.anchors.clone();
		let mut learned: Vec<String> = state.tried.keys().cloned().collect();

		learned.sort();
		targets.extend(learned);

		Ok(targets)
	}

	/// Bounded feeler sample of unverified candidates for this beat.
	///
	/// Sampling round-robins across prefix buckets so one prefix cannot
	/// monopolize probe capacity. Each bucket prefers its least recently
	/// probed candidate. Sampled candidates are stamped with `now_ms` so
	/// later beats rotate through the backlog.
	pub fn probe_sample(&self, now_ms: u64) -> Result<Vec<String>, ClusterError> {
		let mut state = self.state.lock()?;
		let sample = diversity_sample(state.new.iter(), PEER_PROBE_PER_BEAT);
		for addr in &sample {
			if let Some(entry) = state.new.get_mut(addr) {
				entry.last_probe_ms = now_ms;
			}
		}

		Ok(sample)
	}

	/// Diversity-bucketed sample of verified peers to share over PEX.
	///
	/// The shareable set is tried peers plus probe-verified anchors. Draws
	/// round-robin across prefix buckets up to `cap`, so the shared view
	/// spans prefixes instead of amplifying one position.
	///
	/// Only probe-verified peers are shared. Forwarding an unverified hint
	/// would launder it with this gateway's reputation.
	pub fn sample_for_pex(&self, cap: usize) -> Result<Vec<PeerRecord>, ClusterError> {
		let state = self.state.lock()?;

		// Anchors never enter tried, so chaining the two maps borrows a
		// disjoint shareable view without building a merged copy. Only the
		// sampled records own their data, because they outlive the lock.
		let shareable = state.tried.iter().chain(state.anchors_verified.iter());
		let sample = diversity_sample(shareable, cap)
			.into_iter()
			.filter_map(|addr| {
				let entry = state.tried.get(&addr).or_else(|| state.anchors_verified.get(&addr))?;
				Some(PeerRecord {
					gateway_addr: addr,
					peer_id: entry.peer_id.clone(),
					tried: true,
					last_probe_ms: entry.last_probe_ms,
				})
			})
			.collect();
		Ok(sample)
	}

	/// Current learned sizes as `(new, tried)` for operators and tests.
	pub fn learned(&self) -> Result<(usize, usize), ClusterError> {
		let state = self.state.lock()?;
		Ok((state.new.len(), state.tried.len()))
	}

	/// Record this gateway's own advertised address.
	///
	/// Peer exchange must never teach a gateway to dial itself. PEX replies
	/// echo installed routes, which include the requester's own advertised
	/// address.
	pub fn exclude_self(&self, addr: &str) -> Result<(), ClusterError> {
		let Some(key) = address_key(addr) else {
			return Ok(());
		};

		let mut state = self.state.lock()?;
		state.new.remove(&key);
		state.tried.remove(&key);
		state.local = Some(key);
		Ok(())
	}

	/// Whether any dial target exists.
	///
	/// A reflood can skip frame construction when this is false. A poisoned
	/// lock answers `false`. No targets is the fail-closed direction.
	#[must_use]
	pub fn has_targets(&self) -> bool {
		if !self.anchors.is_empty() {
			return true;
		}

		self.state.lock().map(|state| !state.tried.is_empty()).unwrap_or(false)
	}

	/// Admit one record into its table under the capped admission path.
	///
	/// This is the single chokepoint for `learn`, `promote`, and hydration.
	/// No path can bypass anchor exclusion or the prefix bounds.
	fn admit_record(&self, state: &mut TableState, record: PeerRecord) -> bool {
		let Some(key) = address_key(&record.gateway_addr) else {
			return false;
		};
		let Ok(group) = key.parse::<AddressGroup>() else {
			return false;
		};
		if self.anchor_keys.contains(&key) || state.tried.contains_key(&key) {
			return false;
		}
		if state.local.as_deref() == Some(key.as_str()) {
			return false;
		}

		let entry = PeerEntry { peer_id: record.peer_id, last_probe_ms: record.last_probe_ms, failures: 0 };
		if record.tried {
			let within_table = state.tried.len() < MAX_PEER_TABLE_TRIED;
			let within_bucket = bucket_len(&state.tried, group) < MAX_PEER_BUCKET;
			if !(within_table && within_bucket) {
				return false;
			}

			state.new.remove(&key);
			state.tried.insert(key, entry);

			return true;
		}

		if state.new.contains_key(&key) {
			return false;
		}

		let within_table = state.new.len() < MAX_PEER_TABLE_NEW;
		let within_bucket = bucket_len(&state.new, group) < MAX_PEER_BUCKET;
		if !(within_table && within_bucket) {
			return false;
		}

		state.new.insert(key, entry);
		true
	}

	/// Persist the learned tables best-effort.
	///
	/// The in-memory table stays authoritative. A driver write fault never
	/// interrupts the beat. The next mutation retries the write.
	///
	/// Each record is an owned copy: [`PeerRecord`] owns its fields by
	/// the [`PeerStore`] contract, so the snapshot cannot borrow from
	/// the locked maps. Writes happen only on admission or promotion.
	fn persist_snapshot(&self, state: &TableState) {
		let records: Vec<PeerRecord> = state
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
			.collect();
		let _ = self.store.persist(&records);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::atomic::{AtomicUsize, Ordering};

	fn hint(addr: &str) -> PeerHint {
		PeerHint { gateway_addr: addr.to_string(), peer_id: None }
	}

	fn table_with_anchor(anchor: &str) -> PeerTable {
		PeerTable::new(vec![anchor.to_string()], Arc::new(MemoryPeerStore))
	}

	struct CountingStore {
		seed: Vec<PeerRecord>,
		persists: AtomicUsize,
	}

	impl CountingStore {
		fn seeded(seed: Vec<PeerRecord>) -> Self {
			Self { seed, persists: AtomicUsize::new(0) }
		}
	}

	impl PeerStore for CountingStore {
		fn hydrate(&self) -> Result<Vec<PeerRecord>, ClusterError> {
			Ok(self.seed.clone())
		}

		fn persist(&self, _records: &[PeerRecord]) -> Result<(), ClusterError> {
			self.persists.fetch_add(1, Ordering::SeqCst);
			Ok(())
		}
	}

	fn record(addr: &str, tried: bool) -> PeerRecord {
		PeerRecord { gateway_addr: addr.to_string(), peer_id: None, tried, last_probe_ms: 0 }
	}

	#[test]
	fn address_group_prefixes_v4_and_v6() -> Result<(), core::net::AddrParseError> {
		let v4: AddressGroup = "10.1.2.3:80".parse()?;
		let v6: AddressGroup = "[2001:db8::1]:80".parse()?;
		assert_eq!(v4, AddressGroup::V4([10, 1]));
		assert_eq!(v6, AddressGroup::V6([0x20, 0x01, 0x0d, 0xb8]));
		Ok(())
	}

	#[test]
	fn learn_admits_hints_and_skips_anchors() -> Result<(), ClusterError> {
		let table = table_with_anchor("127.0.0.1:9000");
		let admitted = table.learn(vec![hint("127.0.0.1:9000"), hint("10.0.0.1:9000")])?;
		assert_eq!(admitted, 1);
		assert_eq!(table.learned()?, (1, 0));
		Ok(())
	}

	#[test]
	fn learn_drops_unparsable_and_duplicate_hints() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		let admitted = table.learn(vec![hint("not-an-address"), hint("10.0.0.1:9000"), hint("10.0.0.1:9000")])?;
		assert_eq!(admitted, 1);
		Ok(())
	}

	#[test]
	fn pex_entry_converts_to_hint() -> Result<(), ClusterError> {
		let cases = [(vec![7u8], Some(vec![7u8])), (Vec::new(), None)];
		for (wire_id, hint_id) in cases {
			let entry = PeerGossip { peer_id: wire_id, gateway_addr: b"10.0.0.1:9000".to_vec() };
			let converted = PeerHint::try_from(entry)?;
			assert_eq!(converted.gateway_addr, "10.0.0.1:9000");
			assert_eq!(converted.peer_id, hint_id);
		}
		Ok(())
	}

	#[test]
	fn pex_entry_with_non_utf8_address_is_refused() {
		let entry = PeerGossip { peer_id: Vec::new(), gateway_addr: vec![0xFF, 0xFE, 0xFD] };
		assert!(matches!(PeerHint::try_from(entry), Err(ClusterError::InvalidAddress(_))));
	}

	#[test]
	fn learn_caps_one_prefix_bucket() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		let hints: Vec<PeerHint> = (0..MAX_PEER_BUCKET + 3)
			.map(|host| hint(&format!("10.0.0.{}:9000", host + 1)))
			.collect();
		let admitted = table.learn(hints)?;
		assert_eq!(admitted, MAX_PEER_BUCKET);
		Ok(())
	}

	#[test]
	fn promote_moves_candidate_into_tried_once() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.learn(vec![hint("10.0.0.1:9000")])?;

		let first = table.promote("10.0.0.1:9000", Some(b"fp-a"), 1_000)?;
		let second = table.promote("10.0.0.1:9000", Some(b"fp-a"), 2_000)?;
		assert!(first);
		assert!(!second);
		assert_eq!(table.learned()?, (0, 1));
		Ok(())
	}

	#[test]
	fn promote_never_tracks_anchors() -> Result<(), ClusterError> {
		let table = table_with_anchor("127.0.0.1:9000");
		let promoted = table.promote("127.0.0.1:9000", None, 1_000)?;
		assert!(!promoted);
		assert_eq!(table.learned()?, (0, 0));
		Ok(())
	}

	#[test]
	fn verified_anchor_becomes_shareable_over_pex() -> Result<(), ClusterError> {
		let table = table_with_anchor("127.0.0.1:9000");
		assert!(table.sample_for_pex(8)?.is_empty());

		table.promote("127.0.0.1:9000", Some(b"fp-a"), 1_000)?;

		let sample = table.sample_for_pex(8)?;
		assert_eq!(sample.len(), 1);
		assert_eq!(sample[0].gateway_addr, "127.0.0.1:9000");
		assert_eq!(sample[0].peer_id.as_deref(), Some(b"fp-a".as_slice()));
		Ok(())
	}

	#[test]
	fn promote_keeps_residents_of_full_tried_bucket() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		for host in 0..MAX_PEER_BUCKET {
			table.promote(&format!("10.0.0.{}:9000", host + 1), None, 1_000)?;
		}

		table.learn(vec![hint("10.0.9.9:9000")])?;

		let promoted = table.promote("10.0.9.9:9000", None, 2_000)?;
		assert!(!promoted);
		assert_eq!(table.learned()?, (1, MAX_PEER_BUCKET));
		Ok(())
	}

	#[test]
	fn exclude_self_blocks_learning_own_address() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.exclude_self("10.0.0.1:9000")?;

		let admitted = table.learn(vec![hint("10.0.0.1:9000")])?;
		let promoted = table.promote("10.0.0.1:9000", None, 1_000)?;
		assert_eq!(admitted, 0);
		assert!(!promoted);
		Ok(())
	}

	#[test]
	fn discard_prunes_only_the_new_table() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.learn(vec![hint("10.0.0.1:9000")])?;
		table.promote("10.1.0.1:9000", None, 1_000)?;

		table.discard("10.0.0.1:9000")?;
		table.discard("10.1.0.1:9000")?;
		assert_eq!(table.learned()?, (0, 1));
		Ok(())
	}

	#[test]
	fn record_failure_evicts_tried_peer_at_threshold() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.promote("10.0.0.1:9000", None, 1_000)?;

		let evictions: Vec<bool> = (0..MAX_PEER_TRIED_FAILURES)
			.map(|_| table.record_failure("10.0.0.1:9000").unwrap_or_default())
			.collect();
		assert_eq!(evictions, vec![false, false, true]);
		assert_eq!(table.learned()?, (0, 0));
		Ok(())
	}

	#[test]
	fn verified_probe_resets_failure_count() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.promote("10.0.0.1:9000", None, 1_000)?;
		table.record_failure("10.0.0.1:9000")?;
		table.record_failure("10.0.0.1:9000")?;

		table.promote("10.0.0.1:9000", None, 2_000)?;

		table.record_failure("10.0.0.1:9000")?;
		table.record_failure("10.0.0.1:9000")?;
		assert_eq!(table.learned()?, (0, 1));
		Ok(())
	}

	#[test]
	fn record_failure_ignores_anchors_and_unknown_addresses() -> Result<(), ClusterError> {
		let table = table_with_anchor("127.0.0.1:9000");
		let anchor_evicted = table.record_failure("127.0.0.1:9000")?;
		let unknown_evicted = table.record_failure("10.0.0.1:9000")?;
		assert!(!anchor_evicted);
		assert!(!unknown_evicted);
		Ok(())
	}

	#[test]
	fn eviction_frees_the_prefix_bucket_slot() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		for host in 0..MAX_PEER_BUCKET {
			table.promote(&format!("10.0.0.{}:9000", host + 1), None, 1_000)?;
		}
		assert!(!table.promote("10.0.9.9:9000", None, 2_000)?);

		for _ in 0..MAX_PEER_TRIED_FAILURES {
			table.record_failure("10.0.0.1:9000")?;
		}

		assert!(table.promote("10.0.9.9:9000", None, 3_000)?);
		Ok(())
	}

	#[test]
	fn expel_clears_both_learned_tables() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.learn(vec![hint("10.0.0.1:9000")])?;
		table.promote("10.1.0.1:9000", None, 1_000)?;

		table.expel("10.0.0.1:9000")?;
		table.expel("10.1.0.1:9000")?;
		assert_eq!(table.learned()?, (0, 0));
		Ok(())
	}

	#[test]
	fn target_set_leads_with_anchors_and_hides_new() -> Result<(), ClusterError> {
		let table = table_with_anchor("127.0.0.1:9000");
		table.learn(vec![hint("10.0.0.1:9000")])?;
		table.promote("10.1.0.1:9000", None, 1_000)?;

		let targets = table.target_set()?;
		assert_eq!(targets, vec!["127.0.0.1:9000".to_string(), "10.1.0.1:9000".to_string()]);
		Ok(())
	}

	#[test]
	fn probe_sample_spans_prefix_buckets() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		let crowded: Vec<PeerHint> = (0..PEER_PROBE_PER_BEAT + 2)
			.map(|host| hint(&format!("10.0.0.{}:9000", host + 1)))
			.collect();
		table.learn(crowded)?;
		table.learn(vec![hint("10.1.0.1:9000")])?;

		let sample = table.probe_sample(1_000)?;
		assert_eq!(sample.len(), PEER_PROBE_PER_BEAT);
		assert!(sample.contains(&"10.1.0.1:9000".to_string()));
		Ok(())
	}

	#[test]
	fn probe_sample_rotates_through_backlog() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.learn(vec![hint("10.0.0.1:9000"), hint("10.1.0.1:9000")])?;

		let first = table.probe_sample(1_000)?;
		let second = table.probe_sample(2_000)?;
		assert_eq!(first.len(), 2);
		assert_eq!(second.len(), 2);
		Ok(())
	}

	#[test]
	fn sample_for_pex_caps_and_spans_buckets() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.promote("10.0.0.1:9000", Some(b"fp-a"), 1_000)?;
		table.promote("10.0.0.2:9000", Some(b"fp-b"), 1_000)?;
		table.promote("10.1.0.1:9000", Some(b"fp-c"), 1_000)?;

		let sample = table.sample_for_pex(2)?;
		let addrs: Vec<&str> = sample.iter().map(|record| record.gateway_addr.as_str()).collect();
		assert_eq!(sample.len(), 2);
		assert!(addrs.contains(&"10.1.0.1:9000"));
		Ok(())
	}

	#[test]
	fn sample_for_pex_shares_only_tried_peers() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.learn(vec![hint("10.0.0.1:9000")])?;

		let sample = table.sample_for_pex(8)?;
		assert!(sample.is_empty());
		Ok(())
	}

	#[test]
	fn hydrate_replays_records_through_caps() -> Result<(), ClusterError> {
		let mut seed: Vec<PeerRecord> = (0..MAX_PEER_BUCKET + 2)
			.map(|host| record(&format!("10.0.0.{}:9000", host + 1), false))
			.collect();
		seed.push(record("10.1.0.1:9000", true));

		let table = PeerTable::new(Vec::new(), Arc::new(CountingStore::seeded(seed)));
		assert_eq!(table.learned()?, (MAX_PEER_BUCKET, 1));
		Ok(())
	}

	#[test]
	fn mutations_persist_through_the_driver() -> Result<(), ClusterError> {
		let store = Arc::new(CountingStore::seeded(Vec::new()));
		let driver: Arc<dyn PeerStore> = store.clone();
		let table = PeerTable::new(Vec::new(), driver);

		table.learn(vec![hint("10.0.0.1:9000")])?;
		table.promote("10.0.0.1:9000", None, 1_000)?;
		assert_eq!(store.persists.load(Ordering::SeqCst), 2);
		Ok(())
	}
}
