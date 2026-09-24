//! Anchored bounded peer table with pluggable persistence.
//!
//! This module holds discovery state for the peer beat. The design follows
//! Bitcoin's address manager as analyzed against eclipse attacks.
//!
//! - Configured anchors hold their slots for the table's life and are
//!   always dialed.
//! - Learned peers are bucketed by address prefix with per-bucket caps.
//!   One network position therefore holds at most its own bucket's
//!   share of the table (CWE-770).
//! - An unverified hint enters the `new` table only. A probe dial whose
//!   handshake certificate proves the local colony promotes the peer to
//!   `tried`. Only anchors and `tried` peers receive traffic.
//! - A `tried` resident that fails consecutive beats is evicted, so a
//!   bucket slot follows liveness. Discovery refills the table.
//!
//! [`PeerStore`] is the persistence interface beneath [`PeerTable`]. The table
//! owns every eclipse invariant, so a hydrated record re-enters through the
//! dial policy and the same capped admission path as a learned one.
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

use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use core::str::{from_utf8, FromStr};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};

mod guard;

use guard::{GuardedTable, PeerEntry, TableState};

use super::{AdmittedDial, ClusterError, PeerConfig, SharedId};
use crate::constants::{
	MAX_PEER_BUCKET, MAX_PEER_TABLE_NEW, MAX_PEER_TABLE_TRIED, MAX_PEER_TRIED_FAILURES, PEER_PROBE_PER_BEAT,
};
use crate::utils::time::UnixMillis;

/// A gateway socket address, parsed once where it enters.
///
/// Discovery carries this type, inside an [`AdmittedDial`], in place of a
/// `String`, so the peer table, its diversity buckets, and the probe path share
/// one canonical form and parse each address once. A wire entry becomes a
/// `PeerAddress` only when it names a socket, through [`TryFrom<&[u8]>`].
///
/// # Canonical form
///
/// Every constructor stores the socket a dual-stack host dials, so two
/// spellings of one socket are one address (CWE-706):
///
/// - An IPv4-mapped IPv6 address such as `[::ffff:192.0.2.1]:9000` is stored as its IPv4 socket.
/// - An IPv6 flow label names no endpoint, so it is stored as zero.
/// - An IPv6 scope id picks an interface for a link-local or multicast
///   destination alone, so it is stored as zero for every other address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerAddress(SocketAddr);

impl PeerAddress {
	/// The locality bucket this address spends capacity in.
	#[must_use]
	pub fn group(&self) -> AddressGroup {
		AddressGroup::from(self.0.ip())
	}

	/// Whether this address is the unspecified address of its family.
	///
	/// A connect to `0.0.0.0` or `[::]` lands on this host's loopback, so
	/// the unspecified address is an alias of loopback rather than a dial
	/// target (CWE-706).
	#[must_use]
	pub fn is_unspecified(&self) -> bool {
		self.0.ip().is_unspecified()
	}

	/// Whether this address can name one unicast peer.
	///
	/// Multicast, IPv4 broadcast, the reserved `240.0.0.0/4` block, and the
	/// `0.0.0.0/8` block name no host a TCP connect can reach, so a claim of
	/// one only spends a table slot and a probe (CWE-770).
	#[must_use]
	pub fn is_unicast(&self) -> bool {
		match self.0.ip() {
			IpAddr::V4(v4) => Self::is_unicast_v4(v4),
			IpAddr::V6(v6) => !v6.is_multicast(),
		}
	}

	fn is_unicast_v4(v4: Ipv4Addr) -> bool {
		let reserved = v4.octets()[0] >= 240;
		let this_network = v4.octets()[0] == 0;
		!(v4.is_multicast() || v4.is_broadcast() || reserved || this_network)
	}

	/// The bytes a route or a trace payload names this address by.
	///
	/// This method is the one home for the rendering, so a route installed
	/// under this address and a later lookup by it spell the socket the same
	/// way.
	#[must_use]
	pub fn route_bytes(&self) -> SharedId {
		SharedId::from(self.to_string().as_bytes())
	}

	/// The socket to dial.
	#[must_use]
	pub fn socket(&self) -> SocketAddr {
		self.0
	}

	/// The IPv6 scope id the kernel reads for `ip`, which is the one it was
	/// given for a link-local or multicast destination and zero otherwise.
	fn kernel_scope_id(ip: &Ipv6Addr, scope_id: u32) -> u32 {
		if ip.is_unicast_link_local() || ip.is_multicast() {
			scope_id
		} else {
			0
		}
	}
}

impl From<SocketAddr> for PeerAddress {
	fn from(socket: SocketAddr) -> Self {
		let canonical = match socket {
			SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
				Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
				None => {
					let scope_id = Self::kernel_scope_id(v6.ip(), v6.scope_id());
					SocketAddr::V6(SocketAddrV6::new(*v6.ip(), v6.port(), 0, scope_id))
				}
			},
			SocketAddr::V4(_) => socket,
		};

		Self(canonical)
	}
}

impl FromStr for PeerAddress {
	type Err = core::net::AddrParseError;

	fn from_str(addr: &str) -> Result<Self, Self::Err> {
		let socket: SocketAddr = addr.parse()?;
		Ok(Self::from(socket))
	}
}

/// Bytes that are not the UTF-8 spelling of a socket address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotASocket;

impl fmt::Display for NotASocket {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "the bytes are not the UTF-8 spelling of a socket address")
	}
}

impl core::error::Error for NotASocket {}

/// The one parse from wire or registration bytes to a socket.
///
/// A peer's claimed gateway, a hive's servlet address, and this gateway's
/// own advertised address all arrive as bytes, and each becomes an address
/// here or nowhere.
impl TryFrom<&[u8]> for PeerAddress {
	type Error = NotASocket;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		let text = from_utf8(bytes).map_err(|_| NotASocket)?;
		text.parse().map_err(|_| NotASocket)
	}
}

impl fmt::Display for PeerAddress {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

#[cfg(test)]
impl PeerAddress {
	/// A parsed fixture socket, which every fixture spelling names.
	pub(crate) fn fixture(spelling: impl AsRef<str>) -> Self {
		spelling.as_ref().parse().expect("fixture spellings name sockets")
	}
}

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

/// One unverified discovery hint from peer exchange.
///
/// [`PeerConfig::admit_hint`] builds one from a wire entry, so the address
/// a hint carries has passed the dial policy before the table sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHint {
	/// Gateway socket claimed by the sharer, admitted by the dial policy.
	pub dial: AdmittedDial,
	/// Peer certificate fingerprint last seen with this address, when known.
	///
	/// The value is advisory until a probe verifies the peer.
	pub peer_id: Option<Vec<u8>>,
}

/// One learned peer as stored by a [`PeerStore`] driver.
///
/// Every field is public and the struct is exhaustive, so a driver outside
/// this crate builds the records it hydrates:
///
/// ```
/// use core::net::SocketAddr;
///
/// use tightbeam::colony::cluster::{ClusterError, PeerAddress, PeerRecord, PeerStore};
/// use tightbeam::utils::time::UnixMillis;
///
/// struct SeedStore;
///
/// impl PeerStore for SeedStore {
///     fn hydrate(&self) -> Result<Vec<PeerRecord>, ClusterError> {
///         let gateway_addr = PeerAddress::from(SocketAddr::from(([192, 0, 2, 1], 9000)));
///         Ok(vec![PeerRecord { gateway_addr, peer_id: None, tried: false, last_probe: UnixMillis::new(0) }])
///     }
///
///     fn persist(&self, _records: &[PeerRecord]) -> Result<(), ClusterError> {
///         Ok(())
///     }
/// }
///
/// let hydrated = SeedStore.hydrate()?;
/// assert_eq!(hydrated.len(), 1);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
	/// Gateway address for this peer, which hydration passes through the dial
	/// policy before the table dials it.
	pub gateway_addr: PeerAddress,
	/// Peer certificate fingerprint from the last verified probe.
	pub peer_id: Option<Vec<u8>>,
	/// Whether a colony-gated probe has verified this peer.
	pub tried: bool,
	/// When the last probe attempt ran.
	pub last_probe: UnixMillis,
}

/// Persistence driver beneath [`PeerTable`].
///
/// A driver only loads and saves learned records. The table owns every eclipse
/// invariant:
///
/// - Prefix bucketing, and the table and bucket caps.
/// - Anchor permanence.
/// - A full tried bucket keeps its residents, so a newcomer waits for a freed slot.
/// - Hydrated records re-enter through the dial policy and the same capped
///   admission path, so the bounds apply to them as they do to a learned
///   record.
///
/// # Faults
///
/// Persistence is advisory, so routing proceeds through a driver fault.
/// The table's hydration, which the config builder runs, degrades a
/// driver fault to an anchors-only start.
pub trait PeerStore: Send + Sync {
	/// Load learned peers from a prior run.
	fn hydrate(&self) -> Result<Vec<PeerRecord>, ClusterError>;

	/// Replace the persisted snapshot of learned peers.
	fn persist(&self, records: &[PeerRecord]) -> Result<(), ClusterError>;
}

/// In-memory driver that hydrates an empty set and discards every snapshot,
/// so discovery state lives for the process lifetime only.
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

/// Anchored bounded peer discovery table.
///
/// Interior mutability lets the advertise beat, reconcile rounds, and
/// reflood tasks share one instance through configuration.
pub struct PeerTable {
	anchors: Vec<AdmittedDial>,
	anchor_keys: HashSet<AdmittedDial>,
	state: GuardedTable,
	store: Arc<dyn PeerStore>,
	/// Newest generation written, and the gate that orders driver writes.
	///
	/// This is separate from `state`, so a slow driver delays the next
	/// write rather than the routing reads that take the table lock
	/// (CWE-667).
	persisted: Mutex<u64>,
}

impl Default for PeerTable {
	fn default() -> Self {
		Self::assemble(Vec::new(), HashSet::new(), TableState::default(), Arc::new(MemoryPeerStore))
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

/// Count entries in `map` that share the prefix bucket of `group`.
fn bucket_len(map: &HashMap<AdmittedDial, PeerEntry>, group: AddressGroup) -> usize {
	map.keys().filter(|addr| addr.address().group() == group).count()
}

/// Round-robin sample across prefix buckets.
///
/// Buckets are visited in sorted-key order, so the draw is deterministic,
/// and each bucket prefers its least recently probed peer. One prefix
/// therefore draws at most its own share of a bounded sample.
///
/// The walk holds borrowed pairs only. The drawn addresses, at most `cap`
/// of them, are copied out because they outlive the table lock.
fn diversity_sample<'t, I>(entries: I, cap: usize) -> Vec<AdmittedDial>
where
	I: Iterator<Item = (&'t AdmittedDial, &'t PeerEntry)>,
{
	let mut buckets: HashMap<AddressGroup, Vec<(&AdmittedDial, &PeerEntry)>> = HashMap::new();
	for (addr, entry) in entries {
		buckets.entry(addr.address().group()).or_default().push((addr, entry));
	}

	let mut lanes: Vec<Vec<(&AdmittedDial, &PeerEntry)>> = buckets.into_values().collect();
	for lane in &mut lanes {
		lane.sort_by_key(|(_, entry)| entry.last_probe);
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
				sample.push(**addr);
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
fn lane_key<'t>(lane: &[(&'t AdmittedDial, &'t PeerEntry)]) -> Option<&'t AdmittedDial> {
	lane.first().map(|(addr, _)| *addr)
}

/// One peer on its way into a table, with the proof its address was
/// admitted.
///
/// Learned hints, verified probes, and hydrated records all enter through
/// this one shape, so every path applies the anchor exclusion and the
/// prefix bounds to an address the dial policy already admitted.
struct Candidate {
	/// The admitted gateway address, which keys the table.
	dial: AdmittedDial,
	/// Whether a probe has verified the peer, which picks the table.
	tried: bool,
	/// What the table records about the peer.
	entry: PeerEntry,
}

impl PeerTable {
	/// Build a table around `peer`'s anchors and dial policy, over a
	/// persistence driver.
	///
	/// The anchors are [`PeerConfig::peers`], which the config builder
	/// admitted as operator configuration where the operator wrote them.
	///
	/// # Hydration
	///
	/// Hydration replays persisted records through the capped admission path
	/// every other record takes.
	///
	/// - Each record passes [`PeerConfig::admit_dial`] first, so a policy the
	///   operator tightened since the last run drops the peers it refuses.
	/// - A driver fault degrades to an anchors-only start, which is safe
	///   because discovery refills the table.
	///
	/// The config builder is the caller, because [`PeerConfig::table`] is
	/// derived from the config it is built from and a table built elsewhere
	/// would be detached from it.
	#[must_use]
	pub(in crate::colony::cluster) fn new(peer: &PeerConfig, store: Arc<dyn PeerStore>) -> Self {
		let anchors: Vec<AdmittedDial> = peer.peers().to_vec();
		let anchor_keys: HashSet<AdmittedDial> = anchors.iter().copied().collect();

		let records = store.hydrate().unwrap_or_default();
		let mut state = TableState::default();
		for record in records {
			let Ok(dial) = peer.admit_dial(record.gateway_addr) else {
				continue;
			};

			let entry = PeerEntry { peer_id: record.peer_id, last_probe: record.last_probe, failures: 0 };
			Self::admit_into(&anchor_keys, &mut state, Candidate { dial, tried: record.tried, entry });
		}

		Self::assemble(anchors, anchor_keys, state, store)
	}

	/// A table over `state`, built before any caller could reach it.
	///
	/// `anchor_keys` is the set over `anchors`, built once by the caller that
	/// already needed it for hydration.
	fn assemble(
		anchors: Vec<AdmittedDial>,
		anchor_keys: HashSet<AdmittedDial>,
		state: TableState,
		store: Arc<dyn PeerStore>,
	) -> Self {
		Self {
			anchors,
			anchor_keys,
			state: GuardedTable::new(state),
			store,
			persisted: Mutex::new(0),
		}
	}

	/// Admit unverified peer hints into the new table.
	///
	/// Admission drops a hint that names an anchor, a known address, or this
	/// gateway's own address, and a hint beyond the per-prefix or table caps.
	/// Cap overflow is the eclipse bound: one address prefix draws its own
	/// share of discovery (CWE-770).
	///
	/// Returns how many hints were admitted.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the table lock is poisoned.
	pub fn learn<I>(&self, hints: I) -> Result<usize, ClusterError>
	where
		I: IntoIterator<Item = PeerHint>,
	{
		self.with_table(|state| {
			let mut admitted = 0;
			for hint in hints {
				let entry = PeerEntry { peer_id: hint.peer_id, last_probe: UnixMillis::default(), failures: 0 };
				let candidate = Candidate { dial: hint.dial, tried: false, entry };
				if self.admit_record(state, candidate) {
					admitted += 1;
				}
			}

			(admitted, admitted > 0)
		})
	}

	/// Record a verified probe of `addr` and promote it into tried.
	///
	/// Verification is the caller's colony-certificate gate on the probe dial
	/// handshake. Returns `true` only on a promotion into tried, so the caller
	/// can emit one discovery event per peer.
	///
	/// # Test before evict
	///
	/// A full tried prefix bucket keeps its residents and leaves the candidate
	/// in new. Residents re-verify on every beat, so a candidate waits for a
	/// freed slot.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the table lock is poisoned.
	pub fn promote(&self, addr: AdmittedDial, peer_id: Option<&[u8]>, now: UnixMillis) -> Result<bool, ClusterError> {
		// Anchors are configured rather than learned, so a verified anchor
		// lands in its own map and leaves both learned tables as they are.
		if self.anchor_keys.contains(&addr) {
			return self.with_table(|state| {
				let entry = PeerEntry { peer_id: peer_id.map(<[u8]>::to_vec), last_probe: now, failures: 0 };
				state.anchors_verified.insert(addr, entry);

				(false, false)
			});
		}

		self.with_table(|state| {
			if let Some(entry) = state.tried.get_mut(&addr) {
				entry.last_probe = now;
				entry.failures = 0;

				if let Some(peer_id) = peer_id {
					entry.peer_id = Some(peer_id.to_vec());
				}

				return (false, true);
			}

			let entry = PeerEntry { peer_id: peer_id.map(<[u8]>::to_vec), last_probe: now, failures: 0 };
			let promoted = self.admit_record(state, Candidate { dial: addr, tried: true, entry });
			(promoted, promoted)
		})
	}

	/// Drop a candidate whose probe failed.
	///
	/// Pruning applies to the new table, which keeps a prefix bucket holding
	/// live addresses. A tried resident leaves through repeated beat failures
	/// in [`Self::record_failure`], and relay scoring handles misbehavior.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the table lock is poisoned.
	pub fn discard(&self, addr: AdmittedDial) -> Result<(), ClusterError> {
		self.with_table(|state| {
			let removed = state.new.remove(&addr).is_some();
			((), removed)
		})
	}

	/// Record a failed beat dial of a tried peer.
	///
	/// Residents re-verify on every beat, so consecutive failures measure
	/// liveness. Returns `true` only on an eviction so the caller can emit
	/// one event per reclaimed peer.
	///
	/// - Failures reaching [`MAX_PEER_TRIED_FAILURES`] evict the entry.
	/// - Eviction frees the prefix bucket slot for a live candidate.
	/// - The threshold tolerates a transient partition.
	/// - A verified probe resets the count.
	/// - Eviction fails closed: the table shrinks toward its anchors, and
	///   discovery refills it.
	/// - An address outside the tried table leaves the table unchanged.
	///
	/// # Sources
	///
	/// - Heilman, Kendler, Zohar & Goldberg (2015), eclipse attacks on
	///   Bitcoin's peer-to-peer network (feeler probes / tried eviction):
	///   [USENIX Security '15](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/heilman),
	///   [ePrint 2015/263](https://eprint.iacr.org/2015/263)
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the table lock is poisoned.
	pub fn record_failure(&self, addr: AdmittedDial) -> Result<bool, ClusterError> {
		self.with_table(|state| {
			let Some(entry) = state.tried.get_mut(&addr) else {
				return (false, false);
			};

			entry.failures = entry.failures.saturating_add(1);
			if entry.failures < MAX_PEER_TRIED_FAILURES {
				return (false, false);
			}

			state.tried.remove(&addr);

			(true, true)
		})
	}

	/// Remove an address from both learned tables.
	///
	/// A probe that answers with a foreign-colony certificate is a
	/// definitive identity mismatch rather than a transient fault.
	///
	/// - The address leaves discovery at once, ahead of the failure threshold.
	/// - A re-keyed peer therefore stops receiving advertisements.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the table lock is poisoned.
	pub fn expel(&self, addr: AdmittedDial) -> Result<(), ClusterError> {
		self.with_table(|state| {
			let from_new = state.new.remove(&addr).is_some();
			let from_tried = state.tried.remove(&addr).is_some();
			((), from_new || from_tried)
		})
	}

	/// Dial targets for the advertise/reconcile beat and gossip reflood.
	///
	/// Anchors always lead the set, then verified tried peers. A `new` entry
	/// joins the set once a probe promotes it, so advertisements and rumor
	/// bytes reach verified identities only.
	///
	/// The returned targets outlive the table lock, so each beat draws
	/// owned copies. The set is bounded by the anchor and tried caps.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the table lock is poisoned.
	pub fn target_set(&self) -> Result<Vec<AdmittedDial>, ClusterError> {
		let mut learned = self
			.state
			.read(|state| state.tried.keys().copied().collect::<Vec<AdmittedDial>>())?;
		let mut targets = self.anchors.clone();

		learned.sort();
		targets.extend(learned);

		Ok(targets)
	}

	/// Bounded feeler sample of unverified candidates for this beat.
	///
	/// Sampling round-robins across prefix buckets so each prefix draws its
	/// own share of probe capacity. Each bucket prefers its least recently
	/// probed candidate. Sampled candidates are stamped with `now` so
	/// later beats rotate through the backlog.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the table lock is poisoned.
	pub fn probe_sample(&self, now: UnixMillis) -> Result<Vec<AdmittedDial>, ClusterError> {
		// A probe stamp rotates the backlog within a run. The next durable
		// change carries whatever stamp is current, so the beat spends no
		// driver write of its own.
		self.with_table(|state| {
			let sample = diversity_sample(state.new.iter(), PEER_PROBE_PER_BEAT);
			for addr in &sample {
				if let Some(entry) = state.new.get_mut(addr) {
					entry.last_probe = now;
				}
			}

			(sample, false)
		})
	}

	/// Diversity-bucketed sample of verified peers to share over PEX.
	///
	/// The shareable set is tried peers plus probe-verified anchors. Draws
	/// round-robin across prefix buckets up to `cap`, so the shared view
	/// spans prefixes in proportion to what each holds.
	///
	/// Only probe-verified peers are shared. Forwarding an unverified hint
	/// would launder it with this gateway's reputation.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the table lock is poisoned.
	pub fn sample_for_pex(&self, cap: usize) -> Result<Vec<PeerRecord>, ClusterError> {
		self.state.read(|state| {
			// Anchors and tried are disjoint maps, so chaining them borrows a
			// disjoint shareable view without building a merged copy. Only the
			// sampled records own their data, because they outlive the guard.
			let shareable = state.tried.iter().chain(state.anchors_verified.iter());
			diversity_sample(shareable, cap)
				.into_iter()
				.filter_map(|addr| {
					let entry = state.tried.get(&addr).or_else(|| state.anchors_verified.get(&addr))?;
					Some(PeerRecord {
						gateway_addr: addr.address(),
						peer_id: entry.peer_id.clone(),
						tried: true,
						last_probe: entry.last_probe,
					})
				})
				.collect()
		})
	}

	/// Current learned sizes as `(new, tried)` for operators and tests.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the table lock is poisoned.
	pub fn learned(&self) -> Result<(usize, usize), ClusterError> {
		self.state.read(|state| (state.new.len(), state.tried.len()))
	}

	/// Record this gateway's own advertised address.
	///
	/// Peer exchange echoes installed routes, which include the requester's
	/// own advertised address, so the table holds that address out of
	/// admission. PEX replies therefore teach a gateway its peers alone.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the table lock is poisoned.
	pub fn exclude_self(&self, addr: PeerAddress) -> Result<(), ClusterError> {
		// The advertise beat re-excludes on every start, so the local
		// address needs no driver write to stay out of admission.
		self.with_table(|state| {
			state.new.retain(|dial, _| dial.address() != addr);
			state.tried.retain(|dial, _| dial.address() != addr);
			state.local = Some(addr);

			((), false)
		})
	}

	/// Whether any dial target exists.
	///
	/// A reflood can skip frame construction when this is false.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the table lock is poisoned.
	pub fn has_targets(&self) -> Result<bool, ClusterError> {
		if !self.anchors.is_empty() {
			return Ok(true);
		}

		self.state.read(|state| !state.tried.is_empty())
	}

	/// Admit one candidate into its table under the capped admission path.
	///
	/// `learn` and `promote` admit through here, and hydration admits through
	/// [`Self::admit_into`], so every path applies anchor exclusion and the
	/// prefix bounds.
	fn admit_record(&self, state: &mut TableState, candidate: Candidate) -> bool {
		Self::admit_into(&self.anchor_keys, state, candidate)
	}

	/// [`Self::admit_record`] for a table still being built, before its
	/// state is behind the guard.
	fn admit_into(anchor_keys: &HashSet<AdmittedDial>, state: &mut TableState, candidate: Candidate) -> bool {
		let Candidate { dial: key, tried, entry } = candidate;
		let group = key.address().group();
		if anchor_keys.contains(&key) || state.tried.contains_key(&key) {
			return false;
		}
		if state.local == Some(key.address()) {
			return false;
		}

		if tried {
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

	/// Applies `change` under the table guard, then writes the snapshot it
	/// asked for.
	///
	/// `change` returns its outcome and whether the learned tables moved.
	///
	/// # Writes
	///
	/// - Every mutation routes through here, so the decision to write lives in one place.
	/// - The guard is released before the pluggable driver runs, so a driver
	///   that blocks delays no other caller (CWE-667).
	/// - The in-memory table stays authoritative, so the beat proceeds through
	///   a driver write fault, and the next mutation retries the write.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the table lock is poisoned.
	fn with_table<T>(&self, change: impl FnOnce(&mut TableState) -> (T, bool)) -> Result<T, ClusterError> {
		let (outcome, write) = self.state.change(change)?;
		if let Some(write) = write {
			self.persist_at(write.generation, &write.records);
		}

		Ok(outcome)
	}

	/// Writes `records` when `generation` is newer than what the driver holds.
	///
	/// The gate serialises driver writes, so concurrent mutations reach the
	/// driver in generation order. A snapshot a newer generation already
	/// superseded is dropped, which keeps an evicted peer from returning on
	/// the next hydrate. The gate guards one integer, which no panic can
	/// half-write, so a poisoned gate is recovered rather than skipped.
	fn persist_at(&self, generation: u64, records: impl AsRef<[PeerRecord]>) {
		let records = records.as_ref();
		let mut persisted = self.persisted.lock().unwrap_or_else(PoisonError::into_inner);

		if generation <= *persisted {
			return;
		}

		// Persistence is advisory: the in-memory table stays authoritative
		// and the next mutation writes again, so a driver fault is not the
		// beat's to fail on.
		let _ = self.store.persist(records);
		*persisted = generation;
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::tb_cases;
	use core::time::Duration;
	use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

	/// Parse a fixture address, admitted the way the table takes it.
	fn addr(text: impl AsRef<str>) -> AdmittedDial {
		AdmittedDial::fixture(text)
	}

	/// A fixture IPv6 socket with the flow label and scope id given, which
	/// socket syntax cannot spell.
	fn v6_socket(ip: Ipv6Addr, flowinfo: u32, scope_id: u32) -> PeerAddress {
		PeerAddress::from(SocketAddr::V6(SocketAddrV6::new(ip, 9000, flowinfo, scope_id)))
	}

	// Two spellings of one socket share a route, an allowlist row, and a
	// diversity bucket (CWE-706).
	tb_cases! {
		fn one_socket_is_one_address((spelled, canonical): (PeerAddress, &str)) {
			assert_eq!(spelled, PeerAddress::fixture(canonical));
			assert_eq!(spelled.group(), PeerAddress::fixture(canonical).group());
			assert_eq!(spelled.to_string(), canonical);
		}
		cases {
			ipv4_mapped_ipv6 => (PeerAddress::fixture("[::ffff:192.0.2.1]:9000"), "192.0.2.1:9000"),
			ipv4 => (PeerAddress::fixture("192.0.2.1:9000"), "192.0.2.1:9000"),
			ipv6 => (PeerAddress::fixture("[2001:db8::1]:9000"), "[2001:db8::1]:9000"),
			scoped_global_ipv6 => (PeerAddress::fixture("[2001:db8::1%7]:9000"), "[2001:db8::1]:9000"),
			scoped_loopback => (PeerAddress::fixture("[::1%7]:9000"), "[::1]:9000"),
			scoped_link_local => (PeerAddress::fixture("[fe80::1%7]:9000"), "[fe80::1%7]:9000"),
			scoped_multicast => (PeerAddress::fixture("[ff02::1%7]:9000"), "[ff02::1%7]:9000"),
			flow_label => (v6_socket(Ipv6Addr::LOCALHOST, 7, 0), "[::1]:9000"),
			flow_label_and_global_scope => (v6_socket(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 7, 7), "[2001:db8::1]:9000"),
		}
	}

	// The unspecified address is its own class, because a connect to it
	// lands on this host's loopback even when the allowlist names it (CWE-706).
	tb_cases! {
		fn is_unspecified_classifies_the_address((spelling, unspecified): (&str, bool)) {
			assert_eq!(PeerAddress::fixture(spelling).is_unspecified(), unspecified);
		}
		cases {
			ipv4_unspecified => ("0.0.0.0:9000", true),
			ipv6_unspecified => ("[::]:9000", true),
			mapped_unspecified => ("[::ffff:0.0.0.0]:9000", true),
			ipv4_loopback => ("127.0.0.1:9000", false),
			this_network_host => ("0.0.0.1:9000", false),
		}
	}

	// A unicast address can name one peer, and the classes below can name
	// none, so a claim of one buys nothing but a table slot (CWE-770).
	tb_cases! {
		fn is_unicast_classifies_the_address((spelling, unicast): (&str, bool)) {
			assert_eq!(PeerAddress::fixture(spelling).is_unicast(), unicast);
		}
		cases {
			ipv4_multicast => ("224.0.0.1:9000", false),
			ipv4_multicast_block_end => ("239.255.255.255:9000", false),
			ipv4_broadcast => ("255.255.255.255:9000", false),
			ipv4_reserved => ("240.0.0.1:9000", false),
			ipv4_this_network => ("0.0.0.1:9000", false),
			ipv4_unspecified => ("0.0.0.0:9000", false),
			ipv6_multicast => ("[ff02::1]:9000", false),
			ipv4_private => ("10.0.0.1:9000", true),
			ipv4_cgnat => ("100.64.0.1:9000", true),
			ipv4_loopback => ("127.0.0.1:9000", true),
			ipv4_documentation => ("192.0.2.1:9000", true),
			ipv6_unique_local => ("[fd00::1]:9000", true),
			ipv6_global => ("[2001:db8::1]:9000", true),
		}
	}

	// A route address, a hive's servlet address, and a claimed gateway all
	// arrive as bytes, and the one parse decides which of them name a socket.
	tb_cases! {
		fn bytes_become_an_address_only_when_they_spell_a_socket((bytes, expected): (&[u8], Result<PeerAddress, NotASocket>)) {
			assert_eq!(PeerAddress::try_from(bytes), expected);
		}
		cases {
			socket_spelling => (b"192.0.2.1:9000", Ok(PeerAddress::fixture("192.0.2.1:9000"))),
			mapped_spelling => (b"[::ffff:192.0.2.1]:9000", Ok(PeerAddress::fixture("192.0.2.1:9000"))),
			hostname => (b"localhost:9000", Err(NotASocket)),
			empty => (b"", Err(NotASocket)),
			non_utf8 => (&[0xff, 0xfe], Err(NotASocket)),
		}
	}

	fn hint(text: impl AsRef<str>) -> PeerHint {
		PeerHint { dial: addr(text), peer_id: None }
	}

	/// A table over `store` whose one anchor the operator configured at
	/// `anchor`.
	fn anchored(anchor: impl AsRef<str>, store: Arc<dyn PeerStore>) -> PeerTable {
		let mut peer = PeerConfig::default();
		peer.set_anchors([anchor.as_ref()]).expect("fixture anchors name sockets");
		PeerTable::new(&peer, store)
	}

	fn table_with_anchor(anchor: impl AsRef<str>) -> PeerTable {
		anchored(anchor, Arc::new(MemoryPeerStore))
	}

	/// An unanchored table over `store`, on the default dial policy.
	fn table_over(store: Arc<dyn PeerStore>) -> PeerTable {
		PeerTable::new(&PeerConfig::default(), store)
	}

	struct CountingStore {
		seed: Vec<PeerRecord>,
		persists: AtomicUsize,
	}

	impl CountingStore {
		fn seeded(seed: impl IntoIterator<Item = PeerRecord>) -> Self {
			let seed: Vec<PeerRecord> = seed.into_iter().collect();
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

	fn record(text: impl AsRef<str>, tried: bool) -> PeerRecord {
		PeerRecord {
			gateway_addr: PeerAddress::fixture(text),
			peer_id: None,
			tried,
			last_probe: UnixMillis::new(0),
		}
	}

	#[test]
	fn address_group_prefixes_v4_and_v6() {
		let v6 = PeerAddress::fixture("[2001:db8::1]:80");
		assert_eq!(PeerAddress::fixture("10.1.2.3:80").group(), AddressGroup::V4([10, 1]));
		assert_eq!(v6.group(), AddressGroup::V6([0x20, 0x01, 0x0d, 0xb8]));
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
	// A hint always carries an address the dial policy admitted, so a duplicate
	// is the one refusal left for learning to apply here.
	fn learn_drops_duplicate_hints() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		let admitted = table.learn(vec![hint("10.0.0.1:9000"), hint("10.0.0.1:9000")])?;
		assert_eq!(admitted, 1);
		Ok(())
	}

	#[test]
	fn learn_caps_one_prefix_bucket() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		let hints: Vec<PeerHint> = (0..MAX_PEER_BUCKET + 3)
			.map(|host| hint(format!("10.0.0.{}:9000", host + 1)))
			.collect();
		let admitted = table.learn(hints)?;
		assert_eq!(admitted, MAX_PEER_BUCKET);
		Ok(())
	}

	#[test]
	fn promote_moves_candidate_into_tried_once() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.learn(vec![hint("10.0.0.1:9000")])?;

		let first = table.promote(addr("10.0.0.1:9000"), Some(b"fp-a"), UnixMillis::new(1_000))?;
		let second = table.promote(addr("10.0.0.1:9000"), Some(b"fp-a"), UnixMillis::new(2_000))?;
		assert!(first);
		assert!(!second);
		assert_eq!(table.learned()?, (0, 1));
		Ok(())
	}

	#[test]
	fn promote_never_tracks_anchors() -> Result<(), ClusterError> {
		let table = table_with_anchor("127.0.0.1:9000");
		let promoted = table.promote(addr("127.0.0.1:9000"), None, UnixMillis::new(1_000))?;
		assert!(!promoted);
		assert_eq!(table.learned()?, (0, 0));
		Ok(())
	}

	#[test]
	fn verified_anchor_becomes_shareable_over_pex() -> Result<(), ClusterError> {
		let table = table_with_anchor("127.0.0.1:9000");
		assert!(table.sample_for_pex(8)?.is_empty());

		table.promote(addr("127.0.0.1:9000"), Some(b"fp-a"), UnixMillis::new(1_000))?;

		let sample = table.sample_for_pex(8)?;
		assert_eq!(sample.len(), 1);
		assert_eq!(sample[0].gateway_addr.to_string(), "127.0.0.1:9000");
		assert_eq!(sample[0].peer_id.as_deref(), Some(b"fp-a".as_slice()));
		Ok(())
	}

	#[test]
	fn promote_keeps_residents_of_full_tried_bucket() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		for host in 0..MAX_PEER_BUCKET {
			table.promote(addr(format!("10.0.0.{}:9000", host + 1)), None, UnixMillis::new(1_000))?;
		}

		table.learn(vec![hint("10.0.9.9:9000")])?;

		let promoted = table.promote(addr("10.0.9.9:9000"), None, UnixMillis::new(2_000))?;
		assert!(!promoted);
		assert_eq!(table.learned()?, (1, MAX_PEER_BUCKET));
		Ok(())
	}

	#[test]
	fn exclude_self_blocks_learning_own_address() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.exclude_self(PeerAddress::fixture("10.0.0.1:9000"))?;

		let admitted = table.learn(vec![hint("10.0.0.1:9000")])?;
		let promoted = table.promote(addr("10.0.0.1:9000"), None, UnixMillis::new(1_000))?;
		assert_eq!(admitted, 0);
		assert!(!promoted);
		Ok(())
	}

	// A gateway learns its own address before it excludes it when a PEX
	// reply lands first, so exclusion evicts what the table already holds.
	#[test]
	fn exclude_self_evicts_an_address_already_learned() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.learn(vec![hint("10.0.0.1:9000")])?;
		table.promote(addr("10.1.0.1:9000"), None, UnixMillis::new(1_000))?;

		table.exclude_self(PeerAddress::fixture("10.0.0.1:9000"))?;
		table.exclude_self(PeerAddress::fixture("10.1.0.1:9000"))?;

		assert_eq!(table.learned()?, (0, 0));
		Ok(())
	}

	#[test]
	fn discard_prunes_only_the_new_table() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.learn(vec![hint("10.0.0.1:9000")])?;
		table.promote(addr("10.1.0.1:9000"), None, UnixMillis::new(1_000))?;

		table.discard(addr("10.0.0.1:9000"))?;
		table.discard(addr("10.1.0.1:9000"))?;
		assert_eq!(table.learned()?, (0, 1));
		Ok(())
	}

	/// Records `failures` beat failures against `peer` and answers whether
	/// each one evicted it.
	fn evictions_over(table: &PeerTable, peer: AdmittedDial, failures: usize) -> Result<Vec<bool>, ClusterError> {
		let mut evictions = Vec::with_capacity(failures);
		for _ in 0..failures {
			evictions.push(table.record_failure(peer)?);
		}

		Ok(evictions)
	}

	#[test]
	fn record_failure_evicts_tried_peer_at_threshold() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.promote(addr("10.0.0.1:9000"), None, UnixMillis::new(1_000))?;

		let evictions = evictions_over(&table, addr("10.0.0.1:9000"), MAX_PEER_TRIED_FAILURES)?;

		assert_eq!(evictions, vec![false, false, true]);
		assert_eq!(table.learned()?, (0, 0));
		Ok(())
	}

	#[test]
	fn verified_probe_resets_failure_count() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.promote(addr("10.0.0.1:9000"), None, UnixMillis::new(1_000))?;
		table.record_failure(addr("10.0.0.1:9000"))?;
		table.record_failure(addr("10.0.0.1:9000"))?;

		table.promote(addr("10.0.0.1:9000"), None, UnixMillis::new(2_000))?;

		table.record_failure(addr("10.0.0.1:9000"))?;
		table.record_failure(addr("10.0.0.1:9000"))?;
		assert_eq!(table.learned()?, (0, 1));
		Ok(())
	}

	#[test]
	fn record_failure_ignores_anchors_and_unknown_addresses() -> Result<(), ClusterError> {
		let table = table_with_anchor("127.0.0.1:9000");
		let anchor_evicted = table.record_failure(addr("127.0.0.1:9000"))?;
		let unknown_evicted = table.record_failure(addr("10.0.0.1:9000"))?;
		assert!(!anchor_evicted);
		assert!(!unknown_evicted);
		Ok(())
	}

	#[test]
	fn eviction_frees_the_prefix_bucket_slot() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		for host in 0..MAX_PEER_BUCKET {
			table.promote(addr(format!("10.0.0.{}:9000", host + 1)), None, UnixMillis::new(1_000))?;
		}

		assert!(!table.promote(addr("10.0.9.9:9000"), None, UnixMillis::new(2_000))?);

		for _ in 0..MAX_PEER_TRIED_FAILURES {
			table.record_failure(addr("10.0.0.1:9000"))?;
		}

		assert!(table.promote(addr("10.0.9.9:9000"), None, UnixMillis::new(3_000))?);
		Ok(())
	}

	#[test]
	fn expel_clears_both_learned_tables() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.learn(vec![hint("10.0.0.1:9000")])?;
		table.promote(addr("10.1.0.1:9000"), None, UnixMillis::new(1_000))?;
		table.expel(addr("10.0.0.1:9000"))?;
		table.expel(addr("10.1.0.1:9000"))?;
		assert_eq!(table.learned()?, (0, 0));
		Ok(())
	}

	#[test]
	fn target_set_leads_with_anchors_and_hides_new() -> Result<(), ClusterError> {
		let table = table_with_anchor("127.0.0.1:9000");
		table.learn(vec![hint("10.0.0.1:9000")])?;
		table.promote(addr("10.1.0.1:9000"), None, UnixMillis::new(1_000))?;

		let targets = table.target_set()?;
		assert_eq!(targets, vec![addr("127.0.0.1:9000"), addr("10.1.0.1:9000")]);
		Ok(())
	}

	#[test]
	fn probe_sample_spans_prefix_buckets() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		let crowded: Vec<PeerHint> = (0..PEER_PROBE_PER_BEAT + 2)
			.map(|host| hint(format!("10.0.0.{}:9000", host + 1)))
			.collect();
		table.learn(crowded)?;
		table.learn(vec![hint("10.1.0.1:9000")])?;

		let sample = table.probe_sample(UnixMillis::new(1_000))?;
		assert_eq!(sample.len(), PEER_PROBE_PER_BEAT);
		assert!(sample.contains(&addr("10.1.0.1:9000")));
		Ok(())
	}

	#[test]
	fn probe_sample_rotates_through_backlog() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.learn(vec![hint("10.0.0.1:9000"), hint("10.1.0.1:9000")])?;

		let first = table.probe_sample(UnixMillis::new(1_000))?;
		let second = table.probe_sample(UnixMillis::new(2_000))?;
		assert_eq!(first.len(), 2);
		assert_eq!(second.len(), 2);
		Ok(())
	}

	#[test]
	fn sample_for_pex_caps_and_spans_buckets() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.promote(addr("10.0.0.1:9000"), Some(b"fp-a"), UnixMillis::new(1_000))?;
		table.promote(addr("10.0.0.2:9000"), Some(b"fp-b"), UnixMillis::new(1_000))?;
		table.promote(addr("10.1.0.1:9000"), Some(b"fp-c"), UnixMillis::new(1_000))?;

		let sample = table.sample_for_pex(2)?;
		let addrs: Vec<PeerAddress> = sample.iter().map(|record| record.gateway_addr).collect();
		assert_eq!(sample.len(), 2);
		assert!(addrs.contains(&PeerAddress::fixture("10.1.0.1:9000")));
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
			.map(|host| record(format!("10.0.0.{}:9000", host + 1), false))
			.collect();
		seed.push(record("10.1.0.1:9000", true));

		let table = table_over(Arc::new(CountingStore::seeded(seed)));
		assert_eq!(table.learned()?, (MAX_PEER_BUCKET, 1));
		Ok(())
	}

	// A record the current dial policy refuses is dropped on hydration, so a
	// policy the operator tightened between runs binds the persisted peers too.
	#[test]
	fn hydrate_drops_records_the_dial_policy_refuses() -> Result<(), ClusterError> {
		let seed = vec![record("192.0.2.7:9000", true), record("10.0.0.1:9000", true)];

		let table = PeerTable::new(&PeerConfig::allowing(["10.0.0.1:9000"]), Arc::new(CountingStore::seeded(seed)));

		let targets: Vec<PeerAddress> = table.target_set()?.iter().map(AdmittedDial::address).collect();
		assert_eq!(targets, vec![PeerAddress::fixture("10.0.0.1:9000")]);
		Ok(())
	}

	#[test]
	fn mutations_persist_through_the_driver() -> Result<(), ClusterError> {
		let store = Arc::new(CountingStore::seeded(Vec::new()));
		let driver: Arc<dyn PeerStore> = store.clone();
		let table = table_over(driver);

		table.learn(vec![hint("10.0.0.1:9000")])?;
		table.promote(addr("10.0.0.1:9000"), None, UnixMillis::new(1_000))?;
		assert_eq!(store.persists.load(Ordering::SeqCst), 2);
		Ok(())
	}

	/// Driver that stalls its first write until released, and records the
	/// row count each snapshot carried.
	#[derive(Debug, Default)]
	struct StallingStore {
		widths: Mutex<Vec<usize>>,
		started: AtomicUsize,
		released: AtomicBool,
	}

	impl StallingStore {
		/// Blocks until the driver has entered its first write.
		fn await_first_write(&self) {
			while self.started.load(Ordering::SeqCst) == 0 {
				std::thread::yield_now();
			}
		}

		/// Blocks the caller until [`StallingStore::release`] runs.
		fn await_release(&self) {
			while !self.released.load(Ordering::SeqCst) {
				std::thread::yield_now();
			}
		}

		fn release(&self) {
			self.released.store(true, Ordering::SeqCst);
		}
	}

	impl PeerStore for StallingStore {
		fn hydrate(&self) -> Result<Vec<PeerRecord>, ClusterError> {
			Ok(Vec::new())
		}

		fn persist(&self, records: &[PeerRecord]) -> Result<(), ClusterError> {
			if self.started.fetch_add(1, Ordering::SeqCst) == 0 {
				self.await_release();
			}

			if let Ok(mut widths) = self.widths.lock() {
				widths.push(records.len());
			}

			Ok(())
		}
	}

	/// A snapshot taken under the guard holds every earlier change, so the
	/// driver's rows only ever grow. A stale snapshot landing after a newer
	/// one would hydrate peers a later mutation removed (CWE-362).
	///
	/// The first write stalls inside the driver while a second mutation
	/// runs, which is the interleaving that reorders unguarded writes.
	#[test]
	fn driver_writes_land_in_generation_order() -> Result<(), ClusterError> {
		let store = Arc::new(StallingStore::default());
		let table = Arc::new(table_over(Arc::clone(&store) as Arc<dyn PeerStore>));
		let first = Arc::clone(&table);
		let stalled = std::thread::spawn(move || first.learn(vec![hint("10.1.0.1:9000")]));

		store.await_first_write();

		let second = Arc::clone(&table);
		let follower = std::thread::spawn(move || second.learn(vec![hint("10.2.0.1:9000")]));

		std::thread::sleep(Duration::from_millis(50));
		store.release();
		stalled.join().expect("thread joins")?;
		follower.join().expect("thread joins")?;

		let widths = store.widths.lock().expect("driver handle").clone();
		assert!(widths.windows(2).all(|pair| pair[0] <= pair[1]));
		assert_eq!(widths.last().copied(), Some(2));

		Ok(())
	}

	/// A driver that reaches back into the table while it is being written.
	///
	/// The write runs after the table guard is released, so this re-entry
	/// reads the table it was called from (CWE-667).
	struct ReentrantStore {
		table: Mutex<Option<Arc<PeerTable>>>,
		observed: AtomicUsize,
	}

	impl PeerStore for ReentrantStore {
		fn hydrate(&self) -> Result<Vec<PeerRecord>, ClusterError> {
			Ok(Vec::new())
		}

		fn persist(&self, _records: &[PeerRecord]) -> Result<(), ClusterError> {
			let table = self.table.lock().expect("driver handle").clone();
			if let Some(table) = table {
				let (new, tried) = table.learned()?;
				self.observed.store(new + tried, Ordering::SeqCst);
			}

			Ok(())
		}
	}

	#[test]
	fn the_table_lock_is_free_while_the_driver_writes() -> Result<(), ClusterError> {
		let store = Arc::new(ReentrantStore { table: Mutex::new(None), observed: AtomicUsize::new(0) });
		let table = Arc::new(anchored("10.0.0.1:9000", Arc::clone(&store) as Arc<dyn PeerStore>));

		*store.table.lock().expect("driver handle") = Some(Arc::clone(&table));
		table.learn(vec![hint("10.1.0.1:9000")])?;

		assert_eq!(store.observed.load(Ordering::SeqCst), 1);
		Ok(())
	}
}
