//! An anchored, bounded peer table with pluggable persistence.
//!
//! This module holds the discovery state of the peer beat. The design
//! follows Bitcoin's address manager, as the eclipse-attack analysis below
//! reads it.
//!
//! - Configured anchors hold their slots for the table's life, and the beat always dials them.
//! - The table buckets learned peers by address prefix, with a cap on each
//!   bucket, so one network position holds at most its own bucket's share
//!   of the table (CWE-770).
//! - An unverified hint enters the `new` table only. A probe dial whose
//!   handshake certificate proves flood membership promotes the peer to
//!   `tried`. Only anchors and `tried` peers are beat targets.
//! - The table evicts a `tried` resident that fails consecutive beats, so a
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
//!   and per-group capacity), USENIX Security '15 and ePrint 2015/263:
//!   - <https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/heilman>
//!   - <https://eprint.iacr.org/2015/263>
//! - CWE-770, allocation of resources without limits or throttling:
//!   <https://cwe.mitre.org/data/definitions/770.html>

use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use core::str::{from_utf8, FromStr};
use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};

mod guard;

use guard::{Bounds, Candidate, GuardedTable, PeerEntry, TableState};

use super::{AdmittedDial, ClusterError, PeerConfig, SharedId};
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
/// - An IPv4-mapped IPv6 address such as `[::ffff:192.0.2.1]:9000` becomes its IPv4 socket.
/// - An IPv6 flow label names no endpoint, so the constructor stores it as zero.
/// - An IPv6 scope id picks an interface for a link-local or multicast
///   destination alone, so the constructor stores zero for every other address.
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

	/// The IPv6 scope id the kernel reads for `ip`, which is `scope_id` for a
	/// link-local or multicast destination and zero otherwise.
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

/// The error for bytes that are not the UTF-8 spelling of a socket address.
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

/// The network locality bucket of one peer address.
///
/// IPv4 groups by a /16 prefix and IPv6 by a /32 prefix. The table spends
/// capacity per prefix, so one bucket bounds an attacker inside one prefix.
/// See the module-level sources for the eclipse analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AddressGroup {
	/// The IPv4 /16 prefix, formed from the first two octets.
	V4([u8; 2]),
	/// The IPv6 /32 prefix, formed from the first four octets.
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
	/// The gateway socket the sharer claimed, which the dial policy admitted.
	pub dial: AdmittedDial,
	/// The peer certificate fingerprint last seen with this address, when the
	/// sharer knows it.
	///
	/// The value is advisory until a probe verifies the peer.
	pub peer_id: Option<Vec<u8>>,
}

/// One learned peer, as a [`PeerStore`] driver stores it.
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
	/// The gateway address of this peer, which hydration passes through the
	/// dial policy before the table dials it.
	pub gateway_addr: PeerAddress,
	/// The peer certificate fingerprint from the last verified probe.
	pub peer_id: Option<Vec<u8>>,
	/// Whether a probe has verified this peer as a flood member.
	pub tried: bool,
	/// The time the last probe attempt ran.
	pub last_probe: UnixMillis,
}

/// The persistence driver beneath [`PeerTable`].
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

/// An in-memory driver that hydrates an empty set and discards every
/// snapshot, so discovery state lives for the process lifetime only.
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

/// An anchored, bounded peer discovery table.
///
/// Interior mutability lets the advertise beat, reconcile rounds, and
/// reflood tasks share one instance through configuration.
pub struct PeerTable {
	anchors: Vec<AdmittedDial>,
	state: GuardedTable,
	store: Arc<dyn PeerStore>,
	/// The newest generation written, and the gate that orders driver writes.
	///
	/// This is separate from `state`, so a slow driver delays the next
	/// write rather than the routing reads that take the table lock
	/// (CWE-667).
	persisted: Mutex<u64>,
}

impl Default for PeerTable {
	fn default() -> Self {
		Self::assemble(Vec::new(), GuardedTable::new(Bounds::default(), []), Arc::new(MemoryPeerStore))
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
	/// - A signer cap the operator set since the last run binds the persisted peers the same way.
	/// - A driver fault degrades to an anchors-only start, which is safe because discovery refills the table.
	///
	/// The config builder is the caller, because it derives
	/// [`PeerConfig::table`] from its own config, and a table from another
	/// caller would be detached from that config.
	#[must_use]
	pub(in crate::colony::cluster) fn new(peer: &PeerConfig, store: Arc<dyn PeerStore>) -> Self {
		let anchors: Vec<AdmittedDial> = peer.peers().to_vec();
		let anchor_set: HashSet<AdmittedDial> = anchors.iter().copied().collect();
		let bounds = Bounds { anchors: anchor_set, tried_per_signer: peer.tried_per_signer };

		let records = store.hydrate().unwrap_or_default();
		let persisted = records.into_iter().filter_map(|record| {
			let dial = peer.admit_dial(record.gateway_addr).ok()?;
			let entry = PeerEntry { peer_id: record.peer_id, last_probe: record.last_probe, failures: 0 };

			Some(Candidate { dial, tried: record.tried, entry })
		});

		Self::assemble(anchors, GuardedTable::new(bounds, persisted), store)
	}

	/// A table over `state`, built before any caller could reach it.
	fn assemble(anchors: Vec<AdmittedDial>, state: GuardedTable, store: Arc<dyn PeerStore>) -> Self {
		Self { anchors, state, store, persisted: Mutex::new(0) }
	}

	/// Admit unverified peer hints into the new table, each stamped at `now`,
	/// and return how many it admitted.
	///
	/// Admission drops a hint in each case below:
	///
	/// - It names an anchor, a known address, or this gateway's own address.
	/// - It is beyond the per-prefix or table caps, and no candidate that failed a probe yields its slot.
	///
	/// Cap overflow is the eclipse bound: one address prefix draws its own
	/// share of discovery (CWE-770). `now` is the gateway clock's reading, so
	/// a hint the table learns again orders the probe backlog by its return.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the table lock is poisoned.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::cluster::{PeerConfig, PeerTable};
	/// use tightbeam::colony::protocol::PeerGossip;
	/// use tightbeam::utils::time::UnixMillis;
	///
	/// let gossip = PeerGossip { peer_id: Vec::new(), gateway_addr: b"10.0.0.1:9000".to_vec() };
	/// let hint = PeerConfig::default().admit_hint(gossip)?;
	/// let table = PeerTable::default();
	///
	/// let admitted = table.learn([hint], UnixMillis::new(1_000))?;
	/// assert_eq!(admitted, 1);
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn learn<I>(&self, hints: I, now: UnixMillis) -> Result<usize, ClusterError>
	where
		I: IntoIterator<Item = PeerHint>,
	{
		self.with_table(|state| {
			let admitted = state.learn(hints, now);
			(admitted, admitted > 0)
		})
	}

	/// Record a verified probe of `addr` and promote it into tried.
	///
	/// Verification is the caller's proof of flood membership on the probe
	/// dial handshake. It returns `true` only on a promotion into tried, so
	/// the caller can emit one discovery event per peer.
	///
	/// # Test before evict
	///
	/// A full tried prefix bucket keeps its residents and leaves the candidate
	/// in new. Residents re-verify on every beat, so a candidate waits for a
	/// freed slot. A signer at its configured cap waits the same way.
	///
	/// # Signer change
	///
	/// The table admits a resident that answers as another signer again under
	/// that signer, so the cap counts the slot. A signer at its cap sends the
	/// address back to new, and one below its cap keeps the slot with no new
	/// discovery.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the table lock is poisoned.
	pub fn promote(&self, addr: AdmittedDial, peer_id: Option<&[u8]>, now: UnixMillis) -> Result<bool, ClusterError> {
		self.with_table(|state| state.promote(addr, peer_id, now))
	}

	/// Record a failed probe on its candidate, which stays in the new table.
	///
	/// A peer shares an address again in later exchanges, even one this
	/// gateway fails to reach or to trust. A table that erased the candidate
	/// would let the next hint re-admit it at the front of the probe queue, so
	/// the failure stays on the entry:
	///
	/// - [`Self::learn`] drops a hint for an address the table already holds.
	/// - [`Self::probe_sample`] skips the candidate until its wait has passed.
	/// - [`Self::probe_sample`] then draws it after every one in its bucket with fewer failures.
	/// - A full bucket gives the slot of its most-failed candidate to a newcomer.
	///
	/// An address outside the new table leaves the table unchanged.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the table lock is poisoned.
	pub fn record_probe_failure(&self, addr: AdmittedDial, now: UnixMillis) -> Result<(), ClusterError> {
		// The count and the stamp order the backlog within a run, so the
		// change spends no driver write.
		self.with_table(|state| {
			state.record_probe_failure(addr, now);
			((), false)
		})
	}

	/// Drop a candidate whose address fails to convert to a protocol address.
	///
	/// That limit is this gateway's own and permanent, so the candidate
	/// leaves the new table. A failed probe goes to
	/// [`Self::record_probe_failure`], a tried resident leaves through
	/// repeated beat failures in [`Self::record_failure`], and relay scoring
	/// handles misbehavior.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the table lock is poisoned.
	pub fn discard(&self, addr: AdmittedDial) -> Result<(), ClusterError> {
		self.with_table(|state| {
			let removed = state.discard(addr);
			((), removed)
		})
	}

	/// Record a failed beat dial of a tried peer.
	///
	/// Residents re-verify on every beat, so consecutive failures measure
	/// liveness. The call returns whether it evicted the peer, so the caller
	/// can emit one event per reclaimed peer and withdraw the routes that dial
	/// the address.
	///
	/// - The failure that reaches [`MAX_PEER_TRIED_FAILURES`] evicts the entry.
	/// - Eviction frees the prefix bucket slot for a live candidate.
	/// - The threshold tolerates a transient partition.
	/// - A verified probe resets the count.
	/// - Eviction fails closed: the table shrinks toward its anchors, and discovery refills it.
	/// - An address outside the tried table leaves the table unchanged.
	///
	/// # Sources
	///
	/// - Heilman, Kendler, Zohar & Goldberg (2015), eclipse attacks on
	///   Bitcoin's peer-to-peer network (feeler probes / tried eviction),
	///   USENIX Security '15 and ePrint 2015/263:
	///   - <https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/heilman>
	///   - <https://eprint.iacr.org/2015/263>
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the table lock is poisoned.
	///
	/// [`MAX_PEER_TRIED_FAILURES`]: crate::constants::MAX_PEER_TRIED_FAILURES
	pub fn record_failure(&self, addr: AdmittedDial) -> Result<bool, ClusterError> {
		self.with_table(|state| {
			let evicted = state.record_failure(addr);
			(evicted, evicted)
		})
	}

	/// Remove an address from both learned tables and from the verified
	/// anchors.
	///
	/// A dial that answers with a certificate outside the flood settles the
	/// question at once, where a failed dial may be transient.
	///
	/// - A learned address leaves the beat targets at once, ahead of the failure threshold.
	/// - The beat therefore ends its advertisements to a re-keyed peer.
	/// - A configured anchor keeps its slot and leaves the peer exchange sample.
	/// - A learned address leaves that sample too, although its routes stay.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the table lock is poisoned.
	pub fn expel(&self, addr: AdmittedDial) -> Result<(), ClusterError> {
		// The driver stores learned records alone, so an anchor's removal is
		// no durable change.
		self.with_table(|state| {
			let learned_moved = state.expel(addr);
			((), learned_moved)
		})
	}

	/// Poisons the table lock, as a thread that panicked under the guard
	/// leaves it.
	#[cfg(test)]
	pub(crate) fn poison(&self) {
		self.state.poison();
	}

	/// The dial targets of the advertise and reconcile beat and the gossip
	/// reflood.
	///
	/// - Anchors always lead the set, then verified tried peers.
	/// - A `new` entry joins the set once a probe proved it a flood member.
	/// - An anchor is configured and unproven until its first round, so the
	///   caller proves membership before each reconcile round and each rumor.
	///
	/// The returned targets outlive the table lock, so each beat draws
	/// owned copies. The anchor and tried caps bound the set.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the table lock is poisoned.
	pub fn target_set(&self) -> Result<Vec<AdmittedDial>, ClusterError> {
		let mut learned = self.state.read(TableState::tried_dials)?;
		let mut targets = self.anchors.clone();

		learned.sort();
		targets.extend(learned);

		Ok(targets)
	}

	/// A bounded feeler sample of unverified candidates for this beat.
	///
	/// The sample goes round-robin across prefix buckets, so each prefix draws
	/// its own share of probe capacity. Each bucket prefers the candidate with
	/// the fewest failed probes, then its least recently probed one. The method
	/// stamps each sampled candidate with `now`, so later beats rotate through
	/// the backlog.
	///
	/// - Each draw starts at the prefix after the one the last draw ended on.
	///   The walk therefore reaches every prefix when more prefixes hold a
	///   candidate than one beat probes (CWE-770).
	/// - The sample skips a candidate that failed a probe until its wait has
	///   passed, and its prefix yields the slot meanwhile
	///   ([`PEER_PROBE_BACKOFF_MS`](crate::constants::PEER_PROBE_BACKOFF_MS)).
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the table lock is poisoned.
	pub fn probe_sample(&self, now: UnixMillis) -> Result<Vec<AdmittedDial>, ClusterError> {
		// A probe stamp rotates the backlog within a run. The next durable
		// change carries whatever stamp is current, so the beat spends no
		// driver write of its own.
		self.with_table(|state| (state.probe_sample(now), false))
	}

	/// A diversity-bucketed sample of verified peers to share over PEX.
	///
	/// - The shareable set is tried peers plus probe-verified anchors.
	/// - A draw goes round-robin across prefix buckets up to `cap`, so the
	///   shared view spans prefixes in proportion to what each holds.
	/// - Each draw starts at the prefix after the one the last draw ended on,
	///   so successive replies walk every prefix.
	///
	/// The sample holds probe-verified peers alone, because a forwarded
	/// unverified hint would launder it with this gateway's reputation.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the table lock is poisoned.
	pub fn sample_for_pex(&self, cap: usize) -> Result<Vec<PeerRecord>, ClusterError> {
		// The cursor orders successive replies within a run, so the draw
		// spends no driver write.
		self.with_table(|state| (state.pex_sample(cap), false))
	}

	/// The sockets among `advertised` that this table still holds.
	///
	/// Peer exchange shares a route's address on the word of the member that
	/// advertised it, and the table learned that address as a hint. The table
	/// holds it as a candidate, a tried peer, or a verified anchor until
	/// [`Self::expel`] removes it. A route outlives that expel, so this answer
	/// keeps an expelled address out of the sample (CWE-668).
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the table lock is poisoned.
	pub(in crate::colony::cluster) fn held_among(
		&self,
		advertised: impl IntoIterator<Item = PeerAddress>,
	) -> Result<HashSet<PeerAddress>, ClusterError> {
		self.state.read(|state| state.held_among(advertised))
	}

	/// The current learned sizes, as `(new, tried)`, for operators and tests.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the table lock is poisoned.
	pub fn learned(&self) -> Result<(usize, usize), ClusterError> {
		self.state.read(TableState::learned)
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
			state.exclude(addr);
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

		self.state.read(TableState::has_tried)
	}

	/// Applies `change` under the table guard, then writes the snapshot it
	/// asked for.
	///
	/// `change` returns its outcome and whether the learned tables moved.
	///
	/// # Writes
	///
	/// - Every mutation routes through here, so the decision to write lives in one place.
	/// - The method releases the guard before the pluggable driver runs, so a
	///   driver that blocks delays no other caller (CWE-667).
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
	/// driver in generation order. The method drops a snapshot that a newer
	/// generation already superseded, so an evicted peer stays out of the next
	/// hydrate. The gate guards one integer, which no panic can half-write, so
	/// the method recovers a poisoned gate and writes.
	fn persist_at(&self, generation: u64, records: impl AsRef<[PeerRecord]>) {
		let records = records.as_ref();
		let mut persisted = self.persisted.lock().unwrap_or_else(PoisonError::into_inner);

		if generation <= *persisted {
			return;
		}

		// Persistence is advisory: the in-memory table stays authoritative
		// and the next mutation writes again, so the beat proceeds through a
		// driver fault.
		let _ = self.store.persist(records);
		*persisted = generation;
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::constants::{
		MAX_PEER_BUCKET, MAX_PEER_TRIED_FAILURES, PEER_PROBE_BACKOFF_MAX_MS, PEER_PROBE_BACKOFF_MS, PEER_PROBE_PER_BEAT,
	};
	use crate::tb_cases;
	use core::num::NonZeroUsize;
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
		let admitted = table.learn(vec![hint("127.0.0.1:9000"), hint("10.0.0.1:9000")], UnixMillis::default())?;
		assert_eq!(admitted, 1);
		assert_eq!(table.learned()?, (1, 0));
		Ok(())
	}

	#[test]
	// A hint always carries an address the dial policy admitted, so a duplicate
	// is the one refusal left for `learn` to apply here.
	fn learn_drops_duplicate_hints() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		let admitted = table.learn(vec![hint("10.0.0.1:9000"), hint("10.0.0.1:9000")], UnixMillis::default())?;
		assert_eq!(admitted, 1);
		Ok(())
	}

	#[test]
	fn learn_caps_one_prefix_bucket() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		let hints: Vec<PeerHint> = (0..MAX_PEER_BUCKET + 3)
			.map(|host| hint(format!("10.0.0.{}:9000", host + 1)))
			.collect();
		let admitted = table.learn(hints, UnixMillis::default())?;
		assert_eq!(admitted, MAX_PEER_BUCKET);
		Ok(())
	}

	#[test]
	fn promote_moves_candidate_into_tried_once() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.learn(vec![hint("10.0.0.1:9000")], UnixMillis::default())?;

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

		table.learn(vec![hint("10.0.9.9:9000")], UnixMillis::default())?;

		let promoted = table.promote(addr("10.0.9.9:9000"), None, UnixMillis::new(2_000))?;
		assert!(!promoted);
		assert_eq!(table.learned()?, (1, MAX_PEER_BUCKET));
		Ok(())
	}

	/// A table that lets one signer hold `cap` tried entries.
	fn table_capping_signers(cap: usize) -> PeerTable {
		table_capping_signers_over(cap, Arc::new(MemoryPeerStore))
	}

	/// Builds the table of [`table_capping_signers`], hydrated from `store`.
	fn table_capping_signers_over(cap: usize, store: Arc<dyn PeerStore>) -> PeerTable {
		let peer = PeerConfig { tried_per_signer: NonZeroUsize::new(cap), ..Default::default() };
		PeerTable::new(&peer, store)
	}

	/// A persisted tried record of `text` under `signer`.
	fn tried_record_of(text: impl AsRef<str>, signer: &[u8]) -> PeerRecord {
		PeerRecord { peer_id: Some(signer.to_vec()), ..record(text, true) }
	}

	/// Promotes three addresses, the first two under one signer, and answers
	/// which promotions `table` made.
	fn promotions_of_two_signers(table: &PeerTable) -> [bool; 3] {
		let now = UnixMillis::new(1_000);
		let promote = |text: &str, signer: &[u8]| table.promote(addr(text), Some(signer), now);

		[
			promote("10.0.0.1:9000", b"signer-a"),
			promote("10.1.0.1:9000", b"signer-a"),
			promote("10.2.0.1:9000", b"signer-b"),
		]
		.map(|promoted| promoted.expect("a fresh table lock is not poisoned"))
	}

	#[test]
	fn promote_holds_a_signer_at_its_cap_back() {
		let table = table_capping_signers(1);
		assert_eq!(promotions_of_two_signers(&table), [true, false, true]);
	}

	// The store holds two tried peers of one signer, as a run with no cap
	// leaves it. The operator then sets a cap of one.
	#[test]
	fn hydration_holds_a_signer_to_its_cap() -> Result<(), ClusterError> {
		let seed = [
			tried_record_of("10.0.0.1:9000", b"signer-a"),
			tried_record_of("10.1.0.1:9000", b"signer-a"),
		];
		let table = table_capping_signers_over(1, Arc::new(CountingStore::seeded(seed)));
		assert_eq!(table.learned()?, (0, 1));
		Ok(())
	}

	// Two signers hold one slot each, which is the cap. The second address
	// then answers as the first signer.
	#[test]
	fn a_resident_that_answers_as_a_signer_at_its_cap_gives_up_its_slot() -> Result<(), ClusterError> {
		let table = table_capping_signers(1);
		let now = UnixMillis::new(1_000);
		table.promote(addr("10.0.0.1:9000"), Some(b"signer-a"), now)?;
		table.promote(addr("10.1.0.1:9000"), Some(b"signer-b"), now)?;

		let promoted = table.promote(addr("10.1.0.1:9000"), Some(b"signer-a"), now)?;
		assert!(!promoted);
		assert_eq!(table.target_set()?, vec![addr("10.0.0.1:9000")]);
		assert_eq!(table.learned()?, (1, 1));
		Ok(())
	}

	// A resident with a reissued certificate answers as a signer outside the
	// table's count. It keeps its slot, and it is no new discovery.
	#[test]
	fn a_resident_keeps_its_slot_under_a_signer_below_its_cap() -> Result<(), ClusterError> {
		let table = table_capping_signers(1);
		let now = UnixMillis::new(1_000);

		table.promote(addr("10.0.0.1:9000"), Some(b"signer-a"), now)?;

		let promoted = table.promote(addr("10.0.0.1:9000"), Some(b"signer-b"), now)?;
		assert!(!promoted);
		assert_eq!(table.learned()?, (0, 1));
		Ok(())
	}

	// The resident holds the one slot its signer may have, and its next
	// verified probe must not count that slot against it.
	#[test]
	fn a_resident_at_its_cap_keeps_its_slot_when_it_answers_again() -> Result<(), ClusterError> {
		let table = table_capping_signers(1);
		table.promote(addr("10.0.0.1:9000"), Some(b"signer-a"), UnixMillis::new(1_000))?;

		let promoted = table.promote(addr("10.0.0.1:9000"), Some(b"signer-a"), UnixMillis::new(2_000))?;
		assert!(!promoted);
		assert_eq!(table.learned()?, (0, 1));
		Ok(())
	}

	#[test]
	fn promote_sets_no_cap_by_default() {
		let table = PeerTable::default();
		assert_eq!(promotions_of_two_signers(&table), [true, true, true]);
	}

	#[test]
	fn exclude_self_blocks_learning_own_address() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.exclude_self(PeerAddress::fixture("10.0.0.1:9000"))?;

		let admitted = table.learn(vec![hint("10.0.0.1:9000")], UnixMillis::default())?;
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
		table.learn(vec![hint("10.0.0.1:9000")], UnixMillis::default())?;
		table.promote(addr("10.1.0.1:9000"), None, UnixMillis::new(1_000))?;

		table.exclude_self(PeerAddress::fixture("10.0.0.1:9000"))?;
		table.exclude_self(PeerAddress::fixture("10.1.0.1:9000"))?;

		assert_eq!(table.learned()?, (0, 0));
		Ok(())
	}

	#[test]
	fn discard_prunes_only_the_new_table() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.learn(vec![hint("10.0.0.1:9000")], UnixMillis::default())?;
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
	fn record_probe_failure_keeps_the_candidate_in_new() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.learn(vec![hint("10.0.0.1:9000")], UnixMillis::default())?;

		table.record_probe_failure(addr("10.0.0.1:9000"), UnixMillis::new(1_000))?;
		let relearned = table.learn(vec![hint("10.0.0.1:9000")], UnixMillis::default())?;

		assert_eq!(relearned, 0);
		assert_eq!(table.learned()?, (1, 0));
		Ok(())
	}

	// The failed candidate carries the older stamp, so the stamp alone would
	// draw it first.
	#[test]
	fn probe_sample_draws_a_failed_candidate_after_a_fresher_one() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.learn(vec![hint("10.0.0.1:9000"), hint("10.0.0.2:9000")], UnixMillis::default())?;
		table.probe_sample(UnixMillis::new(2_000))?;
		table.record_probe_failure(addr("10.0.0.1:9000"), UnixMillis::new(1_000))?;

		let sample = table.probe_sample(UnixMillis::new(3_000))?;
		assert_eq!(sample, vec![addr("10.0.0.2:9000"), addr("10.0.0.1:9000")]);
		Ok(())
	}

	/// A table whose `10.0.0.0/16` bucket is full of untested candidates.
	fn table_with_a_full_bucket() -> PeerTable {
		let table = PeerTable::default();
		let residents: Vec<PeerHint> = (1..=MAX_PEER_BUCKET).map(|host| hint(format!("10.0.0.{host}:9000"))).collect();
		let learned = table.learn(residents, UnixMillis::default());
		learned.expect("a fresh table lock is not poisoned");

		table
	}

	#[test]
	fn a_full_bucket_refuses_a_newcomer_while_no_candidate_has_failed() -> Result<(), ClusterError> {
		let table = table_with_a_full_bucket();
		let admitted = table.learn(vec![hint("10.0.0.200:9000")], UnixMillis::default())?;
		assert_eq!(admitted, 0);
		Ok(())
	}

	// The table admits the failed address again at the end, which it can do
	// only if the newcomer took its slot.
	#[test]
	fn a_full_bucket_gives_the_slot_of_a_failed_candidate_to_a_newcomer() -> Result<(), ClusterError> {
		let table = table_with_a_full_bucket();
		table.record_probe_failure(addr("10.0.0.3:9000"), UnixMillis::new(1_000))?;

		let newcomer = table.learn(vec![hint("10.0.0.200:9000")], UnixMillis::default())?;
		table.record_probe_failure(addr("10.0.0.5:9000"), UnixMillis::new(2_000))?;

		let returned = table.learn(vec![hint("10.0.0.3:9000")], UnixMillis::default())?;
		assert_eq!((newcomer, returned), (1, 1));
		assert_eq!(table.learned()?, (MAX_PEER_BUCKET, 0));
		Ok(())
	}

	#[test]
	fn expel_clears_both_learned_tables() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.learn(vec![hint("10.0.0.1:9000")], UnixMillis::default())?;
		table.promote(addr("10.1.0.1:9000"), None, UnixMillis::new(1_000))?;
		table.expel(addr("10.0.0.1:9000"))?;
		table.expel(addr("10.1.0.1:9000"))?;
		assert_eq!(table.learned()?, (0, 0));
		Ok(())
	}

	#[test]
	fn expel_takes_a_verified_anchor_out_of_the_pex_sample() -> Result<(), ClusterError> {
		let table = table_with_anchor("127.0.0.1:9000");
		table.promote(addr("127.0.0.1:9000"), Some(b"fp-a"), UnixMillis::new(1_000))?;
		table.expel(addr("127.0.0.1:9000"))?;
		assert!(table.sample_for_pex(8)?.is_empty());
		assert_eq!(table.target_set()?, vec![addr("127.0.0.1:9000")]);
		Ok(())
	}

	#[test]
	fn target_set_leads_with_anchors_and_hides_new() -> Result<(), ClusterError> {
		let table = table_with_anchor("127.0.0.1:9000");
		table.learn(vec![hint("10.0.0.1:9000")], UnixMillis::default())?;
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

		table.learn(crowded, UnixMillis::default())?;
		table.learn(vec![hint("10.1.0.1:9000")], UnixMillis::default())?;

		let sample = table.probe_sample(UnixMillis::new(1_000))?;
		assert_eq!(sample.len(), PEER_PROBE_PER_BEAT);
		assert!(sample.contains(&addr("10.1.0.1:9000")));
		Ok(())
	}

	#[test]
	fn probe_sample_rotates_through_backlog() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.learn(vec![hint("10.0.0.1:9000"), hint("10.1.0.1:9000")], UnixMillis::default())?;

		let first = table.probe_sample(UnixMillis::new(1_000))?;
		let second = table.probe_sample(UnixMillis::new(2_000))?;
		assert_eq!(first.len(), 2);
		assert_eq!(second.len(), 2);
		Ok(())
	}

	/// A table that holds one candidate in each of `prefixes` prefix buckets,
	/// from `10.0.0.1` upward.
	fn table_with_a_candidate_per_prefix(prefixes: usize) -> PeerTable {
		let table = PeerTable::default();
		let hints: Vec<PeerHint> = (0..prefixes).map(|prefix| hint(format!("10.{prefix}.0.1:9000"))).collect();
		let learned = table.learn(hints, UnixMillis::default());
		learned.expect("a fresh table lock is not poisoned");
		table
	}

	// One more prefix holds a candidate than a beat can probe. A walk that
	// always starts at the lowest prefix never reaches the last one.
	#[test]
	fn probe_sample_starts_after_the_last_prefix_it_served() -> Result<(), ClusterError> {
		let table = table_with_a_candidate_per_prefix(PEER_PROBE_PER_BEAT + 1);
		table.probe_sample(UnixMillis::new(1_000))?;

		let last_prefix = addr(format!("10.{PEER_PROBE_PER_BEAT}.0.1:9000"));
		let second = table.probe_sample(UnixMillis::new(2_000))?;
		assert_eq!(second.first(), Some(&last_prefix));
		Ok(())
	}

	/// Records one failed probe at `now` on the candidate of each of the lowest
	/// `prefixes` prefixes of [`table_with_a_candidate_per_prefix`].
	fn fail_lowest_prefixes(table: &PeerTable, prefixes: usize, now: UnixMillis) {
		for prefix in 0..prefixes {
			let failed = table.record_probe_failure(addr(format!("10.{prefix}.0.1:9000")), now);
			failed.expect("a fresh table lock is not poisoned");
		}
	}

	// The sample skips the candidate one millisecond before its wait ends.
	#[test]
	fn probe_sample_skips_a_failed_candidate_until_its_wait_has_passed() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.learn(vec![hint("10.0.0.1:9000")], UnixMillis::default())?;
		table.record_probe_failure(addr("10.0.0.1:9000"), UnixMillis::new(10_000))?;

		let early = table.probe_sample(UnixMillis::new(10_000 + PEER_PROBE_BACKOFF_MS - 1))?;
		let due = table.probe_sample(UnixMillis::new(10_000 + PEER_PROBE_BACKOFF_MS))?;
		assert!(early.is_empty());
		assert_eq!(due, vec![addr("10.0.0.1:9000")]);
		Ok(())
	}

	// Dead addresses fill the lowest prefixes, as many as a beat probes. While
	// they wait, the one live prefix above them takes the probe.
	#[test]
	fn waiting_candidates_yield_their_slots_to_another_prefix() -> Result<(), ClusterError> {
		let table = table_with_a_candidate_per_prefix(PEER_PROBE_PER_BEAT + 1);
		let live_prefix = addr(format!("10.{PEER_PROBE_PER_BEAT}.0.1:9000"));
		fail_lowest_prefixes(&table, PEER_PROBE_PER_BEAT, UnixMillis::new(10_000));

		let sample = table.probe_sample(UnixMillis::new(10_000 + PEER_PROBE_BACKOFF_MS - 1))?;
		assert_eq!(sample, vec![live_prefix]);
		Ok(())
	}

	tb_cases! {
		fn a_failed_probe_doubles_the_wait_up_to_its_ceiling((failures, waited_ms, due): (usize, u64, bool)) {
			let entry = PeerEntry { peer_id: None, last_probe: UnixMillis::new(1_000_000), failures };
			let now = UnixMillis::new(1_000_000 + waited_ms);
			assert_eq!(entry.probe_due(now), due);
		}
		cases {
			never_failed => (0, 0, true),
			one_failure_early => (1, PEER_PROBE_BACKOFF_MS - 1, false),
			one_failure_due => (1, PEER_PROBE_BACKOFF_MS, true),
			two_failures_early => (2, 2 * PEER_PROBE_BACKOFF_MS - 1, false),
			two_failures_due => (2, 2 * PEER_PROBE_BACKOFF_MS, true),
			ceiling_early => (usize::MAX, PEER_PROBE_BACKOFF_MAX_MS - 1, false),
			ceiling_due => (usize::MAX, PEER_PROBE_BACKOFF_MAX_MS, true),
		}
	}

	// The last probe stamp lies after `now`, as a backward clock step leaves
	// it.
	#[test]
	fn a_backward_clock_step_does_not_hold_a_failed_candidate_out() {
		let entry = PeerEntry { peer_id: None, last_probe: UnixMillis::new(1_000_000), failures: 1 };
		assert!(entry.probe_due(UnixMillis::new(1_000_000 - PEER_PROBE_BACKOFF_MS)));
	}

	// The anchor is configured and no beat has verified it, so the table holds
	// no entry for it. The table never learned the last address.
	#[test]
	fn held_among_keeps_what_the_table_holds_and_drops_what_it_expelled() -> Result<(), ClusterError> {
		let table = table_with_anchor("127.0.0.1:9000");
		table.learn(vec![hint("10.0.0.1:9000"), hint("10.0.0.2:9000")], UnixMillis::default())?;
		table.promote(addr("10.1.0.1:9000"), None, UnixMillis::new(1_000))?;
		table.expel(addr("10.0.0.2:9000"))?;

		let advertised = [
			"10.0.0.1:9000",
			"10.0.0.2:9000",
			"10.1.0.1:9000",
			"127.0.0.1:9000",
			"10.9.0.1:9000",
		];

		let held = table.held_among(advertised.map(PeerAddress::fixture))?;
		let expected = HashSet::from([PeerAddress::fixture("10.0.0.1:9000"), PeerAddress::fixture("10.1.0.1:9000")]);
		assert_eq!(held, expected);
		Ok(())
	}

	// The same walk serves peer exchange, so a second reply starts where the
	// first one stopped.
	#[test]
	fn sample_for_pex_starts_after_the_last_prefix_it_served() -> Result<(), ClusterError> {
		let table = PeerTable::default();
		table.promote(addr("10.0.0.1:9000"), Some(b"fp-a"), UnixMillis::new(1_000))?;
		table.promote(addr("10.1.0.1:9000"), Some(b"fp-b"), UnixMillis::new(1_000))?;
		table.promote(addr("10.2.0.1:9000"), Some(b"fp-c"), UnixMillis::new(1_000))?;
		table.sample_for_pex(2)?;

		let second = table.sample_for_pex(2)?;
		let addrs: Vec<PeerAddress> = second.iter().map(|record| record.gateway_addr).collect();
		let wrapped = vec![PeerAddress::fixture("10.2.0.1:9000"), PeerAddress::fixture("10.0.0.1:9000")];
		assert_eq!(addrs, wrapped);
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
		table.learn(vec![hint("10.0.0.1:9000")], UnixMillis::default())?;

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

	// Hydration drops a record the current dial policy refuses, so a policy
	// the operator tightened between runs binds the persisted peers too.
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

		table.learn(vec![hint("10.0.0.1:9000")], UnixMillis::default())?;
		table.promote(addr("10.0.0.1:9000"), None, UnixMillis::new(1_000))?;
		assert_eq!(store.persists.load(Ordering::SeqCst), 2);
		Ok(())
	}

	/// A driver that stalls its first write until the test releases it, and
	/// records the row count each snapshot carried.
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
	/// driver's rows only ever grow. A stale snapshot that lands after a newer
	/// one would hydrate peers a later mutation removed (CWE-362).
	///
	/// The first write stalls inside the driver while a second mutation
	/// runs, which is the interleaving that reorders unguarded writes.
	#[test]
	fn driver_writes_land_in_generation_order() -> Result<(), ClusterError> {
		let store = Arc::new(StallingStore::default());
		let table = Arc::new(table_over(Arc::clone(&store) as Arc<dyn PeerStore>));
		let first = Arc::clone(&table);
		let stalled = std::thread::spawn(move || first.learn(vec![hint("10.1.0.1:9000")], UnixMillis::default()));

		store.await_first_write();

		let second = Arc::clone(&table);
		let follower = std::thread::spawn(move || second.learn(vec![hint("10.2.0.1:9000")], UnixMillis::default()));

		std::thread::sleep(Duration::from_millis(50));
		store.release();
		stalled.join().expect("thread joins")?;
		follower.join().expect("thread joins")?;

		let widths = store.widths.lock().expect("driver handle").clone();
		assert!(widths.windows(2).all(|pair| pair[0] <= pair[1]));
		assert_eq!(widths.last().copied(), Some(2));

		Ok(())
	}

	/// A driver that reaches back into the table while the table writes to
	/// it.
	///
	/// The write runs after the table releases its guard, so this re-entry
	/// reads the table that called it (CWE-667).
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
		table.learn(vec![hint("10.1.0.1:9000")], UnixMillis::default())?;

		assert_eq!(store.observed.load(Ordering::SeqCst), 1);
		Ok(())
	}
}
