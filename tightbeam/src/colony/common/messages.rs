//! Protocol messages for cluster-hive communication
//!
//! All message types used in the protocol between cluster and hive.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "x509")]
use crate::asn1::Frame;
use crate::constants::DEFAULT_HOP_BUDGET;
use crate::der::{Choice, Enumerated, Sequence};
use crate::policy::TransitStatus;
use crate::utils::urn::Urn;
use crate::utils::BasisPoints;
use crate::wire::wire_sequence;
use crate::Beamable;

// =============================================================================
// Cluster Inbound Protocol
// =============================================================================

/// Work request envelope for cluster routing
///
/// Clients send this to the cluster gateway. The gateway selects a local
/// servlet or peer gateway by `servlet_type`, then delivers `payload`.
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct ClusterWorkRequest {
	/// Target servlet type URN (e.g., `urn:tightbeam::servlet:ping`)
	pub servlet_type: Urn<'static>,
	/// Raw message payload (encoded inner message)
	pub payload: Vec<u8>,
	/// Relay budget: how many gateway forwards this work may still spend
	///
	/// A client origin stamps the [`DEFAULT_HOP_BUDGET`] sentinel
	/// ([`ClusterWorkRequest::new`]), which defers the budget to
	/// gateway policy. Each gateway clamps the inbound value to its
	/// own `max_hops`, so one clamp rule covers the origin sentinel
	/// and a relayed value. A gateway that selects a peer route
	/// re-emits with the clamped budget decremented
	/// ([`ClusterWorkRequest::into_relayed`]). An inbound `0` is
	/// served locally only and never re-forwarded.
	pub hops_remaining: u8,
}

wire_sequence!(ClusterWorkRequest {
	servlet_type: plain,
	payload: octets,
	hops_remaining: default(DEFAULT_HOP_BUDGET),
});

impl ClusterWorkRequest {
	/// Origin work from a client: the sentinel budget defers the hop
	/// cap to the first gateway's `max_hops` policy.
	///
	/// `payload` accepts any value convertible into [`Vec<u8>`].
	#[must_use]
	pub fn new(servlet_type: Urn<'static>, payload: impl Into<Vec<u8>>) -> Self {
		Self { servlet_type, payload: payload.into(), hops_remaining: DEFAULT_HOP_BUDGET }
	}

	/// Re-emit toward a peer with the remaining relay budget. A `0`
	/// budget is the terminal hop: the receiver serves locally only.
	#[must_use]
	pub fn into_relayed(mut self, hops_remaining: u8) -> Self {
		self.hops_remaining = hops_remaining;
		self
	}
}

/// Work response from cluster
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct ClusterWorkResponse {
	/// Status of the routing/execution
	pub status: TransitStatus,
	/// Response payload from servlet (if successful)
	pub payload: Option<Vec<u8>>,
}

wire_sequence!(ClusterWorkResponse { status: plain, payload: octets_opt });

impl ClusterWorkResponse {
	/// Create a successful response with payload.
	///
	/// `payload` accepts any value convertible into [`Vec<u8>`].
	#[inline]
	pub fn ok(payload: impl Into<Vec<u8>>) -> Self {
		Self { status: TransitStatus::Ok, payload: Some(payload.into()) }
	}

	/// Create an error response with status
	#[inline]
	pub fn err(status: TransitStatus) -> Self {
		Self { status, payload: None }
	}
}

/// Inbound message envelope for the cluster gateway - ASN.1 CHOICE.
///
/// Every frame sent to a cluster carries exactly one of these variants.
/// The context-specific tag discriminates the type on the wire, so the
/// gateway decodes once and matches.
#[derive(Debug, Beamable, Choice, Clone, PartialEq)]
pub enum ClusterRequest {
	/// Hive announcing its servlets [context 0]
	#[asn1(context_specific = "0", constructed = "true")]
	RegisterHive(RegisterHiveRequest),
	/// Hive scaling notification [context 1]
	#[asn1(context_specific = "1", constructed = "true")]
	ServletAddressUpdate(ServletAddressUpdate),
	/// Client work submission [context 2]
	#[asn1(context_specific = "2", constructed = "true")]
	Work(ClusterWorkRequest),
	/// Peer gateway advertising exported servlet types [context 3]
	#[asn1(context_specific = "3", constructed = "true")]
	AdvertisePeer(PeerAdvertisement),
	/// Relayed origin-signed rumor frame from a peer gateway [context 4]
	///
	/// Boxed because a nested [`Frame`] is far larger than the other
	/// variants. The wire encoding is unchanged.
	#[cfg(feature = "x509")]
	#[asn1(context_specific = "4", constructed = "true")]
	Gossip(Box<Frame>),
	/// Origin gossip rumor from a local publisher [context 5]
	#[cfg(feature = "x509")]
	#[asn1(context_specific = "5", constructed = "true")]
	PublishGossip(GossipRumor),
	/// Anti-entropy digest summary from a peer gateway [context 6]
	#[cfg(feature = "x509")]
	#[asn1(context_specific = "6", constructed = "true")]
	ReconcileGossip(GossipReconciliation),
}

// =============================================================================
// Hive Registration Messages
// =============================================================================

/// Message type for registering a hive with a cluster
///
/// This message is sent from a hive to a cluster controller to announce
/// its availability and capabilities, including actual servlet addresses.
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct RegisterHiveRequest {
	/// The address where this hive can be reached (for heartbeats)
	pub hive_addr: Vec<u8>,
	/// Servlet type-to-address mappings for direct routing
	pub servlet_addresses: Vec<ServletInfo>,
	/// Optional metadata about the hive
	pub metadata: Option<Vec<u8>>,
}

wire_sequence!(RegisterHiveRequest { hive_addr: octets, servlet_addresses: plain, metadata: octets_opt });

/// Response message for hive registration
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct RegisterHiveResponse {
	/// The status of the registration request
	pub status: TransitStatus,
	/// Cluster-assigned hive identity URN (e.g., `urn:tightbeam::hive:10.0.0.5:9000`)
	pub hive_id: Option<Urn<'static>>,
}

/// Notification from hive to cluster about servlet address changes
///
/// Sent by hives when auto-scaling spawns or stops servlet instances.
/// Enables push-based cluster registry updates.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ServletAddressUpdate {
	/// Hive identity URN (matches the identity assigned at registration)
	pub hive_id: Urn<'static>,
	/// Newly spawned servlet addresses
	pub added: Vec<ServletInfo>,
	/// Removed servlet instance URNs. Instance identities travel in
	/// both directions of an update, matching `added`.
	pub removed: Vec<Urn<'static>>,
}

/// Response to servlet address update notification
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ServletAddressUpdateResponse {
	/// Status of the update (Ok = success)
	pub status: TransitStatus,
}

// =============================================================================
// Peer Federation Messages
// =============================================================================

/// A peer gateway advertising the servlet types its colony exports.
///
/// Sent gateway-to-gateway so a receiving colony can learn which types a
/// peer serves and forward work there. Carries only type URNs (never
/// instance addresses): the peer is reached at `gateway_addr`, which
/// resolves the whole peer colony rather than a single servlet.
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct PeerAdvertisement {
	/// Address peers dial to reach the advertising gateway
	pub gateway_addr: Vec<u8>,
	/// Servlet type URNs the advertising colony exports
	pub advertised_types: Vec<Urn<'static>>,
}

wire_sequence!(PeerAdvertisement { gateway_addr: octets, advertised_types: plain });

/// Response to a peer advertisement
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct PeerAdvertisementResponse {
	/// Status of the advertisement (Ok = installed)
	pub status: TransitStatus,
}

/// How a receiving gateway consumes an admitted rumor payload.
///
/// The kind travels inside the signed rumor body, so a relay cannot
/// reinterpret an application payload as routing control.
#[derive(Enumerated, Default, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GossipRumorKind {
	/// Opaque application payload delivered through the ingress policy.
	#[default]
	Application = 0,
	/// Origin-signed peer advertisement frame bytes, applied to the
	/// receiving gateway's peer routing state for transitive discovery.
	PeerAdvertisement = 1,
}

/// The signed content of one gossip rumor: its opaque payload.
///
/// This one structure serves both gossip roles. A publisher sends it as
/// [`ClusterRequest::PublishGossip`] to request a flood. The accepting
/// origin gateway then embeds the identical DER bytes as the `message` of
/// a rumor [`Frame`] it signs with its cluster key, so the payload is
/// bound under the origin signature at every later hop (see §5.7.5:
/// the signature covers version, metadata, and message).
///
/// The rumor names no destination. Flood scope is colony membership,
/// carried in the origin certificate's colony URN SAN and never in rumor
/// bytes: unsigned scope bytes would be weaker than the certificate
/// binding (CWE-345). Local delivery is receiving-gateway policy, the
/// optional gossip ingress servlet type.
///
/// The rumor frame's `metadata.id` is the rumor identity and its
/// `metadata.order` is the issue time in unix milliseconds (§5.7.1 permits
/// a time-based order), both copied from the publish frame. Hop state such
/// as the remaining flood radius MUST stay outside the rumor frame: it
/// travels in the `metadata.lifetime` of the outer relay frame, which each
/// relay rebuilds and re-signs.
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct GossipRumor {
	/// Opaque application payload delivered through the ingress policy.
	pub payload: Vec<u8>,
	/// How the receiving gateway consumes `payload`. The common
	/// application kind is the DER DEFAULT, so it is omitted on the
	/// wire.
	pub kind: GossipRumorKind,
}

wire_sequence!(GossipRumor { payload: octets, kind: default(GossipRumorKind::Application) });

impl GossipRumor {
	/// Application rumor delivered through the ingress policy.
	///
	/// `payload` accepts any value convertible into [`Vec<u8>`].
	#[must_use]
	pub fn application(payload: impl Into<Vec<u8>>) -> Self {
		Self { payload: payload.into(), kind: GossipRumorKind::Application }
	}

	/// Advertisement rumor carrying an origin-signed ad frame's DER
	/// bytes for transitive peer discovery.
	///
	/// `ad_frame` accepts any value convertible into [`Vec<u8>`].
	#[must_use]
	pub fn peer_advertisement(ad_frame: impl Into<Vec<u8>>) -> Self {
		Self { payload: ad_frame.into(), kind: GossipRumorKind::PeerAdvertisement }
	}
}

/// Response to a gossip rumor
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct GossipResponse {
	/// Status of the rumor (Ok = accepted, delivered, and considered for reflood)
	pub status: TransitStatus,
}

/// Summary of rumors a gateway retains, sent so a peer can pull missing ones.
///
/// This is the anti-entropy backstop to best-effort flooding.
/// Reconciliation is a set difference over content digests.
/// There is no cursor or ordering.
/// A receiver refuses a wrong-length entry rather than treating it as a digest (CWE-20).
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct GossipReconciliation {
	/// Content digests the sender currently retains.
	pub held: Vec<Vec<u8>>,
}

wire_sequence!(GossipReconciliation { held: octets_seq });

/// One peer shared over peer exchange: an identity and where to dial it.
///
/// A sharer only exchanges peers it verified itself, yet the entry is
/// still an unverified hint to its receiver: admission is bounded per
/// address prefix, and only a probe dial whose handshake certificate
/// proves the local colony makes the peer a dial target. The
/// fingerprint is advisory identity for deduplication, and trust never
/// derives from exchanged bytes (CWE-345).
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct PeerGossip {
	/// Certificate fingerprint the sharer verified the peer under.
	pub peer_id: Vec<u8>,
	/// Address the peer gateway was dialed at.
	pub gateway_addr: Vec<u8>,
}

wire_sequence!(PeerGossip { peer_id: octets, gateway_addr: octets });

/// Reply to a [`GossipReconciliation`]: digests the peer lacks and wants as `Gossip` rumors.
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct GossipWant {
	/// Content digests the replier lacks and is requesting.
	pub want: Vec<Vec<u8>>,
	/// Peer-exchange sample: verified peers the replier shares so a
	/// seed-bootstrapped requester can discover the colony graph.
	/// Capped at `MAX_PEX_SAMPLE` in both directions.
	pub pex: Vec<PeerGossip>,
}

wire_sequence!(GossipWant { want: octets_seq, pex: plain });

// =============================================================================
// Servlet Activation Messages
// =============================================================================

/// Message type for activating a servlet on a hive
///
/// This message is sent from a cluster controller to a hive to instruct
/// it to morph into a specific servlet configuration.
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct ActivateServletRequest {
	/// Instance URN of the servlet to activate
	pub servlet_id: Urn<'static>,
	/// Optional configuration data for the servlet
	pub config: Option<Vec<u8>>,
}

wire_sequence!(ActivateServletRequest { servlet_id: plain, config: octets_opt });

/// Response message for servlet activation
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct ActivateServletResponse {
	/// The status of the activation request
	pub status: TransitStatus,
	/// The address of the activated servlet (if successful)
	pub servlet_address: Option<Vec<u8>>,
}

wire_sequence!(ActivateServletResponse { status: plain, servlet_address: octets_opt });

impl ActivateServletResponse {
	/// Create a successful activation response
	#[inline]
	pub fn ok(address: Vec<u8>) -> Self {
		Self { status: TransitStatus::Ok, servlet_address: Some(address) }
	}

	/// Create a failed activation response
	#[inline]
	pub fn err(status: TransitStatus) -> Self {
		Self { status, servlet_address: None }
	}
}

// =============================================================================
// Servlet Info
// =============================================================================

/// Servlet information entry
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct ServletInfo {
	/// Servlet instance URN (type URN with a `/{addr}` tail)
	pub servlet_id: Urn<'static>,
	/// The servlet's address
	pub address: Vec<u8>,
}

wire_sequence!(ServletInfo { servlet_id: plain, address: octets });

// =============================================================================
// Hive Management Messages
// =============================================================================

/// Hive management request message
///
/// Uses context-specific tags to distinguish between different request types.
/// Only one field should be set per request.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct HiveManagementRequest {
	/// Spawn a new servlet instance [context 0]
	#[asn1(context_specific = "0", optional = "true")]
	pub spawn: Option<SpawnServletParams>,
	/// List all active servlets [context 1]
	#[asn1(context_specific = "1", optional = "true")]
	pub list: Option<ListServletsParams>,
	/// Stop a specific servlet instance [context 2]
	#[asn1(context_specific = "2", optional = "true")]
	pub stop: Option<StopServletParams>,
}

/// Parameters for spawning a new servlet
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct SpawnServletParams {
	/// Type URN of the servlet to spawn (e.g., `urn:tightbeam::servlet:worker`)
	pub servlet_type: Urn<'static>,
	/// Optional configuration data for the servlet
	pub config: Option<Vec<u8>>,
}

wire_sequence!(SpawnServletParams { servlet_type: plain, config: octets_opt });

/// Parameters for listing servlets
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct ListServletsParams {
	/// Optional filter (reserved for future use)
	pub filter: Option<Vec<u8>>,
}

wire_sequence!(ListServletsParams { filter: octets_opt });

/// Parameters for stopping a servlet
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct StopServletParams {
	/// Instance URN of the servlet to stop
	pub servlet_id: Urn<'static>,
}

/// Hive management response message
///
/// Uses context-specific tags to distinguish between different response types.
/// Only one field should be set per response.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct HiveManagementResponse {
	/// Response to spawn request [context 0]
	#[asn1(context_specific = "0", optional = "true")]
	pub spawn: Option<SpawnServletResult>,
	/// Response to list request [context 1]
	#[asn1(context_specific = "1", optional = "true")]
	pub list: Option<ListServletsResult>,
	/// Response to stop request [context 2]
	#[asn1(context_specific = "2", optional = "true")]
	pub stop: Option<StopServletResult>,
}

/// Result of spawning a servlet
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct SpawnServletResult {
	/// The status of the spawn request
	pub status: TransitStatus,
	/// The address of the newly spawned servlet (if successful)
	pub servlet_address: Option<Vec<u8>>,
	/// Instance URN of the spawned servlet (e.g., `urn:tightbeam::servlet:worker/127.0.0.1:8080`)
	pub servlet_id: Option<Urn<'static>>,
}

wire_sequence!(SpawnServletResult { status: plain, servlet_address: octets_opt, servlet_id: plain });

/// Result of listing servlets
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ListServletsResult {
	/// The status of the request
	pub status: TransitStatus,
	/// List of active servlets
	pub servlets: Vec<ServletInfo>,
}

/// Result of stopping a servlet
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct StopServletResult {
	/// The status of the stop request
	pub status: TransitStatus,
}

impl HiveManagementResponse {
	/// Create a spawn success response
	#[inline]
	pub fn spawn_ok(address: Vec<u8>, servlet_id: Urn<'static>) -> Self {
		Self {
			spawn: Some(SpawnServletResult {
				status: TransitStatus::Ok,
				servlet_address: Some(address),
				servlet_id: Some(servlet_id),
			}),
			list: None,
			stop: None,
		}
	}

	/// Create a spawn failure response
	#[inline]
	pub fn spawn_err(status: TransitStatus) -> Self {
		Self {
			spawn: Some(SpawnServletResult { status, servlet_address: None, servlet_id: None }),
			list: None,
			stop: None,
		}
	}

	/// Create a list response
	#[inline]
	pub fn list_ok(servlets: Vec<ServletInfo>) -> Self {
		Self {
			spawn: None,
			list: Some(ListServletsResult { status: TransitStatus::Ok, servlets }),
			stop: None,
		}
	}

	/// Create a stop success response
	#[inline]
	pub fn stop_ok() -> Self {
		Self {
			spawn: None,
			list: None,
			stop: Some(StopServletResult { status: TransitStatus::Ok }),
		}
	}

	/// Create a stop failure response
	#[inline]
	pub fn stop_err(status: TransitStatus) -> Self {
		Self { spawn: None, list: None, stop: Some(StopServletResult { status }) }
	}
}

// =============================================================================
// Cluster Command Protocol
// =============================================================================

/// Status reported by cluster in heartbeat
///
/// Clusters report their current operational status to hives during heartbeat.
/// Hives may use this to adjust their behavior (e.g., reduce capacity during draining).
#[derive(Enumerated, Default, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClusterStatus {
	/// Normal operation
	#[default]
	Healthy = 0,
	/// Partial degradation (some services unavailable)
	Degraded = 1,
	/// Overloaded (high utilization)
	Overloaded = 2,
	/// Draining (preparing for shutdown)
	Draining = 3,
}

/// Cluster command message - ASN.1 CHOICE
///
/// Commands from cluster to hive. Uses context-specific tags for
/// CHOICE discrimination. Only one field should be set per message.
///
/// **Security**: Requires nonrepudiation signature and frame integrity.
/// Frames without proper authentication will be rejected and may trigger
/// the circuit breaker. Freshness binds to `Frame.metadata.order` (unix
/// milliseconds): hives reject commands outside their freshness window
/// and replays of already-seen signatures within it (CWE-294).
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
#[beam(frame_integrity)]
pub struct ClusterCommand {
	/// Heartbeat request [context 0]
	#[asn1(context_specific = "0", optional = "true")]
	pub heartbeat: Option<HeartbeatParams>,

	/// Hive management request [context 1]
	#[asn1(context_specific = "1", optional = "true")]
	pub manage: Option<HiveManagementRequest>,
}

/// Heartbeat parameters
///
/// Minimal payload - identity is established via certificate in the
/// frame's nonrepudiation signature.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct HeartbeatParams {
	/// Cluster's current operational status
	pub cluster_status: ClusterStatus,
}

/// Cluster command response - ASN.1 CHOICE
///
/// Responses from hive to cluster. Uses context-specific tags for
/// CHOICE discrimination. Only one field should be set per response.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ClusterCommandResponse {
	/// Heartbeat response [context 0]
	#[asn1(context_specific = "0", optional = "true")]
	pub heartbeat: Option<HeartbeatResult>,

	/// Management response [context 1]
	#[asn1(context_specific = "1", optional = "true")]
	pub manage: Option<HiveManagementResponse>,
}

/// Heartbeat response with hive health status
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct HeartbeatResult {
	/// Overall status (Ok = healthy, ResourceExhausted = at capacity)
	pub status: TransitStatus,
	/// Current aggregate utilization across all servlets
	pub utilization: BasisPoints,
	/// Number of active servlet instances
	pub active_servlets: u32,
}

// =============================================================================
// Response Builder Helpers
// =============================================================================

impl ClusterCommandResponse {
	/// Create a heartbeat response
	#[inline]
	pub fn heartbeat(status: TransitStatus, utilization: BasisPoints, active_servlets: u32) -> Self {
		Self {
			heartbeat: Some(HeartbeatResult { status, utilization, active_servlets }),
			manage: None,
		}
	}

	/// Create a management response wrapper
	#[inline]
	pub fn manage(response: HiveManagementResponse) -> Self {
		Self { heartbeat: None, manage: Some(response) }
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::colony::common::{servlet_instance, ColonyNamespace};
	use crate::error::Result;

	fn round_trip(original: ClusterRequest) -> Result<()> {
		let encoded = crate::encode(&original)?;
		let decoded: ClusterRequest = crate::decode(&encoded)?;
		assert_eq!(original, decoded);
		Ok(())
	}

	fn ping_type() -> crate::utils::urn::Urn<'static> {
		ColonyNamespace::default()
			.servlet("ping")
			.expect("test names satisfy the mint grammar")
	}

	fn hive_id() -> crate::utils::urn::Urn<'static> {
		ColonyNamespace::default()
			.hive("127.0.0.1:9000")
			.expect("test locators satisfy the mint grammar")
	}

	#[test]
	fn cluster_request_register_hive_round_trips() -> Result<()> {
		round_trip(ClusterRequest::RegisterHive(RegisterHiveRequest {
			hive_addr: b"127.0.0.1:9000".to_vec(),
			servlet_addresses: vec![ServletInfo {
				servlet_id: servlet_instance(&ping_type(), "127.0.0.1:9001"),
				address: b"127.0.0.1:9001".to_vec(),
			}],
			metadata: None,
		}))
	}

	#[test]
	fn cluster_request_servlet_address_update_round_trips() -> Result<()> {
		round_trip(ClusterRequest::ServletAddressUpdate(ServletAddressUpdate {
			hive_id: hive_id(),
			added: vec![],
			removed: vec![servlet_instance(&ping_type(), "127.0.0.1:9100")],
		}))
	}

	#[test]
	fn cluster_request_work_round_trips() -> Result<()> {
		round_trip(ClusterRequest::Work(ClusterWorkRequest::new(
			ping_type(),
			vec![0x02, 0x01, 0x2A],
		)))
	}

	#[test]
	fn cluster_request_advertise_peer_round_trips() -> Result<()> {
		round_trip(ClusterRequest::AdvertisePeer(PeerAdvertisement {
			gateway_addr: b"127.0.0.1:9000".to_vec(),
			advertised_types: vec![ping_type()],
		}))
	}

	#[cfg(feature = "x509")]
	#[test]
	fn cluster_request_gossip_round_trips() -> Result<()> {
		let rumor_body = GossipRumor::application(vec![0x02, 0x01, 0x2A]);
		let rumor = Frame {
			version: crate::asn1::Version::V0,
			metadata: crate::asn1::Metadata {
				id: b"rumor-1".to_vec(),
				order: 1_000,
				compactness: None,
				integrity: None,
				confidentiality: None,
				priority: None,
				lifetime: None,
				previous_frame: None,
				matrix: None,
			},
			message: crate::encode(&rumor_body)?,
			integrity: None,
			nonrepudiation: None,
		};

		round_trip(ClusterRequest::Gossip(Box::new(rumor)))
	}

	#[cfg(feature = "x509")]
	#[test]
	fn cluster_request_publish_gossip_round_trips() -> Result<()> {
		round_trip(ClusterRequest::PublishGossip(GossipRumor::application(vec![0x02, 0x01, 0x2A])))
	}

	#[cfg(feature = "x509")]
	#[test]
	fn cluster_request_reconcile_gossip_round_trips() -> Result<()> {
		round_trip(ClusterRequest::ReconcileGossip(GossipReconciliation {
			held: vec![vec![0xAAu8; 32], vec![0xBBu8; 32]],
		}))
	}

	#[cfg(feature = "x509")]
	#[test]
	fn cluster_request_reconcile_gossip_empty_round_trips() -> Result<()> {
		round_trip(ClusterRequest::ReconcileGossip(GossipReconciliation { held: vec![] }))
	}

	#[test]
	fn gossip_want_round_trips_with_pex() -> Result<()> {
		let original = GossipWant {
			want: vec![vec![0xAAu8; 32]],
			pex: vec![PeerGossip { peer_id: vec![1, 2, 3], gateway_addr: b"127.0.0.1:9100".to_vec() }],
		};
		let encoded = crate::encode(&original)?;
		let decoded: GossipWant = crate::decode(&encoded)?;
		assert_eq!(original, decoded);
		Ok(())
	}

	#[test]
	fn gossip_want_round_trips_empty() -> Result<()> {
		let original = GossipWant { want: vec![], pex: vec![] };
		let encoded = crate::encode(&original)?;
		let decoded: GossipWant = crate::decode(&encoded)?;
		assert_eq!(original, decoded);
		Ok(())
	}

	#[test]
	fn bare_inner_type_rejected_without_envelope_tag() -> Result<()> {
		let bare = crate::encode(&ClusterWorkRequest::new(ping_type(), vec![]))?;
		let decoded = crate::decode::<ClusterRequest>(&bare);
		assert!(decoded.is_err());
		Ok(())
	}
}
