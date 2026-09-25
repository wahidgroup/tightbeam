//! The protocol messages of the colony control and work planes.
//!
//! - [`ClusterRequest`] is the envelope of every frame sent to a cluster
//!   gateway: hive registration, scaling updates, client work, peer
//!   advertisements, and gossip.
//! - [`ClusterCommand`] carries a heartbeat or a management request from a
//!   cluster to a hive, and [`ClusterCommandResponse`] answers it.
//! - [`ReplyShape`] decides the alternative and the priority of a command's reply.

use super::{reply_frame, reply_frame_with_priority};
use crate::asn1::Frame;
use crate::constants::DEFAULT_HOP_BUDGET;
use crate::der::{Choice, Enumerated, Sequence};
use crate::policy::TransitStatus;
use crate::utils::time::UnixMillis;
use crate::utils::urn::Urn;
use crate::utils::{decode, encode, BasisPoints};
use crate::wire::wire_sequence;
use crate::{Beamable, Errorizable, MessagePriority, TightBeamError};

/// The work request envelope for cluster routing.
///
/// Clients send this to the cluster gateway. The gateway selects a local
/// servlet or peer gateway by `servlet_type`, then delivers the client
/// frame in `payload` to the servlet byte-for-byte.
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct ClusterWorkRequest {
	/// The target servlet type URN, such as `urn:tightbeam::servlet:ping`.
	pub servlet_type: Urn<'static>,
	/// The DER bytes of the client's complete end-to-end [`Frame`].
	///
	/// The frame's `message` is the servlet's typed input. Gateways
	/// forward these bytes unmodified, so the client's signature,
	/// integrity, and previous-frame linkage stay verifiable at the
	/// servlet ([`Frame::verify`]).
	pub payload: Vec<u8>,
	/// The relay budget, counting how many gateway forwards this work
	/// may still spend.
	///
	/// - A client origin stamps the [`DEFAULT_HOP_BUDGET`] sentinel through
	///   [`ClusterWorkRequest::new`], so gateway policy decides the budget.
	/// - Each gateway clamps the inbound value to its own `max_hops`, so one
	///   clamp rule covers the origin sentinel and a relayed value.
	/// - A gateway that selects a peer route re-emits with the clamped budget
	///   decremented ([`ClusterWorkRequest::into_relayed`]).
	pub hops_remaining: u8,
}

wire_sequence!(ClusterWorkRequest {
	servlet_type: plain,
	payload: octets,
	hops_remaining: default(DEFAULT_HOP_BUDGET),
});

impl ClusterWorkRequest {
	/// Builds origin work from a client, nesting the client's complete
	/// frame as the end-to-end payload. The sentinel budget defers the
	/// hop cap to the first gateway's `max_hops` policy.
	pub fn new(servlet_type: Urn<'static>, frame: &Frame) -> Result<Self, TightBeamError> {
		Ok(Self { servlet_type, payload: encode(frame)?, hops_remaining: DEFAULT_HOP_BUDGET })
	}

	/// Re-emits the work toward a peer with the remaining relay budget. A `0`
	/// budget is the terminal hop, so the receiver serves locally only.
	#[must_use]
	pub fn into_relayed(mut self, hops_remaining: u8) -> Self {
		self.hops_remaining = hops_remaining;
		self
	}

	/// Wraps `work` in the hop-local transport frame the gateway expects.
	///
	/// The wrapper serves routing only. It reuses the work frame's id
	/// for correlation and carries the encoded [`ClusterRequest::Work`]
	/// envelope as its message, so the client's own frame travels inside
	/// unmodified.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- `work` or the envelope
	///   does not encode.
	pub(crate) fn transport_frame(servlet_type: Urn<'static>, work: &Frame) -> Result<Frame, TightBeamError> {
		let request = ClusterRequest::Work(Self::new(servlet_type, work)?);
		let message = encode(&request)?;

		Ok(Frame::v0(work.metadata().id(), message))
	}
}

/// The work response from the cluster.
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct ClusterWorkResponse {
	/// The status of the routing and the execution.
	pub status: TransitStatus,
	/// The DER bytes of the servlet's complete response [`Frame`] on
	/// success, and [`None`] on a refusal.
	///
	/// Gateways return the servlet's reply frame unmodified, so its signature
	/// and metadata stay verifiable at the client ([`Frame::verify`]).
	///
	/// Decode with [`ClusterWorkResponse::into_frame`], or resolve success and
	/// refusal in one step with [`ClusterWorkResponse::served`].
	pub payload: Option<Vec<u8>>,
}

wire_sequence!(ClusterWorkResponse { status: plain, payload: octets_opt });

impl ClusterWorkResponse {
	/// Creates a successful response that carries the servlet's encoded
	/// response frame.
	///
	/// `payload` accepts any value convertible into [`Vec<u8>`].
	#[inline]
	pub fn ok(payload: impl Into<Vec<u8>>) -> Self {
		Self { status: TransitStatus::Ok, payload: Some(payload.into()) }
	}

	/// Creates an error response with `status`.
	#[inline]
	pub fn err(status: TransitStatus) -> Self {
		Self { status, payload: None }
	}

	/// Decodes the servlet's complete response frame from the payload.
	///
	/// A refusal carries no payload and yields [`None`]. A caller that treats
	/// a refusal as an error uses [`ClusterWorkResponse::served`] instead.
	pub fn into_frame(self) -> Result<Option<Frame>, TightBeamError> {
		match self.payload {
			Some(payload) => Ok(Some(decode(&payload)?)),
			None => Ok(None),
		}
	}

	/// Resolves the response into the servlet's frame or a typed error.
	///
	/// The unary work plane is request-reply, so a served request always
	/// carries the servlet's complete response frame.
	///
	/// # Errors
	///
	/// - [`TightBeamError::WorkRefused`] -- the status is not `Ok`, so the work was refused.
	/// - [`TightBeamError::MissingResponse`] -- the status is `Ok` with no
	///   payload, which violates the plane contract.
	/// - [`TightBeamError::SerializationError`] -- the payload does not decode as a frame.
	pub fn served(self) -> Result<Frame, TightBeamError> {
		if self.status != TransitStatus::Ok {
			return Err(TightBeamError::WorkRefused(self.status));
		}

		self.into_frame()?.ok_or(TightBeamError::MissingResponse)
	}

	/// Unwraps a gateway reply down to the servlet's response frame.
	///
	/// The inverse of [`ClusterWorkRequest::transport_frame`]: the reply is
	/// the hop-local wrapper, and the servlet's own frame travels inside it.
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingResponse`] -- the gateway answered with
	///   no frame at all.
	/// - Any error that [`Self::served`] reports for the decoded response.
	pub(crate) fn served_reply(reply: Option<Frame>) -> Result<Frame, TightBeamError> {
		let reply = reply.ok_or(TightBeamError::MissingResponse)?;
		let response: Self = decode(reply.message())?;

		response.served()
	}
}

/// The inbound message envelope for the cluster gateway, an ASN.1 CHOICE.
///
/// Every frame sent to a cluster carries exactly one of these variants.
/// The context-specific tag discriminates the type in the encoding, so the
/// gateway decodes once and matches.
#[derive(Debug, Beamable, Choice, Clone, PartialEq)]
pub enum ClusterRequest {
	/// A hive's announcement of its servlets [context 0].
	#[asn1(context_specific = "0", constructed = "true")]
	RegisterHive(RegisterHiveRequest),
	/// A hive's scaling notification [context 1].
	#[asn1(context_specific = "1", constructed = "true")]
	ServletAddressUpdate(ServletAddressUpdate),
	/// A client's work submission [context 2].
	#[asn1(context_specific = "2", constructed = "true")]
	Work(ClusterWorkRequest),
	/// A peer gateway's advertisement of its exported servlet types
	/// [context 3].
	#[asn1(context_specific = "3", constructed = "true")]
	AdvertisePeer(PeerAdvertisement),
	/// A relayed, origin-signed rumor frame from a peer gateway [context 4].
	///
	/// The frame is boxed because a nested [`Frame`] is far larger than the
	/// other variants. The box leaves the DER encoding as it is.
	#[asn1(context_specific = "4", constructed = "true")]
	Gossip(Box<Frame>),
	/// An origin gossip rumor from a local publisher [context 5].
	#[asn1(context_specific = "5", constructed = "true")]
	PublishGossip(GossipRumor),
	/// An anti-entropy digest summary from a peer gateway [context 6].
	#[asn1(context_specific = "6", constructed = "true")]
	ReconcileGossip(GossipReconciliation),
}

/// The request that registers a hive with a cluster.
///
/// A hive sends it to a cluster controller to announce its availability and
/// its servlets, with the address of each one.
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct RegisterHiveRequest {
	/// The address that the cluster reaches this hive on for heartbeats.
	pub hive_addr: Vec<u8>,
	/// The hive's servlet instances and their addresses, for direct routing.
	pub servlet_addresses: Vec<ServletInfo>,
	/// Opaque metadata about the hive, when the hive sends any.
	pub metadata: Option<Vec<u8>>,
}

wire_sequence!(RegisterHiveRequest { hive_addr: octets, servlet_addresses: plain, metadata: octets_opt });

/// The response to a hive registration.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct RegisterHiveResponse {
	/// The status of the registration request.
	pub status: TransitStatus,
	/// The hive identity URN that the cluster assigned, such as
	/// `urn:tightbeam::hive:10.0.0.5:9000`.
	pub hive_id: Option<Urn<'static>>,
}

/// A hive's notice to the cluster that its servlet addresses changed.
///
/// A hive sends it when auto-scaling spawns or stops a servlet instance, so
/// the cluster registry updates by push.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ServletAddressUpdate {
	/// The hive identity URN, which matches the one assigned at registration.
	pub hive_id: Urn<'static>,
	/// The newly spawned servlet instances and their addresses.
	pub added: Vec<ServletInfo>,
	/// The instance URNs of the removed servlets. An update names instances
	/// in both directions, matching `added`.
	pub removed: Vec<Urn<'static>>,
}

/// One servlet instance entering or leaving a hive's slate.
///
/// The encoded update carries an instance under `added` and a bare URN under
/// `removed`, so the direction picks which field the instance lands in.
/// Naming the direction as a variant keeps that choice with the value it
/// applies to.
pub(crate) enum ServletChange {
	/// An instance that has joined the slate, with the address to reach it.
	Added(ServletInfo),
	/// An instance that has left the slate, named by its instance URN.
	Removed(Urn<'static>),
}

impl ServletChange {
	/// The address update that announces this change on behalf of `hive_id`.
	pub(crate) fn into_update(self, hive_id: Urn<'static>) -> ServletAddressUpdate {
		match self {
			Self::Added(servlet) => ServletAddressUpdate { hive_id, added: vec![servlet], removed: vec![] },
			Self::Removed(servlet_id) => ServletAddressUpdate { hive_id, added: vec![], removed: vec![servlet_id] },
		}
	}
}

/// The response to a servlet address update.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ServletAddressUpdateResponse {
	/// The status of the update, where `Ok` means the update applied.
	pub status: TransitStatus,
}

/// A peer gateway advertising the servlet types its colony exports.
///
/// A gateway sends it to a peer gateway, so the receiving colony learns
/// which types the peer serves and forwards work there. It carries type URNs
/// only, and no instance addresses. The peer is reached at `gateway_addr`,
/// which resolves the whole peer colony rather than a single servlet.
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct PeerAdvertisement {
	/// The address that peers dial to reach the advertising gateway.
	pub gateway_addr: Vec<u8>,
	/// The servlet type URNs that the advertising colony exports.
	pub advertised_types: Vec<Urn<'static>>,
}

wire_sequence!(PeerAdvertisement { gateway_addr: octets, advertised_types: plain });

/// The response to a peer advertisement.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct PeerAdvertisementResponse {
	/// The status of the advertisement. `Ok` means the routes installed.
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

/// The signed content of one gossip rumor, which is its opaque payload.
///
/// # Roles
///
/// This one structure serves both gossip roles:
///
/// - A publisher sends it as [`ClusterRequest::PublishGossip`] to request a flood.
/// - The accepting origin gateway embeds the identical DER bytes as the
///   `message` of a rumor [`Frame`] it signs with its cluster key, so the
///   payload is bound under the origin signature at every later hop. The
///   signature covers the version, the metadata, and the message (§5.7.5).
///
/// # Scope
///
/// Flood scope is colony membership, which the origin certificate's colony
/// URN SAN carries. The rumor names no destination and its bytes carry no
/// scope, because unsigned scope bytes would be weaker than the certificate
/// binding (CWE-345).
///
/// Local delivery follows the receiving gateway's policy, which is the
/// optional gossip ingress servlet type.
///
/// # Frame fields
///
/// - The rumor frame's `metadata.id` is the rumor identity, and its
///   `metadata.order` is the issue time in unix milliseconds (§5.7.1 permits
///   a time-based order). Both are copied from the publish frame.
/// - Hop state such as the remaining flood radius MUST stay outside the rumor
///   frame. It travels in the `metadata.lifetime` of the outer relay frame,
///   which each relay rebuilds and re-signs.
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct GossipRumor {
	/// Opaque application payload delivered through the ingress policy.
	pub payload: Vec<u8>,
	/// How the receiving gateway consumes `payload`. The common
	/// application kind is the DER DEFAULT, so the encoding omits it.
	pub kind: GossipRumorKind,
}

wire_sequence!(GossipRumor { payload: octets, kind: default(GossipRumorKind::Application) });

impl GossipRumor {
	/// An application rumor, delivered through the ingress policy.
	///
	/// `payload` accepts any value convertible into [`Vec<u8>`].
	#[must_use]
	pub fn application(payload: impl Into<Vec<u8>>) -> Self {
		Self { payload: payload.into(), kind: GossipRumorKind::Application }
	}

	/// An advertisement rumor that carries an origin-signed ad frame's DER
	/// bytes for transitive peer discovery.
	///
	/// `ad_frame` accepts any value convertible into [`Vec<u8>`].
	#[must_use]
	pub fn peer_advertisement(ad_frame: impl Into<Vec<u8>>) -> Self {
		Self { payload: ad_frame.into(), kind: GossipRumorKind::PeerAdvertisement }
	}
}

/// The response to a gossip rumor.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct GossipResponse {
	/// The status of the rumor, where `Ok` means the rumor was accepted,
	/// delivered, and considered for a reflood.
	pub status: TransitStatus,
}

/// A summary of the rumors a gateway retains, sent so a peer can pull the
/// missing ones.
///
/// This is the anti-entropy backstop to best-effort flooding. Reconciliation
/// is an unordered set difference over content digests, with no cursor. A
/// receiver refuses a wrong-length entry rather than treating it as a digest
/// (CWE-20).
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct GossipReconciliation {
	/// Content digests the sender currently retains.
	pub held: Vec<Vec<u8>>,
}

wire_sequence!(GossipReconciliation { held: octets_seq });

/// One peer shared over peer exchange, as an identity and where to dial it.
///
/// A sharer only exchanges peers it verified itself, yet the entry is still an
/// unverified hint to its receiver:
///
/// - Admission is bounded per address prefix.
/// - Only a probe dial whose handshake certificate proves the local colony
///   makes the peer a dial target.
/// - The fingerprint is advisory identity for deduplication, and trust never
///   derives from exchanged bytes (CWE-345).
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct PeerGossip {
	/// The certificate fingerprint that the sharer verified the peer under.
	pub peer_id: Vec<u8>,
	/// The address that the sharer dialed the peer gateway at.
	pub gateway_addr: Vec<u8>,
}

wire_sequence!(PeerGossip { peer_id: octets, gateway_addr: octets });

/// The reply to a [`GossipReconciliation`], which names the digests the
/// peer lacks and wants as [`ClusterRequest::Gossip`] rumors.
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct GossipWant {
	/// The content digests that the replier lacks and requests.
	pub want: Vec<Vec<u8>>,
	/// A peer-exchange sample of verified peers, which the replier shares so
	/// a seed-bootstrapped requester can discover the colony graph. It holds
	/// at most [`MAX_PEX_SAMPLE`] peers in both directions.
	///
	/// [`MAX_PEX_SAMPLE`]: crate::constants::MAX_PEX_SAMPLE
	pub pex: Vec<PeerGossip>,
}

wire_sequence!(GossipWant { want: octets_seq, pex: plain });

/// The request that activates a servlet on a hive.
///
/// A cluster controller sends it to instruct a hive to take on a specific
/// servlet configuration.
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct ActivateServletRequest {
	/// The instance URN of the servlet to activate.
	pub servlet_id: Urn<'static>,
	/// The servlet's configuration data, when the request carries any.
	pub config: Option<Vec<u8>>,
}

wire_sequence!(ActivateServletRequest { servlet_id: plain, config: octets_opt });

/// The response to a servlet activation.
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct ActivateServletResponse {
	/// The status of the activation request.
	pub status: TransitStatus,
	/// The address of the activated servlet, on success.
	pub servlet_address: Option<Vec<u8>>,
}

wire_sequence!(ActivateServletResponse { status: plain, servlet_address: octets_opt });

impl ActivateServletResponse {
	/// Creates a successful activation response.
	#[inline]
	pub fn ok(address: impl Into<Vec<u8>>) -> Self {
		let address: Vec<u8> = address.into();
		Self { status: TransitStatus::Ok, servlet_address: Some(address) }
	}

	/// Creates a failed activation response.
	#[inline]
	pub fn err(status: TransitStatus) -> Self {
		Self { status, servlet_address: None }
	}
}

/// One servlet instance and the address that reaches it.
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct ServletInfo {
	/// The servlet instance URN, which is the type URN with a `/{addr}` tail.
	pub servlet_id: Urn<'static>,
	/// The address that reaches the servlet.
	pub address: Vec<u8>,
}

wire_sequence!(ServletInfo { servlet_id: plain, address: octets });

/// Why a CHOICE-shaped product named no single alternative.
///
/// DER CHOICE admits exactly one alternative. These products spell a choice
/// as tagged optional fields, so the encoding can carry none or several, and a
/// reader refuses both rather than guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Errorizable)]
pub enum ChoiceRefusal {
	/// No alternative was set.
	#[error("the product named no alternative")]
	NoneSet,
	/// More than one alternative was set.
	#[error("the product named more than one alternative")]
	ManySet,
}

/// The single request a [`HiveManagementRequest`] names.
#[derive(Debug, Clone, PartialEq)]
pub enum HiveManagement {
	/// Spawn one servlet instance.
	Spawn(SpawnServletParams),
	/// List the active servlets.
	List(ListServletsParams),
	/// Stop one servlet instance.
	Stop(StopServletParams),
}

/// The single result a [`HiveManagementResponse`] names.
#[derive(Debug, Clone, PartialEq)]
pub enum HiveManagementOutcome {
	/// The result of a spawn.
	Spawn(SpawnServletResult),
	/// The result of a list.
	List(ListServletsResult),
	/// The result of a stop.
	Stop(StopServletResult),
}

/// The single command a [`ClusterCommand`] names.
#[derive(Debug, Clone, PartialEq)]
pub enum ClusterCommandKind {
	/// A liveness probe.
	Heartbeat(HeartbeatParams),
	/// A management request.
	Manage(HiveManagement),
}

/// The management alternative a manage command is answered in.
///
/// The cluster decodes a management response in the alternative it asked
/// in, so a refusal to a spawn answers in the spawn alternative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManageShape {
	/// Answer in the spawn alternative.
	Spawn,
	/// Answer in the list alternative.
	List,
	/// Answer in the stop alternative.
	Stop,
}

/// The reply shape a cluster command is answered in.
///
/// A sender decodes the response in the shape it asked in, so a refusal
/// answered in another one reads as a malformed response and counts toward
/// eviction. The shape is a property of the command body, so it lives here
/// rather than being re-derived per refusal site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyShape {
	/// Answer in the heartbeat alternative.
	Heartbeat,
	/// Answer in the named management alternative.
	Manage(ManageShape),
}

impl HiveManagement {
	/// The management alternative a reply to this request must use.
	#[must_use]
	pub fn reply_shape(&self) -> ManageShape {
		match self {
			Self::Spawn(_) => ManageShape::Spawn,
			Self::List(_) => ManageShape::List,
			Self::Stop(_) => ManageShape::Stop,
		}
	}
}

impl ClusterCommandKind {
	/// The shape a reply to this command must use.
	#[must_use]
	pub fn reply_shape(&self) -> ReplyShape {
		match self {
			Self::Heartbeat(_) => ReplyShape::Heartbeat,
			Self::Manage(manage) => ReplyShape::Manage(manage.reply_shape()),
		}
	}
}

impl ReplyShape {
	/// The shape a reply to `body` must use.
	///
	/// A body that named no single alternative has no shape of its own, so
	/// it is answered in the stop alternative. That alternative carries only
	/// a status, which is the one thing a refusal of an unreadable command
	/// can report.
	#[must_use]
	pub fn of(body: Option<&ClusterCommandKind>) -> Self {
		body.map_or(Self::Manage(ManageShape::Stop), ClusterCommandKind::reply_shape)
	}

	/// Answers the frame `id` with `response` in this shape.
	///
	/// This is the one place that decides how a reply travels. A heartbeat
	/// reply travels on a V2 frame at [`MessagePriority::NetworkControl`], so
	/// a health check answered under load still leads the queue. A management
	/// reply travels on a V0 frame at the default priority.
	///
	/// # Errors
	///
	/// - [`TightBeamError::BuildError`] -- the reply frame did not build.
	pub fn reply(
		self,
		id: impl AsRef<[u8]>,
		response: ClusterCommandResponse,
	) -> Result<Option<Frame>, TightBeamError> {
		match self {
			Self::Heartbeat => reply_frame_with_priority(id, MessagePriority::NetworkControl, response),
			Self::Manage(_) => reply_frame(id, response),
		}
	}

	/// Refuses the frame `id` with `status` in this shape.
	///
	/// The refusal body is [`ClusterCommandResponse::refusal`] and the
	/// frame is [`ReplyShape::reply`], so every refusal site shares one
	/// body and one priority rule.
	///
	/// # Errors
	///
	/// - [`TightBeamError::BuildError`] -- the reply frame did not build.
	pub fn refuse(self, id: impl AsRef<[u8]>, status: TransitStatus) -> Result<Option<Frame>, TightBeamError> {
		self.reply(id, ClusterCommandResponse::refusal(self, status))
	}
}

/// The single answer a [`ClusterCommandResponse`] names.
#[derive(Debug, Clone, PartialEq)]
pub enum ClusterCommandOutcome {
	/// The answer to a liveness probe.
	Heartbeat(HeartbeatResult),
	/// The answer to a management request.
	Manage(HiveManagementOutcome),
}

/// The hive management request, a CHOICE spelled as tagged optional fields.
///
/// Context-specific tags tell the request types apart. Exactly one field is
/// set per request, and [`HiveManagementRequest::into_choice`] refuses a
/// request that sets none or several.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct HiveManagementRequest {
	/// A request to spawn a new servlet instance [context 0].
	#[asn1(context_specific = "0", optional = "true")]
	pub spawn: Option<SpawnServletParams>,
	/// A request to list all active servlets [context 1].
	#[asn1(context_specific = "1", optional = "true")]
	pub list: Option<ListServletsParams>,
	/// A request to stop a specific servlet instance [context 2].
	#[asn1(context_specific = "2", optional = "true")]
	pub stop: Option<StopServletParams>,
}

/// The parameters for spawning a new servlet.
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct SpawnServletParams {
	/// The type URN of the servlet to spawn, such as
	/// `urn:tightbeam::servlet:worker`.
	pub servlet_type: Urn<'static>,
	/// The servlet's configuration data, when the request carries any.
	pub config: Option<Vec<u8>>,
}

wire_sequence!(SpawnServletParams { servlet_type: plain, config: octets_opt });

/// The parameters for listing servlets.
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct ListServletsParams {
	/// A filter that is reserved for future use.
	pub filter: Option<Vec<u8>>,
}

wire_sequence!(ListServletsParams { filter: octets_opt });

/// The parameters for stopping a servlet.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct StopServletParams {
	/// The instance URN of the servlet to stop.
	pub servlet_id: Urn<'static>,
}

/// The hive management response, a CHOICE spelled as tagged optional fields.
///
/// Context-specific tags tell the response types apart. Exactly one field is
/// set per response, and [`HiveManagementResponse::into_choice`] refuses a
/// response that sets none or several.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct HiveManagementResponse {
	/// The answer to a spawn request [context 0].
	#[asn1(context_specific = "0", optional = "true")]
	pub spawn: Option<SpawnServletResult>,
	/// The answer to a list request [context 1].
	#[asn1(context_specific = "1", optional = "true")]
	pub list: Option<ListServletsResult>,
	/// The answer to a stop request [context 2].
	#[asn1(context_specific = "2", optional = "true")]
	pub stop: Option<StopServletResult>,
}

/// The result of spawning a servlet.
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct SpawnServletResult {
	/// The status of the spawn request.
	pub status: TransitStatus,
	/// The address of the newly spawned servlet, on success.
	pub servlet_address: Option<Vec<u8>>,
	/// The instance URN of the spawned servlet, such as
	/// `urn:tightbeam::servlet:worker/127.0.0.1:8080`.
	pub servlet_id: Option<Urn<'static>>,
}

wire_sequence!(SpawnServletResult { status: plain, servlet_address: octets_opt, servlet_id: plain });

/// The result of listing servlets.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ListServletsResult {
	/// The status of the request.
	pub status: TransitStatus,
	/// The servlets that are active on the hive.
	pub servlets: Vec<ServletInfo>,
}

/// The result of stopping a servlet.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct StopServletResult {
	/// The status of the stop request.
	pub status: TransitStatus,
}

impl HiveManagementResponse {
	/// Creates a spawn success response.
	#[inline]
	pub fn spawn_ok(address: impl Into<Vec<u8>>, servlet_id: Urn<'static>) -> Self {
		let address: Vec<u8> = address.into();
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

	/// Creates a list response.
	#[inline]
	pub fn list_ok(servlets: impl IntoIterator<Item = ServletInfo>) -> Self {
		let servlets: Vec<ServletInfo> = servlets.into_iter().collect();
		Self {
			spawn: None,
			list: Some(ListServletsResult { status: TransitStatus::Ok, servlets }),
			stop: None,
		}
	}

	/// Creates a stop success response.
	#[inline]
	pub fn stop_ok() -> Self {
		Self {
			spawn: None,
			list: None,
			stop: Some(StopServletResult { status: TransitStatus::Ok }),
		}
	}

	/// Refuses a management request with `status` in the alternative that
	/// `shape` names.
	///
	/// A spawn refusal names no address and no instance, and a list refusal
	/// names no servlets, so the sender reads the status and nothing else.
	#[must_use]
	pub fn refusal(shape: ManageShape, status: TransitStatus) -> Self {
		match shape {
			ManageShape::Spawn => Self {
				spawn: Some(SpawnServletResult { status, servlet_address: None, servlet_id: None }),
				list: None,
				stop: None,
			},
			ManageShape::List => Self {
				spawn: None,
				list: Some(ListServletsResult { status, servlets: Vec::new() }),
				stop: None,
			},
			ManageShape::Stop => Self { spawn: None, list: None, stop: Some(StopServletResult { status }) },
		}
	}
}

/// The status that a cluster reports in a heartbeat.
///
/// A cluster reports its operational status to its hives in each heartbeat.
/// A hive may use it to adjust its behavior, such as reducing capacity while
/// the cluster drains.
#[derive(Enumerated, Default, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClusterStatus {
	/// The cluster operates normally.
	#[default]
	Healthy = 0,
	/// The cluster is partly degraded, and some services are unavailable.
	Degraded = 1,
	/// The cluster is overloaded, with high utilization.
	Overloaded = 2,
	/// The cluster is draining in preparation for shutdown.
	Draining = 3,
}

/// The cluster command message, a CHOICE spelled as tagged optional fields.
///
/// It carries commands from the cluster to a hive. Context-specific tags
/// discriminate the CHOICE, and exactly one field is set per message.
///
/// # Security
///
/// - A command requires a nonrepudiation signature and frame integrity. A
///   frame without them is refused as `Unauthenticated`. Only a signature
///   that fails to verify counts toward the circuit breaker.
/// - Freshness binds to `Frame.metadata.order` (unix milliseconds), so hives
///   reject commands outside their freshness window and replays of
///   already-seen signatures within it (CWE-294).
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
#[beam(frame_integrity)]
pub struct ClusterCommand {
	/// A heartbeat request [context 0].
	#[asn1(context_specific = "0", optional = "true")]
	pub heartbeat: Option<HeartbeatParams>,

	/// A hive management request [context 1].
	#[asn1(context_specific = "1", optional = "true")]
	pub manage: Option<HiveManagementRequest>,
}

/// The parameters of a heartbeat.
///
/// The payload is minimal because the certificate in the frame's
/// nonrepudiation signature establishes identity.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct HeartbeatParams {
	/// The cluster's current operational status.
	pub cluster_status: ClusterStatus,
}

/// The cluster command response, a CHOICE spelled as tagged optional fields.
///
/// A hive answers a cluster command with it. Context-specific tags
/// discriminate the CHOICE, and exactly one field is set per response.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ClusterCommandResponse {
	/// The heartbeat answer [context 0].
	#[asn1(context_specific = "0", optional = "true")]
	pub heartbeat: Option<HeartbeatResult>,

	/// The management answer [context 1].
	#[asn1(context_specific = "1", optional = "true")]
	pub manage: Option<HiveManagementResponse>,
}

impl From<HiveManagement> for HiveManagementRequest {
	/// Spells one management alternative as the tagged-optional product that
	/// the encoding carries.
	///
	/// This is the send-side counterpart of
	/// [`HiveManagementRequest::into_choice`]: a request built here names
	/// exactly one alternative, so no sender has to remember the rule.
	fn from(request: HiveManagement) -> Self {
		match request {
			HiveManagement::Spawn(spawn) => Self { spawn: Some(spawn), list: None, stop: None },
			HiveManagement::List(list) => Self { spawn: None, list: Some(list), stop: None },
			HiveManagement::Stop(stop) => Self { spawn: None, list: None, stop: Some(stop) },
		}
	}
}

impl From<ClusterCommandKind> for ClusterCommand {
	/// Spells one command alternative as the tagged-optional product that
	/// the encoding carries.
	fn from(command: ClusterCommandKind) -> Self {
		match command {
			ClusterCommandKind::Heartbeat(heartbeat) => Self { heartbeat: Some(heartbeat), manage: None },
			ClusterCommandKind::Manage(manage) => Self { heartbeat: None, manage: Some(manage.into()) },
		}
	}
}

impl HiveManagementRequest {
	/// Consumes this product for the one request it names.
	///
	/// # Errors
	///
	/// - [`ChoiceRefusal::NoneSet`] -- the product names no request.
	/// - [`ChoiceRefusal::ManySet`] -- the product names several requests.
	pub fn into_choice(self) -> Result<HiveManagement, ChoiceRefusal> {
		match (self.spawn, self.list, self.stop) {
			(Some(spawn), None, None) => Ok(HiveManagement::Spawn(spawn)),
			(None, Some(list), None) => Ok(HiveManagement::List(list)),
			(None, None, Some(stop)) => Ok(HiveManagement::Stop(stop)),
			(None, None, None) => Err(ChoiceRefusal::NoneSet),
			_ => Err(ChoiceRefusal::ManySet),
		}
	}
}

impl HiveManagementResponse {
	/// Consumes this product for the one result it names.
	///
	/// # Errors
	///
	/// - [`ChoiceRefusal::NoneSet`] -- the product names no result.
	/// - [`ChoiceRefusal::ManySet`] -- the product names several results.
	pub fn into_choice(self) -> Result<HiveManagementOutcome, ChoiceRefusal> {
		match (self.spawn, self.list, self.stop) {
			(Some(spawn), None, None) => Ok(HiveManagementOutcome::Spawn(spawn)),
			(None, Some(list), None) => Ok(HiveManagementOutcome::List(list)),
			(None, None, Some(stop)) => Ok(HiveManagementOutcome::Stop(stop)),
			(None, None, None) => Err(ChoiceRefusal::NoneSet),
			_ => Err(ChoiceRefusal::ManySet),
		}
	}
}

impl ClusterCommand {
	/// Consumes this product for the one command it names.
	///
	/// A management command proves its own alternative here as well, so a
	/// dispatcher matches an exhaustive body rather than reading fields.
	///
	/// # Errors
	///
	/// - [`ChoiceRefusal::NoneSet`] -- the product names no command.
	/// - [`ChoiceRefusal::ManySet`] -- the product names both commands, or its
	///   management request names several.
	pub fn into_choice(self) -> Result<ClusterCommandKind, ChoiceRefusal> {
		match (self.heartbeat, self.manage) {
			(Some(heartbeat), None) => Ok(ClusterCommandKind::Heartbeat(heartbeat)),
			(None, Some(manage)) => Ok(ClusterCommandKind::Manage(manage.into_choice()?)),
			(None, None) => Err(ChoiceRefusal::NoneSet),
			(Some(_), Some(_)) => Err(ChoiceRefusal::ManySet),
		}
	}
}

impl ClusterCommandResponse {
	/// Consumes this product for the one answer it names.
	///
	/// # Errors
	///
	/// - [`ChoiceRefusal::NoneSet`] -- the product names no answer.
	/// - [`ChoiceRefusal::ManySet`] -- the product names both answers, or its
	///   management response names several.
	pub fn into_choice(self) -> Result<ClusterCommandOutcome, ChoiceRefusal> {
		match (self.heartbeat, self.manage) {
			(Some(heartbeat), None) => Ok(ClusterCommandOutcome::Heartbeat(heartbeat)),
			(None, Some(manage)) => Ok(ClusterCommandOutcome::Manage(manage.into_choice()?)),
			(None, None) => Err(ChoiceRefusal::NoneSet),
			(Some(_), Some(_)) => Err(ChoiceRefusal::ManySet),
		}
	}
}

/// The heartbeat answer, with the hive's health status.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct HeartbeatResult {
	/// The overall status: `Ok` when the hive is healthy, and
	/// `ResourceExhausted` when it is at capacity.
	pub status: TransitStatus,
	/// The current aggregate utilization across all servlets.
	pub utilization: BasisPoints,
	/// The number of active servlet instances.
	pub active_servlets: u32,
}

impl ClusterCommandResponse {
	/// Creates a heartbeat response.
	#[inline]
	pub fn heartbeat(status: TransitStatus, utilization: BasisPoints, active_servlets: u32) -> Self {
		Self {
			heartbeat: Some(HeartbeatResult { status, utilization, active_servlets }),
			manage: None,
		}
	}

	/// Creates a management response wrapper.
	#[inline]
	pub fn manage(response: HiveManagementResponse) -> Self {
		Self { heartbeat: None, manage: Some(response) }
	}

	/// Refuses a command with `status` in the alternative that `shape` names.
	///
	/// This is the one refusal constructor, so a refusal answers in the
	/// alternative its sender decodes. A heartbeat refusal reports no
	/// capacity, and a management refusal is
	/// [`HiveManagementResponse::refusal`] in its own alternative.
	#[must_use]
	pub fn refusal(shape: ReplyShape, status: TransitStatus) -> Self {
		match shape {
			ReplyShape::Heartbeat => Self::heartbeat(status, BasisPoints::default(), 0),
			ReplyShape::Manage(manage) => Self::manage(HiveManagementResponse::refusal(manage, status)),
		}
	}
}

/// The issue time a colony frame states.
///
/// The frame layer leaves `metadata.order` protocol-opaque. Colony control
/// frames, rumors, and advertisements all put their issue time there as unix
/// milliseconds (§5.7.1 permits a time-based order). This is the one place
/// that reading is made, so every freshness and replay decision compares the
/// same instant.
pub(crate) trait IssuedAt {
	/// The instant this frame says it was issued.
	fn issued_at(&self) -> UnixMillis;
}

impl IssuedAt for Frame {
	fn issued_at(&self) -> UnixMillis {
		UnixMillis::new(self.metadata().order())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::asn1::Version;
	use crate::builder::{FrameBuilder, TypeBuilder};
	use crate::colony::common::ColonyNamespace;
	use crate::error::Result;
	use crate::tb_cases;

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

	fn ping_instance() -> Urn<'static> {
		ping_type()
			.servlet_instance("127.0.0.1:9001")
			.expect("a servlet type URN yields an instance URN")
	}

	fn hive_id() -> crate::utils::urn::Urn<'static> {
		ColonyNamespace::default()
			.hive("127.0.0.1:9000")
			.expect("test locators satisfy the mint grammar")
	}

	fn work_frame() -> Frame {
		Frame::v0(b"work-1", vec![0x02, 0x01, 0x2A])
	}

	#[test]
	fn cluster_request_register_hive_round_trips() -> Result<()> {
		round_trip(ClusterRequest::RegisterHive(RegisterHiveRequest {
			hive_addr: b"127.0.0.1:9000".to_vec(),
			servlet_addresses: vec![ServletInfo {
				servlet_id: ping_type()
					.servlet_instance("127.0.0.1:9001")
					.expect("a servlet type URN yields an instance URN"),
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
			removed: vec![ping_type()
				.servlet_instance("127.0.0.1:9100")
				.expect("a servlet type URN yields an instance URN")],
		}))
	}

	#[test]
	fn cluster_request_work_round_trips() -> Result<()> {
		round_trip(ClusterRequest::Work(ClusterWorkRequest::new(ping_type(), &work_frame())?))
	}

	#[test]
	fn work_response_into_frame_round_trips() -> Result<()> {
		let frame = work_frame();
		let response = ClusterWorkResponse::ok(encode(&frame)?);
		assert_eq!(response.into_frame()?, Some(frame));
		Ok(())
	}

	#[test]
	fn work_response_err_into_frame_is_none() -> Result<()> {
		assert_eq!(ClusterWorkResponse::err(TransitStatus::Unavailable).into_frame()?, None);
		Ok(())
	}

	#[test]
	fn work_response_served_yields_frame() -> Result<()> {
		let frame = work_frame();
		let response = ClusterWorkResponse::ok(encode(&frame)?);
		assert_eq!(response.served()?, frame);
		Ok(())
	}

	#[test]
	fn work_response_served_maps_refusal_to_work_refused() {
		let served = ClusterWorkResponse::err(TransitStatus::Unavailable).served();
		assert!(matches!(served, Err(TightBeamError::WorkRefused(TransitStatus::Unavailable))));
	}

	#[test]
	fn work_response_served_rejects_ok_without_payload() {
		let response = ClusterWorkResponse { status: TransitStatus::Ok, payload: None };
		assert!(matches!(response.served(), Err(TightBeamError::MissingResponse)));
	}

	#[test]
	fn cluster_request_advertise_peer_round_trips() -> Result<()> {
		round_trip(ClusterRequest::AdvertisePeer(PeerAdvertisement {
			gateway_addr: b"127.0.0.1:9000".to_vec(),
			advertised_types: vec![ping_type()],
		}))
	}

	#[test]
	fn cluster_request_gossip_round_trips() -> Result<()> {
		let rumor_body = GossipRumor::application(vec![0x02, 0x01, 0x2A]);
		let rumor = FrameBuilder::from(Version::V0)
			.with_id("rumor-1")
			.with_order(1_000)
			.with_message(rumor_body)
			.build()?;

		round_trip(ClusterRequest::Gossip(Box::new(rumor)))
	}

	#[test]
	fn cluster_request_publish_gossip_round_trips() -> Result<()> {
		round_trip(ClusterRequest::PublishGossip(GossipRumor::application(vec![0x02, 0x01, 0x2A])))
	}

	#[test]
	fn cluster_request_reconcile_gossip_round_trips() -> Result<()> {
		round_trip(ClusterRequest::ReconcileGossip(GossipReconciliation {
			held: vec![vec![0xAAu8; 32], vec![0xBBu8; 32]],
		}))
	}

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
		let bare = encode(&ClusterWorkRequest::new(ping_type(), &work_frame())?)?;
		let decoded = decode::<ClusterRequest>(&bare);
		assert!(decoded.is_err());
		Ok(())
	}

	fn stop_request() -> HiveManagementRequest {
		HiveManagementRequest {
			spawn: None,
			list: None,
			stop: Some(StopServletParams {
				servlet_id: ping_type()
					.servlet_instance("127.0.0.1:9001")
					.expect("a servlet type URN yields an instance URN"),
			}),
		}
	}

	#[test]
	fn a_command_naming_no_alternative_is_refused() {
		let empty = ClusterCommand { heartbeat: None, manage: None };
		assert_eq!(empty.into_choice(), Err(ChoiceRefusal::NoneSet));
	}

	#[test]
	fn a_command_naming_both_alternatives_is_refused() {
		let both = ClusterCommand {
			heartbeat: Some(HeartbeatParams { cluster_status: ClusterStatus::Healthy }),
			manage: Some(stop_request()),
		};
		assert_eq!(both.into_choice(), Err(ChoiceRefusal::ManySet));
	}

	#[test]
	fn a_management_request_naming_several_alternatives_is_refused() {
		let mut several = stop_request();
		several.list = Some(ListServletsParams { filter: None });
		let command = ClusterCommand { heartbeat: None, manage: Some(several) };
		assert_eq!(command.into_choice(), Err(ChoiceRefusal::ManySet));
	}

	/// Every alternative survives the trip out to the tagged product and
	/// back, so the send side and the receive side agree on which field
	/// names which command.
	#[test]
	fn a_command_round_trips_through_its_choice() {
		let alternatives = [
			ClusterCommandKind::Heartbeat(HeartbeatParams { cluster_status: ClusterStatus::Healthy }),
			ClusterCommandKind::Manage(HiveManagement::Spawn(SpawnServletParams {
				servlet_type: ping_type(),
				config: None,
			})),
			ClusterCommandKind::Manage(HiveManagement::List(ListServletsParams { filter: None })),
			ClusterCommandKind::Manage(HiveManagement::Stop(StopServletParams {
				servlet_id: ping_type()
					.servlet_instance("127.0.0.1:9001")
					.expect("a servlet type URN yields an instance URN"),
			})),
		];

		for alternative in alternatives {
			let wire = ClusterCommand::from(alternative.clone());
			assert_eq!(wire.into_choice(), Ok(alternative));
		}
	}

	/// The shape a sender would read `response` in, with the status it
	/// carries.
	fn answered_shape(
		response: ClusterCommandResponse,
	) -> core::result::Result<(ReplyShape, TransitStatus), ChoiceRefusal> {
		let answered = match response.into_choice()? {
			ClusterCommandOutcome::Heartbeat(heartbeat) => (ReplyShape::Heartbeat, heartbeat.status),
			ClusterCommandOutcome::Manage(HiveManagementOutcome::Spawn(spawn)) => {
				(ReplyShape::Manage(ManageShape::Spawn), spawn.status)
			}
			ClusterCommandOutcome::Manage(HiveManagementOutcome::List(list)) => {
				(ReplyShape::Manage(ManageShape::List), list.status)
			}
			ClusterCommandOutcome::Manage(HiveManagementOutcome::Stop(stop)) => {
				(ReplyShape::Manage(ManageShape::Stop), stop.status)
			}
		};

		Ok(answered)
	}

	// A refusal answers in the one alternative its shape names, so the
	// sender decodes it in the shape it asked in.
	tb_cases! {
		fn a_refusal_answers_in_the_alternative_its_shape_names(shape: ReplyShape) {
			let status = TransitStatus::ResourceExhausted;

			let refusal = ClusterCommandResponse::refusal(shape, status);

			assert_eq!(answered_shape(refusal), Ok((shape, status)));
		}
		cases {
			heartbeat => ReplyShape::Heartbeat,
			spawn => ReplyShape::Manage(ManageShape::Spawn),
			list => ReplyShape::Manage(ManageShape::List),
			stop => ReplyShape::Manage(ManageShape::Stop),
		}
	}

	// A command names its own alternative, so a refusal of it answers
	// where the sender reads its result.
	tb_cases! {
		fn a_command_names_its_own_alternative((command, shape): (ClusterCommandKind, ReplyShape)) {
			assert_eq!(ReplyShape::of(Some(&command)), shape);
		}
		cases {
			heartbeat => (
				ClusterCommandKind::Heartbeat(HeartbeatParams { cluster_status: ClusterStatus::Healthy }),
				ReplyShape::Heartbeat,
			),
			spawn => (
				ClusterCommandKind::Manage(HiveManagement::Spawn(SpawnServletParams {
					servlet_type: ping_type(),
					config: None,
				})),
				ReplyShape::Manage(ManageShape::Spawn),
			),
			list => (
				ClusterCommandKind::Manage(HiveManagement::List(ListServletsParams { filter: None })),
				ReplyShape::Manage(ManageShape::List),
			),
			stop => (
				ClusterCommandKind::Manage(HiveManagement::Stop(StopServletParams { servlet_id: ping_instance() })),
				ReplyShape::Manage(ManageShape::Stop),
			),
		}
	}

	/// A body that named no single alternative is answered in the stop
	/// alternative, which carries only the status a refusal has to report.
	#[test]
	fn an_unreadable_command_is_answered_in_the_stop_alternative() {
		assert_eq!(ReplyShape::of(None), ReplyShape::Manage(ManageShape::Stop));
	}

	/// A heartbeat reply travels on a V2 frame at network-control priority,
	/// so a health check answered under load still leads the queue.
	#[test]
	fn a_heartbeat_reply_travels_at_network_control_priority() -> Result<()> {
		let response = ClusterCommandResponse::heartbeat(TransitStatus::Ok, BasisPoints::default(), 0);

		let reply = ReplyShape::Heartbeat
			.reply(b"hb", response)?
			.ok_or(TightBeamError::MissingResponse)?;

		assert_eq!(reply.metadata().priority(), Some(MessagePriority::NetworkControl));
		Ok(())
	}

	/// A management reply travels on a V0 frame, which has no priority field.
	#[test]
	fn a_manage_reply_travels_at_the_default_priority() -> Result<()> {
		let response = ClusterCommandResponse::manage(HiveManagementResponse::stop_ok());

		let reply = ReplyShape::Manage(ManageShape::Stop).reply(b"stop", response)?;
		let reply = reply.ok_or(TightBeamError::MissingResponse)?;

		assert_eq!(reply.metadata().priority(), None);
		Ok(())
	}
}
