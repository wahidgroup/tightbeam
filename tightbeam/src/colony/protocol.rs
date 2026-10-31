//! The protocol messages of the colony control and work planes.
//!
//! - [`ClusterRequest`] is the envelope of every frame sent to a cluster
//!   gateway: hive registration, scaling updates, client work, peer
//!   advertisements, and gossip.
//! - [`ClusterCommand`] carries a heartbeat or a management request from a
//!   cluster to a hive, and [`ClusterCommandResponse`] answers it.
//! - [`ReplyShape`] decides the alternative and the priority of a command's reply.

use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::asn1::Frame;
use crate::basis_points::BasisPoints;
use crate::builder::TypeBuilder;
use crate::clock::{Clock, UnixMillis};
use crate::cms::signed_data::SignerIdentifier;
use crate::constants::DEFAULT_HOP_BUDGET;
use crate::der::{Choice, Enumerated, Sequence};
use crate::policy::TransitStatus;
use crate::urn::Urn;
use crate::utils::{decode, encode};
use crate::wire::wire_sequence;
use crate::{Beamable, Message, MessagePriority, TightBeamError, Version};

/// The work request envelope for cluster routing.
///
/// Clients send it to the cluster gateway, which selects a local servlet or a
/// peer gateway by `servlet_type` and delivers the client frame in `payload`
/// to the servlet byte-for-byte.
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct ClusterWorkRequest {
	/// The target servlet type URN, such as `urn:tightbeam::servlet:ping`.
	pub servlet_type: Urn<'static>,
	/// The DER bytes of the client's complete end-to-end [`Frame`].
	///
	/// The frame's `message` is the servlet's typed input. Gateways forward
	/// these bytes unmodified, so the client's signature, integrity, and
	/// previous-frame linkage stay verifiable at the servlet
	/// ([`Frame::verify`]).
	pub payload: Vec<u8>,
	/// The relay budget: the count of gateway forwards that remain for this
	/// work.
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
	/// Builds origin work from a client, with the client's complete frame
	/// nested as the end-to-end payload. The sentinel budget defers the hop
	/// cap to the first gateway's `max_hops` policy.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- `frame` does not encode.
	pub fn new(servlet_type: Urn<'static>, frame: &Frame) -> Result<Self, TightBeamError> {
		Ok(Self { servlet_type, payload: encode(frame)?, hops_remaining: DEFAULT_HOP_BUDGET })
	}

	/// Re-emits the work toward a peer with the relay budget that remains. A
	/// `0` budget is the terminal hop, so the receiver serves locally only.
	#[must_use]
	pub fn into_relayed(mut self, hops_remaining: u8) -> Self {
		self.hops_remaining = hops_remaining;
		self
	}

	/// Wraps `work` in the hop-local transport frame the gateway expects.
	///
	/// The wrapper serves routing alone. It reuses the work frame's id for
	/// correlation, and its message is the encoded [`ClusterRequest::Work`]
	/// envelope, so the client's own frame travels inside unmodified.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- `work` or the envelope does not encode.
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
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- the payload does not decode as a frame.
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
	/// It is the inverse of [`ClusterWorkRequest::transport_frame`]: the reply
	/// is the hop-local wrapper, with the servlet's own frame inside it.
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingResponse`] -- the gateway answered with no frame.
	/// - The errors of [`Frame::decode_message`] -- the reply is no carrier of a work response.
	/// - Any error that [`Self::served`] reports for the decoded response.
	pub(crate) fn served_reply(reply: Option<Frame>) -> Result<Frame, TightBeamError> {
		let reply = reply.ok_or(TightBeamError::MissingResponse)?;
		let response: Self = reply.decode_message()?;

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
	/// Boxed, because a nested [`Frame`] is far larger than the other
	/// variants. The box leaves the DER encoding as it is.
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
	/// in both directions, as `added` does.
	pub removed: Vec<Urn<'static>>,
}

/// One servlet instance that enters or leaves a hive's slate.
///
/// The encoded update carries an instance under `added` and a bare URN under
/// `removed`. A variant names the direction, so the choice of field stays
/// with the value it applies to.
pub(crate) enum ServletChange {
	/// An instance that joined the slate, with the address that reaches it.
	Added(ServletInfo),
	/// An instance that left the slate, named by its instance URN.
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

/// A peer gateway's advertisement of the servlet types its colony exports.
///
/// The colony that receives it learns which types the peer serves and
/// forwards work there. It carries type URNs alone, and `gateway_addr` is the
/// one address for the whole peer colony.
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct PeerAdvertisement {
	/// The address peers dial to reach the sending gateway.
	pub gateway_addr: Vec<u8>,
	/// The servlet type URNs that the sender's colony exports.
	pub advertised_types: Vec<Urn<'static>>,
}

wire_sequence!(PeerAdvertisement { gateway_addr: octets, advertised_types: plain });

/// The response to a peer advertisement.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct PeerAdvertisementResponse {
	/// The status of the advertisement. `Ok` means the routes installed.
	pub status: TransitStatus,
}

/// How the gateway that receives an admitted rumor consumes its payload.
///
/// The kind travels inside the signed rumor body, so a relay cannot
/// reinterpret an application payload as routing control.
#[derive(Enumerated, Default, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GossipRumorKind {
	/// An opaque application payload, delivered through the ingress policy.
	#[default]
	Application = 0,
	/// The bytes of an origin-signed peer advertisement frame, which the
	/// receiver applies to its peer routing state for transitive discovery.
	PeerAdvertisement = 1,
}

/// The signed content of one gossip rumor: an opaque payload, and the kind
/// that names how a gateway consumes it.
///
/// # Roles
///
/// - A publisher sends it as [`ClusterRequest::PublishGossip`] to ask for a flood.
/// - The origin gateway embeds the same DER as the `message` of a rumor
///   [`Frame`] it signs with its cluster key. That signature covers the
///   version, the metadata, and the message (§5.7.5), so it binds the payload
///   at every later hop.
///
/// # Scope
///
/// The flood scope is the namespace: a rumor travels between gateways that
/// peer trust admits and whose certificates carry a colony URN of it. The
/// rumor names no destination and carries no scope bytes, which, unsigned,
/// would be weaker than the certificate binding (CWE-345).
///
/// Local delivery is the receiver's policy: its optional ingress servlet
/// receives the origin-signed frame.
///
/// # Frame fields
///
/// - The rumor frame's `metadata.id` is the rumor identity, and its
///   `metadata.order` the issue time in Unix milliseconds (§5.7.1 permits a
///   time-based order). The origin gateway copies both from the publish frame.
/// - Hop state, such as the remaining flood radius, MUST stay outside the
///   rumor frame. It travels in the `metadata.lifetime` of the outer relay
///   frame, which each relay rebuilds and re-signs.
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct GossipRumor {
	/// The opaque payload: an application payload for the ingress policy, or
	/// the bytes of a peer advertisement frame, as `kind` names.
	pub payload: Vec<u8>,
	/// How the receiver consumes `payload`. The common application kind is the
	/// DER DEFAULT, so the encoding omits it.
	pub kind: GossipRumorKind,
}

wire_sequence!(GossipRumor { payload: octets, kind: default(GossipRumorKind::Application) });

impl GossipRumor {
	/// An application rumor, delivered through the ingress policy.
	#[must_use]
	pub fn application(payload: impl Into<Vec<u8>>) -> Self {
		Self { payload: payload.into(), kind: GossipRumorKind::Application }
	}

	/// An advertisement rumor that carries an origin-signed ad frame's DER
	/// bytes for transitive peer discovery.
	#[must_use]
	pub fn peer_advertisement(ad_frame: impl Into<Vec<u8>>) -> Self {
		Self { payload: ad_frame.into(), kind: GossipRumorKind::PeerAdvertisement }
	}
}

/// The response to a gossip rumor.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct GossipResponse {
	/// The status of the rumor, where `Ok` means the receiver accepted the
	/// rumor, delivered it, and considered it for a reflood.
	///
	/// On a relayed rumor, `Unauthenticated` means the receiver's trust does
	/// not hold the rumor's origin, and it tells the sender to withhold that
	/// origin from this receiver. A frame with no signature answers the same
	/// status.
	pub status: TransitStatus,
}

impl GossipResponse {
	/// Whether the receiver refused the rumor because its trust does not hold
	/// the rumor's origin.
	///
	/// A gateway signs every frame it relays, so on the reply to its own relay
	/// `Unauthenticated` names the origin. It is the one reading of that
	/// status, for the reflood and the repair push.
	#[must_use]
	pub(crate) fn refuses_origin(&self) -> bool {
		self.status == TransitStatus::Unauthenticated
	}
}

/// A summary of the rumors a gateway retains, sent so a peer can pull the
/// ones it lacks.
///
/// It is the anti-entropy backstop to the best-effort flood: a stateless,
/// unordered set difference over content digests. A receiver drops an entry
/// of the wrong length (CWE-20).
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct GossipReconciliation {
	/// The content digests the sender retains.
	pub held: Vec<Vec<u8>>,
}

wire_sequence!(GossipReconciliation { held: octets_seq });

/// One peer shared over peer exchange, as an identity and where to dial it.
///
/// A sharer only exchanges peers it verified itself, yet the entry is an
/// unverified hint to its receiver:
///
/// - Admission is bounded per address prefix.
/// - Only a probe dial whose handshake certificate proves flood membership makes the peer a dial target.
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
	/// a seed-bootstrapped requester can discover the flood's gateways. It
	/// holds at most [`MAX_PEX_SAMPLE`] peers in both directions.
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
	/// Creates an `Ok` response that carries the activated servlet's address.
	#[inline]
	pub fn ok(address: impl Into<Vec<u8>>) -> Self {
		let address: Vec<u8> = address.into();
		Self { status: TransitStatus::Ok, servlet_address: Some(address) }
	}

	/// Creates a refusal that carries `status` and no address.
	#[inline]
	pub fn err(status: TransitStatus) -> Self {
		Self { status, servlet_address: None }
	}
}

/// One servlet instance, the address that reaches it, and the identity it
/// answers under.
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct ServletInfo {
	/// The servlet instance URN, which is the type URN with a `/{addr}` tail.
	pub servlet_id: Urn<'static>,
	/// The address that reaches the servlet.
	pub address: Vec<u8>,
	/// The [`SignerIdentifier`] that names the certificate the servlet
	/// presents in its handshake (RFC 5652 §5.3), encoded as its own DER.
	///
	/// A gateway that dials the servlet admits only the certificate this
	/// signer names, so a party that answers at the address under another
	/// identity receives no frame (CWE-346).
	pub signer: SignerIdentifier,
}

wire_sequence!(ServletInfo { servlet_id: plain, address: octets, signer: plain });

#[cfg(test)]
impl ServletInfo {
	/// The signer of the certificate on the fixed test key, which a fixture
	/// servlet that serves under that key presents.
	pub(crate) fn fixture_signer() -> SignerIdentifier {
		use crate::crypto::x509::utils::CertificateExt;
		use crate::testing::TestCertificate;

		let certificate = TestCertificate::insecure_fixed();
		certificate.signer_identifier().expect("the fixture certificate names its key")
	}

	/// The servlet `ping` at `addr`, whose locator names that same address and
	/// whose signer is [`Self::fixture_signer`].
	pub(crate) fn fixture(addr: impl AsRef<str>) -> Self {
		let addr = addr.as_ref();
		let servlet_id = crate::colony::urn::ColonyNamespace::instance_fixture("ping", addr);
		let address = addr.as_bytes().to_vec();
		ServletInfo { servlet_id, address, signer: ServletInfo::fixture_signer() }
	}
}

/// The hive management request, an ASN.1 CHOICE.
///
/// The context-specific tag names the one request the value carries, and the
/// encoding is the chosen alternative alone (X.690 § 8.13), so a request
/// names exactly one alternative.
///
/// # Examples
///
/// ```
/// use tightbeam::colony::protocol::{HiveManagement, ListServletsParams};
/// use tightbeam::{decode, encode};
///
/// let list = HiveManagement::List(ListServletsParams { filter: None });
///
/// let encoded = encode(&list)?;
/// assert_eq!(encoded, [0xa1, 0x02, 0x30, 0x00]);
/// assert_eq!(decode::<HiveManagement>(&encoded)?, list);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Debug, Beamable, Choice, Clone, PartialEq)]
pub enum HiveManagement {
	/// Spawn one servlet instance [context 0].
	#[asn1(context_specific = "0", constructed = "true")]
	Spawn(SpawnServletParams),
	/// List the active servlets [context 1].
	#[asn1(context_specific = "1", constructed = "true")]
	List(ListServletsParams),
	/// Stop one servlet instance [context 2].
	#[asn1(context_specific = "2", constructed = "true")]
	Stop(StopServletParams),
}

/// The hive management response, an ASN.1 CHOICE.
///
/// The context-specific tag names the one result the value carries, and the
/// encoding is the chosen alternative alone (X.690 § 8.13). A result answers
/// in the alternative of its request.
///
/// # Examples
///
/// ```
/// use tightbeam::colony::protocol::HiveManagementOutcome;
/// use tightbeam::{decode, encode};
///
/// let stopped = HiveManagementOutcome::stop_ok();
///
/// let encoded = encode(&stopped)?;
/// assert_eq!(encoded, [0xa2, 0x05, 0x30, 0x03, 0x0a, 0x01, 0x00]);
/// assert_eq!(decode::<HiveManagementOutcome>(&encoded)?, stopped);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Debug, Beamable, Choice, Clone, PartialEq)]
pub enum HiveManagementOutcome {
	/// The result of a spawn [context 0].
	#[asn1(context_specific = "0", constructed = "true")]
	Spawn(SpawnServletResult),
	/// The result of a list [context 1].
	#[asn1(context_specific = "1", constructed = "true")]
	List(ListServletsResult),
	/// The result of a stop [context 2].
	#[asn1(context_specific = "2", constructed = "true")]
	Stop(StopServletResult),
}

/// The management alternative that answers a manage command.
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

/// The reply shape that answers a cluster command.
///
/// A sender decodes the response in the shape it asked in, so a refusal
/// answered in another one reads as a malformed response and counts toward
/// eviction. The shape is a property of the command body, so every refusal
/// site reads it here.
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

/// The record of a command that a hive carried out: the name of the command
/// and the instance it changed, which render its label as
/// `<command>/<instance>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AcceptedRecord<'a> {
	/// The name of the command, such as `Spawn`.
	name: &'static str,
	/// The instance that the command changed. The record of a spawn whose
	/// answer names no instance renders the name of the command alone.
	instance: Option<&'a Urn<'static>>,
}

impl fmt::Display for AcceptedRecord<'_> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self.instance {
			Some(instance) => write!(f, "{}/{instance}", self.name),
			None => f.write_str(self.name),
		}
	}
}

impl ClusterCommand {
	/// The shape a reply to this command must use.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::protocol::{ClusterCommand, ClusterStatus, HeartbeatParams, ReplyShape};
	///
	/// let heartbeat = ClusterCommand::Heartbeat(HeartbeatParams { cluster_status: ClusterStatus::Healthy });
	/// assert_eq!(heartbeat.reply_shape(), ReplyShape::Heartbeat);
	/// ```
	#[must_use]
	pub fn reply_shape(&self) -> ReplyShape {
		match self {
			Self::Heartbeat(_) => ReplyShape::Heartbeat,
			Self::Manage(manage) => ReplyShape::Manage(manage.reply_shape()),
		}
	}

	/// Whether a hive under drain or backpressure refuses this command.
	///
	/// The reply shape decides it, and the reply priority reads the same
	/// answer, so a command that survives load is one whose reply leads the
	/// queue.
	pub(crate) fn yields_to_load(&self) -> bool {
		self.reply_shape().yields_to_load()
	}

	/// The record of this command once the hive carries it out and answers it
	/// with `response`.
	///
	/// A spawn names the instance `response` names, a stop names its own, and a
	/// command that reads the hive has no record.
	pub(crate) fn accepted<'a>(&'a self, response: &'a ClusterCommandResponse) -> Option<AcceptedRecord<'a>> {
		match self {
			Self::Manage(HiveManagement::Spawn(_)) => {
				let instance = response.spawned();
				Some(AcceptedRecord { name: "Spawn", instance })
			}
			Self::Manage(HiveManagement::Stop(stop)) => {
				let instance = Some(&stop.servlet_id);
				Some(AcceptedRecord { name: "Stop", instance })
			}
			Self::Heartbeat(_) | Self::Manage(HiveManagement::List(_)) => None,
		}
	}
}

impl ReplyShape {
	/// The shape a reply to `body` must use.
	///
	/// A body that does not decode as a command has no shape of its own, so
	/// its reply uses the stop alternative. It carries only a status, the one
	/// thing a refusal of an unreadable command can report.
	#[must_use]
	pub fn of(body: Option<&ClusterCommand>) -> Self {
		body.map_or(Self::Manage(ManageShape::Stop), ClusterCommand::reply_shape)
	}

	/// Whether a command answered in this shape yields to load.
	///
	/// A liveness command, the heartbeat, survives drain and backpressure,
	/// and its reply leads the queue, so a health check reports even under
	/// load. A management command yields to both.
	fn yields_to_load(self) -> bool {
		match self {
			Self::Heartbeat => false,
			Self::Manage(_) => true,
		}
	}

	/// The form a reply in this shape travels in.
	///
	/// The reply to a command that survives load travels at
	/// [`MessagePriority::NetworkControl`], and the reply to one that yields
	/// at the default priority.
	fn form(self) -> ReplyForm {
		if self.yields_to_load() {
			ReplyForm::Plain
		} else {
			ReplyForm::Prioritized(MessagePriority::NetworkControl)
		}
	}

	/// Answers the frame `id` with `response` in this shape, at the priority
	/// the shape names.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- `response` does not encode.
	/// - [`TightBeamError::BuildError`] -- the reply metadata fails validation.
	pub fn reply(
		self,
		id: impl AsRef<[u8]>,
		response: ClusterCommandResponse,
	) -> Result<Option<Frame>, TightBeamError> {
		self.form().reply(id, response)
	}

	/// Refuses the frame `id` with `status` in this shape.
	///
	/// The refusal body is [`ClusterCommandResponse::refusal`] and the
	/// frame is [`ReplyShape::reply`], so every refusal site shares one
	/// body and one priority rule.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- the refusal body does not encode.
	/// - [`TightBeamError::BuildError`] -- the reply metadata fails validation.
	pub fn refuse(self, id: impl AsRef<[u8]>, status: TransitStatus) -> Result<Option<Frame>, TightBeamError> {
		self.reply(id, ClusterCommandResponse::refusal(self, status))
	}
}

/// How a colony reply frame travels.
///
/// A reply echoes the id of its request at order 0. Its priority decides its
/// version, because a V2 frame is the first to carry a priority field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplyForm {
	/// A V0 frame at the default priority.
	Plain,
	/// A V2 frame at the priority it names.
	Prioritized(MessagePriority),
}

impl ReplyForm {
	/// Answers the frame `id` with `message` in this form.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the frame builder refuses the frame, such as when `message` fails to encode.
	pub(crate) fn reply<M: Message>(self, id: impl AsRef<[u8]>, message: M) -> Result<Option<Frame>, TightBeamError> {
		let frame = match self {
			Self::Plain => Version::V0.compose().with_id(id).with_order(0).with_message(message).build()?,
			Self::Prioritized(priority) => {
				let prioritized = Version::V2.compose().with_priority(priority);
				prioritized.with_id(id).with_order(0).with_message(message).build()?
			}
		};

		Ok(Some(frame))
	}
}

/// The parameters of a request that spawns one servlet instance.
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct SpawnServletParams {
	/// The type URN of the servlet to spawn, such as
	/// `urn:tightbeam::servlet:worker`.
	pub servlet_type: Urn<'static>,
	/// The servlet's configuration data, when the request carries any.
	pub config: Option<Vec<u8>>,
}

wire_sequence!(SpawnServletParams { servlet_type: plain, config: octets_opt });

/// The parameters of a request that lists servlets.
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct ListServletsParams {
	/// A filter that is reserved for future use.
	pub filter: Option<Vec<u8>>,
}

wire_sequence!(ListServletsParams { filter: octets_opt });

/// The parameters of a request that stops a servlet.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct StopServletParams {
	/// The instance URN of the servlet to stop.
	pub servlet_id: Urn<'static>,
}

/// The result of a spawn request.
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

/// The result of a list request.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ListServletsResult {
	/// The status of the request.
	pub status: TransitStatus,
	/// The servlets that are active on the hive.
	pub servlets: Vec<ServletInfo>,
}

/// The result of a stop request.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct StopServletResult {
	/// The status of the stop request.
	pub status: TransitStatus,
}

impl HiveManagementOutcome {
	/// Creates an `Ok` spawn result that names the spawned servlet's address
	/// and instance URN.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::protocol::HiveManagementOutcome;
	/// use tightbeam::colony::urn::ColonyNamespace;
	/// use tightbeam::policy::TransitStatus;
	///
	/// let worker = ColonyNamespace::default().servlet("worker")?;
	/// let instance = worker.servlet_instance("127.0.0.1:8080")?;
	///
	/// let spawned = HiveManagementOutcome::spawn_ok("127.0.0.1:8080", instance);
	/// assert!(matches!(spawned, HiveManagementOutcome::Spawn(result) if result.status == TransitStatus::Ok));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	#[inline]
	pub fn spawn_ok(address: impl Into<Vec<u8>>, servlet_id: Urn<'static>) -> Self {
		let address: Vec<u8> = address.into();
		let result = SpawnServletResult {
			status: TransitStatus::Ok,
			servlet_address: Some(address),
			servlet_id: Some(servlet_id),
		};

		Self::Spawn(result)
	}

	/// Creates an `Ok` list result that carries the hive's active `servlets`.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::protocol::HiveManagementOutcome;
	///
	/// let listed = HiveManagementOutcome::list_ok([]);
	/// assert!(matches!(listed, HiveManagementOutcome::List(result) if result.servlets.is_empty()));
	/// ```
	#[inline]
	pub fn list_ok(servlets: impl IntoIterator<Item = ServletInfo>) -> Self {
		let servlets: Vec<ServletInfo> = servlets.into_iter().collect();
		Self::List(ListServletsResult { status: TransitStatus::Ok, servlets })
	}

	/// Creates an `Ok` stop result.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::protocol::HiveManagementOutcome;
	/// use tightbeam::policy::TransitStatus;
	///
	/// let stopped = HiveManagementOutcome::stop_ok();
	/// assert!(matches!(stopped, HiveManagementOutcome::Stop(result) if result.status == TransitStatus::Ok));
	/// ```
	#[inline]
	pub fn stop_ok() -> Self {
		Self::Stop(StopServletResult { status: TransitStatus::Ok })
	}

	/// Refuses a management request with `status` in the alternative that
	/// `shape` names.
	///
	/// A spawn refusal names no address and no instance, and a list refusal
	/// names no servlets, so the sender reads the status and nothing else.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::protocol::{HiveManagementOutcome, ManageShape};
	/// use tightbeam::policy::TransitStatus;
	///
	/// let refused = HiveManagementOutcome::refusal(ManageShape::Spawn, TransitStatus::Unavailable);
	/// assert!(matches!(refused, HiveManagementOutcome::Spawn(result) if result.servlet_id.is_none()));
	/// ```
	#[must_use]
	pub fn refusal(shape: ManageShape, status: TransitStatus) -> Self {
		match shape {
			ManageShape::Spawn => Self::Spawn(SpawnServletResult { status, servlet_address: None, servlet_id: None }),
			ManageShape::List => Self::List(ListServletsResult { status, servlets: Vec::new() }),
			ManageShape::Stop => Self::Stop(StopServletResult { status }),
		}
	}
}

/// The status that a cluster reports in a heartbeat.
///
/// A hive may use it to adjust its behavior, such as a lower capacity while
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
	/// The cluster drains before it shuts down.
	Draining = 3,
}

/// The cluster command message, an ASN.1 CHOICE.
///
/// It carries one command from the cluster to a hive. The context-specific
/// tag names the command, and the encoding is the chosen alternative alone
/// (X.690 § 8.13). The management alternative tags its own CHOICE
/// explicitly, as X.680 § 31.2.9 requires of a tagged CHOICE.
///
/// # Security
///
/// - A command requires a nonrepudiation signature and frame integrity. A
///   hive refuses a frame without them as `Unauthenticated`. Only a signature
///   that fails to verify counts toward the circuit breaker.
/// - Freshness binds to `Frame.metadata.order` (unix milliseconds), so hives
///   reject commands outside their freshness window and replays of
///   already-seen signatures within it (CWE-294).
///
/// # Examples
///
/// ```
/// use tightbeam::colony::protocol::{ClusterCommand, ClusterStatus, HeartbeatParams};
/// use tightbeam::{decode, encode};
///
/// let heartbeat = ClusterCommand::Heartbeat(HeartbeatParams { cluster_status: ClusterStatus::Healthy });
///
/// let encoded = encode(&heartbeat)?;
/// assert_eq!(encoded, [0xa0, 0x05, 0x30, 0x03, 0x0a, 0x01, 0x00]);
/// assert_eq!(decode::<ClusterCommand>(&encoded)?, heartbeat);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Debug, Beamable, Choice, Clone, PartialEq)]
#[beam(frame_integrity)]
pub enum ClusterCommand {
	/// A heartbeat request [context 0].
	#[asn1(context_specific = "0", constructed = "true")]
	Heartbeat(HeartbeatParams),
	/// A hive management request [context 1].
	#[asn1(context_specific = "1", constructed = "true")]
	Manage(HiveManagement),
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

/// The cluster command response, an ASN.1 CHOICE.
///
/// A hive answers a cluster command with it, in the alternative of the
/// command. The context-specific tag names the answer, and the encoding is the
/// chosen alternative alone (X.690 § 8.13).
///
/// # Examples
///
/// ```
/// use tightbeam::colony::protocol::{ClusterCommandResponse, HiveManagementOutcome};
/// use tightbeam::{decode, encode};
///
/// let stopped = ClusterCommandResponse::Manage(HiveManagementOutcome::stop_ok());
///
/// let encoded = encode(&stopped)?;
/// assert_eq!(encoded, [0xa1, 0x07, 0xa2, 0x05, 0x30, 0x03, 0x0a, 0x01, 0x00]);
/// assert_eq!(decode::<ClusterCommandResponse>(&encoded)?, stopped);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Debug, Beamable, Choice, Clone, PartialEq)]
pub enum ClusterCommandResponse {
	/// The heartbeat answer [context 0].
	#[asn1(context_specific = "0", constructed = "true")]
	Heartbeat(HeartbeatResult),
	/// The management answer [context 1].
	#[asn1(context_specific = "1", constructed = "true")]
	Manage(HiveManagementOutcome),
}

impl ClusterCommand {
	/// The one command `frame` carries, or [`None`] for a frame that is no
	/// carrier of one ([`Frame::decode_message`]).
	///
	/// A frame that carries no command is the sender's own fault, so a
	/// refusal reads its reply shape from this answer through
	/// [`ReplyShape::of`].
	#[must_use]
	pub(crate) fn choice_of(frame: &Frame) -> Option<Self> {
		frame.decode_message::<Self>().ok()
	}
}

/// The heartbeat answer, with the hive's health status.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct HeartbeatResult {
	/// The overall status: `Ok` when the hive is healthy, `ResourceExhausted`
	/// when it is at capacity, and the refusal status when the hive refuses
	/// the heartbeat.
	pub status: TransitStatus,
	/// The current aggregate utilization across all servlets.
	pub utilization: BasisPoints,
	/// The number of active servlet instances.
	pub active_servlets: u32,
}

impl HeartbeatResult {
	/// The utilization of a hive that answered alive.
	///
	/// A hive at capacity answers `ResourceExhausted` and stays alive, because
	/// it still serves the work it holds.
	///
	/// # Errors
	///
	/// - [`TransitStatus`] -- the status of a hive that answered any status but `Ok` or `ResourceExhausted`.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::basis_points::BasisPoints;
	/// use tightbeam::colony::protocol::HeartbeatResult;
	/// use tightbeam::policy::TransitStatus;
	///
	/// let full = HeartbeatResult {
	///     status: TransitStatus::ResourceExhausted,
	///     utilization: BasisPoints::MAX,
	///     active_servlets: 2,
	/// };
	/// assert_eq!(full.liveness(), Ok(BasisPoints::MAX));
	///
	/// let refused = HeartbeatResult { status: TransitStatus::PermissionDenied, ..full };
	/// assert_eq!(refused.liveness(), Err(TransitStatus::PermissionDenied));
	/// ```
	pub fn liveness(&self) -> Result<BasisPoints, TransitStatus> {
		match self.status {
			TransitStatus::Ok | TransitStatus::ResourceExhausted => Ok(self.utilization),
			status => Err(status),
		}
	}
}

impl ClusterCommandResponse {
	/// Answers a heartbeat with the hive's status, utilization, and servlet
	/// count.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::basis_points::BasisPoints;
	/// use tightbeam::colony::protocol::ClusterCommandResponse;
	/// use tightbeam::policy::TransitStatus;
	///
	/// let alive = ClusterCommandResponse::heartbeat(TransitStatus::Ok, BasisPoints::default(), 2);
	/// assert!(matches!(alive, ClusterCommandResponse::Heartbeat(result) if result.active_servlets == 2));
	/// ```
	#[inline]
	pub fn heartbeat(status: TransitStatus, utilization: BasisPoints, active_servlets: u32) -> Self {
		Self::Heartbeat(HeartbeatResult { status, utilization, active_servlets })
	}

	/// Refuses a command with `status` in the alternative that `shape` names.
	///
	/// It is the one refusal constructor, so a refusal answers in the
	/// alternative its sender decodes. A heartbeat refusal reports no
	/// capacity, and a management refusal is
	/// [`HiveManagementOutcome::refusal`] in its own alternative.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::protocol::{ClusterCommandResponse, ReplyShape};
	/// use tightbeam::policy::TransitStatus;
	///
	/// let refused = ClusterCommandResponse::refusal(ReplyShape::Heartbeat, TransitStatus::PermissionDenied);
	/// assert!(matches!(refused, ClusterCommandResponse::Heartbeat(result) if result.active_servlets == 0));
	/// ```
	#[must_use]
	pub fn refusal(shape: ReplyShape, status: TransitStatus) -> Self {
		match shape {
			ReplyShape::Heartbeat => Self::heartbeat(status, BasisPoints::default(), 0),
			ReplyShape::Manage(manage) => Self::Manage(HiveManagementOutcome::refusal(manage, status)),
		}
	}

	/// The instance that this response names as spawned, for the answer to a
	/// spawn.
	pub(crate) fn spawned(&self) -> Option<&Urn<'static>> {
		let Self::Manage(HiveManagementOutcome::Spawn(spawned)) = self else {
			return None;
		};

		spawned.servlet_id.as_ref()
	}
}

/// The issue time a colony frame states.
///
/// The frame layer leaves `metadata.order` protocol-opaque. Colony control
/// frames, rumors, and advertisements all put their issue time there as unix
/// milliseconds (§5.7.1 permits a time-based order). It is the one place
/// that reads it, so every freshness and replay decision compares the same
/// instant.
pub(crate) trait IssuedAt {
	/// The issue time this frame states.
	fn issued_at(&self) -> UnixMillis;
}

impl IssuedAt for Frame {
	fn issued_at(&self) -> UnixMillis {
		UnixMillis::new(self.metadata().order())
	}
}

/// The issue times one sender stamps on the signed control frames it sends.
///
/// Each stamp is the clock's reading, or one millisecond past the stamp
/// before it while the clock has not passed that stamp. The stamps of one
/// sender so increase strictly (README §5.7.1), and a receiver, whose replay
/// guard refuses a second frame of one signer at one order, admits each frame
/// the sender issues.
pub(crate) struct IssueClock {
	clock: Arc<dyn Clock>,
	/// The least instant the next stamp may take.
	floor: AtomicU64,
}

impl IssueClock {
	/// A sender's stamps on `clock`.
	pub(crate) fn new(clock: Arc<dyn Clock>) -> Self {
		Self { clock, floor: AtomicU64::new(0) }
	}

	/// The issue time of the next control frame: the later of the clock's
	/// reading and the floor that the stamp before it left.
	pub(crate) fn issue(&self) -> IssuedOrder {
		let now = self.clock.unix().get();
		let advance = |floor: u64| Some(now.max(floor).saturating_add(1));

		// The closure returns `Some` for every floor, so the update lands, and
		// either arm carries the floor it replaced.
		let (Ok(floor) | Err(floor)) = self.floor.fetch_update(Ordering::AcqRel, Ordering::Acquire, advance);

		IssuedOrder(UnixMillis::new(now.max(floor)))
	}
}

/// An issue time that an [`IssueClock`] stamped, which a signed control frame
/// states in `metadata.order`.
///
/// [`IssueClock::issue`] alone makes one, so a control frame that a builder
/// stamps from it takes the strictly increasing order of its sender (README
/// §5.7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IssuedOrder(UnixMillis);

impl IssuedOrder {
	/// The instant of this stamp.
	pub(crate) const fn instant(self) -> UnixMillis {
		self.0
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::asn1::admission::fixtures::der_refusal;
	use crate::asn1::Version;
	use crate::builder::{FrameBuilder, TypeBuilder};
	use crate::clock::ManualClock;
	use crate::colony::urn::ColonyNamespace;
	use crate::crypto::hash::Sha3_256;
	use crate::der::{DecodeOwned, Encode, ErrorKind, Tag, TagNumber};
	use crate::tb_cases;
	use crate::testing::fixtures::{der_round_trip, TestClock};
	use crate::testing::TestResult;

	/// An issue clock over a manual clock, beside that clock.
	fn issue_clock() -> (IssueClock, Arc<ManualClock>) {
		let clock = TestClock::manual();
		(IssueClock::new(TestClock::erased(&clock)), clock)
	}

	/// Two control frames issued at one clock reading take two orders, one
	/// millisecond apart, so a receiver admits both (README §5.7.1).
	#[test]
	fn two_frames_issued_at_one_instant_take_two_orders() {
		let (issue, clock) = issue_clock();
		let stamps = (issue.issue().instant(), issue.issue().instant());
		let next = clock.unix().saturating_add(core::time::Duration::from_millis(1));
		assert_eq!(stamps, (clock.unix(), next));
	}

	/// A stamp after the clock passes the floor is the clock's reading.
	#[test]
	fn a_stamp_after_the_clock_moves_on_is_its_reading() {
		let (issue, clock) = issue_clock();
		let _first = issue.issue();
		clock.advance(core::time::Duration::from_secs(1));
		assert_eq!(issue.issue().instant(), clock.unix());
	}

	fn work_frame() -> Frame {
		Frame::v0(b"work-1", vec![0x02, 0x01, 0x2A])
	}

	/// The work request of `ping` that carries [`work_frame`].
	fn work_request() -> ClusterWorkRequest {
		let request = ClusterWorkRequest::new(ColonyNamespace::servlet_fixture("ping"), &work_frame());
		request.expect("the fixture frame encodes")
	}

	/// The DER of [`work_request`], with no envelope tag around it.
	fn work_request_der() -> Vec<u8> {
		encode(&work_request()).expect("the fixture request encodes")
	}

	/// The `Ok` work response whose payload is the encoding of
	/// [`work_frame`].
	fn ok_response() -> ClusterWorkResponse {
		ClusterWorkResponse::ok(encode(&work_frame()).expect("the fixture frame encodes"))
	}

	/// A V1 frame whose body is `body`, beside the frame integrity digest that
	/// a carrier of a `ClusterCommand` requires.
	fn witnessed_frame(body: impl Into<Vec<u8>>) -> Frame {
		let heartbeat = ClusterCommand::Heartbeat(healthy());
		let builder = FrameBuilder::from(Version::V1)
			.with_id(b"command-1")
			.with_order(1)
			.with_message(heartbeat);
		let witnessed = builder
			.with_witness_hasher::<Sha3_256>()
			.build()
			.expect("a witnessed command builds");

		let (metadata, integrity) = (witnessed.metadata().clone(), witnessed.integrity().cloned());
		Frame::assemble(Version::V1, metadata, body, integrity).expect("a V1 frame carries frame integrity")
	}

	/// A frame whose body is the DER encoding of `command`.
	fn command_frame(command: &ClusterCommand) -> Frame {
		let body = encode(command).expect("a cluster command encodes");
		witnessed_frame(body)
	}

	/// The parameters of a heartbeat from a healthy cluster.
	fn healthy() -> HeartbeatParams {
		HeartbeatParams { cluster_status: ClusterStatus::Healthy }
	}

	/// The DER of a heartbeat command from a healthy cluster: the `[0]`
	/// alternative around `HeartbeatParams`, a SEQUENCE of one ENUMERATED 0.
	const HEARTBEAT_COMMAND: [u8; 7] = [0xa0, 0x05, 0x30, 0x03, 0x0a, 0x01, 0x00];

	/// The DER of a list request: the `[1]` alternative around
	/// `ListServletsParams`, an empty SEQUENCE.
	const LIST_REQUEST: [u8; 4] = [0xa1, 0x02, 0x30, 0x00];

	/// The DER of an `Ok` stop result: the `[2]` alternative around
	/// `StopServletResult`, a SEQUENCE of one ENUMERATED 0.
	const STOP_OUTCOME: [u8; 7] = [0xa2, 0x05, 0x30, 0x03, 0x0a, 0x01, 0x00];

	/// A frame that carries one command reads as that command.
	#[test]
	fn choice_of_reads_the_one_command_a_frame_carries() {
		let frame = command_frame(&ClusterCommand::Heartbeat(healthy()));
		let choice = ClusterCommand::choice_of(&frame);
		assert_eq!(choice, Some(ClusterCommand::Heartbeat(healthy())));
	}

	// A frame carries a command only when its body is one command and the
	// frame carries the integrity digest that `ClusterCommand` requires.
	tb_cases! {
		fn choice_of_finds_no_command(frame: Frame) {
			let choice = ClusterCommand::choice_of(&frame);

			assert_eq!(choice, None);
		}
		cases {
			/// A CHOICE value is one alternative, so a body that spells a
			/// second alternative after the first holds trailing data.
			in_a_body_that_names_two_commands => witnessed_frame(
				[HEARTBEAT_COMMAND.as_slice(), [0xa1, 0x04].as_slice(), LIST_REQUEST.as_slice()].concat(),
			),
			in_a_body_that_is_no_command => witnessed_frame(work_frame().message()),
			/// A frame without frame integrity carries no command, whatever
			/// its body holds.
			in_a_command_frame_without_frame_integrity => Frame::v0(b"command-1", HEARTBEAT_COMMAND),
		}
	}

	/// The rumor frame of an application payload, issued at order 1,000.
	fn gossip_frame() -> Frame {
		let rumor_body = GossipRumor::application(vec![0x02, 0x01, 0x2A]);
		let rumor = FrameBuilder::from(Version::V0)
			.with_id("rumor-1")
			.with_order(1_000)
			.with_message(rumor_body)
			.build();

		rumor.expect("an unsigned rumor builds")
	}

	// Each request alternative decodes to the request it encodes.
	tb_cases! {
		fn a_cluster_request_round_trips(request: ClusterRequest) {
			assert_eq!(der_round_trip(&request), request);
		}
		cases {
			register_hive => ClusterRequest::RegisterHive(RegisterHiveRequest {
				hive_addr: b"127.0.0.1:9000".to_vec(),
				servlet_addresses: vec![ServletInfo::fixture("127.0.0.1:9001")],
				metadata: None,
			}),
			servlet_address_update => ClusterRequest::ServletAddressUpdate(ServletAddressUpdate {
				hive_id: ColonyNamespace::hive_fixture("127.0.0.1:9000"),
				added: vec![],
				removed: vec![ColonyNamespace::instance_fixture("ping", "127.0.0.1:9100")],
			}),
			work => ClusterRequest::Work(work_request()),
			advertise_peer => ClusterRequest::AdvertisePeer(PeerAdvertisement {
				gateway_addr: b"127.0.0.1:9000".to_vec(),
				advertised_types: vec![ColonyNamespace::servlet_fixture("ping")],
			}),
			gossip => ClusterRequest::Gossip(Box::new(gossip_frame())),
			publish_gossip => ClusterRequest::PublishGossip(GossipRumor::application(vec![0x02, 0x01, 0x2A])),
			reconcile_gossip => ClusterRequest::ReconcileGossip(GossipReconciliation {
				held: vec![vec![0xAAu8; 32], vec![0xBBu8; 32]],
			}),
			reconcile_gossip_empty => ClusterRequest::ReconcileGossip(GossipReconciliation { held: vec![] }),
		}
	}

	// A want list decodes to the want list it encodes, with or without a
	// peer exchange.
	tb_cases! {
		fn a_gossip_want_round_trips(want: GossipWant) {
			assert_eq!(der_round_trip(&want), want);
		}
		cases {
			with_pex => GossipWant {
				want: vec![vec![0xAAu8; 32]],
				pex: vec![PeerGossip { peer_id: vec![1, 2, 3], gateway_addr: b"127.0.0.1:9100".to_vec() }],
			},
			empty => GossipWant { want: vec![], pex: vec![] },
		}
	}

	// The status and the payload of a work response are the ones its
	// constructor names, from owned bytes or a byte slice.
	tb_cases! {
		fn a_work_response_carries((response, status, payload): (ClusterWorkResponse, TransitStatus, Option<Vec<u8>>)) {
			assert_eq!((response.status, response.payload), (status, payload));
		}
		cases {
			ok_of_owned_bytes => (ClusterWorkResponse::ok(b"test".to_vec()), TransitStatus::Ok, Some(b"test".to_vec())),
			ok_of_a_byte_slice => (ClusterWorkResponse::ok(b"test"), TransitStatus::Ok, Some(b"test".to_vec())),
			err => (ClusterWorkResponse::err(TransitStatus::PermissionDenied), TransitStatus::PermissionDenied, None),
		}
	}

	// An `Ok` response yields the frame its payload encodes, and a refusal
	// yields none.
	tb_cases! {
		fn a_work_response_into_frame_yields_its_payload((response, frame): (ClusterWorkResponse, Option<Frame>))
			-> TestResult
		{
			let yielded = response.into_frame()?;

			assert_eq!(yielded, frame);
			Ok(())
		}
		cases {
			ok => (ok_response(), Some(work_frame())),
			err => (ClusterWorkResponse::err(TransitStatus::Unavailable), None),
		}
	}

	/// An `Ok` work response serves the frame its payload encodes.
	#[test]
	fn work_response_served_yields_frame() -> TestResult {
		let served = ok_response().served()?;
		assert_eq!(served, work_frame());
		Ok(())
	}

	/// A refusal serves as a work refusal that names its status.
	#[test]
	fn work_response_served_maps_refusal_to_work_refused() {
		let served = ClusterWorkResponse::err(TransitStatus::Unavailable).served();
		assert!(matches!(served, Err(TightBeamError::WorkRefused(TransitStatus::Unavailable))));
	}

	/// An `Ok` work response with no payload serves no frame.
	#[test]
	fn work_response_served_rejects_ok_without_payload() {
		let response = ClusterWorkResponse { status: TransitStatus::Ok, payload: None };
		assert!(matches!(response.served(), Err(TightBeamError::MissingResponse)));
	}

	/// The DER of `value`, beside what that DER decodes to.
	fn known_answer<T: Encode + DecodeOwned>(value: &T) -> (Vec<u8>, T) {
		let encoded = encode(value).expect("the value encodes");
		let decoded = decode(&encoded).expect("what the encoder wrote, the decoder reads");
		(encoded, decoded)
	}

	// A command encodes as its chosen alternative, an EXPLICIT context tag
	// around the alternative's own encoding (X.690 § 8.13, § 8.14). The
	// management alternative tags the management CHOICE explicitly, so its
	// encoding nests the request's own tag (X.680 § 31.2.9).
	tb_cases! {
		fn a_command_round_trips_through_its_known_answer((command, der): (ClusterCommand, Vec<u8>)) {
			assert_eq!(known_answer(&command), (der, command));
		}
		cases {
			heartbeat => (ClusterCommand::Heartbeat(healthy()), HEARTBEAT_COMMAND.to_vec()),
			manage => (
				ClusterCommand::Manage(HiveManagement::List(ListServletsParams { filter: None })),
				[[0xa1, 0x04].as_slice(), LIST_REQUEST.as_slice()].concat(),
			),
		}
	}

	/// A management request encodes to its known answer and decodes back.
	#[test]
	fn a_management_request_round_trips_through_its_known_answer() {
		let request = HiveManagement::List(ListServletsParams { filter: None });
		assert_eq!(known_answer(&request), (LIST_REQUEST.to_vec(), request));
	}

	/// A management outcome encodes to its known answer and decodes back.
	#[test]
	fn a_management_outcome_round_trips_through_its_known_answer() {
		let outcome = HiveManagementOutcome::stop_ok();
		assert_eq!(known_answer(&outcome), (STOP_OUTCOME.to_vec(), outcome));
	}

	/// The DER of the `HeartbeatResult` of an `Ok` beat at zero utilization
	/// and zero servlets: a SEQUENCE of an ENUMERATED status and two INTEGER
	/// fields.
	const HEARTBEAT_RESULT: [u8; 11] = [0x30, 0x09, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00];

	// A response encodes as its alternative, an EXPLICIT context tag around
	// the result it carries.
	tb_cases! {
		fn a_command_response_round_trips_through_its_known_answer(
			(response, der): (ClusterCommandResponse, Vec<u8>)
		) {
			assert_eq!(known_answer(&response), (der, response));
		}
		cases {
			heartbeat => (
				ClusterCommandResponse::heartbeat(TransitStatus::Ok, BasisPoints::default(), 0),
				[[0xa0, 0x0b].as_slice(), HEARTBEAT_RESULT.as_slice()].concat(),
			),
			manage => (
				ClusterCommandResponse::Manage(HiveManagementOutcome::stop_ok()),
				[[0xa1, 0x07].as_slice(), STOP_OUTCOME.as_slice()].concat(),
			),
		}
	}

	/// The kind of error a decode of `bytes` as `T` meets.
	fn decode_refusal<T: DecodeOwned>(bytes: &[u8]) -> Option<ErrorKind> {
		der_refusal(T::from_der(bytes))
	}

	/// The refusal a CHOICE decoder gives a SEQUENCE where it reads an
	/// alternative tag.
	fn sequence_refused() -> Option<ErrorKind> {
		Some(ErrorKind::TagUnexpected { expected: None, actual: Tag::Sequence })
	}

	/// A decode of bytes as one CHOICE type, which returns the kind of its
	/// error.
	type RefusalOf = fn(&[u8]) -> Option<ErrorKind>;

	// A CHOICE spelled as a SEQUENCE of OPTIONAL fields decodes as no value,
	// whether it names none, one, or each of its alternatives, at the top
	// and inside an alternative. A bare request without the alternative tag
	// of its envelope is the same SEQUENCE.
	tb_cases! {
		fn a_value_of_the_sequence_shape_fails_to_decode((refusal_of, sequence): (RefusalOf, Vec<u8>)) {
			assert_eq!(refusal_of(&sequence), sequence_refused());
		}
		cases {
			command_naming_none => (decode_refusal::<ClusterCommand>, vec![0x30, 0x00]),
			command_naming_the_heartbeat => (
				decode_refusal::<ClusterCommand>,
				[[0x30, 0x07].as_slice(), HEARTBEAT_COMMAND.as_slice()].concat(),
			),
			command_naming_both => (
				decode_refusal::<ClusterCommand>,
				[
					[0x30, 0x0f].as_slice(),
					HEARTBEAT_COMMAND.as_slice(),
					[0xa1, 0x06, 0x30, 0x04].as_slice(),
					LIST_REQUEST.as_slice(),
				]
				.concat(),
			),
			/// The SEQUENCE fails inside the `[1]` alternative.
			manage_command_around_a_management_sequence => (
				decode_refusal::<ClusterCommand>,
				[[0xa1, 0x06, 0x30, 0x04].as_slice(), LIST_REQUEST.as_slice()].concat(),
			),
			management_request => (
				decode_refusal::<HiveManagement>,
				[[0x30, 0x04].as_slice(), LIST_REQUEST.as_slice()].concat(),
			),
			management_outcome => (
				decode_refusal::<HiveManagementOutcome>,
				[[0x30, 0x07].as_slice(), STOP_OUTCOME.as_slice()].concat(),
			),
			/// A SEQUENCE around a management SEQUENCE.
			response => (
				decode_refusal::<ClusterCommandResponse>,
				[[0x30, 0x0b, 0xa1, 0x09, 0x30, 0x07].as_slice(), STOP_OUTCOME.as_slice()].concat(),
			),
			bare_work_request_without_its_envelope_tag => (decode_refusal::<ClusterRequest>, work_request_der()),
		}
	}

	/// The refusal a CHOICE decoder gives the constructed context tag
	/// `[number]` where none of its alternatives carries that tag.
	fn unknown_alternative(number: TagNumber) -> Option<ErrorKind> {
		let actual = Tag::ContextSpecific { constructed: true, number };
		Some(ErrorKind::TagUnexpected { expected: None, actual })
	}

	// A command that names an alternative its CHOICE does not define decodes
	// as no command, at the top and inside the `[1]` management alternative
	// (X.690 § 8.13).
	tb_cases! {
		fn a_command_of_an_unknown_alternative_fails_to_decode((body, number): (Vec<u8>, TagNumber)) {
			assert_eq!(decode_refusal::<ClusterCommand>(&body), unknown_alternative(number));
		}
		cases {
			at_the_command => (vec![0xa2, 0x05, 0x30, 0x03, 0x0a, 0x01, 0x00], TagNumber::N2),
			inside_the_management_alternative => (vec![0xa1, 0x04, 0xa3, 0x02, 0x30, 0x00], TagNumber::N3),
		}
	}

	// A field after the one value an alternative holds is trailing data,
	// inside the EXPLICIT `[0]` tag and inside `HeartbeatParams` alike
	// (X.690 § 8.14).
	tb_cases! {
		fn a_command_with_a_trailing_field_fails_to_decode(body: Vec<u8>) {
			let refused = decode_refusal::<ClusterCommand>(&body);
			assert!(matches!(refused, Some(ErrorKind::TrailingData { .. })));
		}
		cases {
			inside_the_heartbeat_alternative => vec![0xa0, 0x07, 0x30, 0x03, 0x0a, 0x01, 0x00, 0x05, 0x00],
			inside_the_heartbeat_parameters => vec![0xa0, 0x07, 0x30, 0x05, 0x0a, 0x01, 0x00, 0x05, 0x00],
		}
	}

	/// The shape a sender would read `response` in, with the status it
	/// carries.
	fn answered_shape(response: ClusterCommandResponse) -> (ReplyShape, TransitStatus) {
		match response {
			ClusterCommandResponse::Heartbeat(heartbeat) => (ReplyShape::Heartbeat, heartbeat.status),
			ClusterCommandResponse::Manage(HiveManagementOutcome::Spawn(spawn)) => {
				(ReplyShape::Manage(ManageShape::Spawn), spawn.status)
			}
			ClusterCommandResponse::Manage(HiveManagementOutcome::List(list)) => {
				(ReplyShape::Manage(ManageShape::List), list.status)
			}
			ClusterCommandResponse::Manage(HiveManagementOutcome::Stop(stop)) => {
				(ReplyShape::Manage(ManageShape::Stop), stop.status)
			}
		}
	}

	// A liveness command survives drain and backpressure, and a management
	// command yields to both.
	tb_cases! {
		fn a_command_yields_to_load_by_its_kind((command, yields): (ClusterCommand, bool)) {
			assert_eq!(command.yields_to_load(), yields);
		}
		cases {
			heartbeat => (ClusterCommand::Heartbeat(healthy()), false),
			manage => (ClusterCommand::Manage(HiveManagement::List(ListServletsParams { filter: None })), true),
		}
	}

	// A refusal answers in the one alternative its shape names, so the
	// sender decodes it in the shape it asked in.
	tb_cases! {
		fn a_refusal_answers_in_the_alternative_its_shape_names(shape: ReplyShape) {
			let status = TransitStatus::ResourceExhausted;
			let refusal = ClusterCommandResponse::refusal(shape, status);
			assert_eq!(answered_shape(refusal), (shape, status));
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
		fn a_command_names_its_own_alternative((command, shape): (ClusterCommand, ReplyShape)) {
			assert_eq!(ReplyShape::of(Some(&command)), shape);
		}

		cases {
			heartbeat => (ClusterCommand::Heartbeat(healthy()), ReplyShape::Heartbeat),
			spawn => (
				ClusterCommand::Manage(HiveManagement::Spawn(SpawnServletParams {
					servlet_type: ColonyNamespace::servlet_fixture("ping"),
					config: None,
				})),
				ReplyShape::Manage(ManageShape::Spawn),
			),
			list => (
				ClusterCommand::Manage(HiveManagement::List(ListServletsParams { filter: None })),
				ReplyShape::Manage(ManageShape::List),
			),
			stop => (
				ClusterCommand::Manage(HiveManagement::Stop(StopServletParams {
					servlet_id: ColonyNamespace::instance_fixture("ping", "127.0.0.1:9001"),
				})),
				ReplyShape::Manage(ManageShape::Stop),
			),
		}
	}

	/// The reply to a body that decodes as no command uses the stop
	/// alternative, which carries only the status a refusal has to report.
	#[test]
	fn an_unreadable_command_is_answered_in_the_stop_alternative() {
		assert_eq!(ReplyShape::of(None), ReplyShape::Manage(ManageShape::Stop));
	}

	/// The reply frame that `shape` builds around `response`.
	fn reply_of(shape: ReplyShape, response: ClusterCommandResponse) -> Frame {
		let reply = shape.reply(b"reply", response).expect("a reply frame builds");
		reply.expect("a reply shape answers a response")
	}

	// A heartbeat reply travels on a V2 frame at network-control priority, so
	// a health check answered under load leads the queue. A management reply
	// travels on a V0 frame, which has no priority field.
	tb_cases! {
		fn a_reply_travels_at_its_shape_priority(
			(shape, response, priority): (ReplyShape, ClusterCommandResponse, Option<MessagePriority>)
		) {
			let reply = reply_of(shape, response);

			assert_eq!(reply.metadata().priority(), priority);
		}
		cases {
			heartbeat => (
				ReplyShape::Heartbeat,
				ClusterCommandResponse::heartbeat(TransitStatus::Ok, BasisPoints::default(), 0),
				Some(MessagePriority::NetworkControl),
			),
			manage => (
				ReplyShape::Manage(ManageShape::Stop),
				ClusterCommandResponse::Manage(HiveManagementOutcome::stop_ok()),
				None,
			),
		}
	}

	/// The utilization of a live hive, or the status of a failed beat.
	type Liveness = core::result::Result<BasisPoints, TransitStatus>;

	// A hive that answers `Ok` or `ResourceExhausted` is alive at the
	// utilization it reports, and any other status fails the beat with that
	// status.
	tb_cases! {
		fn a_heartbeat_answer_is_alive_by_its_status((status, expected): (TransitStatus, Liveness)) {
			let answer = HeartbeatResult { status, utilization: crate::bps!(4000), active_servlets: 1 };
			assert_eq!(answer.liveness(), expected);
		}
		cases {
			healthy => (TransitStatus::Ok, Ok(crate::bps!(4000))),
			at_capacity => (TransitStatus::ResourceExhausted, Ok(crate::bps!(4000))),
			refused => (TransitStatus::Unavailable, Err(TransitStatus::Unavailable)),
		}
	}
}
