//! Peer-advertisement admission for the cluster gateway.

use core::str::FromStr;
use std::sync::Arc;

use super::{ClusterConfig, PeerHint, PheromoneConfig, ServletEntry, SharedId};
use crate::colony::common::ColonyResource;
use crate::colony::common::{ClusterWorkRequest, ColonyNamespace, PeerAdvertisement};
use crate::constants::{DEFAULT_HOP_BUDGET, MAX_ADVERTISED_TYPES};
use crate::crypto::x509::store::{CertificateTrust, CertificateTrustStore};
use crate::crypto::x509::utils::CertificateExt;
use crate::crypto::x509::Certificate;
use crate::policy::TransitStatus;
use crate::transport::multiplex::StreamRoute;
use crate::transport::tcp::TightBeamSocketAddr;
use crate::utils::urn::Urn;
use crate::x509::ext::pkix::name::GeneralName;
use crate::x509::ext::pkix::SubjectAltName;
use crate::Frame;

/// Forwards a work request or routed stream open may still spend.
///
/// The wire carries a raw count, so the budget is parsed once at the
/// gateway boundary through [`HopBudget::from_wire`], which clamps it to
/// the operator's [`PeerConfig::max_hops`]. Every downstream rule reads
/// this value rather than the raw octet, so a peer cannot spend more
/// forwards than the operator allows (CWE-770).
///
/// [`PeerConfig::max_hops`]: super::PeerConfig::max_hops
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HopBudget {
	/// Forwards this gateway may still spend, under the operator's cap.
	remaining: u8,
	/// Whether the sender had already spent part of the budget.
	relayed: bool,
}

impl HopBudget {
	/// Clamps a wire budget to the operator's cap.
	///
	/// An origin request carries the sentinel budget, so the clamp also
	/// stamps the origin with the local cap.
	#[must_use]
	pub fn from_wire(wire: u8, max_hops: u8) -> Self {
		Self { remaining: wire.min(max_hops), relayed: wire != DEFAULT_HOP_BUDGET }
	}

	/// Spends one forward, saturating at zero.
	#[must_use]
	pub fn spend(self) -> Self {
		Self { remaining: self.remaining.saturating_sub(1), relayed: self.relayed }
	}

	/// Whether a peer already spent part of this budget.
	///
	/// An origin request arrives carrying the sentinel, so anything below
	/// it reached this gateway through at least one relay. The answer is
	/// read from the wire count before the cap clamps it, because a cap
	/// below the sentinel would otherwise make every origin request look
	/// relayed. The export boundary reads this to tell a direct caller
	/// from a relayed one.
	#[must_use]
	pub fn is_relayed(&self) -> bool {
		self.relayed
	}

	/// Whether the budget affords a forward to a peer gateway.
	#[must_use]
	pub fn allows_forward(&self) -> bool {
		self.remaining > 0
	}

	/// Whether the budget affords the two forwards a relay trail needs.
	///
	/// A relay trail spends one hop at the relay before the owner is
	/// reached, so a shorter budget could never select it.
	#[must_use]
	pub fn allows_relay_trail(&self) -> bool {
		self.remaining >= 2
	}

	/// The count this budget puts back on the wire.
	#[must_use]
	pub fn wire(&self) -> u8 {
		self.remaining
	}

	/// Relayed stream route for one peer hop out of this budget.
	///
	/// The route reaches the same `target` with one forward spent. Minting
	/// it through the budget is what spends the hop, so a relay cannot
	/// stamp a route it did not pay for (CWE-834).
	#[must_use]
	pub(crate) fn relayed_route(self, target: &Urn<'static>) -> StreamRoute {
		StreamRoute::relayed_to(target.clone(), self.spend().wire())
	}

	/// Relayed work envelope for one peer hop out of this budget.
	///
	/// The unary twin of [`Self::relayed_route`]. `payload` is already the
	/// client's encoded frame and travels opaquely, so a relay hop
	/// re-encodes nothing.
	#[must_use]
	pub(crate) fn relayed_work(self, servlet_type: Urn<'static>, payload: Vec<u8>) -> ClusterWorkRequest {
		ClusterWorkRequest { servlet_type, payload, hops_remaining: self.spend().wire() }
	}

	/// A budget clamped to the default cap, for tests that pick a wire count.
	#[cfg(test)]
	pub(crate) fn for_test(wire: u8) -> Self {
		Self::from_wire(wire, DEFAULT_HOP_BUDGET)
	}
}

/// Peer advertisement that passed signer resolution and wire checks.
///
/// [`AdmittedPeerAd::admit`] is the only public path: the registry never
/// receives an unvalidated slate, and signer identity cannot be
/// transposed with the claimed dial address.
pub struct AdmittedPeerAd {
	/// Signer cert fingerprint (claimed address when x509 is off)
	pub(super) peer_hive_id: SharedId,
	/// Claimed gateway socket every slate entry dials
	pub(super) dial_addr: SharedId,
	/// Peer-routed entries keyed by `peer_hive_id NUL type`
	pub(super) slate: Vec<ServletEntry>,
	/// Issue order of the signed advertisement frame. Reconciliation
	/// refuses an order older than the newest applied (CWE-294).
	pub(super) order: u64,
}

/// Fallback trails for one admitted advertisement through one relay.
///
/// The slate reconciles under the composite `origin NUL relay` bucket,
/// so relay trails live and die independently of the origin's direct
/// slate. The origin's next direct advertisement cannot evict them.
/// A dead relay decays away by staleness pruning.
pub struct RelayTrail {
	/// The composite `origin NUL relay` bucket this slate reconciles under.
	pub(super) bucket: SharedId,
	/// Relay-routed entries keyed by `bucket NUL type`.
	pub(super) slate: Vec<ServletEntry>,
	/// Issue order of the advertisement the trails derive from.
	pub(super) order: u64,
}

impl AdmittedPeerAd {
	/// Admit a wire advertisement. Fail closed with a refusal status.
	///
	/// Resolves the signer (slates key by cert fingerprint, never claimed
	/// `gateway_addr`), gates colony membership (local and peer certs
	/// must carry a colony URN SAN), then runs wire checks. Caps and
	/// local-route conflicts are registry policy under
	/// [`super::ServletRegistry::reconcile_peer_slate`].
	pub fn admit(frame: &Frame, ad: &PeerAdvertisement, conf: &ClusterConfig) -> Result<Self, TransitStatus> {
		let dial_addr: SharedId = Arc::from(ad.gateway_addr.as_slice());

		// The signer certificate resolves exactly once. The slate key
		// (fingerprint) and the membership gate both derive from it.
		let signer_cert =
			frame_signer_cert(conf.tls.peer_trust.as_deref(), frame).ok_or(TransitStatus::PermissionDenied)?;
		let peer_hive_id = signer_cert.fingerprint_id().ok_or(TransitStatus::PermissionDenied)?;

		// Federation is a colony operation: both this gateway and the
		// advertising peer must carry a valid colony URN SAN. A cert
		// without one still serves general transport and work, never
		// membership. Without x509 there is no certificate to carry
		// membership, so no gate applies.
		{
			let local_member = conf.colony_urn().is_some();
			let peer_member = conf.namespace.cert_colony_urn(signer_cert).is_some();
			if !(local_member && peer_member) {
				return Err(TransitStatus::PermissionDenied);
			}
		}

		peer_advertisement_wire_ok(
			&ad.gateway_addr,
			&ad.advertised_types,
			&conf.namespace,
			conf.peer.peer_dial_allowlist.as_deref(),
		)?;

		let dial = Arc::clone(&dial_addr);
		let slate = conf.pheromone.peer_slate(&peer_hive_id, dial, &ad.advertised_types);

		Ok(Self { peer_hive_id, dial_addr, slate, order: frame.metadata.order })
	}

	/// Relay trails through `relay_id`, the gateway that relayed this
	/// advertisement: one per advertised type, dialing `relay_dial`.
	///
	/// Routing then holds two trails per type: the direct trail dialing
	/// the origin, and a relay trail through the relaying peer.
	/// Pheromone feedback can therefore fail over to the relay when
	/// the origin is unreachable. The trails reconcile under their own
	/// `origin NUL relay` bucket
	/// ([`super::ServletRegistry::reconcile_relay_trail`]), so the
	/// origin's direct slate lifecycle never evicts the fallback.
	/// Returns `None` when the relay is the origin itself (the direct
	/// trail already dials it) or when the slate advertises nothing.
	#[must_use]
	pub fn relay_trail(
		&self,
		relay_id: &SharedId,
		relay_dial: SharedId,
		pheromone: &PheromoneConfig,
	) -> Option<RelayTrail> {
		if relay_id.as_ref() == self.peer_hive_id.as_ref() {
			return None;
		}
		if self.slate.is_empty() {
			return None;
		}

		let bucket = ServletEntry::relay_bucket(&self.peer_hive_id, relay_id);
		let slate: Vec<ServletEntry> = self
			.slate
			.iter()
			.map(|entry| {
				ServletEntry::peer_relay(
					Arc::clone(&self.peer_hive_id),
					Arc::clone(relay_id),
					Arc::clone(entry.servlet_type()),
					Arc::clone(&relay_dial),
					pheromone.initial_pheromone,
					pheromone.abandonment_limit,
				)
			})
			.collect();

		Some(RelayTrail { bucket, slate, order: self.order })
	}

	/// Discovery hint from this admitted advertisement: the verified
	/// signer's claimed dial address plus its certificate fingerprint.
	///
	/// The advertiser dialed this gateway, so nothing proves the claimed
	/// address dials back yet. The peer table holds the hint in `new`
	/// until this gateway's own probe passes the colony gate. The
	/// Bitcoin address manager holds a self-announced address the same
	/// way.
	///
	/// The hint owns its fields because it outlives this borrowed
	/// advertisement inside the peer table.
	#[must_use]
	pub fn discovery_hint(&self) -> Option<PeerHint> {
		let gateway_addr = core::str::from_utf8(&self.dial_addr).ok()?;

		Some(PeerHint {
			gateway_addr: gateway_addr.to_string(),
			peer_id: Some(self.peer_hive_id.to_vec()),
		})
	}
}

/// Whether a claimed peer gateway address is safe dial data.
///
/// Refuses empty, non-UTF-8, NUL-bearing, or non-parseable sockets.
/// The dial path parses UTF-8, and NUL would corrupt composite route keys.
#[must_use]
fn peer_gateway_addr_valid(gateway_addr: &[u8]) -> bool {
	let nonempty = !gateway_addr.is_empty();
	let no_nul = !gateway_addr.contains(&0);
	let Ok(addr) = core::str::from_utf8(gateway_addr) else {
		return false;
	};

	let parseable = TightBeamSocketAddr::from_str(addr).is_ok();
	nonempty && no_nul && parseable
}

/// Whether `gateway_addr` is on an optional exact-match allowlist.
///
/// `None` accepts any address that already passed [`peer_gateway_addr_valid`].
#[must_use]
pub(crate) fn peer_dial_allowed(gateway_addr: &[u8], allowlist: Option<&[String]>) -> bool {
	let Some(allowed) = allowlist else {
		return true;
	};
	let Ok(addr) = core::str::from_utf8(gateway_addr) else {
		return false;
	};

	let matched = allowed.iter().any(|entry| entry.as_str() == addr);
	matched
}

/// Wire-level advertisement checks. No registry lock.
fn peer_advertisement_wire_ok(
	gateway_addr: &[u8],
	types: &[Urn<'static>],
	namespace: &ColonyNamespace,
	allowlist: Option<&[String]>,
) -> Result<(), TransitStatus> {
	let dial_valid = peer_gateway_addr_valid(gateway_addr);
	let dial_allowed = peer_dial_allowed(gateway_addr, allowlist);
	let types_valid = namespace.all_bare_servlet_types(types);
	let within_type_cap = types.len() <= MAX_ADVERTISED_TYPES;
	if dial_valid && dial_allowed && types_valid && within_type_cap {
		Ok(())
	} else {
		Err(TransitStatus::PermissionDenied)
	}
}

/// Resolve a frame's signer certificate on the given trust plane.
///
/// Single resolution for signer-derived facts: fingerprint and colony
/// membership both start here so callers resolve the cert once.
/// Missing trust, signer, or certificate fails closed with `None`.
#[must_use]
pub fn frame_signer_cert<'t>(trust: Option<&'t dyn CertificateTrust>, frame: &Frame) -> Option<&'t Certificate> {
	let trust = trust?;
	let signer_info = frame.nonrepudiation.as_ref()?;

	trust.find_by_signer_info(signer_info)
}

/// Peer identity from the signer's certificate fingerprint.
///
/// Slates reconcile and score misbehavior by fingerprint, never claimed
/// `gateway_addr`. Missing trust, signer, or fingerprint fails closed.
#[must_use]
pub fn peer_signer_fingerprint(trust: Option<&dyn CertificateTrust>, frame: &Frame) -> Option<SharedId> {
	let cert = frame_signer_cert(trust, frame)?;
	cert.fingerprint_id()
}

impl ColonyNamespace {
	/// Colony URN a certificate asserts, when exactly one is present.
	///
	/// Membership binds to the URI SAN (RFC 5280 §4.2.1.6), never the
	/// Subject DN. Non-URI SANs and URIs that fail colony validation in
	/// this namespace are ignored. `None` when the extension is absent or
	/// malformed, when no entry validates, or when more than one distinct
	/// colony URN is present: ambiguous identity fails closed (CWE-706).
	#[must_use]
	pub fn cert_colony_urn(&self, cert: &Certificate) -> Option<Urn<'static>> {
		let mut colony: Option<Urn<'static>> = None;

		let san: SubjectAltName = cert.extension().ok()??;
		for entry in &san.0 {
			let GeneralName::UniformResourceIdentifier(uri) = entry else {
				continue;
			};
			let Ok(urn) = uri.as_str().parse::<Urn<'static>>() else {
				continue;
			};
			if !matches!(self.validate(&urn), Ok(ColonyResource::Colony { .. })) {
				continue;
			}

			match colony.as_ref() {
				Some(existing) if *existing == urn => {}
				Some(_) => return None,
				None => colony = Some(urn),
			}
		}

		colony
	}

	/// Colony URN of a frame's signer on the given trust plane.
	///
	/// Membership travels in the signer certificate, never frame bytes:
	/// unsigned scope would be weaker than the certificate binding
	/// (CWE-345). Missing trust, signer, or certificate fails closed.
	#[must_use]
	pub fn frame_colony_urn(&self, trust: Option<&dyn CertificateTrust>, frame: &Frame) -> Option<Urn<'static>> {
		let cert = frame_signer_cert(trust, frame)?;
		self.cert_colony_urn(cert)
	}
}

/// Peer identity derived from a certificate.
pub(crate) trait ColonyCertificate {
	/// Stable peer key derived from the certificate itself.
	///
	/// Slates and misbehavior scoring key on this fingerprint, so one peer
	/// keeps one identity across every `gateway_addr` it advertises.
	/// `None` when the trust store yields no fingerprint, so an
	/// unidentifiable peer fails closed.
	fn fingerprint_id(&self) -> Option<SharedId>;
}

impl ColonyCertificate for Certificate {
	fn fingerprint_id(&self) -> Option<SharedId> {
		let fingerprint = CertificateTrustStore::to_fingerprint(self).ok()?;
		Some(Arc::from(fingerprint.as_slice()))
	}
}

#[cfg(test)]
mod tests {
	use super::super::RouteKind;
	use super::*;

	fn nestmate_ns() -> ColonyNamespace {
		ColonyNamespace::default()
	}

	fn ping_type() -> Urn<'static> {
		nestmate_ns().servlet("ping").expect("static servlet name")
	}

	#[test]
	fn peer_gateway_addr_valid_cases() {
		let cases: &[(&[u8], bool)] = &[
			(b"127.0.0.1:9000", true),
			(b"", false),
			(b"127.0.0.1\09000", false),
			(&[0xff, 0xfe], false),
			(b"not-a-socket", false),
		];
		for &(addr, expected) in cases {
			assert_eq!(peer_gateway_addr_valid(addr), expected);
		}
	}

	#[test]
	fn peer_dial_allowed_respects_allowlist() {
		let addr = b"127.0.0.1:9000";
		assert!(peer_dial_allowed(addr, None));
		assert!(peer_dial_allowed(addr, Some(&[String::from("127.0.0.1:9000")])));
		assert!(!peer_dial_allowed(addr, Some(&[String::from("10.0.0.1:9000")])));
	}

	#[test]
	fn advertised_types_accept_bare_reject_instance() {
		let ns = nestmate_ns();
		let bare = ping_type();
		assert!(ns.all_bare_servlet_types(core::slice::from_ref(&bare)));

		let instance = bare.servlet_instance("127.0.0.1:1");
		assert!(!ns.all_bare_servlet_types(&[instance]));
	}

	/// Pheromone settings the slate tests read: the shipped defaults, so a
	/// changed default shows up here rather than silently diverging.
	fn test_pheromone() -> PheromoneConfig {
		PheromoneConfig::default()
	}

	#[test]
	fn build_peer_slate_keys_by_hive_and_sets_dial() {
		let hive: SharedId = Arc::from([1u8; 32].as_slice());
		let slate = test_pheromone().peer_slate(&hive, Arc::from(b"127.0.0.1:9000".as_slice()), &[ping_type()]);
		assert_eq!(slate.len(), 1);
		assert_eq!(slate[0].route_kind(), RouteKind::Peer);
		assert_eq!(slate[0].dial_target().as_ref(), b"127.0.0.1:9000");
		assert_eq!(slate[0].owner_id().as_ref(), hive.as_ref());
		assert_eq!(slate[0].route_key()[0], 1);
		assert_eq!(slate[0].route_key()[32], 0);
	}

	fn admitted_ad(origin: &SharedId, dial: &[u8], types: &[Urn<'static>]) -> AdmittedPeerAd {
		let slate = test_pheromone().peer_slate(origin, Arc::from(dial), types);
		AdmittedPeerAd { peer_hive_id: Arc::clone(origin), dial_addr: Arc::from(dial), slate, order: 0 }
	}

	fn some_trail(trail: Option<RelayTrail>) -> RelayTrail {
		trail.expect("relay trail for a distinct relay with a live slate")
	}

	#[test]
	fn relay_trail_none_for_self_relay() {
		let origin: SharedId = Arc::from([1u8; 32].as_slice());
		let ad = admitted_ad(&origin, b"127.0.0.1:9000", &[ping_type()]);
		let trail = ad.relay_trail(&origin, Arc::from(b"127.0.0.1:9001".as_slice()), &PheromoneConfig::default());
		assert!(trail.is_none());
	}

	#[test]
	fn relay_trail_none_for_empty_slate() {
		let origin: SharedId = Arc::from([1u8; 32].as_slice());
		let relay: SharedId = Arc::from([2u8; 32].as_slice());
		let ad = admitted_ad(&origin, b"127.0.0.1:9000", &[]);
		let trail = ad.relay_trail(&relay, Arc::from(b"127.0.0.1:9001".as_slice()), &PheromoneConfig::default());
		assert!(trail.is_none());
	}

	#[test]
	fn relay_trail_buckets_by_origin_and_relay() {
		let origin: SharedId = Arc::from([1u8; 32].as_slice());
		let relay: SharedId = Arc::from([2u8; 32].as_slice());
		let ad = admitted_ad(&origin, b"127.0.0.1:9000", &[ping_type()]);

		let trail =
			some_trail(ad.relay_trail(&relay, Arc::from(b"127.0.0.1:9001".as_slice()), &PheromoneConfig::default()));

		let expected_bucket: Vec<u8> = [origin.as_ref(), &[0u8], relay.as_ref()].concat();
		assert_eq!(trail.bucket.as_ref(), expected_bucket.as_slice());
		assert_eq!(trail.slate.len(), 1);
		assert_eq!(trail.slate[0].route_kind(), RouteKind::PeerRelay);
		assert_eq!(trail.slate[0].bucket().as_ref(), expected_bucket.as_slice());
		assert_eq!(trail.slate[0].owner_id().as_ref(), origin.as_ref());
		assert_eq!(trail.slate[0].relay_id().map(|id| id.as_ref()), Some(relay.as_ref()));
		assert_eq!(trail.slate[0].dial_target().as_ref(), b"127.0.0.1:9001");
	}

	#[test]
	fn peer_advertisement_wire_ok_refuses_bad_dial() {
		let ns = nestmate_ns();
		let status = peer_advertisement_wire_ok(b"", &[ping_type()], &ns, None);
		assert_eq!(status, Err(TransitStatus::PermissionDenied));
	}

	#[test]
	fn peer_advertisement_wire_ok_refuses_allowlist_miss() {
		let ns = nestmate_ns();
		let allow = [String::from("10.0.0.1:9000")];
		let status = peer_advertisement_wire_ok(b"127.0.0.1:9000", &[ping_type()], &ns, Some(&allow));
		assert_eq!(status, Err(TransitStatus::PermissionDenied));
	}

	mod colony_urn {
		use super::*;
		use crate::testing::utils::{
			create_test_certificate, create_test_certificate_with_uri_sans, create_test_signing_key,
		};

		fn main_colony() -> Urn<'static> {
			nestmate_ns().colony("main").expect("static colony name")
		}

		fn other_colony() -> Urn<'static> {
			nestmate_ns().colony("other").expect("static colony name")
		}

		fn foreign_colony() -> Urn<'static> {
			let foreign = ColonyNamespace::new("acme", "").unwrap_or_default();
			foreign.colony("main").expect("static colony name")
		}

		#[test]
		fn cert_colony_urn_extracts_a_valid_san() {
			let key = create_test_signing_key();
			let cert = create_test_certificate_with_uri_sans(&key, &[&main_colony().to_string()]);
			assert_eq!(nestmate_ns().cert_colony_urn(&cert), Some(main_colony()));
		}

		#[test]
		fn cert_colony_urn_ignores_non_colony_entries() {
			let key = create_test_signing_key();
			let servlet = ping_type().to_string();
			let cert = create_test_certificate_with_uri_sans(
				&key,
				&[&servlet, "https://example.test", &main_colony().to_string()],
			);
			assert_eq!(nestmate_ns().cert_colony_urn(&cert), Some(main_colony()));
		}

		#[test]
		fn cert_colony_urn_tolerates_duplicate_identical_entries() {
			let key = create_test_signing_key();
			let urn = main_colony().to_string();
			let cert = create_test_certificate_with_uri_sans(&key, &[&urn, &urn]);
			assert_eq!(nestmate_ns().cert_colony_urn(&cert), Some(main_colony()));
		}

		#[test]
		fn cert_colony_urn_fails_closed_on_ambiguity() {
			let key = create_test_signing_key();
			let cert =
				create_test_certificate_with_uri_sans(&key, &[&main_colony().to_string(), &other_colony().to_string()]);
			assert_eq!(nestmate_ns().cert_colony_urn(&cert), None);
		}

		#[test]
		fn cert_colony_urn_is_none_without_san() {
			let key = create_test_signing_key();
			let cert = create_test_certificate(&key);
			assert_eq!(nestmate_ns().cert_colony_urn(&cert), None);
		}

		#[test]
		fn cert_colony_urn_is_none_for_foreign_namespace() {
			let key = create_test_signing_key();
			let cert = create_test_certificate_with_uri_sans(&key, &[&foreign_colony().to_string()]);
			assert_eq!(nestmate_ns().cert_colony_urn(&cert), None);
		}
	}
}
