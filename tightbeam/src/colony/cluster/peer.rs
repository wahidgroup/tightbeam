//! Peer-advertisement admission for the cluster gateway.
//!
//! [`AdmittedPeerAd`] is the only path from a wire advertisement to a
//! reconcilable slate. Signer resolution and wire checks run at
//! construction so identity, dial address, and slate travel as one value.

use core::str::FromStr;
use std::sync::Arc;

use super::{ClusterConfig, PeerHint, ServletEntry, SharedId};
use crate::colony::common::{is_bare_servlet_type, type_canonical_bytes, ColonyNamespace, PeerAdvertisement};
use crate::constants::MAX_ADVERTISED_TYPES;
use crate::policy::TransitStatus;
use crate::transport::tcp::TightBeamSocketAddr;
use crate::utils::urn::Urn;
use crate::Frame;

#[cfg(feature = "x509")]
use crate::colony::common::ColonyResource;
#[cfg(feature = "x509")]
use crate::crypto::x509::store::{CertificateTrust, CertificateTrustStore};
#[cfg(feature = "x509")]
use crate::crypto::x509::utils::certificate_extension;
#[cfg(feature = "x509")]
use crate::crypto::x509::Certificate;
#[cfg(feature = "x509")]
use crate::x509::ext::pkix::name::GeneralName;
#[cfg(feature = "x509")]
use crate::x509::ext::pkix::SubjectAltName;

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

		// The signer certificate resolves exactly once; the slate key
		// (fingerprint) and the membership gate both derive from it.
		#[cfg(feature = "x509")]
		let signer_cert = frame_signer_cert(conf.tls.peer_trust.as_deref(), frame).ok_or(TransitStatus::PermissionDenied)?;
		#[cfg(feature = "x509")]
		let peer_hive_id = cert_fingerprint_id(signer_cert).ok_or(TransitStatus::PermissionDenied)?;

		// Without x509 there is no signer fingerprint to bind: the
		// claimed address is the only available slate key.
		#[cfg(not(feature = "x509"))]
		let peer_hive_id = {
			let _ = frame;
			Arc::clone(&dial_addr)
		};

		// Federation is a colony operation: both this gateway and the
		// advertising peer must carry a valid colony URN SAN. A cert
		// without one still serves general transport and work, never
		// membership. Without x509 there is no certificate to carry
		// membership, so no gate applies.
		#[cfg(feature = "x509")]
		{
			let local_member = conf.colony_urn().is_some();
			let peer_member = cert_colony_urn(&conf.namespace, signer_cert).is_some();
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

		let slate = build_peer_slate(
			&peer_hive_id,
			Arc::clone(&dial_addr),
			&ad.advertised_types,
			conf.pheromone.initial_pheromone,
			conf.pheromone.abandonment_limit,
		);

		Ok(Self { peer_hive_id, dial_addr, slate })
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
/// The dial path parses UTF-8; NUL would corrupt composite route keys.
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
fn peer_dial_allowed(gateway_addr: &[u8], allowlist: Option<&[String]>) -> bool {
	let Some(allowed) = allowlist else {
		return true;
	};
	let Ok(addr) = core::str::from_utf8(gateway_addr) else {
		return false;
	};

	let matched = allowed.iter().any(|entry| entry.as_str() == addr);
	matched
}

/// Whether every advertised type is a bare servlet URN in `namespace`.
#[must_use]
fn advertised_types_are_nestmate(namespace: &ColonyNamespace, types: &[Urn<'static>]) -> bool {
	types.iter().all(|urn| is_bare_servlet_type(namespace, urn))
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
	let types_valid = advertised_types_are_nestmate(namespace, types);
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
#[cfg(feature = "x509")]
#[must_use]
pub fn frame_signer_cert<'t>(trust: Option<&'t dyn CertificateTrust>, frame: &Frame) -> Option<&'t Certificate> {
	let trust = trust?;
	let signer_info = frame.nonrepudiation.as_ref()?;

	trust.find_by_signer_info(signer_info)
}

/// Certificate fingerprint as a shared slate/attribution identifier.
///
/// Fail closed with `None` when the fingerprint cannot be computed:
/// an unkeyed slate or unattributable misbehavior is refused.
#[cfg(feature = "x509")]
#[must_use]
pub(crate) fn cert_fingerprint_id(cert: &Certificate) -> Option<SharedId> {
	let fingerprint = CertificateTrustStore::to_fingerprint(cert).ok()?;
	Some(Arc::from(fingerprint.as_slice()))
}

/// Peer identity from the signer's certificate fingerprint.
///
/// Slates reconcile and score misbehavior by fingerprint, never claimed
/// `gateway_addr`. Missing trust, signer, or fingerprint fails closed.
#[cfg(feature = "x509")]
#[must_use]
pub fn peer_signer_fingerprint(trust: Option<&dyn CertificateTrust>, frame: &Frame) -> Option<SharedId> {
	let cert = frame_signer_cert(trust, frame)?;
	cert_fingerprint_id(cert)
}

/// Colony URN from the certificate URI Subject Alternative Name.
///
/// Membership binds to the URI SAN (RFC 5280 §4.2.1.6), never the
/// Subject DN. Non-URI SANs and URIs that fail colony validation in
/// `namespace` are ignored. `None` when the extension is absent or
/// malformed, when no entry validates, or when more than one distinct
/// colony URN is present: ambiguous identity fails closed (CWE-706).
#[cfg(feature = "x509")]
#[must_use]
pub fn cert_colony_urn(namespace: &ColonyNamespace, cert: &Certificate) -> Option<Urn<'static>> {
	let mut colony: Option<Urn<'static>> = None;

	let san: SubjectAltName = certificate_extension(cert).ok()??;
	for entry in &san.0 {
		let GeneralName::UniformResourceIdentifier(uri) = entry else {
			continue;
		};
		let Ok(urn) = uri.as_str().parse::<Urn<'static>>() else {
			continue;
		};
		if !matches!(namespace.validate(&urn), Ok(ColonyResource::Colony { .. })) {
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
/// unsigned scope would be weaker than the certificate binding (CWE-345).
/// Missing trust, signer, or certificate fails closed.
#[cfg(feature = "x509")]
#[must_use]
pub fn frame_colony_urn(
	namespace: &ColonyNamespace,
	trust: Option<&dyn CertificateTrust>,
	frame: &Frame,
) -> Option<Urn<'static>> {
	let cert = frame_signer_cert(trust, frame)?;

	cert_colony_urn(namespace, cert)
}

/// Peer-routed slate keyed by `peer_hive_id` NUL type.
///
/// `dial` is the claimed gateway socket stored on every entry.
#[must_use]
fn build_peer_slate(
	peer_hive_id: &SharedId,
	dial: SharedId,
	types: &[Urn<'static>],
	initial_pheromone: u64,
	abandonment_limit: u32,
) -> Vec<ServletEntry> {
	types
		.iter()
		.map(|urn| {
			let type_bytes = type_canonical_bytes(urn);
			ServletEntry::peer(
				Arc::clone(peer_hive_id),
				Arc::from(type_bytes.as_slice()),
				Arc::clone(&dial),
				initial_pheromone,
				abandonment_limit,
			)
		})
		.collect()
}

#[cfg(test)]
mod tests {
	use super::super::RouteKind;
	use super::*;
	use crate::colony::common::servlet_instance;

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
		assert!(advertised_types_are_nestmate(&ns, core::slice::from_ref(&bare)));

		let instance = servlet_instance(&bare, "127.0.0.1:1");
		assert!(!advertised_types_are_nestmate(&ns, &[instance]));
	}

	#[test]
	fn build_peer_slate_keys_by_hive_and_sets_dial() {
		let hive: SharedId = Arc::from([1u8; 32].as_slice());
		let slate = build_peer_slate(&hive, Arc::from(b"127.0.0.1:9000".as_slice()), &[ping_type()], 5000, 5);
		assert_eq!(slate.len(), 1);
		assert_eq!(slate[0].route_kind(), RouteKind::Peer);
		assert_eq!(slate[0].dial_target().as_ref(), b"127.0.0.1:9000");
		assert_eq!(slate[0].owner_id().as_ref(), hive.as_ref());
		assert_eq!(slate[0].route_key()[0], 1);
		assert_eq!(slate[0].route_key()[32], 0);
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

	#[cfg(all(feature = "x509", feature = "secp256k1", feature = "signature"))]
	mod colony_urn {
		use super::*;
		use crate::testing::utils::{
			create_test_certificate, create_test_certificate_with_uri_sans, create_test_signing_key,
		};

		fn main_colony() -> Urn<'static> {
			nestmate_ns().colony("main").expect("static colony name")
		}

		#[test]
		fn cert_colony_urn_extracts_a_valid_san() {
			let key = create_test_signing_key();
			let cert = create_test_certificate_with_uri_sans(&key, &[&main_colony().to_string()]);
			assert_eq!(cert_colony_urn(&nestmate_ns(), &cert), Some(main_colony()));
		}

		#[test]
		fn cert_colony_urn_ignores_non_colony_entries() {
			let key = create_test_signing_key();
			let servlet = ping_type().to_string();
			let cert = create_test_certificate_with_uri_sans(
				&key,
				&[&servlet, "https://example.test", &main_colony().to_string()],
			);
			assert_eq!(cert_colony_urn(&nestmate_ns(), &cert), Some(main_colony()));
		}

		#[test]
		fn cert_colony_urn_tolerates_duplicate_identical_entries() {
			let key = create_test_signing_key();
			let urn = main_colony().to_string();
			let cert = create_test_certificate_with_uri_sans(&key, &[&urn, &urn]);
			assert_eq!(cert_colony_urn(&nestmate_ns(), &cert), Some(main_colony()));
		}

		#[test]
		fn cert_colony_urn_fails_closed_on_ambiguity() {
			let key = create_test_signing_key();
			let other = nestmate_ns().colony("other").expect("static colony name");
			let cert = create_test_certificate_with_uri_sans(&key, &[&main_colony().to_string(), &other.to_string()]);
			assert_eq!(cert_colony_urn(&nestmate_ns(), &cert), None);
		}

		#[test]
		fn cert_colony_urn_is_none_without_san() {
			let key = create_test_signing_key();
			let cert = create_test_certificate(&key);
			assert_eq!(cert_colony_urn(&nestmate_ns(), &cert), None);
		}

		#[test]
		fn cert_colony_urn_is_none_for_foreign_namespace() {
			let key = create_test_signing_key();
			let foreign = ColonyNamespace::new("acme", "").unwrap_or_default();
			let urn = foreign.colony("main").expect("static colony name");
			let cert = create_test_certificate_with_uri_sans(&key, &[&urn.to_string()]);
			assert_eq!(cert_colony_urn(&nestmate_ns(), &cert), None);
		}
	}
}
