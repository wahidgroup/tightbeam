//! Peer-advertisement admission for the cluster gateway macro
//!
//! [`AdmittedPeerAd`] is the only path from a wire advertisement to a
//! reconcilable slate: construction runs signer resolution and wire
//! checks, so the identity, dial address, and slate of one verified
//! advertisement travel as a single value.

use core::str::FromStr;
use std::sync::Arc;

use super::{ClusterConf, ServletEntry, SharedId};
use crate::colony::common::{is_bare_servlet_type, type_canonical_bytes, ColonyNamespace, PeerAdvertisement};
use crate::constants::MAX_ADVERTISED_TYPES;
use crate::policy::TransitStatus;
use crate::transport::tcp::TightBeamSocketAddr;
use crate::utils::urn::Urn;
use crate::Frame;

#[cfg(feature = "x509")]
use crate::crypto::x509::store::{CertificateTrust, CertificateTrustStore};

/// Peer advertisement that passed signer resolution and wire checks
///
/// Construction via [`AdmittedPeerAd::admit`] is the only public path,
/// so the registry can never receive an unvalidated slate and the
/// signer identity cannot be transposed with the claimed dial address.
pub struct AdmittedPeerAd {
	/// Signer cert fingerprint (or claimed address without x509)
	pub(super) peer_hive_id: SharedId,
	/// Claimed gateway socket the slate dials through
	pub(super) dial_addr: SharedId,
	/// Peer-routed entries keyed by `peer_hive_id NUL type`
	pub(super) slate: Vec<ServletEntry>,
}

impl AdmittedPeerAd {
	/// Admit a wire advertisement, failing closed with the refusal status
	///
	/// Runs signer resolution (slates key by cert fingerprint, never the
	/// claimed `gateway_addr`) and wire checks. Caps and local-route
	/// conflicts are registry policy, checked under the reconcile gate in
	/// [`super::ServletRegistry::reconcile_peer_slate`].
	pub fn admit(frame: &Frame, ad: &PeerAdvertisement, conf: &ClusterConf) -> Result<Self, TransitStatus> {
		let dial_addr: SharedId = Arc::from(ad.gateway_addr.as_slice());

		#[cfg(feature = "x509")]
		let peer_hive_id =
			peer_signer_hive_id(conf.tls.peer_trust.as_deref(), frame).ok_or(TransitStatus::PermissionDenied)?;

		// Without x509 there is no signer fingerprint to bind: the
		// claimed address is the only available slate key.
		#[cfg(not(feature = "x509"))]
		let peer_hive_id = {
			let _ = frame;
			Arc::clone(&dial_addr)
		};

		peer_advertisement_wire_ok(
			&ad.gateway_addr,
			&ad.advertised_types,
			&conf.namespace,
			conf.peer_dial_allowlist.as_deref(),
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
}

/// Whether a claimed peer gateway address is safe dial data
///
/// Refuses empty, non-UTF-8, NUL-bearing, or non-parseable sockets: the
/// dial path parses UTF-8 sockets, and NUL would corrupt composite route keys.
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

/// Whether `gateway_addr` is permitted by an optional exact-match allowlist
///
/// `None` allowlist accepts any address that already passed
/// [`peer_gateway_addr_valid`].
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

/// Whether every advertised type is a bare servlet URN in `namespace`
#[must_use]
fn advertised_types_are_nestmate(namespace: &ColonyNamespace, types: &[Urn<'static>]) -> bool {
	types.iter().all(|urn| is_bare_servlet_type(namespace, urn))
}

/// Wire-level advertisement checks (no registry lock)
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

/// Resolve the peer hive key from the advertising signer's certificate
///
/// Peer slates reconcile by cert fingerprint, not claimed `gateway_addr`.
/// Missing trust, signer, or fingerprint computation fails closed.
#[cfg(feature = "x509")]
#[must_use]
fn peer_signer_hive_id(trust: Option<&dyn CertificateTrust>, frame: &Frame) -> Option<SharedId> {
	let trust = trust?;
	let signer_info = frame.nonrepudiation.as_ref()?;
	let cert = trust.find_by_signer_info(signer_info)?;
	let fingerprint = CertificateTrustStore::to_fingerprint(cert).ok()?;

	Some(Arc::from(fingerprint.as_slice()))
}

/// Build a Peer-routed slate keyed by `peer_hive_id` NUL type
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
}
