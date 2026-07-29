//! Peer-advertisement helpers shared by the cluster gateway macro
//!
//! Keeps fingerprint keying, dial-addr checks, and slate construction out
//! of the `cluster!` expansion so AdvertisePeer stays wiring-only.

use core::str::FromStr;
use std::sync::Arc;

use super::{ServletEntry, SharedId};
use crate::colony::common::{is_bare_servlet_type, type_canonical_bytes, ColonyNamespace};
use crate::constants::MAX_ADVERTISED_TYPES;
use crate::policy::TransitStatus;
use crate::transport::tcp::TightBeamSocketAddr;
use crate::utils::urn::Urn;

#[cfg(feature = "x509")]
use crate::crypto::x509::store::{CertificateTrust, CertificateTrustStore};
#[cfg(feature = "x509")]
use crate::Frame;

/// Whether a claimed peer gateway address is safe dial data
///
/// Refuses empty, non-UTF-8, NUL-bearing, or non-parseable sockets: the
/// dial path parses UTF-8 sockets, and NUL would corrupt composite route keys.
#[doc(hidden)]
#[must_use]
pub fn peer_gateway_addr_valid(gateway_addr: &[u8]) -> bool {
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
#[doc(hidden)]
#[must_use]
pub fn peer_dial_allowed(gateway_addr: &[u8], allowlist: Option<&[String]>) -> bool {
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
#[doc(hidden)]
#[must_use]
pub fn advertised_types_are_nestmate(namespace: &ColonyNamespace, types: &[Urn<'static>]) -> bool {
	types.iter().all(|urn| is_bare_servlet_type(namespace, urn))
}

/// Wire-level advertisement checks (no registry lock)
///
/// Caps and local-route conflicts are checked inside
/// [`super::ServletRegistry::reconcile_peer_slate`] under one install lock.
#[doc(hidden)]
pub fn peer_advertisement_wire_ok(
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
#[doc(hidden)]
#[must_use]
pub fn peer_signer_hive_id(trust: Option<&dyn CertificateTrust>, frame: &Frame) -> Option<SharedId> {
	let trust = trust?;
	let signer_info = frame.nonrepudiation.as_ref()?;
	let cert = trust.find_by_signer_info(signer_info)?;
	let fingerprint = CertificateTrustStore::to_fingerprint(cert).ok()?;

	Some(Arc::from(fingerprint.as_slice()))
}

/// Without x509 there is no signer fingerprint.
#[cfg(not(feature = "x509"))]
#[doc(hidden)]
#[must_use]
pub fn peer_signer_hive_id_from_gateway(gateway_addr: &[u8]) -> SharedId {
	Arc::from(gateway_addr)
}

/// Build a Peer-routed slate keyed by `peer_hive_id` NUL type
///
/// `dial_addr` is the claimed gateway socket stored on every entry.
#[doc(hidden)]
#[must_use]
pub fn build_peer_slate(
	peer_hive_id: &SharedId,
	dial_addr: &[u8],
	types: &[Urn<'static>],
	initial_pheromone: u64,
	abandonment_limit: u32,
) -> Vec<ServletEntry> {
	let dial: SharedId = Arc::from(dial_addr);
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
		let slate = build_peer_slate(&hive, b"127.0.0.1:9000", &[ping_type()], 5000, 5);
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
