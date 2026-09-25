//! Dial admission for the addresses peers claim, and the address this
//! gateway claims to them.
//!
//! A peer advertisement and a peer-exchange entry each name a socket this
//! gateway would dial. [`PeerConfig::admit_dial`] is the one decider for
//! such a claim, and [`AdmittedDial`] is its proof. Every path that installs
//! or dials a claimed address takes the proof, so a claim reaches a dial
//! only through the decider (CWE-918).
//!
//! # Sources
//!
//! - CWE-918, server-side request forgery:
//!   <https://cwe.mitre.org/data/definitions/918.html>

use core::fmt;
use core::str::FromStr;
#[cfg(test)]
use std::collections::HashSet;
#[cfg(test)]
use std::sync::Arc;

use super::{ClusterError, DialTarget, NotASocket, PeerAddress, PeerConfig, PeerHint, SharedId};
use crate::colony::common::PeerGossip;
use crate::Errorizable;

/// A dial address this gateway's dial policy admitted.
///
/// The field is private, so a value exists through two authorities only,
/// and a claimed address reaches a dial through one of the two:
///
/// - [`PeerConfig::admit_dial`] applies the operator's policy to a peer's claim.
/// - [`ClusterConfigBuilder::with_peers`] records the operator's anchors.
///
/// [`ClusterConfigBuilder::with_peers`]: super::ClusterConfigBuilder::with_peers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AdmittedDial(PeerAddress);

impl AdmittedDial {
	/// The admitted socket address.
	#[must_use]
	pub fn address(&self) -> PeerAddress {
		self.0
	}

	/// The admitted socket as the dialing protocol's address type.
	///
	/// This delegates to [`DialTarget::protocol_address`], the one place a
	/// dial becomes a protocol address.
	///
	/// # Errors
	///
	/// - [`ClusterError::InvalidAddress`] -- the protocol does not address by socket.
	pub fn protocol_address<A: FromStr>(&self) -> Result<A, ClusterError> {
		DialTarget::from(*self).protocol_address()
	}
}

impl fmt::Display for AdmittedDial {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

/// Why a claimed dial address was refused.
#[derive(Errorizable, Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialRefusal {
	/// The claim is not the UTF-8 spelling of a socket address.
	#[error("Claimed dial address names no socket")]
	NotASocket,
	/// The claim is the unspecified address, which connects to this host's
	/// loopback even when the allowlist names it.
	#[error("Claimed dial address is unspecified")]
	Unspecified,
	/// The claim is a multicast, broadcast, reserved, or this-network
	/// address, which names no unicast peer.
	#[error("Claimed dial address names no unicast peer")]
	NotUnicast,
	/// The operator's allowlist is set and omits the address.
	#[error("Claimed dial address is outside the allowlist")]
	OffAllowlist,
}

impl From<NotASocket> for DialRefusal {
	fn from(NotASocket: NotASocket) -> Self {
		Self::NotASocket
	}
}

impl PeerConfig {
	/// Admits a socket a peer claims as its gateway, or refuses it.
	///
	/// This is the one decider for every claimed dial. Two refusals hold on
	/// every plane, and the allowlist decides the rest, in order:
	///
	/// - An unspecified address ([`PeerAddress::is_unspecified`]) is refused,
	///   because a connect to it lands on this host's loopback even when the
	///   allowlist names it (CWE-706).
	/// - An address that names no unicast peer ([`PeerAddress::is_unicast`]) is
	///   refused, because a dial to it can only spend a probe (CWE-770).
	/// - An allowlist, when set, decides alone. Without one, every other address is admitted.
	///
	/// # Errors
	///
	/// - [`DialRefusal::Unspecified`] -- the address is `0.0.0.0` or `[::]`.
	/// - [`DialRefusal::NotUnicast`] -- the address is multicast, broadcast, or reserved.
	/// - [`DialRefusal::OffAllowlist`] -- the allowlist is set and omits the address.
	pub fn admit_dial(&self, claimed: impl Into<PeerAddress>) -> Result<AdmittedDial, DialRefusal> {
		let claimed: PeerAddress = claimed.into();
		if claimed.is_unspecified() {
			return Err(DialRefusal::Unspecified);
		}
		if !claimed.is_unicast() {
			return Err(DialRefusal::NotUnicast);
		}

		let allowlist = self.peer_dial_allowlist.as_ref();
		let allowed = allowlist.is_none_or(|allowed| allowed.contains(&claimed));
		if !allowed {
			return Err(DialRefusal::OffAllowlist);
		}

		Ok(AdmittedDial(claimed))
	}

	/// Parses the bytes a peer wrote as its gateway address and admits the
	/// socket they name through [`Self::admit_dial`].
	///
	/// The policy is the whole check on a claimed address, so the admitted
	/// value is both the proof and the address the caller stores (CWE-918).
	///
	/// # Errors
	///
	/// - [`DialRefusal::NotASocket`] -- the bytes are not the UTF-8 spelling of a socket.
	/// - [`DialRefusal::Unspecified`] -- the socket is `0.0.0.0` or `[::]`.
	/// - [`DialRefusal::NotUnicast`] -- the socket names no unicast peer.
	/// - [`DialRefusal::OffAllowlist`] -- the allowlist is set and omits the socket.
	pub fn admit_claim(&self, claimed: impl AsRef<[u8]>) -> Result<AdmittedDial, DialRefusal> {
		let socket = PeerAddress::try_from(claimed.as_ref())?;
		self.admit_dial(socket)
	}

	/// Admits one peer-exchange entry as a discovery hint.
	///
	/// The entry is untrusted wire input, so its address passes
	/// [`Self::admit_claim`] before the discovery table may learn it. An
	/// empty fingerprint means the sharer sent no identity.
	///
	/// # Errors
	///
	/// - [`DialRefusal::NotASocket`] -- the entry's address is not the UTF-8 spelling of a socket.
	/// - [`DialRefusal::Unspecified`] -- the socket is `0.0.0.0` or `[::]`.
	/// - [`DialRefusal::NotUnicast`] -- the socket names no unicast peer.
	/// - [`DialRefusal::OffAllowlist`] -- the allowlist is set and omits the socket.
	pub fn admit_hint(&self, entry: PeerGossip) -> Result<PeerHint, DialRefusal> {
		let dial = self.admit_claim(&entry.gateway_addr)?;
		let peer_id = (!entry.peer_id.is_empty()).then_some(entry.peer_id);

		Ok(PeerHint { dial, peer_id })
	}

	/// Records the anchors the operator configured, one per spelling.
	///
	/// Configuration is the operator's own choice, so an anchor is admitted
	/// as written. This is the one place beside [`Self::admit_dial`] that
	/// creates an [`AdmittedDial`], and the builder's `with_peers` is its
	/// caller.
	///
	/// # Errors
	///
	/// - [`ClusterError::InvalidPeerAddress`] -- a spelling names no socket.
	pub(super) fn set_anchors<I, S>(&mut self, spellings: I) -> Result<(), ClusterError>
	where
		I: IntoIterator<Item = S>,
		S: AsRef<str>,
	{
		let mut anchors = Vec::new();
		for spelling in spellings {
			let address: PeerAddress = spelling.as_ref().parse()?;
			anchors.push(AdmittedDial(address));
		}

		self.peers = anchors;
		Ok(())
	}

	/// The address this gateway advertises to peers, given the address it
	/// bound.
	///
	/// An advertise address the operator configured wins. Otherwise the bound
	/// address is advertised as it is, unless this gateway beats and the
	/// bound address is unspecified: every peer refuses that claim, so the
	/// gateway refuses to start instead of federating silently.
	///
	/// # Errors
	///
	/// - [`ClusterError::AdvertiseAddressRequired`] -- the gateway beats from
	///   a wildcard bind with no advertise address.
	pub(in crate::colony::cluster) fn advertised_address(
		&self,
		bound: impl AsRef<[u8]>,
	) -> Result<SharedId, ClusterError> {
		let bound = bound.as_ref();
		if let Some(advertised) = self.advertise_addr {
			return Ok(advertised.route_bytes());
		}

		let beating = self.advertise_interval.is_some();
		let bound_unspecified = PeerAddress::try_from(bound).is_ok_and(|socket| socket.is_unspecified());
		if beating && bound_unspecified {
			return Err(ClusterError::AdvertiseAddressRequired);
		}

		Ok(SharedId::from(bound))
	}
}

#[cfg(test)]
impl PeerConfig {
	/// A plane restricted to an allowlist, which dials only what it names.
	pub(crate) fn allowing<I, S>(entries: I) -> Self
	where
		I: IntoIterator<Item = S>,
		S: AsRef<str>,
	{
		let allowlist: HashSet<PeerAddress> = entries.into_iter().map(PeerAddress::fixture).collect();
		Self { peer_dial_allowlist: Some(Arc::new(allowlist)), ..Self::default() }
	}
}

#[cfg(test)]
impl AdmittedDial {
	/// A fixture socket admitted by the default plane, so a test holds the
	/// proof production would hold for that socket.
	pub(crate) fn fixture(spelling: impl AsRef<str>) -> Self {
		PeerConfig::default()
			.admit_dial(PeerAddress::fixture(spelling))
			.expect("the default plane admits every fixture socket")
	}
}

#[cfg(test)]
mod tests {
	use core::mem::discriminant;
	use core::time::Duration;

	use super::*;
	use crate::tb_cases;

	/// The admitted form of a fixture spelling, for a case that expects
	/// admission.
	fn admitted(spelling: &str) -> Result<PeerAddress, DialRefusal> {
		Ok(PeerAddress::fixture(spelling))
	}

	// The unspecified and non-unicast classes are refused on every plane,
	// and an allowlist decides the rest alone.
	tb_cases! {
		fn admit_dial_applies_the_fixed_classes_then_the_allowlist((plane, claimed, expected): (PeerConfig, &str, Result<PeerAddress, DialRefusal>)) {
			let verdict = plane.admit_dial(PeerAddress::fixture(claimed));

			assert_eq!(verdict.map(|dial| dial.address()), expected);
		}
		cases {
			default_refuses_ipv4_unspecified => (PeerConfig::default(), "0.0.0.0:9000", Err(DialRefusal::Unspecified)),
			default_refuses_ipv6_unspecified => (PeerConfig::default(), "[::]:9000", Err(DialRefusal::Unspecified)),
			allowlist_naming_unspecified_still_refuses_it => (PeerConfig::allowing(["0.0.0.0:9000"]), "0.0.0.0:9000", Err(DialRefusal::Unspecified)),
			default_refuses_multicast => (PeerConfig::default(), "224.0.0.1:9000", Err(DialRefusal::NotUnicast)),
			default_refuses_ipv6_multicast => (PeerConfig::default(), "[ff02::1]:9000", Err(DialRefusal::NotUnicast)),
			default_refuses_broadcast => (PeerConfig::default(), "255.255.255.255:9000", Err(DialRefusal::NotUnicast)),
			default_refuses_the_reserved_block => (PeerConfig::default(), "240.0.0.1:9000", Err(DialRefusal::NotUnicast)),
			default_refuses_this_network => (PeerConfig::default(), "0.0.0.1:9000", Err(DialRefusal::NotUnicast)),
			allowlist_naming_multicast_still_refuses_it => (PeerConfig::allowing(["224.0.0.1:9000"]), "224.0.0.1:9000", Err(DialRefusal::NotUnicast)),
			default_admits_a_routable_address => (PeerConfig::default(), "192.0.2.1:9000", admitted("192.0.2.1:9000")),
			default_admits_a_routable_ipv6_address => (PeerConfig::default(), "[2001:db8::1]:9000", admitted("[2001:db8::1]:9000")),
			default_admits_loopback => (PeerConfig::default(), "127.0.0.1:9000", admitted("127.0.0.1:9000")),
			allowlist_compares_sockets_not_spellings => (PeerConfig::allowing(["[::1]:9000"]), "[0:0:0:0:0:0:0:1]:9000", admitted("[::1]:9000")),
			allowlist_refuses_a_routable_address_it_omits => (PeerConfig::allowing(["10.0.0.1:9000"]), "192.0.2.1:9000", Err(DialRefusal::OffAllowlist)),
		}
	}

	// The one parse decides which bytes spell a socket, and its refusal
	// arrives here as the claim's refusal.
	#[test]
	fn admit_claim_refuses_bytes_that_name_no_socket() {
		let verdict = PeerConfig::default().admit_claim(b"not-a-socket");
		assert_eq!(verdict, Err(DialRefusal::NotASocket));
	}

	#[test]
	fn admit_claim_admits_a_socket_spelling() -> Result<(), DialRefusal> {
		let admitted = PeerConfig::default().admit_claim(b"192.0.2.1:9000")?;
		assert_eq!(admitted.address(), PeerAddress::fixture("192.0.2.1:9000"));
		Ok(())
	}

	// A wire entry becomes a hint through the same decider a claimed
	// advertisement passes, so a peer cannot pass one gate and fail the
	// other with one address.
	tb_cases! {
		fn admit_hint_carries_the_fingerprint_when_one_was_sent((wire_id, hint_id): (Vec<u8>, Option<Vec<u8>>)) -> Result<(), DialRefusal> {
			let entry = PeerGossip { peer_id: wire_id, gateway_addr: b"10.0.0.1:9000".to_vec() };
			let hint = PeerConfig::default().admit_hint(entry)?;
			assert_eq!(hint.dial.to_string(), "10.0.0.1:9000");
			assert_eq!(hint.peer_id, hint_id);
			Ok(())
		}
		cases {
			with_fingerprint => (vec![7u8], Some(vec![7u8])),
			without_fingerprint => (Vec::new(), None),
		}
	}

	/// A plane that federates on a beat.
	fn beating() -> PeerConfig {
		PeerConfig { advertise_interval: Some(Duration::from_secs(5)), ..PeerConfig::default() }
	}

	// A gateway that beats from a wildcard bind must name the address it is
	// dialed at or refuse to start. A gateway that does not beat may bind any
	// address.
	tb_cases! {
		fn advertised_address_is_the_configured_one_or_a_dialable_bound_one((plane, bound, expected): (PeerConfig, &[u8], Result<&[u8], ClusterError>)) {
			let advertised = plane.advertised_address(bound);
			let outcome = advertised.as_deref().map_err(discriminant);
			let expected = expected.map_err(|error| discriminant(&error));
			assert_eq!(outcome, expected);
		}
		cases {
			bound_loopback_on_a_beat => (beating(), b"127.0.0.1:9000", Ok(b"127.0.0.1:9000")),
			bound_wildcard_on_a_beat => (beating(), b"0.0.0.0:9000", Err(ClusterError::AdvertiseAddressRequired)),
			bound_ipv6_wildcard_on_a_beat => (beating(), b"[::]:9000", Err(ClusterError::AdvertiseAddressRequired)),
			bound_wildcard_without_federating => (PeerConfig::default(), b"0.0.0.0:9000", Ok(b"0.0.0.0:9000")),
			bound_a_non_socket_on_a_beat => (beating(), b"airspace-slot-7", Ok(b"airspace-slot-7")),
		}
	}
}
