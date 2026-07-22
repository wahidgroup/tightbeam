//! Security profile negotiation for TightBeam handshakes.
//!
//! Provides minimal wire-level structures (Offer, Accept) for algorithm negotiation
//! without forcing concrete algorithm instantiation during the negotiation phase.

#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::constants::MAX_MUX_STREAM_CAP;
use crate::crypto::profiles::SecurityProfileDesc;
use crate::der::asn1::ObjectIdentifier;
use crate::der::Error as DerDecodeError;
use crate::der::Sequence;
use crate::Beamable;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(feature = "derive")]
use crate::Errorizable;

/// Maximum number of profiles accepted in a [`SecurityOffer`].
///
/// Bounds the pre-authentication O(offer x supported) negotiation scan
/// against offer-flood DoS (CWE-770).
pub const MAX_OFFER_PROFILES: usize = 32;

/// Handshake offer carrying a list of supported security profiles.
///
/// Client sends this to advertise which algorithm combinations it supports.
/// Serializable to DER for wire transmission.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "derive", derive(Beamable, Sequence))]
pub struct SecurityOffer {
	/// Ordered list of security profile descriptors (preference: first is most preferred).
	pub profiles: Vec<SecurityProfileDesc>,
}

impl SecurityOffer {
	/// Create a new offer with the given profiles (first = most preferred).
	pub fn new(profiles: Vec<SecurityProfileDesc>) -> Self {
		Self { profiles }
	}

	/// Create an offer for a single profile.
	pub fn single(profile: SecurityProfileDesc) -> Self {
		Self { profiles: Vec::from([profile]) }
	}
}

/// Handshake accept response carrying the selected security profile.
///
/// Server sends this after selecting a mutually supported profile from the client's offer.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "derive", derive(Beamable, Sequence))]
pub struct SecurityAccept {
	/// The selected security profile descriptor.
	pub profile: SecurityProfileDesc,
}

impl SecurityAccept {
	/// Create a new accept with the selected profile.
	pub fn new(profile: SecurityProfileDesc) -> Self {
		Self { profile }
	}
}

/// Transport capability offer (multiplexing).
///
/// Each side advertises how many streams its *peer* may concurrently initiate
/// (RFC 9113 § 5.1.2 directional semantics). Sent by the client inside its
/// handshake opening message so the offer is bound into the transcript.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "derive", derive(Beamable, Sequence))]
pub struct TransportOffer {
	/// Sender supports stream multiplexing.
	pub mux: bool,
	/// Concurrent streams the peer may initiate toward the sender.
	pub max_peer_initiated_streams: u32,
}

impl TransportOffer {
	/// Create a multiplexing offer advertising the given peer-initiated cap.
	pub fn mux(max_peer_initiated_streams: u32) -> Self {
		Self { mux: true, max_peer_initiated_streams }
	}
}

/// Transport capability accept (multiplexing).
///
/// Same shape as [`TransportOffer`]: the server advertises how many streams
/// the client may concurrently initiate. Sent inside the server's handshake
/// response and bound into the transcript.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "derive", derive(Beamable, Sequence))]
pub struct TransportAccept {
	/// Sender supports stream multiplexing.
	pub mux: bool,
	/// Concurrent streams the peer may initiate toward the sender.
	pub max_peer_initiated_streams: u32,
}

/// Negotiated multiplexing settings for one connection.
///
/// Caps are directional (RFC 9113 § 5.1.2): each endpoint enforces the
/// value it advertised and respects the value its peer advertised. There is
/// no symmetric min-collapse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MuxSettings {
	/// Concurrent streams this endpoint may initiate (peer-advertised).
	pub local_initiated_cap: u32,
	/// Concurrent streams the peer may initiate.
	pub peer_initiated_cap: u32,
}

impl MuxSettings {
	/// Equal caps in both directions, for links without handshake
	/// negotiation (cleartext multiplexing). Both endpoints MUST configure
	/// the same value or their concurrency enforcement diverges. The cap is
	/// clamped to [`MAX_MUX_STREAM_CAP`].
	pub fn symmetric(cap: u32) -> Self {
		let cap = clamp_stream_cap(cap);
		Self { local_initiated_cap: cap, peer_initiated_cap: cap }
	}
}

/// Clamp a wire-advertised concurrent-stream cap to
/// [`MAX_MUX_STREAM_CAP`] (CWE-770). Applied identically by both endpoints
/// to the same wire value, so directional views stay lock-step.
fn clamp_stream_cap(cap: u32) -> u32 {
	cap.min(MAX_MUX_STREAM_CAP)
}

/// Server-side accept rule: multiplexing activates only when the peer
/// offered it AND it is locally enabled. No offer or no local config means
/// no accept, which keeps the connection lock-step.
pub fn accept_transport(offer: Option<&TransportOffer>, local: Option<&TransportOffer>) -> Option<TransportAccept> {
	let offer = offer?;
	let local = local?;
	if !offer.mux || !local.mux {
		return None;
	}

	Some(TransportAccept { mux: true, max_peer_initiated_streams: local.max_peer_initiated_streams })
}

/// Client-side settings rule: validates the server's accept against the
/// local offer and derives the directional caps, each clamped to
/// [`MAX_MUX_STREAM_CAP`].
///
/// An accept without a matching offer is a protocol violation (a peer must
/// never activate an unrequested capability) and fails closed.
pub fn client_mux_settings(
	offer: Option<&TransportOffer>,
	accept: Option<&TransportAccept>,
) -> Result<Option<MuxSettings>, NegotiationError> {
	let accept = match accept {
		Some(accept) => accept,
		None => return Ok(None),
	};
	if !accept.mux {
		return Ok(None);
	}

	match offer {
		Some(offer) if offer.mux => Ok(Some(MuxSettings {
			local_initiated_cap: clamp_stream_cap(accept.max_peer_initiated_streams),
			peer_initiated_cap: clamp_stream_cap(offer.max_peer_initiated_streams),
		})),
		_ => Err(NegotiationError::UnsolicitedTransportAccept),
	}
}

/// Server-side settings rule: derives the directional caps from the
/// client's offer and the accept the server just emitted, each clamped
/// to [`MAX_MUX_STREAM_CAP`].
pub fn server_mux_settings(offer: &TransportOffer, accept: &TransportAccept) -> MuxSettings {
	MuxSettings {
		local_initiated_cap: clamp_stream_cap(offer.max_peer_initiated_streams),
		peer_initiated_cap: clamp_stream_cap(accept.max_peer_initiated_streams),
	}
}

/// Errors during profile negotiation.
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiationError {
	/// No mutually supported profile found.
	#[cfg_attr(feature = "derive", error("No mutually supported security profile"))]
	NoMutualProfile,

	/// Offer contains no profiles.
	#[cfg_attr(feature = "derive", error("Security offer is empty"))]
	EmptyOffer,

	/// No profile meets the configured minimum-strength policy.
	#[cfg_attr(feature = "derive", error("No profile meets the minimum-strength policy"))]
	BelowStrengthFloor,

	/// Offer exceeds the maximum accepted profile count.
	#[cfg_attr(
		feature = "derive",
		error("Security offer too large: {count} profiles exceeds cap of {max}")
	)]
	OfferTooLarge { count: usize, max: usize },

	/// Peer accepted a transport capability that was never offered.
	#[cfg_attr(
		feature = "derive",
		error("Peer accepted a transport capability that was never offered")
	)]
	UnsolicitedTransportAccept,

	/// DER encoding/decoding error.
	#[cfg_attr(feature = "derive", error("DER encoding error: {0}"))]
	DerError(DerDecodeError),
}

crate::impl_error_display!(NegotiationError {
	NoMutualProfile => "No mutually supported security profile",
	EmptyOffer => "Security offer is empty",
	BelowStrengthFloor => "No profile meets the minimum-strength policy",
	OfferTooLarge { count, max } => "Security offer too large: {count} profiles exceeds cap of {max}",
	UnsolicitedTransportAccept => "Peer accepted a transport capability that was never offered",
	DerError(e) => "DER encoding error: {e}",
});

impl From<DerDecodeError> for NegotiationError {
	fn from(e: DerDecodeError) -> Self {
		Self::DerError(e)
	}
}

/// Minimum-strength policy applied to profiles before negotiation.
///
/// Prevents downgrade attacks (CWE-757): even when a weak profile is mutually
/// supported, negotiation refuses it unless the policy admits it.
pub trait ProfileStrengthPolicy {
	/// Returns `true` when the profile meets the policy floor.
	fn meets_floor(&self, profile: &SecurityProfileDesc) -> bool;
}

/// Default strength floor: 256-bit AEAD key and a known digest of at least 256 bits.
///
/// Unknown digest OIDs fail closed.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultStrengthFloor;

/// Security strength in bits of a known digest OID; `0` for unknown OIDs (fail closed).
fn digest_bits(oid: &ObjectIdentifier) -> u16 {
	use crate::oids::{HASH_SHA256, HASH_SHA3_256, HASH_SHA3_384, HASH_SHA3_512};

	if *oid == HASH_SHA256 || *oid == HASH_SHA3_256 {
		return 256;
	}
	if *oid == HASH_SHA3_384 {
		return 384;
	}
	if *oid == HASH_SHA3_512 {
		return 512;
	}
	0
}

impl ProfileStrengthPolicy for DefaultStrengthFloor {
	fn meets_floor(&self, profile: &SecurityProfileDesc) -> bool {
		let aead_ok = matches!(profile.aead_key_size, Some(size) if size >= 32);
		let digest_ok = matches!(profile.digest.as_ref(), Some(oid) if digest_bits(oid) >= 256);
		aead_ok && digest_ok
	}
}

/// Accepts every profile; explicitly opts out of the minimum-strength floor.
///
/// Use only where weaker profiles must remain negotiable (e.g. compatibility
/// deployments or downgrade-attack test harnesses). Prefer
/// [`DefaultStrengthFloor`].
#[derive(Debug, Default, Clone, Copy)]
pub struct NoStrengthFloor;

impl ProfileStrengthPolicy for NoStrengthFloor {
	fn meets_floor(&self, _profile: &SecurityProfileDesc) -> bool {
		true
	}
}

/// Select the first mutually supported profile in *local* (server) preference order.
///
/// Iterates `supported` in its configured order and picks the first profile the
/// peer also offered. The peer's ordering carries no weight: a MITM rewriting
/// the offer ordering cannot steer selection toward a weaker mutual profile
/// (CWE-757).
///
/// # Arguments
/// * `offer` - Peer's offered profiles (ordering ignored).
/// * `supported` - Local profiles in preference order (first = most preferred).
///
/// # Returns
/// * `Ok(SecurityProfileDesc)` - The selected profile.
/// * `Err(NegotiationError::NoMutualProfile)` - No intersection.
/// * `Err(NegotiationError::EmptyOffer)` - Peer sent empty offer.
pub fn select_profile(
	offer: &SecurityOffer,
	supported: &[SecurityProfileDesc],
) -> Result<SecurityProfileDesc, NegotiationError> {
	if offer.profiles.is_empty() {
		return Err(NegotiationError::EmptyOffer);
	}
	if offer.profiles.len() > MAX_OFFER_PROFILES {
		return Err(NegotiationError::OfferTooLarge { count: offer.profiles.len(), max: MAX_OFFER_PROFILES });
	}

	for candidate in supported {
		if offer.profiles.contains(candidate) {
			return Ok(*candidate);
		}
	}

	Err(NegotiationError::NoMutualProfile)
}

#[cfg(test)]
mod tests {
	use core::error::Error;

	use super::*;
	use crate::oids::{
		AES_128_WRAP, AES_192_WRAP, AES_256_GCM, AES_256_WRAP, CURVE_SECP256K1, HASH_SHA3_256,
		SIGNER_ECDSA_WITH_SHA3_512,
	};

	fn mock_profile(id: u8) -> SecurityProfileDesc {
		SecurityProfileDesc {
			digest: Some(HASH_SHA3_256),
			aead: Some(AES_256_GCM),
			aead_key_size: Some(32),
			signature: Some(SIGNER_ECDSA_WITH_SHA3_512),
			kdf: Some(HASH_SHA3_256),
			curve: Some(CURVE_SECP256K1),
			// Use different key wrap algorithms to differentiate profiles
			key_wrap: match id {
				1 => Some(AES_128_WRAP),
				2 => Some(AES_256_WRAP),
				3 => Some(AES_192_WRAP),
				_ => None,
			},
			kem: None,
		}
	}

	#[test]
	fn test_offer_single() {
		let profile = mock_profile(1);
		let offer = SecurityOffer::single(profile);
		assert_eq!(offer.profiles.len(), 1);
		assert_eq!(offer.profiles[0], profile);
	}

	#[test]
	fn test_select_first_mutual() -> Result<(), Box<dyn Error>> {
		let p1 = mock_profile(1);
		let p2 = mock_profile(2);
		let p3 = mock_profile(3);

		let offer = SecurityOffer::new(Vec::from([p1, p2, p3]));
		let supported = [p2, p3];

		let selected = select_profile(&offer, &supported)?;
		assert_eq!(selected, p2);

		Ok(())
	}

	#[test]
	fn test_select_follows_server_preference_not_client_order() -> Result<(), Box<dyn Error>> {
		let p1 = mock_profile(1);
		let p2 = mock_profile(2);

		// Client prefers p1, server prefers p2; server preference must win
		// so a MITM reordering the offer cannot force the weaker profile.
		let offer = SecurityOffer::new(Vec::from([p1, p2]));
		let supported = [p2, p1];

		let selected = select_profile(&offer, &supported)?;
		assert_eq!(selected, p2);

		Ok(())
	}

	#[test]
	fn test_no_mutual_profile() {
		let p1 = mock_profile(1);
		let p2 = mock_profile(2);
		let p3 = mock_profile(3);

		let offer = SecurityOffer::new(Vec::from([p1, p2]));
		let supported = [p3];

		let result = select_profile(&offer, &supported);
		assert!(matches!(result, Err(NegotiationError::NoMutualProfile)));
	}

	#[test]
	fn test_oversized_offer_rejected() {
		let profile = mock_profile(1);
		let offer = SecurityOffer::new(vec![profile; MAX_OFFER_PROFILES + 1]);
		let supported = [profile];

		let result = select_profile(&offer, &supported);
		assert!(matches!(result, Err(NegotiationError::OfferTooLarge { count: 33, max: 32 })));
	}

	#[test]
	fn test_empty_offer() {
		let offer = SecurityOffer::new(Vec::new());
		let supported = [mock_profile(1)];

		let result = select_profile(&offer, &supported);
		assert!(matches!(result, Err(NegotiationError::EmptyOffer)));
	}

	#[test]
	fn test_accept_transport_requires_offer_and_local_config() {
		let offer = TransportOffer::mux(8);
		let local = TransportOffer::mux(4);

		let accept = accept_transport(Some(&offer), Some(&local));
		assert!(matches!(
			accept,
			Some(TransportAccept { mux: true, max_peer_initiated_streams: 4 })
		));

		assert!(accept_transport(None, Some(&local)).is_none());
		assert!(accept_transport(Some(&offer), None).is_none());

		let disabled = TransportOffer { mux: false, max_peer_initiated_streams: 8 };
		assert!(accept_transport(Some(&disabled), Some(&local)).is_none());
		assert!(accept_transport(Some(&offer), Some(&disabled)).is_none());
	}

	#[test]
	fn test_mux_settings_directional_caps() -> Result<(), NegotiationError> {
		let offer = TransportOffer::mux(8);
		let accept = TransportAccept { mux: true, max_peer_initiated_streams: 4 };

		let client =
			client_mux_settings(Some(&offer), Some(&accept))?.ok_or(NegotiationError::UnsolicitedTransportAccept)?;
		assert_eq!(client.local_initiated_cap, 4);
		assert_eq!(client.peer_initiated_cap, 8);

		let server = server_mux_settings(&offer, &accept);
		assert_eq!(server.local_initiated_cap, 8);
		assert_eq!(server.peer_initiated_cap, 4);

		Ok(())
	}

	#[test]
	fn test_mux_settings_clamp_peer_advertised_caps() -> Result<(), NegotiationError> {
		let offer = TransportOffer::mux(u32::MAX);
		let accept = TransportAccept { mux: true, max_peer_initiated_streams: u32::MAX };

		let client =
			client_mux_settings(Some(&offer), Some(&accept))?.ok_or(NegotiationError::UnsolicitedTransportAccept)?;
		assert_eq!(client.local_initiated_cap, MAX_MUX_STREAM_CAP);
		assert_eq!(client.peer_initiated_cap, MAX_MUX_STREAM_CAP);

		let server = server_mux_settings(&offer, &accept);
		assert_eq!(server.local_initiated_cap, MAX_MUX_STREAM_CAP);
		assert_eq!(server.peer_initiated_cap, MAX_MUX_STREAM_CAP);

		Ok(())
	}

	#[test]
	fn test_symmetric_settings_clamp_cap() {
		let settings = MuxSettings::symmetric(u32::MAX);
		assert_eq!(settings.local_initiated_cap, MAX_MUX_STREAM_CAP);
		assert_eq!(settings.peer_initiated_cap, MAX_MUX_STREAM_CAP);
	}

	#[test]
	fn test_unsolicited_transport_accept_fails_closed() {
		let accept = TransportAccept { mux: true, max_peer_initiated_streams: 4 };

		let result = client_mux_settings(None, Some(&accept));
		assert!(matches!(result, Err(NegotiationError::UnsolicitedTransportAccept)));

		let disabled = TransportOffer { mux: false, max_peer_initiated_streams: 8 };
		let result = client_mux_settings(Some(&disabled), Some(&accept));
		assert!(matches!(result, Err(NegotiationError::UnsolicitedTransportAccept)));
	}

	#[test]
	fn test_no_accept_means_lock_step() -> Result<(), NegotiationError> {
		let offer = TransportOffer::mux(8);
		assert!(client_mux_settings(Some(&offer), None)?.is_none());
		assert!(client_mux_settings(None, None)?.is_none());

		let declined = TransportAccept { mux: false, max_peer_initiated_streams: 0 };
		assert!(client_mux_settings(Some(&offer), Some(&declined))?.is_none());

		Ok(())
	}

	#[cfg(feature = "aead")]
	#[test]
	fn test_select_profile_multiple_aead_ciphers() -> Result<(), Box<dyn Error>> {
		use crate::oids::{
			AES_128_GCM, AES_128_WRAP, AES_256_GCM, AES_256_WRAP, CURVE_SECP256K1, HASH_SHA256,
			SIGNER_ECDSA_WITH_SHA256,
		};

		// AES-128-GCM profile
		let aes128_gcm = SecurityProfileDesc {
			digest: Some(HASH_SHA256),
			aead: Some(AES_128_GCM),
			aead_key_size: Some(16),
			signature: Some(SIGNER_ECDSA_WITH_SHA256),
			kdf: Some(HASH_SHA256),
			curve: Some(CURVE_SECP256K1),
			key_wrap: Some(AES_128_WRAP),
			kem: None,
		};

		// AES-256-GCM profile
		let aes256_gcm = SecurityProfileDesc {
			digest: Some(HASH_SHA256),
			aead: Some(AES_256_GCM),
			aead_key_size: Some(32),
			signature: Some(SIGNER_ECDSA_WITH_SHA256),
			kdf: Some(HASH_SHA256),
			curve: Some(CURVE_SECP256K1),
			key_wrap: Some(AES_256_WRAP),
			kem: None,
		};

		// Client offers AES-128 first; server prefers AES-256.
		let client_offer = SecurityOffer::new(Vec::from([aes128_gcm, aes256_gcm]));
		let server_supported = [aes256_gcm, aes128_gcm];

		// Server preference wins: AES-256-GCM regardless of client ordering
		let selected = select_profile(&client_offer, &server_supported)?;
		assert_eq!(selected.aead, Some(AES_256_GCM));
		assert_eq!(selected.aead_key_size, Some(32));

		let client_offer_256 = SecurityOffer::new(Vec::from([aes256_gcm, aes128_gcm]));
		let selected_256 = select_profile(&client_offer_256, &server_supported)?;
		assert_eq!(selected_256.aead, Some(AES_256_GCM));
		assert_eq!(selected_256.aead_key_size, Some(32));

		// Server preferring AES-128 gets AES-128 even if client leads with AES-256
		let server_128_first = [aes128_gcm, aes256_gcm];
		let selected_128 = select_profile(&client_offer_256, &server_128_first)?;
		assert_eq!(selected_128.aead, Some(AES_128_GCM));
		assert_eq!(selected_128.aead_key_size, Some(16));

		// Server only supports AES-256; client offering AES-128 first still gets AES-256
		let server_256_only = [aes256_gcm];
		let selected_fallback = select_profile(&client_offer, &server_256_only)?;
		assert_eq!(selected_fallback.aead, Some(AES_256_GCM));
		assert_eq!(selected_fallback.aead_key_size, Some(32));

		Ok(())
	}
}
