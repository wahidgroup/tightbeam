//! Security profile negotiation for TightBeam handshakes.
//!
//! Provides minimal wire-level structures (Offer, Accept) for algorithm negotiation
//! without forcing concrete algorithm instantiation during the negotiation phase.

#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::crypto::profiles::SecurityProfileDesc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(feature = "derive")]
use crate::Errorizable;

/// Handshake offer carrying a list of supported security profiles.
///
/// Client sends this to advertise which algorithm combinations it supports.
/// Serializable to DER for wire transmission.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "derive", derive(crate::Beamable, crate::der::Sequence))]
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
#[cfg_attr(feature = "derive", derive(crate::Beamable, crate::der::Sequence))]
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

	/// DER encoding/decoding error.
	#[cfg_attr(feature = "derive", error("DER encoding error: {0}"))]
	DerError(crate::der::Error),
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for NegotiationError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::NoMutualProfile => write!(f, "No mutually supported security profile"),
			Self::EmptyOffer => write!(f, "Security offer is empty"),
			Self::DerError(e) => write!(f, "DER encoding error: {}", e),
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for NegotiationError {}

impl From<crate::der::Error> for NegotiationError {
	fn from(e: crate::der::Error) -> Self {
		Self::DerError(e)
	}
}

/// Select the first mutually supported profile from an offer against a list of supported profiles.
///
/// Server-side selection logic: iterate the client's offer (in preference order)
/// and pick the first profile that appears in the server's supported set.
///
/// # Arguments
/// * `offer` - Client's offered profiles (ordered by preference).
/// * `supported` - Server's supported profiles (order doesn't matter for intersection).
///
/// # Returns
/// * `Ok(SecurityProfileDesc)` - The selected profile.
/// * `Err(NegotiationError::NoMutualProfile)` - No intersection.
/// * `Err(NegotiationError::EmptyOffer)` - Client sent empty offer.
pub fn select_profile(
	offer: &SecurityOffer,
	supported: &[SecurityProfileDesc],
) -> Result<SecurityProfileDesc, NegotiationError> {
	if offer.profiles.is_empty() {
		return Err(NegotiationError::EmptyOffer);
	}

	// Find first client-preferred profile that server supports.
	for candidate in &offer.profiles {
		if supported.contains(candidate) {
			return Ok(*candidate);
		}
	}

	Err(NegotiationError::NoMutualProfile)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::der::asn1::ObjectIdentifier;

	fn mock_profile(id: u8) -> SecurityProfileDesc {
		SecurityProfileDesc {
			digest: ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.8"),
			#[cfg(feature = "aead")]
			aead: Some(ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.46")),
			#[cfg(feature = "signature")]
			signature: Some(ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.10")),
			// Use different key wrap algorithms to differentiate profiles
			key_wrap: match id {
				1 => Some(ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.5")), // AES-128 wrap
				2 => Some(ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.45")), // AES-256 wrap
				3 => Some(ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.25")), // AES-192 wrap
				_ => None,
			},
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
	fn test_select_first_mutual() {
		let p1 = mock_profile(1);
		let p2 = mock_profile(2);
		let p3 = mock_profile(3);

		let offer = SecurityOffer::new(Vec::from([p1, p2, p3]));
		let supported = [p2, p3];

		let selected = select_profile(&offer, &supported).unwrap();
		assert_eq!(selected, p2); // p2 comes first in offer
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
	fn test_empty_offer() {
		let offer = SecurityOffer::new(Vec::new());
		let supported = [mock_profile(1)];

		let result = select_profile(&offer, &supported);
		assert!(matches!(result, Err(NegotiationError::EmptyOffer)));
	}
}
