//! Properties the wire types hold for every value, not just the sampled ones.
//!
//! A round trip is the one property a codec cannot be correct without: what
//! the encoder writes, the decoder must read back unchanged. Example-based
//! tests fix the field combination they happen to name, so they cover the
//! shapes someone thought of. These generate the shape.

#![cfg(all(feature = "testing-property", feature = "std"))]

use proptest::prelude::*;
use tightbeam::asn1::{DigestInfo, Frame, Metadata, SignerInfo, Version};
use tightbeam::der::{Decode, Encode};
use tightbeam::testing::{TestDigest, TestSigner};

/// Every wire version, so a field a later version added is exercised under
/// the version that does not carry it as well as the ones that do.
fn any_version() -> impl Strategy<Value = Version> {
	prop_oneof![Just(Version::V0), Just(Version::V1), Just(Version::V2), Just(Version::V3)]
}

/// Present or absent, which is what makes the two optional fields a power set
/// rather than two independent cases.
fn any_digest() -> impl Strategy<Value = Option<DigestInfo>> {
	prop_oneof![Just(None), Just(Some(TestDigest::info()))]
}

fn any_signer() -> impl Strategy<Value = Option<SignerInfo>> {
	prop_oneof![Just(None), Just(Some(TestSigner::info()))]
}

proptest! {
	/// Four versions against the power set of the two optional fields, over
	/// arbitrary identifiers, orders, and payloads.
	#[test]
	fn a_frame_survives_a_der_round_trip(
		version in any_version(),
		id in prop::collection::vec(any::<u8>(), 0..32),
		order in any::<u64>(),
		message in prop::collection::vec(any::<u8>(), 0..512),
		integrity in any_digest(),
		nonrepudiation in any_signer(),
	) {
		// `Metadata` zeroizes on drop, so the struct-update shorthand cannot
		// move the rest out of a default. Build it and set the two fields.
		let mut metadata = Metadata::default();
		metadata.id = id;
		metadata.order = order;

		let frame = Frame { version, metadata, message, integrity, nonrepudiation };
		let encoded = frame.to_der().expect("a frame built from valid parts encodes");
		let decoded = Frame::from_der(&encoded).expect("what the encoder wrote, the decoder reads");
		prop_assert_eq!(frame, decoded);
	}
}
