//! Properties the wire types hold for every value, not just the sampled ones.
//!
//! A round trip is the one property a codec cannot be correct without: what
//! the encoder writes, the decoder must read back unchanged. Example-based
//! tests fix the field combination they happen to name, so they cover the
//! shapes someone thought of. These generate the shape.

#![cfg(all(
	feature = "testing-property",
	feature = "std",
	feature = "sha3",
	feature = "signature"
))]

use proptest::prelude::*;

use tightbeam::asn1::{Frame, GatedField, Version};
use tightbeam::builder::TypeBuilder;
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::der::{Decode, Encode};
use tightbeam::testing::{TestMessage, TestSigner};

/// Every wire version, so a field a later version added is exercised under
/// the version that does not carry it as well as the ones that do.
fn any_version() -> impl Strategy<Value = Version> {
	prop_oneof![Just(Version::V0), Just(Version::V1), Just(Version::V2), Just(Version::V3)]
}

/// Present or absent where `version` carries `field`, and always absent where
/// it does not.
fn carried(version: Version, field: GatedField) -> BoxedStrategy<bool> {
	if version.allows(field) {
		any::<bool>().boxed()
	} else {
		Just(false).boxed()
	}
}

/// A version with the power set of the two frame-level optional fields that
/// version carries.
fn any_shape() -> impl Strategy<Value = (Version, bool, bool)> {
	any_version().prop_flat_map(|version| {
		(
			Just(version),
			carried(version, GatedField::FrameIntegrity),
			carried(version, GatedField::Nonrepudiation),
		)
	})
}

/// The frame a sender builds from these parts.
fn built(version: Version, id: &[u8], order: u64, content: &str, witnessed: bool, signed: bool) -> Frame {
	let builder = version
		.compose()
		.with_id(id)
		.with_order(order)
		.with_message(TestMessage::sample(Some(content)));
	let builder = match witnessed {
		true => builder.with_witness_hasher::<Sha3_256>(),
		false => builder,
	};

	let mut frame = builder.build().expect("parts the version carries build");
	if signed {
		frame
			.attach_signer_info(TestSigner::info())
			.expect("a version that carries a signature accepts one");
	}

	frame
}

proptest! {
	/// Four versions against the power set of the frame-level optional fields
	/// each carries, over arbitrary identifiers, orders, and payloads.
	#[test]
	fn a_frame_survives_a_der_round_trip(
		(version, witnessed, signed) in any_shape(),
		id in prop::collection::vec(any::<u8>(), 0..32),
		order in any::<u64>(),
		content in ".{0,256}",
	) {
		let frame = built(version, &id, order, &content, witnessed, signed);
		let encoded = frame.to_der().expect("a built frame encodes");
		let decoded = Frame::from_der(&encoded).expect("what the encoder wrote, the decoder reads");
		prop_assert_eq!(frame, decoded);
	}
}
