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

#[cfg(feature = "colony")]
mod colony;
#[cfg(all(feature = "tokio", feature = "transport-multiplex"))]
mod transport;

use proptest::prelude::*;

use tightbeam::asn1::{Frame, GatedField, Version};
use tightbeam::builder::TypeBuilder;
use tightbeam::constants::MIN_SALT_SIZE;
use tightbeam::crypto::commitment::Opening;
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::profiles::SecurityProfileDesc;
use tightbeam::der::oid::ObjectIdentifier;
use tightbeam::der::{Decode, Encode};
use tightbeam::flags::{Flags, FlagsError};
use tightbeam::matrix::{Matrix, MatrixError};
use tightbeam::oids::{AES_256_GCM, CURVE_SECP256K1, HASH_SHA3_256};
use tightbeam::testing::{TestMessage, TestSigner};
use tightbeam::utils::urn::Urn;

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
fn built(
	version: Version,
	id: impl AsRef<[u8]>,
	order: u64,
	content: impl AsRef<str>,
	witnessed: bool,
	signed: bool,
) -> Frame {
	let id = id.as_ref();
	let content = content.as_ref();
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

/// A frame of any shape the four versions carry.
fn any_frame() -> impl Strategy<Value = Frame> {
	(any_shape(), prop::collection::vec(any::<u8>(), 0..32), any::<u64>(), ".{0,64}").prop_map(
		|((version, witnessed, signed), id, order, content)| built(version, id, order, content, witnessed, signed),
	)
}

/// Absent, or one OID from a pool every descriptor slot draws from, so an OID
/// that lands in the wrong slot is a visible difference.
fn any_algorithm() -> impl Strategy<Value = Option<ObjectIdentifier>> {
	prop::option::of(prop::sample::select(vec![HASH_SHA3_256, AES_256_GCM, CURVE_SECP256K1]))
}

/// The plain-digest salt, or a hiding salt drawn from two byte values so two
/// salts of one length can be equal or differ.
fn any_salt() -> impl Strategy<Value = Vec<u8>> {
	prop_oneof![Just(Vec::new()), prop::collection::vec(0u8..2, MIN_SALT_SIZE)]
}

/// The cells of `matrix` in the row-major order its `TryFrom` reads.
fn row_major(matrix: Matrix<3>) -> Vec<u8> {
	(0..3).filter_map(|r| matrix.row(r)).flatten().copied().collect()
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

	/// Nine bytes are both a 3 by 3 matrix and a set of nine flags, and each
	/// reads them back unchanged.
	#[test]
	fn a_matrix_and_a_flag_set_read_back_nine_bytes(bytes in prop::collection::vec(any::<u8>(), 9)) {
		let matrix = Matrix::<3>::try_from(bytes.as_slice()).map(row_major);
		let flags = Flags::<9>::try_from(bytes.as_slice()).map(Vec::<u8>::from);
		prop_assert_eq!(matrix, Ok(bytes.clone()));
		prop_assert_eq!(flags, Ok(bytes));
	}

	/// A matrix and a flag set both refuse every length but nine.
	#[test]
	fn a_matrix_and_a_flag_set_refuse_any_other_length(
		bytes in prop_oneof![prop::collection::vec(any::<u8>(), 0..9), prop::collection::vec(any::<u8>(), 10..20)],
	) {
		let len = bytes.len();
		let matrix = Matrix::<3>::try_from(bytes.as_slice()).map(row_major);
		let flags = Flags::<9>::try_from(bytes.as_slice()).map(Vec::<u8>::from);
		prop_assert_eq!(matrix, Err(MatrixError::LengthMismatch { n: 3, len }));
		prop_assert_eq!(flags, Err(FlagsError::LengthMismatch { expected: 9, len }));
	}

	/// What a URN displays, the parser reads back as the same URN.
	#[test]
	fn a_urn_survives_display_and_parse(nid in "[a-zA-Z][a-zA-Z0-9-]{1,31}", nss in ".{1,64}") {
		let urn = Urn::from_parts(nid, nss)?;
		prop_assert_eq!(urn.to_string().parse::<Urn<'static>>()?, urn);
	}

	/// Each algorithm carries its own tag, so any set of absent algorithms
	/// decodes back to the descriptor that was encoded.
	#[test]
	fn a_profile_descriptor_keeps_each_algorithm_in_its_slot(
		digest in any_algorithm(),
		aead in any_algorithm(),
		signature in any_algorithm(),
		kdf in any_algorithm(),
		curve in any_algorithm(),
		key_wrap in any_algorithm(),
	) {
		let descriptor = SecurityProfileDesc { digest, aead, signature, kdf, curve, key_wrap };
		prop_assert_eq!(SecurityProfileDesc::from_der(&descriptor.to_der()?)?, descriptor);
	}

	/// An opening verifies the commitment it was proven with, and no
	/// commitment over a different body or salt.
	#[test]
	fn an_opening_verifies_only_its_own_commitment(
		body in "[ab]{0,2}",
		salt in any_salt(),
		other_body in "[ab]{0,2}",
		other_salt in any_salt(),
	) {
		let (commitment, opening) = Opening::prove::<Sha3_256, _>(&TestMessage::sample(Some(&body)), &salt)?;
		let (other, _) = Opening::prove::<Sha3_256, _>(&TestMessage::sample(Some(&other_body)), &other_salt)?;
		prop_assert!(opening.verify::<Sha3_256>(&commitment)?);
		prop_assert_eq!(opening.verify::<Sha3_256>(&other)?, (body, salt) == (other_body, other_salt));
	}
}
