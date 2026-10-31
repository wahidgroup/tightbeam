//! The integration tests that pin the wire format of the mux open envelope
//! across feature builds.

#[cfg(feature = "transport-multiplex")]
mod with_multiplex {
	use tightbeam::der::Encode;
	use tightbeam::transport::envelopes::{MuxOpenPackage, MuxStreamKind};
	use tightbeam::transport::TransportEnvelope;

	use crate::common::result::TestResult;

	/// Pins [`super::super::MUX_OPEN_WIRE_DER`] to real encoder output so the
	/// non-mux rejection test rejects the same bytes a mux build emits.
	#[test]
	fn mux_open_wire_literal_matches_encoder() -> TestResult {
		let open_package = MuxOpenPackage::new(1, true, MuxStreamKind::Unary, Vec::new())?;
		let envelope = TransportEnvelope::from(open_package);

		let encoded = envelope.to_der()?;
		assert_eq!(encoded, super::super::MUX_OPEN_WIRE_DER);
		Ok(())
	}
}

#[cfg(not(feature = "transport-multiplex"))]
mod without_multiplex {
	use tightbeam::der::{Decode, ErrorKind, Tag, TagNumber};
	use tightbeam::transport::TransportEnvelope;

	/// The `[4]` tag that the `Mux` alternative takes in a build with
	/// multiplexing.
	const MUX_TAG: Tag = Tag::ContextSpecific { constructed: true, number: TagNumber::N4 };

	/// Context tag 4 (`Mux`) is not a valid `TransportEnvelope`
	/// alternative when multiplexing is compiled out, so the envelope must
	/// fail to decode instead of being silently misinterpreted.
	#[test]
	fn muxed_wire_tag_fails_decode_on_non_mux_build() {
		let decoded = TransportEnvelope::from_der(&super::super::MUX_OPEN_WIRE_DER);
		let refused = decoded.map_err(|error| error.kind());
		assert_eq!(refused, Err(ErrorKind::TagUnexpected { expected: None, actual: MUX_TAG }));
	}
}
