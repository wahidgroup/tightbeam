//! Wire-format pins for mux open envelopes across feature builds.

#[cfg(feature = "transport-multiplex")]
mod with_multiplex {
	use tightbeam::der::Encode;
	use tightbeam::transport::envelopes::{MuxOpenPackage, MuxStreamKind};
	use tightbeam::transport::TransportEnvelope;
	use tightbeam::TightBeamError;

	/// Pins [`super::super::MUX_OPEN_WIRE_DER`] to real encoder output so the
	/// non-mux rejection test rejects the same bytes a mux build emits.
	#[test]
	fn mux_open_wire_literal_matches_encoder() -> Result<(), TightBeamError> {
		let open_package = MuxOpenPackage::new(1, true, MuxStreamKind::Unary, Vec::new())?;
		let envelope = TransportEnvelope::from(open_package);

		let encoded = envelope.to_der()?;
		assert_eq!(
			encoded,
			super::super::MUX_OPEN_WIRE_DER,
			"wire literal must match encoder output"
		);
		Ok(())
	}
}

#[cfg(not(feature = "transport-multiplex"))]
mod without_multiplex {
	use tightbeam::der::Decode;
	use tightbeam::transport::TransportEnvelope;

	/// Context tag 4 (`Mux`) is not a valid `TransportEnvelope`
	/// alternative when multiplexing is compiled out, so the envelope must
	/// fail to decode instead of being silently misinterpreted.
	#[test]
	fn muxed_wire_tag_fails_decode_on_non_mux_build() {
		assert!(
			TransportEnvelope::from_der(&super::super::MUX_OPEN_WIRE_DER).is_err(),
			"mux wire tag must not decode when multiplexing is compiled out"
		);
	}
}
