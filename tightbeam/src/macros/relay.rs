/// Relay a `Beamable` value over an MPSC-style channel as a V0 frame.
///
/// Evaluates to `Result<(), TightBeamError>`: build and send failures
/// propagate to the caller instead of being swallowed, and the macro never
/// returns from the enclosing function.
#[macro_export]
macro_rules! relay {
	($beamable:expr, $tx:expr) => {{
		// Build a simple V0 wrapper with id=0, order=0. `build` is called
		// through its trait path so callers need not import `TypeBuilder`.
		let __result: ::core::result::Result<(), $crate::TightBeamError> = $crate::builder::TypeBuilder::build(
			$crate::utils::compose($crate::Version::V0)
				.with_id(b"\0")
				.with_order(0u64)
				.with_message($beamable),
		)
		.and_then(|__frame| $tx.send(__frame).map_err(|_| $crate::TightBeamError::ChannelClosed));
		__result
	}};
}

#[cfg(test)]
mod tests {
	use crate::der::Sequence;
	use crate::{Beamable, TightBeamError};

	#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
	struct RelayMessage {
		value: u64,
	}

	#[test]
	fn relays_frame_over_channel() -> Result<(), TightBeamError> {
		let (tx, rx) = std::sync::mpsc::channel();

		relay!(RelayMessage { value: 7 }, tx)?;

		let frame = rx.recv().map_err(|_| TightBeamError::ChannelClosed)?;
		let decoded: RelayMessage = crate::decode(&frame.message)?;
		assert_eq!(decoded, RelayMessage { value: 7 });

		Ok(())
	}

	#[test]
	fn send_failure_surfaces_as_error() {
		let (tx, rx) = std::sync::mpsc::channel::<crate::Frame>();
		drop(rx);

		let result = relay!(RelayMessage { value: 7 }, tx);
		assert!(matches!(result, Err(TightBeamError::ChannelClosed)));
	}
}
