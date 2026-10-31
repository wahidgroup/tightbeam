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
			$crate::Version::V0
				.compose()
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
	use crate::testing::{TestMessage, TestResult};
	use crate::TightBeamError;

	/// The relay sends a V0 frame of the message, and the receiver decodes the
	/// message back from it.
	#[cfg(feature = "router")]
	#[test]
	fn relays_frame_over_channel() -> TestResult {
		let (tx, rx) = std::sync::mpsc::channel();

		relay!(TestMessage::sample(Some("relayed")), tx)?;

		let frame = rx.recv()?;
		let decoded: TestMessage = frame.decode_message()?;
		assert_eq!(decoded, TestMessage::sample(Some("relayed")));

		Ok(())
	}

	/// A send to a channel whose receiver is gone fails as a closed channel.
	#[test]
	fn send_failure_surfaces_as_error() {
		let (tx, rx) = std::sync::mpsc::channel::<crate::Frame>();
		drop(rx);

		let result = relay!(TestMessage::sample(Some("relayed")), tx);
		assert!(matches!(result, Err(TightBeamError::ChannelClosed)));
	}
}
