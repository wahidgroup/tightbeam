/// Relay - A simple MPSC relay for any Beamable type
#[macro_export]
macro_rules! relay {
	($beamable:expr, $tx:expr) => {{
		// Build a simple V0 wrapper with id=0, order=0
		let __frame = match $crate::compose! {
			V0: id: b"\0",
				order: 0u64,
				message: $beamable
		} {
			Ok(f) => f,
			Err(_) => return None,
		};

		// Send over any std::sync::mpsc::Sender<Frame>-like channel
		match $tx.send(__frame) {
			Ok(_) => Some(()),
			Err(_) => None,
		}
	}};
}
