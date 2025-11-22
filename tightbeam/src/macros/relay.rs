/// Relay - A simple MPSC relay for any Beamable type
#[macro_export]
macro_rules! relay {
	($beamable:expr, $tx:expr) => {{
		// Build a simple V0 wrapper with id=0, order=0
		let __frame = match $crate::utils::compose($crate::Version::V0)
			.with_id(b"\0")
			.with_order(0u64)
			.with_message($beamable)
			.build()
		{
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
