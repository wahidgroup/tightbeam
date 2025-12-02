use std::sync::{Arc, RwLock};

use tightbeam::{job, Frame, TightBeamError};

use crate::dtn::{ordering::OutOfOrderBuffer, storage::FrameStore};

job! {
	/// Persists a frame and inserts into the order buffer.
	/// Returns `Some(frames)` if ready for validation, `None` if buffered.
	name: PersistAndBufferFrame,
	fn run(
		(frame, store, buffer): (Frame, Arc<RwLock<FrameStore>>, Arc<RwLock<OutOfOrderBuffer>>)
	) -> Result<Option<Vec<Frame>>, TightBeamError> {
		store.write()?.persist(&frame)?;
		buffer.write()?.insert(frame)
	}
}
