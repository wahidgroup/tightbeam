//! The reassembly of a peer's chunks into one buffer, under the ceiling of
//! its stream and the budget of its connection.
//!
//! The reader reassembles a unary stream here, and a [`StreamBody`] collects
//! its chunks here, so both paths hold one bound.
//!
//! [`StreamBody`]: super::body::StreamBody

#[cfg(not(all(test, tightbeam_loom)))]
use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[cfg(all(test, tightbeam_loom))]
use loom::sync::atomic::{AtomicUsize, Ordering};

use crate::constants::{MAX_MUX_CONNECTION_REASSEMBLY_BYTES, MAX_MUX_REASSEMBLY_BYTES};
use crate::transport::{TransportError, TransportFailure, TransportResult};

/// The reassembly bytes that every stream on one connection buffers.
///
/// A per-stream ceiling multiplies by the number of streams a peer opens, so
/// the connection holds this shared counter and every [`Reassembly`] charges
/// against it.
#[derive(Debug)]
pub(crate) struct ReassemblyBudget {
	used: AtomicUsize,
	ceiling: usize,
}

impl Default for ReassemblyBudget {
	fn default() -> Self {
		Self::with_ceiling(MAX_MUX_CONNECTION_REASSEMBLY_BYTES)
	}
}

impl ReassemblyBudget {
	pub(crate) fn with_ceiling(ceiling: usize) -> Self {
		Self { used: AtomicUsize::new(0), ceiling }
	}

	/// Reserve `bytes` for a stream, or refuse when the connection is full.
	fn try_charge(&self, bytes: usize) -> bool {
		let mut used = self.used.load(Ordering::Relaxed);
		loop {
			let Some(next) = used.checked_add(bytes).filter(|next| *next <= self.ceiling) else {
				return false;
			};

			match self
				.used
				.compare_exchange_weak(used, next, Ordering::Relaxed, Ordering::Relaxed)
			{
				Ok(_) => return true,
				Err(observed) => used = observed,
			}
		}
	}

	/// Return `bytes` to the connection.
	fn release(&self, bytes: usize) {
		self.used.fetch_sub(bytes, Ordering::Relaxed);
	}

	/// Returns the bytes that the streams of the connection hold.
	#[cfg(test)]
	pub(crate) fn used(&self) -> usize {
		self.used.load(Ordering::Relaxed)
	}
}

/// The bytes one peer stream reassembles, under the stream ceiling and a share
/// of its connection's [`ReassemblyBudget`].
///
/// One predicate checks both ceilings for every chunk. The capacity of the
/// buffer stays within the stream ceiling, and the bytes it holds return to
/// the budget when it drops or hands them over.
pub(crate) struct Reassembly {
	/// The chunks concatenated in arrival order.
	buffer: Vec<u8>,
	/// The hard byte ceiling on `buffer`, fixed whatever credit the reader
	/// grants.
	max_bytes: usize,
	/// The connection-wide ceiling that this stream charges its bytes against.
	///
	/// The reassembly holds the budget instead of a borrow per call, so the
	/// [`Drop`] below returns the bytes whichever path discards it.
	budget: Arc<ReassemblyBudget>,
}

/// Return the buffered bytes to the connection budget.
///
/// Map removal, an error return, and task teardown all run this, so every
/// path that discards a stream releases its reservation.
impl Drop for Reassembly {
	fn drop(&mut self) {
		self.budget.release(self.buffer.len());
	}
}

impl Reassembly {
	/// Creates an empty reassembly under [`MAX_MUX_REASSEMBLY_BYTES`], charged
	/// against `budget`.
	pub(crate) fn new(budget: Arc<ReassemblyBudget>) -> Self {
		Self::with_ceiling(MAX_MUX_REASSEMBLY_BYTES, budget)
	}

	/// Creates an empty reassembly under a ceiling of `max_bytes`, charged
	/// against `budget`.
	pub(crate) fn with_ceiling(max_bytes: usize, budget: Arc<ReassemblyBudget>) -> Self {
		Self { buffer: Vec::new(), max_bytes, budget }
	}

	/// Append `payload` under the stream ceiling and the connection ceiling.
	///
	/// It charges the connection ceiling before it holds the bytes, so the
	/// budget refuses a peer that spreads its payload across many streams once
	/// their total passes the connection ceiling, as the stream ceiling refuses
	/// one stream. The capacity doubles up to the stream ceiling, so the buffer
	/// holds at most what the ceiling admits (CWE-770).
	///
	/// # Errors
	///
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::SizeExceeded`] -- `payload` passes the stream
	///   ceiling or the connection ceiling.
	pub(crate) fn append(&mut self, payload: impl AsRef<[u8]>) -> TransportResult<()> {
		let payload = payload.as_ref();
		let collected = self.buffer.len().saturating_add(payload.len());
		if collected > self.max_bytes {
			return Err(TransportError::OperationFailed(TransportFailure::SizeExceeded));
		}
		if !self.budget.try_charge(payload.len()) {
			return Err(TransportError::OperationFailed(TransportFailure::SizeExceeded));
		}

		if collected > self.buffer.capacity() {
			let doubled = self.buffer.capacity().saturating_mul(2);
			let capacity = doubled.max(collected).min(self.max_bytes);
			self.buffer.reserve_exact(capacity.saturating_sub(self.buffer.len()));
		}
		self.buffer.extend_from_slice(payload);

		Ok(())
	}

	/// Returns the bytes reassembled so far.
	pub(crate) fn as_slice(&self) -> &[u8] {
		&self.buffer
	}

	/// Whether the bytes reach the stream ceiling, so no further payload fits.
	pub(crate) fn is_full(&self) -> bool {
		self.buffer.len() >= self.max_bytes
	}

	/// Hand the reassembled bytes over, and return their share of the
	/// connection budget, because they leave the reassembly.
	pub(crate) fn into_bytes(mut self) -> Vec<u8> {
		let bytes = core::mem::take(&mut self.buffer);
		self.budget.release(bytes.len());

		bytes
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The stream ceiling of the reassemblies under test.
	const CEILING: usize = 100;

	/// The capacity grows toward the stream ceiling and stops there, where a
	/// plain `Vec` would double past it.
	#[test]
	fn a_reassembly_holds_no_capacity_past_its_ceiling() -> TransportResult<()> {
		let mut reassembly = Reassembly::with_ceiling(CEILING, Arc::new(ReassemblyBudget::default()));
		reassembly.append([0u8; 30])?;
		reassembly.append([0u8; 30])?;
		reassembly.append([0u8; 30])?;

		let bytes = reassembly.into_bytes();
		assert!(bytes.capacity() <= CEILING);
		Ok(())
	}

	/// The reassembly refuses a payload past the stream ceiling, though the
	/// connection has room.
	#[test]
	fn a_payload_past_the_stream_ceiling_is_refused() {
		let mut reassembly = Reassembly::with_ceiling(CEILING, Arc::new(ReassemblyBudget::default()));

		let refusal = reassembly.append([0u8; CEILING + 1]);
		let oversize = matches!(refusal, Err(TransportError::OperationFailed(TransportFailure::SizeExceeded)));
		assert!(oversize);
	}

	/// Bytes handed over leave the reassembly, so they return to the
	/// connection budget.
	#[test]
	fn handing_bytes_over_returns_them_to_the_connection() -> TransportResult<()> {
		let budget = Arc::new(ReassemblyBudget::with_ceiling(CEILING));
		let mut reassembly = Reassembly::with_ceiling(CEILING, Arc::clone(&budget));
		reassembly.append([0u8; CEILING])?;

		let _bytes = reassembly.into_bytes();
		assert_eq!(budget.used(), 0);
		Ok(())
	}
}

/// The loom models of the connection budget, whose charge and release race on
/// one counter from the reader task and the stream bodies.
#[cfg(all(test, tightbeam_loom))]
mod loom_models {
	use loom::thread::{self, JoinHandle};

	use super::*;

	/// The stream ceiling of the reassemblies under test, past every payload.
	const CEILING: usize = 100;

	/// Appends `len` octets to a new reassembly charged against `budget`, and
	/// returns the reassembly, which holds its charge, and whether the
	/// reassembly admitted the append.
	fn append(budget: &Arc<ReassemblyBudget>, len: usize) -> (Reassembly, bool) {
		let mut reassembly = Reassembly::with_ceiling(CEILING, Arc::clone(budget));
		let admitted = reassembly.append(vec![0u8; len]).is_ok();
		(reassembly, admitted)
	}

	/// Runs [`append`] on a new thread.
	fn spawn_append(budget: &Arc<ReassemblyBudget>, len: usize) -> JoinHandle<(Reassembly, bool)> {
		let budget = Arc::clone(budget);
		thread::spawn(move || append(&budget, len))
	}

	/// Drops `reassembly` on a new thread, which returns its bytes to the
	/// budget.
	fn spawn_drop(reassembly: Reassembly) -> JoinHandle<()> {
		thread::spawn(move || drop(reassembly))
	}

	/// Waits for `handle` and returns the output of its thread.
	fn joined<T>(handle: JoinHandle<T>) -> T {
		handle.join().expect("the model thread finishes")
	}

	/// Two appends that together pass the connection ceiling race, and the
	/// budget admits one of them and holds its bytes alone.
	#[test]
	fn two_racing_appends_past_the_ceiling_admit_one() {
		loom::model(|| {
			let budget = Arc::new(ReassemblyBudget::with_ceiling(8));
			let racer = spawn_append(&budget, 5);
			let (_here, admitted_here) = append(&budget, 5);
			let (_there, admitted_there) = joined(racer);

			assert_ne!(admitted_here, admitted_there);
			assert_eq!(budget.used(), 5);
		});
	}

	/// A reassembly that drops while another appends returns its bytes, and
	/// the charge of the append stays whole.
	#[test]
	fn a_release_racing_an_append_keeps_the_charge_of_the_append() {
		loom::model(|| {
			let budget = Arc::new(ReassemblyBudget::with_ceiling(10));
			let (held, _) = append(&budget, 5);
			let releasing = spawn_drop(held);
			let (_kept, admitted) = append(&budget, 5);
			joined(releasing);

			assert_eq!((admitted, budget.used()), (true, 5));
		});
	}
}
