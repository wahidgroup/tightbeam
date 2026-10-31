//! [`TraceHandle`] holds the live trace of an owner. The owner can replace
//! that trace while its readers share the handle.

use std::sync::{Arc, PoisonError, RwLock};

use crate::trace::TraceCollector;

/// A shared handle to the trace that an owner records into.
///
/// Each reader takes the trace the handle holds when its work starts, so a
/// replacement reaches the work that starts after it. A servlet reads its
/// handle once for each connection it accepts and on each read of the
/// [`ServletContext::trace`] of a request.
///
/// # Poisoning
///
/// The handle holds one whole collector, so a lock that a holder poisoned in
/// a panic still holds a whole one, and a read or a replacement goes ahead.
///
/// [`ServletContext::trace`]: crate::colony::servlet::ServletContext::trace
#[derive(Clone)]
pub(crate) struct TraceHandle(Arc<RwLock<Arc<TraceCollector>>>);

impl TraceHandle {
	/// A handle that holds `trace`.
	pub(crate) fn new(trace: Arc<TraceCollector>) -> Self {
		Self(Arc::new(RwLock::new(trace)))
	}

	/// The trace that this handle holds at the call.
	pub(crate) fn current(&self) -> Arc<TraceCollector> {
		let held = self.0.read().unwrap_or_else(PoisonError::into_inner);
		Arc::clone(&held)
	}

	/// Replaces the trace this handle holds with `trace`, for every share of
	/// the handle.
	pub(crate) fn replace(&self, trace: Arc<TraceCollector>) {
		let mut held = self.0.write().unwrap_or_else(PoisonError::into_inner);
		*held = trace;
	}
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use super::TraceHandle;
	use crate::testing::fixtures::poison_write;
	use crate::trace::TraceCollector;

	/// A handle whose lock a holder poisoned with a panic while it held the
	/// lock for a write.
	fn poisoned_handle() -> TraceHandle {
		let handle = TraceHandle::new(Arc::new(TraceCollector::default()));
		poison_write(&handle.0);
		handle
	}

	/// A replacement on a poisoned handle installs the new collector, because
	/// the handle holds one whole value.
	#[test]
	fn a_poisoned_handle_takes_the_replacement() {
		let handle = poisoned_handle();
		let trace = Arc::new(TraceCollector::default());
		handle.replace(Arc::clone(&trace));
		assert!(Arc::ptr_eq(&handle.current(), &trace));
	}

	/// Every share of a handle reads the trace that a replacement installs.
	#[test]
	fn a_share_of_a_handle_reads_the_replacement() {
		let handle = TraceHandle::new(Arc::new(TraceCollector::default()));
		let share = handle.clone();
		let trace = Arc::new(TraceCollector::default());

		handle.replace(Arc::clone(&trace));

		assert!(Arc::ptr_eq(&share.current(), &trace));
	}
}
