//! Scenario teardown that survives a panic.
//!
//! A scenario tears down what it started: a servlet, an accept task, a hive,
//! a gateway. Running that cleanup on the line after the closure returns is
//! enough only while the closure returns. A test fails by panicking, so the
//! line after it is exactly the line a failing run skips, and the failing run
//! is the one that leaks.
//!
//! [`Teardown`] moves the cleanup into a drop, which unwinding runs.

/// Runs one cleanup action when it is dropped.
///
/// Hold the guard for as long as the resource must live. A panic anywhere
/// inside that scope still runs the action, because unwinding drops locals.
///
/// ```ignore
/// let servlet = start().await;
/// let _stop = Teardown::new(move || servlet.stop());
/// // Anything from here on may panic. The servlet still stops.
/// ```
pub struct Teardown(Option<Box<dyn FnOnce() + Send>>);

impl Teardown {
	/// Registers `action` to run when the guard is dropped.
	pub fn new(action: impl FnOnce() + Send + 'static) -> Self {
		Self(Some(Box::new(action)))
	}

	/// Runs the action now rather than at the end of the scope.
	///
	/// Use this where the scenario must observe the torn-down state, such as
	/// a port that has to be free before the next assertion reads it.
	pub fn run(mut self) {
		self.fire();
	}

	/// Runs the action once, if it has not run already.
	fn fire(&mut self) {
		if let Some(action) = self.0.take() {
			action();
		}
	}
}

impl Drop for Teardown {
	fn drop(&mut self) {
		self.fire();
	}
}

impl core::fmt::Debug for Teardown {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let state = if self.0.is_some() {
			"pending"
		} else {
			"done"
		};

		f.debug_tuple("Teardown").field(&state).finish()
	}
}

#[cfg(test)]
mod tests {
	use std::sync::atomic::{AtomicUsize, Ordering};
	use std::sync::Arc;

	use super::*;

	fn counting_teardown() -> (Teardown, Arc<AtomicUsize>) {
		let runs = Arc::new(AtomicUsize::new(0));
		let recorded = Arc::clone(&runs);

		(
			Teardown::new(move || {
				recorded.fetch_add(1, Ordering::SeqCst);
			}),
			runs,
		)
	}

	#[test]
	fn dropping_the_guard_runs_the_action() {
		let (guard, runs) = counting_teardown();
		drop(guard);

		assert_eq!(runs.load(Ordering::SeqCst), 1);
	}

	#[test]
	fn unwinding_past_the_guard_runs_the_action() {
		let (guard, runs) = counting_teardown();
		let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
			let _guard = guard;
			panic!("the scenario body failed");
		}));
		assert!(panicked.is_err(), "the panic must reach the caller");
		assert_eq!(runs.load(Ordering::SeqCst), 1);
	}

	#[test]
	fn running_the_action_early_does_not_run_it_again_on_drop() {
		let (guard, runs) = counting_teardown();
		guard.run();

		assert_eq!(runs.load(Ordering::SeqCst), 1);
	}
}
