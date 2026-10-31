//! The task group that owns the background work of one colony runtime.

use core::future::Future;

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

#[cfg(test)]
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(test)]
use core::time::Duration;

use crate::runtime::rt;

/// The background tasks one runtime started.
///
/// A runtime keeps one group and puts every task it spawns in it, so one call
/// stops that work when the runtime stops. The handle is shared, so a context
/// handed to a request handler can adopt work the handler starts.
///
/// # Single spawn path
///
/// A task spawned outside the group runs past the stop meant to end it
/// (CWE-772), so the group is the one spawn path these runtimes offer.
#[derive(Clone, Default)]
pub struct TaskGroup(Arc<Mutex<TaskGroupState>>);

/// The handles of the tasks that run, and whether the group has stopped.
#[derive(Default)]
struct TaskGroupState {
	running: Vec<rt::JoinHandle>,
	stopped: bool,
}

impl TaskGroupState {
	/// Holds `handle`, and releases each handle whose task ended.
	///
	/// The sweep bounds the group by the tasks that still run, which keeps a
	/// runtime that spawns per request at the size of its live work.
	fn hold(&mut self, handle: rt::JoinHandle) {
		self.running.retain(|task| !task.is_finished());
		self.running.push(handle);
	}
}

impl TaskGroup {
	/// Takes ownership of `handle`, and releases each handle whose task ended.
	///
	/// A stopped group aborts `handle` on arrival, so work that starts while
	/// the runtime stops ends with the stop (CWE-772).
	pub fn adopt(&self, handle: rt::JoinHandle) {
		let mut state = self.state();
		if state.stopped {
			rt::abort(&handle);
			return;
		}

		state.hold(handle);
	}

	/// Runs `task` under this group's ownership.
	///
	/// The group reads its stop and starts the task under one hold of its
	/// lock, so a task that a stopped group refuses drops unstarted
	/// (CWE-367).
	pub fn spawn<F>(&self, task: F)
	where
		F: Future<Output = ()> + Send + 'static,
	{
		let mut state = self.state();
		if state.stopped {
			return;
		}

		state.hold(rt::spawn(task));
	}

	/// Stops the group and aborts every task it still owns.
	///
	/// A stop is terminal: a later [`TaskGroup::spawn`] starts nothing, and a
	/// later [`TaskGroup::adopt`] aborts on arrival, so the stop reaches every
	/// task the group owns.
	pub fn abort_all(&self) {
		let mut state = self.state();
		state.stopped = true;
		for task in state.running.drain(..) {
			rt::abort(&task);
		}
	}

	/// The group state, recovered from a poisoned lock because every write
	/// under the guard leaves a whole handle list and a whole flag.
	fn state(&self) -> MutexGuard<'_, TaskGroupState> {
		self.0.lock().unwrap_or_else(PoisonError::into_inner)
	}
}

#[cfg(test)]
impl TaskGroup {
	/// Spawns onto this group a task that sleeps out `span` and then raises
	/// the flag this returns, and yields once, so the task starts its sleep
	/// before the call returns.
	///
	/// The sleep runs on the tokio clock. Under `start_paused`, the flag rises
	/// only after the test moves the clock past `span`. A group that refuses
	/// the task leaves the flag down.
	async fn spawn_flagged(&self, span: Duration) -> Arc<AtomicBool> {
		let flag = Arc::new(AtomicBool::new(false));
		let raised = Arc::clone(&flag);
		self.spawn(async move {
			tokio::time::sleep(span).await;
			raised.store(true, Ordering::SeqCst);
		});

		tokio::task::yield_now().await;
		flag
	}
}

#[cfg(test)]
mod tests {
	use core::sync::atomic::{AtomicUsize, Ordering};
	use core::time::Duration;

	use std::sync::mpsc::{self, TryRecvError};

	use super::TaskGroup;
	use crate::testing::fixtures::poison;

	/// Counts the handles the group still holds.
	fn owned(group: &TaskGroup) -> usize {
		group.state().running.len()
	}

	/// Moves the paused test clock forward by `span` and lets every task it
	/// woke run.
	///
	/// The test runtime runs on one thread, so the yield hands that thread to
	/// each task the advance made ready before the test reads what it did.
	async fn advance_past(span: Duration) {
		tokio::time::advance(span).await;
		tokio::task::yield_now().await;
	}

	/// A span longer than any test moves its clock. A task that sleeps it out
	/// and then finishes shows that the stop missed it.
	const LONG_RUN: Duration = Duration::from_secs(30);

	/// The pause between two beats of the task under test.
	const BEAT: Duration = Duration::from_millis(5);

	// A stop aborts every task the group owns. A poisoned lock still holds
	// every handle the group adopted, so the stop reaches them all (CWE-772).
	crate::tb_cases! {
		#[tokio::test(start_paused = true)]
		async fn stopping_a_group_aborts_the_work_it_owns(prepare: fn(&TaskGroup)) {
			let group = TaskGroup::default();
			let finished = group.spawn_flagged(LONG_RUN).await;
			prepare(&group);

			group.abort_all();
			advance_past(LONG_RUN * 2).await;

			assert!(!finished.load(Ordering::SeqCst));
		}
		cases {
			under_a_live_lock => |_| {},
			under_a_poisoned_lock => |group| poison(&group.0),
		}
	}

	/// The group that owns a beat ends it even past the beat's own checks,
	/// so work cannot outlast the stop that withdrew its routes (CWE-362).
	#[tokio::test(start_paused = true)]
	async fn a_running_task_ends_when_its_group_stops() {
		static BEATS: AtomicUsize = AtomicUsize::new(0);

		let group = TaskGroup::default();
		group.spawn(async {
			loop {
				BEATS.fetch_add(1, Ordering::SeqCst);
				tokio::time::sleep(BEAT).await;
			}
		});

		tokio::task::yield_now().await;
		group.abort_all();
		let settled = BEATS.load(Ordering::SeqCst);
		assert_ne!(settled, 0);

		advance_past(BEAT * 8).await;
		assert_eq!(BEATS.load(Ordering::SeqCst), settled);
	}

	/// The state under a poisoned lock is whole, so a live group still runs
	/// the work it adopts.
	#[tokio::test(start_paused = true)]
	async fn a_poisoned_group_runs_the_work_it_adopts() {
		let group = TaskGroup::default();
		poison(&group.0);

		let finished = group.spawn_flagged(BEAT).await;
		advance_past(BEAT * 8).await;
		assert!(finished.load(Ordering::SeqCst));
	}

	/// A stopped group refuses the work that starts after the stop, so the
	/// work stays unfinished and the group holds no handle of it (CWE-772).
	#[tokio::test(start_paused = true)]
	async fn work_started_after_the_stop_does_not_outlive_it() {
		let group = TaskGroup::default();
		group.abort_all();

		let finished = group.spawn_flagged(BEAT).await;
		advance_past(BEAT * 8).await;
		assert_eq!((finished.load(Ordering::SeqCst), owned(&group)), (false, 0));
	}

	/// A stopped group reads its stop before it starts a task, so the task it
	/// refuses drops unstarted before the spawn returns, and the work before
	/// its first await never happens (CWE-367). A group that starts the task
	/// and then aborts it leaves the drop to the runtime, so the report
	/// channel of the task is still open at the check.
	#[tokio::test]
	async fn a_task_spawned_after_the_stop_does_no_work_before_its_first_await() {
		let group = TaskGroup::default();
		group.abort_all();

		let (report, ran) = mpsc::channel();

		group.spawn(async move {
			// The test reads the channel itself, so the result of the send
			// carries nothing more.
			let _reported = report.send(());
		});

		assert_eq!(ran.try_recv(), Err(TryRecvError::Disconnected));
	}

	/// The test runtime runs on one thread, so the yield runs the empty task
	/// to its end before the second spawn sweeps the group.
	#[tokio::test]
	async fn a_finished_task_leaves_the_group_on_the_next_spawn() {
		let group = TaskGroup::default();
		group.spawn(async {});
		tokio::task::yield_now().await;

		group.spawn(core::future::pending());
		assert_eq!(owned(&group), 1);
	}
}
