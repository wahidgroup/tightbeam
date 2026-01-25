//! Async runtime abstraction layer
//!
//! Provides unified primitives for task spawning, joining, and inter-task
//! communication with feature-gated implementations for tokio vs std threads.
//!
//! # Features
//!
//! - `tokio`: Uses tokio runtime primitives (recommended for async workloads)
//! - `std` (without tokio): Falls back to std threads with manual polling

/// Runtime primitives module
///
/// Contains type aliases and functions that abstract over the underlying
/// async runtime (tokio) or std threading.
#[cfg(feature = "tokio")]
pub mod rt {
	use core::future::Future;

	// =========================================================================
	// Types
	// =========================================================================

	/// Handle to a spawned task
	pub type JoinHandle = tokio::task::JoinHandle<()>;

	/// Error returned when joining a task fails
	pub type JoinError = tokio::task::JoinError;

	/// Multi-producer, single-consumer channel sender
	pub type Sender<T> = tokio::sync::mpsc::Sender<T>;

	/// Multi-producer, single-consumer channel receiver
	pub type Receiver<T> = tokio::sync::mpsc::Receiver<T>;

	/// One-shot channel sender (single value, single consumer)
	pub type OneshotSender<T> = tokio::sync::oneshot::Sender<T>;

	/// One-shot channel receiver (single value, single consumer)
	pub type OneshotReceiver<T> = tokio::sync::oneshot::Receiver<T>;

	// =========================================================================
	// Task Management
	// =========================================================================

	/// Spawn a future as an async task
	pub fn spawn<F>(fut: F) -> JoinHandle
	where
		F: Future<Output = ()> + Send + 'static,
	{
		tokio::spawn(fut)
	}

	/// Abort a spawned task
	pub fn abort(handle: &JoinHandle) {
		handle.abort();
	}

	/// Wait for a task to complete
	pub async fn join(handle: JoinHandle) -> Result<(), JoinError> {
		handle.await
	}

	/// Sleep for a duration
	pub async fn sleep(duration: core::time::Duration) {
		tokio::time::sleep(duration).await;
	}

	// =========================================================================
	// Channels
	// =========================================================================

	/// Create a bounded multi-producer, single-consumer channel
	pub fn channel<T>(capacity: usize) -> (Sender<T>, Receiver<T>) {
		tokio::sync::mpsc::channel(capacity)
	}

	/// Create a one-shot channel for single value transfer
	pub fn oneshot<T>() -> (OneshotSender<T>, OneshotReceiver<T>) {
		tokio::sync::oneshot::channel()
	}

	/// Send a value through a channel
	pub async fn send<T>(sender: &Sender<T>, value: T) -> Result<(), ()> {
		sender.send(value).await.map_err(|_| ())
	}

	/// Receive a value from a channel
	pub async fn recv<T>(receiver: &mut Receiver<T>) -> Option<T> {
		receiver.recv().await
	}

	/// Wait for a response on a oneshot channel
	pub async fn wait_response<T>(receiver: OneshotReceiver<T>) -> Result<T, ()> {
		receiver.await.map_err(|_| ())
	}

	// =========================================================================
	// Blocking
	// =========================================================================

	/// Block on a future from a synchronous context
	///
	/// # Panics
	/// Panics if called outside of a tokio runtime context.
	pub fn block_on<F>(future: F) -> F::Output
	where
		F: Future,
	{
		tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(future))
	}
}

#[cfg(all(not(feature = "tokio"), feature = "std"))]
#[allow(unsafe_code)]
pub mod rt {
	use core::{
		future::Future,
		pin::Pin,
		task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
	};
	use std::{
		io::{Error, ErrorKind},
		sync::mpsc,
		thread,
	};

	// =========================================================================
	// Types
	// =========================================================================

	/// Handle to a spawned thread
	pub type JoinHandle = thread::JoinHandle<()>;

	/// Error returned when joining a thread fails
	pub type JoinError = Error;

	/// Multi-producer, single-consumer channel sender (std)
	pub type Sender<T> = mpsc::Sender<T>;

	/// Multi-producer, single-consumer channel receiver (std)
	pub type Receiver<T> = mpsc::Receiver<T>;

	/// One-shot channel sender (simulated with mpsc)
	pub type OneshotSender<T> = mpsc::Sender<T>;

	/// One-shot channel receiver (simulated with mpsc)
	pub type OneshotReceiver<T> = mpsc::Receiver<T>;

	// =========================================================================
	// Task Management
	// =========================================================================

	/// Spawn a closure as a thread
	pub fn spawn<F>(task: F) -> JoinHandle
	where
		F: FnOnce() + Send + 'static,
	{
		thread::spawn(task)
	}

	/// Abort a thread (no-op for std threads - dropping detaches)
	pub fn abort(_handle: &JoinHandle) {
		// No cooperative cancellation for std threads
	}

	/// Wait for a thread to complete
	pub fn join(handle: JoinHandle) -> Result<(), JoinError> {
		handle.join().map_err(|_| Error::new(ErrorKind::Other, "thread panicked"))
	}

	// =========================================================================
	// Channels
	// =========================================================================

	/// Create an unbounded multi-producer, single-consumer channel
	///
	/// Note: std mpsc doesn't support bounded channels, capacity is ignored.
	pub fn channel<T>(_capacity: usize) -> (Sender<T>, Receiver<T>) {
		mpsc::channel()
	}

	/// Create a one-shot channel (simulated with mpsc)
	pub fn oneshot<T>() -> (OneshotSender<T>, OneshotReceiver<T>) {
		mpsc::channel()
	}

	/// Send a value through a channel (blocking)
	pub fn send<T>(sender: &Sender<T>, value: T) -> Result<(), ()> {
		sender.send(value).map_err(|_| ())
	}

	/// Receive a value from a channel (blocking)
	pub fn recv<T>(receiver: &Receiver<T>) -> Option<T> {
		receiver.recv().ok()
	}

	/// Wait for a response on a oneshot channel (blocking)
	pub fn wait_response<T>(receiver: OneshotReceiver<T>) -> Result<T, ()> {
		receiver.recv().map_err(|_| ())
	}

	/// Sleep for a duration (blocking)
	pub fn sleep(duration: core::time::Duration) {
		thread::sleep(duration);
	}

	// =========================================================================
	// Blocking
	// =========================================================================

	/// Block on a future using a minimal executor
	pub fn block_on<F: Future>(mut future: F) -> F::Output {
		fn raw_waker() -> RawWaker {
			fn clone(_: *const ()) -> RawWaker {
				raw_waker()
			}
			fn wake(_: *const ()) {}
			fn wake_by_ref(_: *const ()) {}
			fn drop(_: *const ()) {}

			static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
			RawWaker::new(core::ptr::null(), &VTABLE)
		}

		let waker = unsafe { Waker::from_raw(raw_waker()) };
		let mut cx = Context::from_waker(&waker);

		// SAFETY: we never move `future` after pinning
		let mut future = unsafe { Pin::new_unchecked(&mut future) };

		loop {
			match future.as_mut().poll(&mut cx) {
				Poll::Ready(result) => return result,
				Poll::Pending => thread::yield_now(),
			}
		}
	}
}
