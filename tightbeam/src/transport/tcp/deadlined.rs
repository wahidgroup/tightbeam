//! Wire I/O of the async transport, under a deadline on the clock of the link.
//!
//! Each wrapper owns its stream in a private field, beside the [`Timer`] that
//! bounds its waits. Its only read takes the [`ReadPolicy`] that sets the
//! ceiling and the deadline, and its only write takes the [`CheckedLimits`] of
//! the link. A transport in this crate reaches the wire through these methods
//! alone, so each read and write of the wire runs within the deadline its rule
//! sets, wherever [`Clock::timing`] lets a timer race it.
//!
//! Where the clock offers `Clock::resetting_sleep`, the timer keeps one sleep
//! across the waits of its wrapper. It makes that sleep at the first wait
//! still pending after its first poll, and resets it for each later wait.

use core::pin::pin;
use std::sync::Arc;

use crate::clock::{Clock, MonotonicInstant, Timer};
use crate::transport::protocols::{AsyncProtocolStream, AsyncReadStream, AsyncWriteStream, SplittableStream};
use crate::transport::state::ReadPolicy;
use crate::transport::{CheckedLimits, TransportError, TransportResult};

/// A whole stream that reads and writes only under a deadline.
///
/// It also keeps the timer of an exchange, which bounds several reads and
/// writes together, beside the timer of each read and write.
pub(crate) struct Deadlined<S> {
	stream: S,
	timer: Timer,
	exchange: Option<Timer>,
}

/// The read half of a split stream, which reads only under a deadline.
pub(crate) struct DeadlinedRead<R> {
	stream: R,
	timer: Timer,
}

/// The write half of a split stream, which writes only under a deadline.
pub(crate) struct DeadlinedWrite<W> {
	stream: W,
	timer: Timer,
}

impl<S> Deadlined<S> {
	/// `stream`, whose waits run on `clock`.
	pub(crate) fn new(stream: S, clock: &Arc<dyn Clock>) -> Self {
		Self { stream, timer: Timer::new(Arc::clone(clock)), exchange: None }
	}

	/// The timer of an exchange that bounds several reads and writes, an emit
	/// cycle or a server handshake round, which the exchange hands back
	/// through [`Self::keep_exchange_timer`] once it ends.
	pub(crate) fn exchange_timer(&mut self) -> Timer {
		let clock = self.timer.clock();
		self.exchange.take().unwrap_or_else(|| Timer::new(Arc::clone(clock)))
	}

	/// Keep `timer` for the next exchange.
	pub(crate) fn keep_exchange_timer(&mut self, timer: Timer) {
		self.exchange = Some(timer);
	}
}

impl<S> Deadlined<S>
where
	S: AsyncProtocolStream,
	TransportError: From<S::Error>,
{
	/// Read one envelope under `policy`, measured from `now`.
	///
	/// # Errors
	///
	/// - The errors of [`ReadPolicy::bound`] and the read error of the stream.
	pub(crate) async fn read(&mut self, policy: &ReadPolicy, now: MonotonicInstant) -> TransportResult<Vec<u8>> {
		let Self { stream, timer, .. } = self;
		let read = policy.bound(timer, now, pin!(stream.read_frame(policy.cap()))).await?;
		Ok(read?)
	}

	/// Write `frame` under the operation timeout of `limits`.
	///
	/// # Errors
	///
	/// - The errors of [`CheckedLimits::bound`] and the write error of the stream.
	pub(crate) async fn write(&mut self, limits: &CheckedLimits, frame: &[u8]) -> TransportResult<()> {
		let Self { stream, timer, .. } = self;
		let written = limits.bound(timer, pin!(stream.write_frame(frame))).await?;
		Ok(written?)
	}

	/// Whether the stream appears connected. The check returns at once.
	pub(crate) fn is_alive(&self) -> bool {
		self.stream.is_alive()
	}
}

impl<S: SplittableStream> Deadlined<S> {
	/// The read half and the write half of this stream, each still under a
	/// deadline. The read half keeps the timer of this stream.
	pub(crate) fn into_split(self) -> (DeadlinedRead<S::ReadHalf>, DeadlinedWrite<S::WriteHalf>) {
		let (read_half, write_half) = self.stream.into_split();
		let write_timer = Timer::new(Arc::clone(self.timer.clock()));
		let reader = DeadlinedRead { stream: read_half, timer: self.timer };
		(reader, DeadlinedWrite { stream: write_half, timer: write_timer })
	}
}

#[cfg(test)]
impl<R> DeadlinedRead<R> {
	/// `stream`, whose waits run on `clock`.
	pub(crate) fn new(stream: R, clock: &Arc<dyn Clock>) -> Self {
		Self { stream, timer: Timer::new(Arc::clone(clock)) }
	}
}

impl<R> DeadlinedRead<R>
where
	R: AsyncReadStream,
	TransportError: From<R::Error>,
{
	/// Read one envelope under `policy`, measured from `now`.
	///
	/// # Errors
	///
	/// - The errors of [`ReadPolicy::bound`] and the read error of the stream.
	pub(crate) async fn read(&mut self, policy: &ReadPolicy, now: MonotonicInstant) -> TransportResult<Vec<u8>> {
		let Self { stream, timer } = self;
		let read = policy.bound(timer, now, pin!(stream.read_frame(policy.cap()))).await?;
		Ok(read?)
	}
}

#[cfg(test)]
impl<W> DeadlinedWrite<W> {
	/// `stream`, whose waits run on `clock`.
	pub(crate) fn new(stream: W, clock: &Arc<dyn Clock>) -> Self {
		Self { stream, timer: Timer::new(Arc::clone(clock)) }
	}
}

impl<W> DeadlinedWrite<W>
where
	W: AsyncWriteStream,
	TransportError: From<W::Error>,
{
	/// Write `frame` under the operation timeout of `limits`.
	///
	/// # Errors
	///
	/// - The errors of [`CheckedLimits::bound`] and the write error of the stream.
	pub(crate) async fn write(&mut self, limits: &CheckedLimits, frame: &[u8]) -> TransportResult<()> {
		let Self { stream, timer } = self;
		let written = limits.bound(timer, pin!(stream.write_frame(frame))).await?;
		Ok(written?)
	}
}
