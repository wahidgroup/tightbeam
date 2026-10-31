use core::any::{Any, TypeId};
use core::future::Future;
use core::pin::Pin;
use std::collections::HashMap;
use std::sync::Arc;

use crate::colony::hive::HiveContext;
use crate::colony::worker::{Worker, WorkerKillFuture};
use crate::core::{Inflator, Message};
use crate::crypto::aead::Decryptor;
use crate::frame::BodyTransform;
use crate::router::RouterError;
use crate::trace::{TraceCollector, TraceHandle};
use crate::{Frame, TightBeamError};

#[cfg(feature = "instrument")]
use crate::trace::InternalEvent;

/// The boxed future that [`WorkerBox::start_boxed`] returns.
pub type WorkerBoxStartFuture = Pin<Box<dyn Future<Output = Result<Box<dyn WorkerBox>, TightBeamError>> + Send>>;

/// The type-erased lifecycle of a worker in a worker map that a servlet owns.
///
/// Every [`Worker`] implements it, so a servlet starts and kills a worker of
/// any type through it.
pub trait WorkerBox: Send + Sync + Any {
	fn start_boxed(self: Box<Self>, trace: Arc<TraceCollector>) -> WorkerBoxStartFuture;

	/// Ends the worker through [`Worker::kill`], so its run loop answers each
	/// message its queue holds before it exits.
	///
	/// It takes the worker by reference, because the servlet shares its
	/// workers with every handler. [`ServletRuntime::drain`] calls it on each
	/// worker of the servlet.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::colony::servlet::WorkerBox;
	/// use tightbeam::testing::TestMessage;
	/// use tightbeam::trace::TraceCollector;
	/// use tightbeam::worker;
	///
	/// worker! {
	///     name: Echo<TestMessage, usize>,
	///     handle: |message, _trace| async move { message.content.len() }
	/// }
	///
	/// # let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
	/// # runtime.block_on(async {
	/// let worker: Box<dyn WorkerBox> = Box::new(Echo::new(()));
	/// let started = worker.start_boxed(Arc::new(TraceCollector::new())).await?;
	/// started.kill_shared().await?;
	/// # Ok::<(), tightbeam::TightBeamError>(())
	/// # })?;
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	///
	/// [`ServletRuntime::drain`]: crate::colony::servlet::ServletRuntime::drain
	fn kill_shared(&self) -> WorkerKillFuture;
}

impl<W: Worker + 'static> WorkerBox for W {
	fn start_boxed(self: Box<Self>, trace: Arc<TraceCollector>) -> WorkerBoxStartFuture {
		Box::pin(async move {
			let started = (*self).start(trace).await?;
			Ok(Box::new(started) as Box<dyn WorkerBox>)
		})
	}

	fn kill_shared(&self) -> WorkerKillFuture {
		self.kill()
	}
}

impl dyn WorkerBox {
	pub fn downcast_ref<W: 'static>(&self) -> Option<&W> {
		(self as &dyn Any).downcast_ref()
	}

	/// The key of this worker in the worker map of a servlet: the [`TypeId`]
	/// of the worker's own type, which the erased box reads through its value.
	pub(crate) fn type_key(&self) -> TypeId {
		(self as &dyn Any).type_id()
	}
}

/// The context of a servlet handler: its trace, its environment config, its
/// workers, an optional link to its hive, and the decryptor and inflator of
/// message bodies.
///
/// `Env` is the application configuration that the servlet starts with. The
/// context holds it by type, so [`Self::env_config`] returns a typed `&Env`
/// and the read is infallible.
pub struct ServletContext<Env = ()> {
	trace: TraceHandle,
	env_config: Arc<Env>,
	/// The servlet's workers, one of each type and keyed by that type, which
	/// the servlet runtime shares to kill them at its drain.
	workers: Arc<HashMap<TypeId, Box<dyn WorkerBox>>>,
	hive_context: Option<Arc<dyn HiveContext>>,
	message_decryptor: Option<Arc<dyn Decryptor + Send + Sync>>,
	message_inflator: Option<Arc<dyn Inflator + Send + Sync>>,
}

impl<Env> ServletContext<Env> {
	/// Build a context whose message-body decryptor and inflator are unset.
	///
	/// The context keys each worker of `workers` by the type of the worker the
	/// box holds, so [`Self::worker`] finds it by that type. A second worker of
	/// one type replaces the first.
	pub fn new(
		trace: Arc<TraceCollector>,
		env_config: Arc<Env>,
		workers: impl IntoIterator<Item = Box<dyn WorkerBox>>,
		hive_context: Option<Arc<dyn HiveContext>>,
	) -> Self {
		let workers = workers.into_iter().map(|worker| (worker.type_key(), worker)).collect();
		Self::sharing_trace(TraceHandle::new(trace), env_config, Arc::new(workers), hive_context)
	}

	/// A context that reads its trace from `trace`, the handle that the servlet
	/// runtime replaces, and its workers from `workers`, the map the runtime
	/// shares, with its message-body decryptor and inflator unset.
	pub(crate) fn sharing_trace(
		trace: TraceHandle,
		env_config: Arc<Env>,
		workers: Arc<HashMap<TypeId, Box<dyn WorkerBox>>>,
		hive_context: Option<Arc<dyn HiveContext>>,
	) -> Self {
		Self {
			trace,
			env_config,
			workers,
			hive_context,
			message_decryptor: None,
			message_inflator: None,
		}
	}

	/// Attach the frame-body decryptor used by typed delivery.
	#[must_use]
	pub fn with_message_decryptor(mut self, decryptor: Option<Arc<dyn Decryptor + Send + Sync>>) -> Self {
		self.message_decryptor = decryptor;
		self
	}

	/// Attach the frame-body inflator used by typed delivery.
	#[must_use]
	pub fn with_message_inflator(mut self, inflator: Option<Arc<dyn Inflator + Send + Sync>>) -> Self {
		self.message_inflator = inflator;
		self
	}

	/// The frame-body decryptor, when one is configured. It is `Sync`, so a
	/// dispatch that awaits its open stays `Send`.
	pub fn message_decryptor(&self) -> Option<&(dyn Decryptor + Send + Sync)> {
		self.message_decryptor.as_deref()
	}

	/// The frame-body inflator, when one is configured. It is `Sync`, so a
	/// dispatch that awaits a decryption stays `Send`.
	pub fn message_inflator(&self) -> Option<&(dyn Inflator + Send + Sync)> {
		self.message_inflator.as_deref()
	}

	/// The trace collector that this servlet records into at the call.
	///
	/// [`ServletRuntime::set_trace`] replaces the trace of a live servlet,
	/// so each read returns the trace that the servlet holds at that read.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::colony::servlet::ServletContext;
	/// use tightbeam::trace::TraceCollector;
	///
	/// let trace = Arc::new(TraceCollector::default());
	/// let ctx: ServletContext = ServletContext::new(Arc::clone(&trace), Arc::new(()), [], None);
	///
	/// assert!(Arc::ptr_eq(&ctx.trace(), &trace));
	/// ```
	///
	/// [`ServletRuntime::set_trace`]: crate::colony::servlet::ServletRuntime::set_trace
	pub fn trace(&self) -> Arc<TraceCollector> {
		self.trace.current()
	}

	/// The environment configuration that this servlet starts with.
	pub fn env_config(&self) -> &Env {
		&self.env_config
	}

	/// The intra-hive communication handle, when this servlet runs in a hive.
	pub fn hive_context(&self) -> Option<&Arc<dyn HiveContext>> {
		self.hive_context.as_ref()
	}

	/// The worker of type `W` that the servlet holds, if it holds one.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::colony::servlet::{ServletContext, WorkerBox};
	/// use tightbeam::testing::TestMessage;
	/// use tightbeam::trace::TraceCollector;
	/// use tightbeam::worker;
	///
	/// worker! {
	///     name: Echo<TestMessage, usize>,
	///     handle: |message, _trace| async move { message.content.len() }
	/// }
	///
	/// let workers: [Box<dyn WorkerBox>; 1] = [Box::new(Echo::new(()))];
	/// let ctx: ServletContext = ServletContext::new(Arc::new(TraceCollector::new()), Arc::new(()), workers, None);
	///
	/// assert!(ctx.worker::<Echo>().is_some());
	/// ```
	pub fn worker<W: 'static>(&self) -> Option<&W> {
		let key = TypeId::of::<W>();
		self.workers.get(&key)?.downcast_ref()
	}

	/// Relay `input` to the worker of type `W` that the servlet holds.
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingConfiguration`] -- the servlet holds no worker of type `W`.
	/// - [`TightBeamError::WorkerRelay`] -- the worker refused or failed the relay.
	pub async fn relay<W>(&self, input: Arc<W::Input>) -> Result<W::Output, TightBeamError>
	where
		W: Worker + 'static,
	{
		let worker = self.worker::<W>().ok_or(TightBeamError::MissingConfiguration)?;
		worker.relay(input).await.map_err(|error| error.into())
	}
}
impl Frame {
	/// Decrypt or inflate this frame's body in place for typed dispatch.
	///
	/// The open takes the FI digest and the signature out of the frame, and
	/// typed dispatch drops them.
	///
	/// The trace of `ctx` records a decrypt as the internal event
	/// `CRYPTO_STEP`, and the inflate of a cleartext body as `COMPRESS_STEP`.
	///
	/// # Errors
	///
	/// - [`RouterError::ConfidentialFrame`] -- the body is encrypted and the context has no decryptor.
	/// - [`RouterError::CompressedFrame`] -- the body is compressed and the context has no inflator.
	/// - [`TightBeamError`] -- the configured decryptor or inflator fails.
	/// - [`TightBeamError`] -- the runtime fault model injects a fault at the record of the step.
	pub async fn prepare_typed<Env>(&mut self, ctx: &ServletContext<Env>) -> Result<(), TightBeamError> {
		match self.body_transform() {
			Some(BodyTransform::Decrypt) => {
				let decryptor = ctx.message_decryptor().ok_or(RouterError::ConfidentialFrame)?;
				let inflator = ctx.message_inflator().map(|inflator| inflator as &(dyn Inflator + Sync));
				// The digest and the signature verify only before the open,
				// where the collector gates run. The typed handler reads the
				// cleartext, so the two drop here.
				let _opened = self.decrypt_in_place(decryptor, inflator).await?;
				#[cfg(feature = "instrument")]
				ctx.trace().emit_internal_event(InternalEvent::CryptoStep)?;
			}
			Some(BodyTransform::Inflate) => {
				let inflator = ctx.message_inflator().ok_or(RouterError::CompressedFrame)?;
				// The digest and the signature drop as in the decrypt arm.
				let _opened = self.inflate_in_place(inflator)?;
				#[cfg(feature = "instrument")]
				ctx.trace().emit_internal_event(InternalEvent::CompressStep)?;
			}
			None => {}
		}

		Ok(())
	}

	/// Open this frame's body for the typed delivery of `ctx`, and decode it
	/// as `I`.
	///
	/// The typed arm of [`servlet!`](crate::servlet) and
	/// [`Frame::dispatch_typed_unary`] decode through it, in this order:
	///
	/// 1. The frame, as it arrived, meets the requirements of `I` ([`Frame::validate_for`]).
	/// 2. [`Frame::prepare_typed`] opens the body, so a body with no matching transform fails closed.
	/// 3. The cleartext decodes as `I`.
	///
	/// # Errors
	///
	/// - [`TightBeamError::Requirement`] -- the frame, as it arrived, fails a requirement of `I`.
	/// - The errors of [`Frame::prepare_typed`].
	/// - [`TightBeamError::SerializationError`] -- the cleartext is no DER
	///   encoding of `I`, or a SET in it holds its elements out of DER order.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::colony::servlet::ServletContext;
	/// use tightbeam::core::RequirementError;
	/// use tightbeam::der::Sequence;
	/// use tightbeam::trace::TraceCollector;
	/// use tightbeam::{compose, Beamable, TightBeamError};
	///
	/// #[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
	/// struct Ping {
	///     sequence: u64,
	/// }
	///
	/// #[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
	/// #[beam(min_version = "V2")]
	/// struct RecentPing {
	///     sequence: u64,
	/// }
	///
	/// # let runtime = tokio::runtime::Builder::new_current_thread().build()?;
	/// # runtime.block_on(async {
	/// let ctx: ServletContext = ServletContext::new(Arc::new(TraceCollector::default()), Arc::new(()), [], None);
	/// let mut frame = compose! { V1: id: "ping", order: 1u64, message: Ping { sequence: 7 } }?;
	/// assert_eq!(frame.open_typed::<Ping, _>(&ctx).await?, Ping { sequence: 7 });
	///
	/// // The same body is no carrier of a type whose minimum is V2.
	/// let refused = frame.open_typed::<RecentPing, _>(&ctx).await;
	/// assert!(matches!(refused, Err(TightBeamError::Requirement(RequirementError::Version(_)))));
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// # })?;
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub async fn open_typed<I, Env>(&mut self, ctx: &ServletContext<Env>) -> Result<I, TightBeamError>
	where
		I: Message,
	{
		let open = async |frame: &mut Self| frame.prepare_typed(ctx).await;
		self.open_message::<I>(open).await
	}

	/// Open and decode this frame's body as `I` ([`Frame::open_typed`]), then
	/// invoke a typed unary handler with the message, the frame, and `ctx`.
	///
	/// # Errors
	///
	/// - The errors of [`Frame::open_typed`], before the handler runs.
	/// - The error that `handler` returns.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::colony::servlet::ServletContext;
	/// use tightbeam::der::Sequence;
	/// use tightbeam::trace::TraceCollector;
	/// use tightbeam::{compose, Beamable, Frame};
	///
	/// #[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
	/// struct Ping {
	///     sequence: u64,
	/// }
	///
	/// # let runtime = tokio::runtime::Builder::new_current_thread().build()?;
	/// # runtime.block_on(async {
	/// let ctx: ServletContext = ServletContext::new(Arc::new(TraceCollector::default()), Arc::new(()), [], None);
	/// let frame = compose! { V1: id: "ping", order: 1u64, message: Ping { sequence: 7 } }?;
	///
	/// // The handler answers no frame, so the delivery returns none.
	/// let handler = |ping: Ping, _: Frame, _: &ServletContext| async move {
	///     assert_eq!(ping, Ping { sequence: 7 });
	///     Ok(None)
	/// };
	/// assert!(frame.dispatch_typed_unary(&ctx, handler).await?.is_none());
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// # })?;
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub async fn dispatch_typed_unary<I, Env, F, Fut>(
		mut self,
		ctx: &ServletContext<Env>,
		handler: F,
	) -> Result<Option<Frame>, TightBeamError>
	where
		I: Message,
		F: FnOnce(I, Frame, &ServletContext<Env>) -> Fut,
		Fut: Future<Output = Result<Option<Frame>, TightBeamError>>,
	{
		let message = self.open_typed::<I, Env>(ctx).await?;
		handler(message, self, ctx).await
	}
}

/// The internal events that typed delivery records into the trace of its
/// servlet.
#[cfg(all(test, feature = "instrument"))]
mod tests {
	use std::sync::Arc;

	use super::ServletContext;
	use crate::crypto::aead::Decryptor;
	use crate::instrumentation::events;
	use crate::tb_cases;
	use crate::testing::fixtures::TestTrace;
	use crate::testing::{TestKey, TestMessage};
	use crate::urn::Urn;
	use crate::Frame;

	#[cfg(feature = "zstd")]
	use crate::compress::ZstdCompression;
	#[cfg(feature = "zstd")]
	use crate::core::Inflator;

	/// A servlet context whose trace config sets `enable_internal_detail` to
	/// `detail`, with no message transform.
	fn context_with_detail(detail: bool) -> ServletContext {
		let trace = TestTrace::with_detail(detail);
		ServletContext::new(Arc::new(trace), Arc::new(()), [], None)
	}

	/// A context that decrypts under the fixed cipher, with the detail flag
	/// `detail`, beside a frame that the fixed cipher encrypts.
	fn encrypted(detail: bool) -> (ServletContext, Frame) {
		let (_, cipher) = TestKey::insecure_fixed_cipher();
		let (_, decryptor) = TestKey::insecure_fixed_cipher();
		let decryptor: Arc<dyn Decryptor + Send + Sync> = Arc::new(decryptor);
		let ctx = context_with_detail(detail).with_message_decryptor(Some(decryptor));
		let message = TestMessage::sample(Some("crypto-step"));
		let encrypted = compose! { V1: id: "crypto-step", order: 1u64, message: message, confidentiality: cipher };

		(ctx, encrypted.expect("the fixed cipher encrypts a frame"))
	}

	/// A context that inflates zstd, with the detail flag `detail`, beside a
	/// cleartext frame that zstd compresses.
	#[cfg(feature = "zstd")]
	fn compressed(detail: bool) -> (ServletContext, Frame) {
		let inflator: Arc<dyn Inflator + Send + Sync> = Arc::new(ZstdCompression::default());
		let ctx = context_with_detail(detail).with_message_inflator(Some(inflator));
		let message = TestMessage::sample(Some("compress-step"));
		let compactness = ZstdCompression::default();
		let compressed = compose! { V0: id: "compress-step", order: 1u64, message: message, compactness: compactness };

		(ctx, compressed.expect("zstd compresses a frame"))
	}

	/// The records of `event` that the typed delivery of `frame` on `ctx`
	/// leaves in its trace.
	async fn recorded_steps(ctx: ServletContext, mut frame: Frame, event: Urn<'static>) -> Vec<Urn<'static>> {
		let prepared = frame.prepare_typed(&ctx).await;
		prepared.expect("the context opens the frame");
		TestTrace::trail(&ctx.trace(), &[event])
	}

	// Typed delivery records the decrypt of a frame body when the trace
	// config sets the detail flag, and leaves the trail empty when the config
	// clears it.
	tb_cases! {
		async fn a_decrypted_body_records_its_crypto_step_under_the_detail_flag_alone(
			(detail, steps): (bool, Vec<Urn<'static>>)
		) {
			let (ctx, frame) = encrypted(detail);
			let recorded = recorded_steps(ctx, frame, events::CRYPTO_STEP).await;
			assert_eq!(recorded, steps);
		}
		cases {
			with_detail => (true, vec![events::CRYPTO_STEP]),
			without_detail => (false, Vec::new()),
		}
	}

	// Typed delivery records the inflate of a cleartext frame body when the
	// trace config sets the detail flag, and leaves the trail empty when the
	// config clears it.
	tb_cases! {
		async fn an_inflated_body_records_its_compress_step_under_the_detail_flag_alone(
			(detail, steps): (bool, Vec<Urn<'static>>)
		) {
			let (ctx, frame) = compressed(detail);
			let recorded = recorded_steps(ctx, frame, events::COMPRESS_STEP).await;
			assert_eq!(recorded, steps);
		}
		cases {
			#[cfg(feature = "zstd")]
			with_detail => (true, vec![events::COMPRESS_STEP]),
			#[cfg(feature = "zstd")]
			without_detail => (false, Vec::new()),
		}
	}
}
