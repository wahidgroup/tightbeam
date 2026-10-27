use core::any::Any;
use core::future::Future;
use core::pin::Pin;
use std::collections::HashMap;
use std::sync::Arc;

use crate::colony::hive::HiveContext;
use crate::colony::worker::{Worker, WorkerMetadata};
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
pub trait WorkerBox: Send + Sync + Any {
	fn start_boxed(self: Box<Self>, trace: Arc<TraceCollector>) -> WorkerBoxStartFuture;
}

impl<W: Worker + 'static> WorkerBox for W {
	fn start_boxed(self: Box<Self>, trace: Arc<TraceCollector>) -> WorkerBoxStartFuture {
		Box::pin(async move {
			let started = (*self).start(trace).await?;
			Ok(Box::new(started) as Box<dyn WorkerBox>)
		})
	}
}

impl dyn WorkerBox {
	pub fn downcast_ref<W: 'static>(&self) -> Option<&W> {
		(self as &dyn Any).downcast_ref()
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
	workers: HashMap<String, Box<dyn WorkerBox>>,
	hive_context: Option<Arc<dyn HiveContext>>,
	message_decryptor: Option<Arc<dyn Decryptor + Send + Sync>>,
	message_inflator: Option<Arc<dyn Inflator + Send + Sync>>,
}

impl<Env> ServletContext<Env> {
	/// Build a context whose message-body decryptor and inflator are unset.
	pub fn new(
		trace: Arc<TraceCollector>,
		env_config: Arc<Env>,
		workers: HashMap<String, Box<dyn WorkerBox>>,
		hive_context: Option<Arc<dyn HiveContext>>,
	) -> Self {
		Self::sharing_trace(TraceHandle::new(trace), env_config, workers, hive_context)
	}

	/// A context that reads its trace from `trace`, the handle that the servlet
	/// runtime replaces, with its message-body decryptor and inflator unset.
	pub(crate) fn sharing_trace(
		trace: TraceHandle,
		env_config: Arc<Env>,
		workers: HashMap<String, Box<dyn WorkerBox>>,
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
	/// use std::collections::HashMap;
	/// use std::sync::Arc;
	///
	/// use tightbeam::colony::servlet::ServletContext;
	/// use tightbeam::trace::TraceCollector;
	///
	/// let trace = Arc::new(TraceCollector::default());
	/// let ctx: ServletContext = ServletContext::new(Arc::clone(&trace), Arc::new(()), HashMap::new(), None);
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

	/// The worker registered under `name`, downcast to `W`.
	pub fn worker<W: 'static>(&self, name: impl AsRef<str>) -> Option<&W> {
		let name = name.as_ref();
		self.workers.get(name)?.downcast_ref()
	}

	/// Relay `input` to the worker named by [`WorkerMetadata`].
	pub async fn relay<W>(&self, input: Arc<W::Input>) -> Result<W::Output, TightBeamError>
	where
		W: Worker + WorkerMetadata + 'static,
	{
		let name = W::name();
		let worker = self.worker::<W>(name).ok_or(TightBeamError::MissingConfiguration)?;
		worker.relay(input).await.map_err(|error| error.into())
	}
}
impl Frame {
	/// Decrypt or inflate this frame's body in place for typed dispatch.
	///
	/// The trace of `ctx` records a decrypt as the internal event
	/// `CRYPTO_STEP`, and the inflate of a cleartext body as `COMPRESS_STEP`.
	///
	/// # Errors
	///
	/// - [`RouterError::ConfidentialFrame`] -- the body is encrypted and the context has no decryptor.
	/// - [`RouterError::CompressedFrame`] -- the body is compressed and the context has no inflator.
	/// - The errors of the configured decryptor or inflator.
	/// - The injected error, when the runtime fault model injects a fault at the record of the step.
	pub async fn prepare_typed<Env>(&mut self, ctx: &ServletContext<Env>) -> Result<(), TightBeamError> {
		match self.body_transform() {
			Some(BodyTransform::Decrypt) => {
				let decryptor = ctx.message_decryptor().ok_or(RouterError::ConfidentialFrame)?;
				let inflator = ctx.message_inflator().map(|inflator| inflator as &(dyn Inflator + Sync));
				self.decrypt_in_place(decryptor, inflator).await?;
				#[cfg(feature = "instrument")]
				ctx.trace().emit_internal_event(InternalEvent::CryptoStep)?;
			}
			Some(BodyTransform::Inflate) => {
				let inflator = ctx.message_inflator().ok_or(RouterError::CompressedFrame)?;
				self.inflate_in_place(inflator)?;
				#[cfg(feature = "instrument")]
				ctx.trace().emit_internal_event(InternalEvent::CompressStep)?;
			}
			None => {}
		}

		Ok(())
	}

	/// Prepare, decode, and invoke a typed unary handler.
	///
	/// It runs [`Frame::prepare_typed`] first, so an encrypted or compressed
	/// body without the transform that matches it fails closed before the
	/// decode.
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
		self.prepare_typed(ctx).await?;

		let message: I = crate::decode(self.message())?;
		handler(message, self, ctx).await
	}
}

/// The internal events that typed delivery records into the trace of its
/// servlet.
#[cfg(all(test, feature = "instrument"))]
mod tests {
	use std::collections::HashMap;
	use std::sync::Arc;

	use super::ServletContext;
	use crate::crypto::aead::Decryptor;
	use crate::instrumentation::events;
	use crate::testing::fixtures::TestTrace;
	use crate::testing::{TestKey, TestMessage};
	use crate::urn::Urn;
	use crate::{Frame, TightBeamError};

	#[cfg(feature = "zstd")]
	use crate::compress::ZstdCompression;
	#[cfg(feature = "zstd")]
	use crate::core::Inflator;

	/// A servlet context whose trace config sets `enable_internal_detail` to
	/// `detail`, with no message transform.
	fn context_with_detail(detail: bool) -> ServletContext {
		let trace = TestTrace::with_detail(detail);
		ServletContext::new(Arc::new(trace), Arc::new(()), HashMap::new(), None)
	}

	/// The crypto steps that the typed delivery of one encrypted frame records
	/// under the detail flag `detail`.
	async fn crypto_steps(detail: bool) -> Result<Vec<Urn<'static>>, TightBeamError> {
		let (_, cipher) = TestKey::insecure_fixed_cipher();
		let (_, decryptor) = TestKey::insecure_fixed_cipher();
		let decryptor: Arc<dyn Decryptor + Send + Sync> = Arc::new(decryptor);
		let ctx = context_with_detail(detail).with_message_decryptor(Some(decryptor));
		let message = TestMessage::sample(Some("crypto-step"));
		let encrypted = compose! { V1: id: "crypto-step", order: 1u64, message: message, confidentiality: cipher };
		let mut frame: Frame = encrypted?;
		frame.prepare_typed(&ctx).await?;

		Ok(TestTrace::trail(&ctx.trace(), &[events::CRYPTO_STEP]))
	}

	/// Typed delivery records the decrypt of a frame body when the trace
	/// config sets the detail flag, and leaves the trail empty when the config
	/// clears it.
	#[tokio::test]
	async fn a_decrypted_body_records_its_crypto_step_under_the_detail_flag_alone() -> Result<(), TightBeamError> {
		let steps = [crypto_steps(true).await?, crypto_steps(false).await?];
		assert_eq!(steps, [vec![events::CRYPTO_STEP], vec![]]);
		Ok(())
	}

	/// The compress steps that the typed delivery of one compressed cleartext
	/// frame records under the detail flag `detail`.
	#[cfg(feature = "zstd")]
	async fn compress_steps(detail: bool) -> Result<Vec<Urn<'static>>, TightBeamError> {
		let inflator: Arc<dyn Inflator + Send + Sync> = Arc::new(ZstdCompression::default());
		let ctx = context_with_detail(detail).with_message_inflator(Some(inflator));
		let message = TestMessage::sample(Some("compress-step"));
		let compactness = ZstdCompression::default();
		let compressed = compose! { V0: id: "compress-step", order: 1u64, message: message, compactness: compactness };
		let mut frame: Frame = compressed?;
		frame.prepare_typed(&ctx).await?;

		Ok(TestTrace::trail(&ctx.trace(), &[events::COMPRESS_STEP]))
	}

	/// Typed delivery records the inflate of a cleartext frame body when the
	/// trace config sets the detail flag, and leaves the trail empty when the
	/// config clears it.
	#[cfg(feature = "zstd")]
	#[tokio::test]
	async fn an_inflated_body_records_its_compress_step_under_the_detail_flag_alone() -> Result<(), TightBeamError> {
		let steps = [compress_steps(true).await?, compress_steps(false).await?];
		assert_eq!(steps, [vec![events::COMPRESS_STEP], vec![]]);
		Ok(())
	}
}
