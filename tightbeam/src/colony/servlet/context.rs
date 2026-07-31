use core::any::Any;
use core::future::Future;
use core::pin::Pin;
use std::collections::HashMap;
use std::sync::Arc;

use crate::colony::hive::HiveContext;
use crate::colony::worker::{Worker, WorkerMetadata};
use crate::core::{Inflator, Message};
use crate::crypto::aead::Decryptor;
use crate::router::RouterError;
use crate::trace::TraceCollector;
use crate::{Frame, TightBeamError};

/// Boxed future returned by [`WorkerBox::start_boxed`].
pub type WorkerBoxStartFuture = Pin<Box<dyn Future<Output = Result<Box<dyn WorkerBox>, TightBeamError>> + Send>>;

/// Type-erased worker lifecycle for servlet-owned worker maps.
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

/// Handler context: trace, env config, workers, optional hive link, and
/// message-body decryptor/inflator.
pub struct ServletContext {
	trace: Arc<TraceCollector>,
	env_config: Arc<dyn Any + Send + Sync>,
	workers: HashMap<String, Box<dyn WorkerBox>>,
	hive_context: Option<Arc<dyn HiveContext>>,
	message_decryptor: Option<Arc<dyn Decryptor + Send + Sync>>,
	message_inflator: Option<Arc<dyn Inflator + Send + Sync>>,
}

impl ServletContext {
	/// Build a context without message-body crypto or compression.
	pub fn new(
		trace: Arc<TraceCollector>,
		env_config: Arc<dyn Any + Send + Sync>,
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

	/// Frame-body decryptor, when configured.
	pub fn message_decryptor(&self) -> Option<&dyn Decryptor> {
		self.message_decryptor.as_deref().map(|decryptor| decryptor as &dyn Decryptor)
	}

	/// Frame-body inflator, when configured.
	pub fn message_inflator(&self) -> Option<&dyn Inflator> {
		self.message_inflator.as_deref().map(|inflator| inflator as &dyn Inflator)
	}

	/// Trace collector for this servlet.
	pub fn trace(&self) -> &Arc<TraceCollector> {
		&self.trace
	}

	/// Environment configuration downcast to `T`.
	pub fn env_config<T: 'static>(&self) -> Result<&T, TightBeamError> {
		self.env_config.downcast_ref().ok_or(TightBeamError::MissingConfiguration)
	}

	/// Intra-hive communication handle, when this servlet runs inside a hive.
	pub fn hive_context(&self) -> Option<&Arc<dyn HiveContext>> {
		self.hive_context.as_ref()
	}

	/// Worker registered under `name`, downcast to `W`.
	pub fn worker<W: 'static>(&self, name: &str) -> Option<&W> {
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

/// Normalize a frame to cleartext before typed delivery.
///
/// Fail-closed and in place: encrypted bodies without a decryptor, and
/// compressed bodies without an inflator, are rejected before decode.
/// On success the body is cleartext for the servlet's declared input type.
///
/// # Errors
///
/// - [`RouterError::ConfidentialFrame`]: encrypted body, no decryptor.
/// - [`RouterError::CompressedFrame`]: compressed body, no inflator.
/// - Decryption or decompression errors from the configured implementations.
pub fn prepare_typed_frame(frame: &mut Frame, ctx: &ServletContext) -> Result<(), TightBeamError> {
	if frame.metadata.confidentiality.is_some() {
		let decryptor = ctx.message_decryptor().ok_or(RouterError::ConfidentialFrame)?;
		frame.decrypt_in_place(decryptor, ctx.message_inflator())?;

		return Ok(());
	}

	if frame.metadata.compactness.is_some() {
		let inflator = ctx.message_inflator().ok_or(RouterError::CompressedFrame)?;
		frame.inflate_in_place(inflator)?;
	}

	Ok(())
}

/// Prepare, decode, and invoke a typed unary handler.
///
/// Runs [`prepare_typed_frame`] first. Encrypted or compressed bodies
/// without the matching transform fail closed before decode.
pub async fn dispatch_typed_unary<I, F, Fut>(
	mut frame: Frame,
	ctx: &ServletContext,
	handler: F,
) -> Result<Option<Frame>, TightBeamError>
where
	I: Message,
	F: FnOnce(I, Frame, &ServletContext) -> Fut,
	Fut: Future<Output = Result<Option<Frame>, TightBeamError>>,
{
	prepare_typed_frame(&mut frame, ctx)?;

	let message: I = crate::decode(&frame.message)?;
	let response = handler(message, frame, ctx).await?;
	Ok(response)
}
