use core::future::Future;
use core::pin::Pin;
use std::sync::Arc;

use crate::colony::servlet::{dispatch_typed_unary, ServletConfig, ServletContext};
use crate::core::Message;
use crate::trace::TraceCollector;
use crate::transport::multiplex::{ReplySink, StreamBody};
use crate::transport::serve::unimplemented_error;
use crate::transport::{Protocol, TightBeamAddress};
use crate::utils::BasisPoints;
use crate::{Frame, TightBeamError};

#[cfg(feature = "x509")]
use crate::crypto::profiles::{CryptoProvider, DefaultCryptoProvider};

use crate::colony::servlet::servlet_runtime::rt;

/// Lifecycle interface for named servlets and [`ServletRuntime`].
///
/// Generic over input message type `I`. Workers attached to a servlet share
/// that same input type. `servlet!` implements this for the generated type;
/// macro-free code uses [`ServletRuntime`] with [`RuntimeServletConf`].
pub trait Servlet<I> {
	/// Configuration type (typically [`ServletConfig`]).
	type Conf;

	/// Protocol-specific listen address.
	type Address: TightBeamAddress;

	/// Bind, start workers, and spawn the accept loop.
	fn start(
		trace: Arc<TraceCollector>,
		config: Option<Self::Conf>,
	) -> impl Future<Output = Result<Self, TightBeamError>> + Send
	where
		Self: Sized;

	/// Bound listen address (borrowed; no clone).
	fn addr(&self) -> &Self::Address;

	/// Stop accepting connections and abort in-flight accept work.
	fn stop(self);

	/// Block until the accept loop task has exited.
	fn join(self) -> impl Future<Output = Result<(), rt::JoinError>> + Send;

	/// Utilization in basis points (`0..=10000`) for hive balancing.
	///
	/// Default `None` means no metrics. Override (for example with
	/// [`LatencyTracker`]) when the hive should read load.
	fn utilization(&self) -> Option<BasisPoints> {
		None
	}
}

/// Dispatch contract for unary, streaming, and duplex servlet traffic.
///
/// Handlers receive [`ServletContext`] (workers, env, decryptor/inflator,
/// hive link), not the transport session. Missing kinds refuse with
/// `Unimplemented`. Build with [`ServletHandlers`], or implement this trait
/// and pass it to [`ServletRuntime::start`].
pub trait ServletService: Send + Sync + 'static {
	/// Handle one request/response exchange on a unary stream.
	///
	/// # Errors
	///
	/// Failure closes the stream with its mapped status.
	fn unary(
		&self,
		frame: Frame,
		ctx: Arc<ServletContext>,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		let _ = (frame, ctx);
		async { Err(unimplemented_error()) }
	}

	/// Read a chunked request body and optionally return one unary reply.
	///
	/// # Errors
	///
	/// Failure closes the stream with its mapped status.
	fn streaming(
		&self,
		body: StreamBody,
		ctx: Arc<ServletContext>,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		let _ = (body, ctx);
		async { Err(unimplemented_error()) }
	}

	/// Exchange request and reply chunks on one multiplexed stream.
	///
	/// # Errors
	///
	/// Failure closes the stream with its mapped status.
	fn duplex(
		&self,
		body: StreamBody,
		reply: ReplySink,
		ctx: Arc<ServletContext>,
	) -> impl Future<Output = Result<(), TightBeamError>> + Send {
		let _ = (body, reply, ctx);
		async { Err(unimplemented_error()) }
	}
}

/// Boxed handler future used by [`ServletHandlers`].
pub type ServletFuture<T> = Pin<Box<dyn Future<Output = Result<T, TightBeamError>> + Send>>;

type UnaryHandler = Box<dyn Fn(Frame, Arc<ServletContext>) -> ServletFuture<Option<Frame>> + Send + Sync>;
type StreamingHandler = Box<dyn Fn(StreamBody, Arc<ServletContext>) -> ServletFuture<Option<Frame>> + Send + Sync>;
type DuplexHandler = Box<dyn Fn(StreamBody, ReplySink, Arc<ServletContext>) -> ServletFuture<()> + Send + Sync>;

/// Closure-built [`ServletService`]. Absent kinds refuse with `Unimplemented`.
///
/// Assembled by `servlet!` handler arms. Hand-written services implement
/// [`ServletService`] directly instead.
#[derive(Default)]
pub struct ServletHandlers {
	unary: Option<UnaryHandler>,
	streaming: Option<StreamingHandler>,
	duplex: Option<DuplexHandler>,
}

impl ServletHandlers {
	/// Set the unary handler used by [`ServletService::unary`].
	pub fn on_unary<F, Fut>(mut self, handler: F) -> Self
	where
		F: Fn(Frame, Arc<ServletContext>) -> Fut + Send + Sync + 'static,
		Fut: Future<Output = Result<Option<Frame>, TightBeamError>> + Send + 'static,
	{
		self.unary = Some(Box::new(move |frame, ctx| Box::pin(handler(frame, ctx))));
		self
	}

	/// Set the streaming handler used by [`ServletService::streaming`].
	pub fn on_streaming<F, Fut>(mut self, handler: F) -> Self
	where
		F: Fn(StreamBody, Arc<ServletContext>) -> Fut + Send + Sync + 'static,
		Fut: Future<Output = Result<Option<Frame>, TightBeamError>> + Send + 'static,
	{
		self.streaming = Some(Box::new(move |body, ctx| Box::pin(handler(body, ctx))));
		self
	}

	/// Set the duplex handler used by [`ServletService::duplex`].
	pub fn on_duplex<F, Fut>(mut self, handler: F) -> Self
	where
		F: Fn(StreamBody, ReplySink, Arc<ServletContext>) -> Fut + Send + Sync + 'static,
		Fut: Future<Output = Result<(), TightBeamError>> + Send + 'static,
	{
		self.duplex = Some(Box::new(move |body, reply, ctx| Box::pin(handler(body, reply, ctx))));
		self
	}

	/// Decode message type `I` after [`prepare_typed_frame`], then run `handler`.
	pub fn on_typed_unary<I, F, Fut>(self, handler: F) -> Self
	where
		I: Message + Send + 'static,
		F: Fn(I, Frame, &ServletContext) -> Fut + Send + Sync + 'static,
		Fut: Future<Output = Result<Option<Frame>, TightBeamError>> + Send + 'static,
	{
		let handler = Arc::new(handler);
		self.on_unary(move |frame, ctx| {
			let handler = Arc::clone(&handler);
			async move {
				dispatch_typed_unary(frame, ctx.as_ref(), |message, frame, ctx| handler(message, frame, ctx)).await
			}
		})
	}
}

impl ServletService for ServletHandlers {
	fn unary(
		&self,
		frame: Frame,
		ctx: Arc<ServletContext>,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		match self.unary.as_ref() {
			Some(handler) => handler(frame, ctx),
			None => Box::pin(async { Err(unimplemented_error()) }) as ServletFuture<_>,
		}
	}

	fn streaming(
		&self,
		body: StreamBody,
		ctx: Arc<ServletContext>,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		match self.streaming.as_ref() {
			Some(handler) => handler(body, ctx),
			None => Box::pin(async { Err(unimplemented_error()) }) as ServletFuture<_>,
		}
	}

	fn duplex(
		&self,
		body: StreamBody,
		reply: ReplySink,
		ctx: Arc<ServletContext>,
	) -> impl Future<Output = Result<(), TightBeamError>> + Send {
		match self.duplex.as_ref() {
			Some(handler) => handler(body, reply, ctx),
			None => Box::pin(async { Err(unimplemented_error()) }) as ServletFuture<_>,
		}
	}
}

/// Config + handlers for [`Servlet`] on [`ServletRuntime`].
///
/// Use this when a call site needs [`Servlet::start`] without `servlet!`.
/// Hive registration only needs [`ServletBox`], which [`ServletRuntime`]
/// already implements.
#[cfg(feature = "x509")]
pub struct RuntimeServletConf<P, M, C: CryptoProvider = DefaultCryptoProvider>
where
	P: Protocol,
	M: Message,
{
	/// Bind, workers, gates, and env for the accept loop.
	pub config: ServletConfig<P, M, C>,
	/// Request handlers installed on the runtime.
	pub service: ServletHandlers,
}

#[cfg(feature = "x509")]
impl<P, M, C> Default for RuntimeServletConf<P, M, C>
where
	P: Protocol,
	M: Message,
	C: CryptoProvider + Send + Sync + 'static,
{
	fn default() -> Self {
		Self { config: ServletConfig::default(), service: ServletHandlers::default() }
	}
}

/// Config + handlers for [`Servlet`] on [`ServletRuntime`].
#[cfg(not(feature = "x509"))]
pub struct RuntimeServletConf<P, M>
where
	P: Protocol,
	M: Message,
{
	/// Bind, workers, gates, and env for the accept loop.
	pub config: ServletConfig<P, M>,
	/// Request handlers installed on the runtime.
	pub service: ServletHandlers,
}

#[cfg(not(feature = "x509"))]
impl<P, M> Default for RuntimeServletConf<P, M>
where
	P: Protocol,
	M: Message,
{
	fn default() -> Self {
		Self { config: ServletConfig::default(), service: ServletHandlers::default() }
	}
}
