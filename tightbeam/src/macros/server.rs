#![allow(clippy::type_complexity)]

use core::{future::Future, pin::Pin};

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, sync::Arc};
#[cfg(feature = "std")]
use core::pin::pin;
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::policy::SessionContext;
use crate::Frame;

#[cfg(feature = "std")]
use crate::policy::TransitStatus;
#[cfg(feature = "std")]
use crate::transport::messaging::{GateAudit, HandlerAudit};
#[cfg(pooled_mux)]
use crate::transport::multiplex::MuxAcceptor;
#[cfg(pooled_mux)]
use crate::transport::multiplex::{CallContext, MuxService, ReplySink, StreamBody, StreamRoute};
#[cfg(feature = "std")]
use crate::transport::state::EncryptedProtocolState;
#[cfg(feature = "tokio")]
use crate::transport::MessageCollector;
#[cfg(feature = "std")]
use crate::utils::marker::MaybeSend;
#[cfg(feature = "std")]
use crate::TightBeamError;

#[cfg(feature = "tokio")]
use self::server_runtime::rt::{ErrorSender, OkSender};

#[doc(hidden)]
pub type HandlerFuture = Pin<Box<dyn Future<Output = Result<Option<Frame>, crate::TightBeamError>> + Send>>;

/// A connection-scoped handler, which receives the session's authenticated
/// peer context beside each frame.
///
/// The wrapped closure arrives through [`SharedHandler::from`] or
/// [`SharedHandler::from_context_blind`], so every value of this type
/// carries a closure one of those two conversions accepted.
#[doc(hidden)]
#[derive(Clone)]
pub struct SharedHandler(Arc<dyn Fn(Frame, SessionContext) -> HandlerFuture + Send + Sync>);

impl SharedHandler {
	/// Wrap a context-blind handler (`handle: move |frame| ...`), which the
	/// shared handler invokes with the frame alone.
	///
	/// The session-aware shape reaches the same type through
	/// [`SharedHandler::from`]. Rust resolves one blanket `From<F>` impl per
	/// target type, so the second closure shape takes a named conversion.
	pub fn from_context_blind<F, Fut>(handler: F) -> Self
	where
		F: Fn(Frame) -> Fut + Send + Sync + 'static,
		Fut: Future<Output = Result<Option<Frame>, crate::TightBeamError>> + Send + 'static,
	{
		let handler = Arc::new(handler);
		let shared = move |frame: Frame, _session: SessionContext| -> HandlerFuture {
			let handler = Arc::clone(&handler);
			Box::pin(async move { handler(frame).await })
		};

		Self(Arc::new(shared))
	}

	/// Serve one frame on one session.
	pub fn call(&self, frame: Frame, session: SessionContext) -> HandlerFuture {
		(self.0)(frame, session)
	}
}

/// Wrap a session-aware handler (`handle: move |frame, session| ...`).
impl<F, Fut> From<F> for SharedHandler
where
	F: Fn(Frame, SessionContext) -> Fut + Send + Sync + 'static,
	Fut: Future<Output = Result<Option<Frame>, crate::TightBeamError>> + Send + 'static,
{
	fn from(handler: F) -> Self {
		let handler = Arc::new(handler);
		let shared = move |frame: Frame, session: SessionContext| -> HandlerFuture {
			let handler = Arc::clone(&handler);
			Box::pin(async move { handler(frame, session).await })
		};

		Self(Arc::new(shared))
	}
}

/// The capabilities that one accepted async server connection provides.
///
/// - Message collection serves the single-flight loop.
/// - Mux negotiation serves the takeover.
/// - Handshake state serves session capture.
///
/// A blanket impl covers every type that implements the supertraits.
#[cfg(pooled_mux)]
#[doc(hidden)]
pub trait AcceptedConnection: MessageCollector + MuxAcceptor + EncryptedProtocolState + Send {}

#[cfg(pooled_mux)]
impl<T: MessageCollector + MuxAcceptor + EncryptedProtocolState + Send> AcceptedConnection for T {}

#[cfg(all(feature = "tokio", not(pooled_mux), feature = "x509"))]
#[doc(hidden)]
pub trait AcceptedConnection: MessageCollector + EncryptedProtocolState + Send {}

#[cfg(all(feature = "tokio", not(pooled_mux), feature = "x509"))]
impl<T: MessageCollector + EncryptedProtocolState + Send> AcceptedConnection for T {}

/// An adapter that runs a [`SharedHandler`] as a unary-only service.
///
/// The closure grammar of `server!` serves unary interactions, and the
/// streaming kinds answer `Unimplemented` through the [`MuxService`]
/// defaults.
#[cfg(pooled_mux)]
struct SharedHandlerService(SharedHandler);

#[cfg(pooled_mux)]
impl MuxService for SharedHandlerService {
	fn unary(
		&self,
		frame: Frame,
		cx: CallContext,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		self.0.call(frame, cx.into_session())
	}
}

/// Report a service failure to the error channel and return the opaque
/// `Internal` failure in its place, so the original error goes to the
/// application and the peer sees `Internal`. When the server has no error
/// channel, the original error returns unchanged.
#[cfg(pooled_mux)]
async fn report_failure(errors: &mut Option<ErrorSender>, err: TightBeamError) -> TightBeamError {
	match errors.as_mut() {
		Some(tx) => {
			// The error channel belongs to the application, and a receiver that
			// is gone wants no report.
			let _ = tx.send(err.into()).await;
			TightBeamError::TransportError(crate::transport::TransportError::OperationFailed(
				crate::transport::TransportFailure::Internal,
			))
		}
		None => err,
	}
}

/// A [`MuxService`] adapter that reports every handler failure to the server's
/// error channel before the stream closes with its status.
#[cfg(pooled_mux)]
struct ReportedService<S> {
	service: Arc<S>,
	errors: Option<ErrorSender>,
}

#[cfg(pooled_mux)]
impl<S: MuxService> MuxService for ReportedService<S> {
	fn unary(
		&self,
		frame: Frame,
		cx: CallContext,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		let service = Arc::clone(&self.service);
		let mut errors = self.errors.clone();
		async move {
			match service.unary(frame, cx).await {
				Ok(response) => Ok(response),
				Err(err) => Err(report_failure(&mut errors, err).await),
			}
		}
	}

	fn streaming(
		&self,
		body: StreamBody,
		cx: CallContext,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		let service = Arc::clone(&self.service);
		let mut errors = self.errors.clone();
		async move {
			match service.streaming(body, cx).await {
				Ok(response) => Ok(response),
				Err(err) => Err(report_failure(&mut errors, err).await),
			}
		}
	}

	fn duplex(
		&self,
		body: StreamBody,
		reply: ReplySink,
		cx: CallContext,
	) -> impl Future<Output = Result<(), TightBeamError>> + Send {
		let service = Arc::clone(&self.service);
		let mut errors = self.errors.clone();
		async move {
			match service.duplex(body, reply, cx).await {
				Ok(()) => Ok(()),
				Err(err) => Err(report_failure(&mut errors, err).await),
			}
		}
	}
}

/// Serve one accepted connection with a [`MuxService`].
///
/// - When the peer negotiated multiplexing, the mux takes over and the service routes every stream kind.
/// - Otherwise a single-flight unary loop serves the connection.
///
/// The function is generic over the accepted transport
/// ([`AcceptedConnection`]), so every protocol's connections serve
/// identically.
#[cfg(pooled_mux)]
#[doc(hidden)]
pub async fn serve_connection_service<T, S>(
	mut transport: T,
	service: Arc<S>,
	mut error_tx: Option<ErrorSender>,
	mut ok_tx: Option<OkSender>,
) where
	T: AcceptedConnection,
	S: MuxService,
{
	match transport.negotiate_mux().await {
		Ok(Some(settings)) => {
			let reported = ReportedService { service, errors: error_tx.clone() };
			match transport.serve(settings, reported, None).await {
				Ok(()) => {
					if let Some(tx) = ok_tx.as_mut() {
						// The ok channel belongs to the application, and a
						// receiver that is gone wants no notice.
						let _ = tx.send(()).await;
					}
				}
				Err(err) => {
					if let Some(tx) = error_tx.as_mut() {
						// The error channel belongs to the application, and a
						// receiver that is gone wants no report.
						let _ = tx.send(err).await;
					}
				}
			}
			return;
		}
		Ok(None) => {}
		Err(err) => {
			if let Some(tx) = error_tx.as_mut() {
				// The error channel belongs to the application, and a receiver
				// that is gone wants no report.
				let _ = tx.send(err).await;
			}
			return;
		}
	}

	let respond = move |frame: Frame, session: SessionContext| {
		let service = Arc::clone(&service);
		// The single-flight fallback serves unary only, and a unary
		// open carries no route, so the call context is local.
		let cx = CallContext::new(session, StreamRoute::local());
		async move { service.unary(frame, cx).await }
	};
	serve_single_flight(transport, respond, error_tx, ok_tx).await;
}

/// Serve one accepted connection with a closure-form handler.
///
/// When the mux plane is compiled in, [`serve_connection_service`] runs
/// over the unary-only adapter. Otherwise the single-flight loop runs alone.
#[cfg(feature = "tokio")]
#[doc(hidden)]
pub async fn serve_connection<T>(
	transport: T,
	handler: SharedHandler,
	error_tx: Option<ErrorSender>,
	ok_tx: Option<OkSender>,
) where
	T: AcceptedConnection,
{
	#[cfg(pooled_mux)]
	{
		let service = Arc::new(SharedHandlerService(handler));
		serve_connection_service(transport, service, error_tx, ok_tx).await;
	}

	#[cfg(not(pooled_mux))]
	{
		let respond = move |frame: Frame, session: SessionContext| handler.call(frame, session);
		serve_single_flight(transport, respond, error_tx, ok_tx).await;
	}
}

/// The single-flight request and response loop over one connection.
///
/// Each turn collects a frame, answers it through
/// [`SingleFlightAnswer::of`], and sends the reply. The error of a failed
/// handler goes to the channel, and so does a collect or send failure, which
/// also ends the loop.
#[cfg(feature = "tokio")]
async fn serve_single_flight<T, F, Fut>(
	mut transport: T,
	respond: F,
	mut error_tx: Option<ErrorSender>,
	mut ok_tx: Option<OkSender>,
) where
	T: AcceptedConnection,
	F: Fn(Frame, SessionContext) -> Fut,
	Fut: Future<Output = Result<Option<Frame>, TightBeamError>> + MaybeSend,
{
	// The session context fills after the first collected frame,
	// because the lazy handshake is complete by then.
	let mut session_slot: Option<SessionContext> = None;
	loop {
		let collected = match transport.collect_message().await {
			Ok(result) => result,
			Err(err) => {
				if let Some(tx) = error_tx.as_mut() {
					// The error channel belongs to the application, and a
					// receiver that is gone wants no report.
					let _ = tx.send(err).await;
				}
				break;
			}
		};

		let answer = SingleFlightAnswer::of(&mut transport, &mut session_slot, collected, &respond);
		let SingleFlightAnswer { status, response, failure } = answer.await;
		if let (Some(err), Some(tx)) = (failure, error_tx.as_mut()) {
			// The error channel belongs to the application, and a receiver
			// that is gone wants no report.
			let _ = tx.send(err.into()).await;
		}

		match transport.send_response(status, response).await {
			Ok(()) => {
				if let Some(tx) = ok_tx.as_mut() {
					// The ok channel belongs to the application, and a receiver
					// that is gone wants no notice.
					let _ = tx.send(()).await;
				}
			}
			Err(err) => {
				if let Some(tx) = error_tx.as_mut() {
					// The error channel belongs to the application, and a
					// receiver that is gone wants no report.
					let _ = tx.send(err).await;
				}
				break;
			}
		}
	}
}

/// The answer that one single-flight turn sends for a frame it collected, and
/// the error of a handler that failed.
///
/// The async loop and the blocking `server!` loop answer each frame through
/// [`SingleFlightAnswer::of`], the one home of a turn's decisions. The
/// blocking loop expands in the caller's crate, so the type is public and
/// hidden from the documented surface.
#[cfg(feature = "std")]
#[doc(hidden)]
pub struct SingleFlightAnswer {
	/// The status that the turn sends.
	pub status: TransitStatus,
	/// The frame that the turn sends with the status.
	pub response: Option<Frame>,
	/// The error of a handler that failed, which the turn answers with
	/// [`TransitStatus::Internal`].
	pub failure: Option<TightBeamError>,
}

#[cfg(feature = "std")]
impl SingleFlightAnswer {
	/// Answers `collected`, a frame and the status that a single-flight
	/// connection collected it under.
	///
	/// - An admitted frame runs through `respond`, in the handler span of the
	///   audit trail of `transport`, with the session that `session` holds.
	///   The first admitted frame captures that session, because the lazy
	///   handshake is complete by then.
	/// - A handler that fails answers [`TransitStatus::Internal`], so the peer
	///   can tell it apart from an accepted empty reply, and the answer keeps
	///   its error.
	/// - A refused frame answers its own status.
	///
	/// The handler future stays pinned in the turn, so the span wraps it by
	/// reference and the turn moves it no further.
	pub async fn of<T, F, Fut>(
		transport: &mut T,
		session: &mut Option<SessionContext>,
		collected: (Arc<Frame>, TransitStatus),
		respond: F,
	) -> Self
	where
		T: EncryptedProtocolState + GateAudit,
		F: FnOnce(Frame, SessionContext) -> Fut,
		Fut: Future<Output = Result<Option<Frame>, TightBeamError>> + MaybeSend,
	{
		let (frame, status) = collected;
		if status != TransitStatus::Ok {
			return Self { status, response: None, failure: None };
		}

		// Move the frame out of the Arc, and deep-copy it only when the
		// inbound path still holds a shared reference.
		let frame = Arc::try_unwrap(frame).unwrap_or_else(|shared| (*shared).clone());
		let session = session.get_or_insert_with(|| SessionContext::capture(&*transport)).clone();
		let handled = pin!(respond(frame, session));
		let spanned = transport.run_handler(handled);

		match spanned.await {
			Ok(response) => Self { status, response, failure: None },
			Err(failure) => Self { status: TransitStatus::Internal, response: None, failure: Some(failure) },
		}
	}
}

#[cfg(feature = "tokio")]
#[doc(hidden)]
#[macro_export]
macro_rules! __tightbeam_server_protocol_handle {
	($protocol:path, $listener:expr, $handler:expr) => {{
		let __listener = $listener;
		$crate::macros::server::server_runtime::rt::spawn(async move {
			let __error_tx = $crate::macros::server::server_runtime::rt::empty_error_channel();
			let __ok_tx = $crate::macros::server::server_runtime::rt::empty_ok_channel();
			$crate::server!(@async_loop $protocol, __listener, $handler, __error_tx, __ok_tx,)
		})
	}};

	($protocol:path, $listener:expr, assertions: $assertions:expr, ($param1:ident, $param2:ident, $handler_body:expr)) => {{
		#[allow(unused_imports)]
		use $crate::trace::TraceCollector;

		let __listener = $listener;
		let __assertions = $assertions;
		$crate::macros::server::server_runtime::rt::spawn(async move {
			let __error_tx = $crate::macros::server::server_runtime::rt::empty_error_channel();
			let __ok_tx = $crate::macros::server::server_runtime::rt::empty_ok_channel();
			$crate::server!(@async_loop_assertions $protocol, __listener, __assertions, ($param1, $param2, $handler_body), __error_tx, __ok_tx,)
		})
	}};
}

#[cfg(all(not(feature = "tokio"), feature = "std"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __tightbeam_server_protocol_handle {
	($protocol:path, $listener:expr, $handler:expr) => {{
		let __listener = $listener;
		::std::thread::spawn(move || {
			$crate::server!(@sync_loop $protocol, __listener, $handler,)
		})
	}};
}

#[cfg(not(any(feature = "tokio", feature = "std")))]
#[doc(hidden)]
#[macro_export]
macro_rules! __tightbeam_server_protocol_handle {
	($protocol:path, $listener:expr, $handler:expr) => {
		compile_error!("server!(protocol ...) requires tightbeam to be built with either the `tokio` or `std` feature");
	};
}

#[cfg(feature = "tokio")]
#[doc(hidden)]
#[macro_export]
macro_rules! __tightbeam_server_protocol_bind_handle {
	($protocol:path, $addr:expr, $handler:expr) => {{
		let (listener, _) = <$protocol as $crate::transport::Protocol>::bind_cleartext($addr).await?;
		let __server = <$protocol>::from(listener);
		$crate::macros::server::server_runtime::rt::spawn(async move {
			let __error_tx = $crate::macros::server::server_runtime::rt::empty_error_channel();
			let __ok_tx = $crate::macros::server::server_runtime::rt::empty_ok_channel();
			$crate::server!(@async_loop $protocol, __server, $handler, __error_tx, __ok_tx,)
		})
	}};
}

#[cfg(all(not(feature = "tokio"), feature = "std"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __tightbeam_server_protocol_bind_handle {
	($protocol:path, $addr:expr, $handler:expr) => {{
		let (listener, _) = $crate::macros::server::server_runtime::rt::block_on(<$protocol as $crate::transport::Protocol>::bind_cleartext($addr))?;
		let __server = <$protocol>::from(listener);
		::std::thread::spawn(move || {
			$crate::server!(@sync_loop $protocol, __server, $handler,)
		})
	}};
}

#[cfg(not(any(feature = "tokio", feature = "std")))]
#[doc(hidden)]
#[macro_export]
macro_rules! __tightbeam_server_protocol_bind_handle {
	($protocol:path, $addr:expr, $handler:expr) => {
		compile_error!(
			"server!(protocol ...) with `bind_cleartext` requires tightbeam to be built with either the `tokio` or `std` feature"
		);
	};
}

#[cfg(feature = "tokio")]
#[doc(hidden)]
#[macro_export]
macro_rules! __tightbeam_server_protocol_policies_handle {
	($protocol:path, $listener:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {{
		let __listener = $listener;
		$crate::macros::server::server_runtime::rt::spawn(async move {
			let __error_tx = $crate::macros::server::server_runtime::rt::empty_error_channel();
			let __ok_tx = $crate::macros::server::server_runtime::rt::empty_ok_channel();
			$crate::server!(@async_loop $protocol, __listener, $handler, __error_tx, __ok_tx, $($policy_name: [ $( $policy_expr ),* ]),*)
		})
	}};
}

#[cfg(all(not(feature = "tokio"), feature = "std"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __tightbeam_server_protocol_policies_handle {
	($protocol:path, $listener:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {{
		let __listener = $listener;
		::std::thread::spawn(move || {
			$crate::server!(@sync_loop $protocol, __listener, $handler, $($policy_name: [ $( $policy_expr ),* ]),*)
		})
	}};
}

#[cfg(not(any(feature = "tokio", feature = "std")))]
#[doc(hidden)]
#[macro_export]
macro_rules! __tightbeam_server_protocol_policies_handle {
	($protocol:path, $listener:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {
		compile_error!(
			"server!(protocol ..., policies: ...) requires tightbeam to be built with either the `tokio` or `std` feature"
		);
	};
}

#[cfg(feature = "tokio")]
#[doc(hidden)]
#[macro_export]
macro_rules! __tightbeam_server_protocol_policies_session_handle {
	($protocol:path, $listener:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {{
		let __listener = $listener;
		$crate::macros::server::server_runtime::rt::spawn(async move {
			let __error_tx = $crate::macros::server::server_runtime::rt::empty_error_channel();
			let __ok_tx = $crate::macros::server::server_runtime::rt::empty_ok_channel();
			$crate::server!(@async_session_loop $protocol, __listener, $handler, __error_tx, __ok_tx, $($policy_name: [ $( $policy_expr ),* ]),*)
		})
	}};
}

#[cfg(not(feature = "tokio"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __tightbeam_server_protocol_policies_session_handle {
	($protocol:path, $listener:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {
		compile_error!("server!(protocol ..., handle: move |frame, session| ...) requires the `tokio` feature");
	};
}

#[cfg(feature = "tokio")]
#[doc(hidden)]
#[macro_export]
macro_rules! __tightbeam_server_protocol_policies_assertions_handle {
	($protocol:path, $listener:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $assertions:expr, ($param1:ident, $param2:ident, $handler_body:expr)) => {{
		#[allow(unused_imports)]
		use $crate::trace::TraceCollector;

		let __listener = $listener;
		let __assertions = $assertions;
		$crate::macros::server::server_runtime::rt::spawn(async move {
			let __error_tx = $crate::macros::server::server_runtime::rt::empty_error_channel();
			let __ok_tx = $crate::macros::server::server_runtime::rt::empty_ok_channel();
			$crate::server!(@async_loop_assertions $protocol, __listener, __assertions, ($param1, $param2, $handler_body), __error_tx, __ok_tx, $($policy_name: [ $( $policy_expr ),* ]),*)
		})
	}};
}

#[cfg(all(not(feature = "tokio"), feature = "std"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __tightbeam_server_protocol_policies_assertions_handle {
	($protocol:path, $listener:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $assertions:expr, ($param1:ident, $param2:ident, $handler_body:expr)) => {{
		compile_error!("server!(protocol ..., policies: ..., assertions: ...) requires the `tokio` feature");
	}};
}

#[cfg(not(any(feature = "tokio", feature = "std")))]
#[doc(hidden)]
#[macro_export]
macro_rules! __tightbeam_server_protocol_policies_assertions_handle {
	($protocol:path, $listener:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $assertions:expr, ($param1:ident, $param2:ident, $handler_body:expr)) => {{
		compile_error!(
			"server!(protocol ..., policies: ..., assertions: ...) requires tightbeam to be built with either the `tokio` or `std` feature"
		);
	}};
}

#[cfg(feature = "tokio")]
#[doc(hidden)]
#[macro_export]
macro_rules! __tightbeam_server_protocol_channels_handle {
	($protocol:path, $listener:expr, $error_tx:expr, $ok_tx:expr, $handler:expr) => {{
		let __listener = $listener;
		$crate::macros::server::server_runtime::rt::spawn(async move {
			let __error_tx = Some($error_tx);
			let __ok_tx = Some($ok_tx);
			$crate::server!(@async_loop $protocol, __listener, $handler, __error_tx, __ok_tx,)
		})
	}};
}

#[cfg(all(not(feature = "tokio"), feature = "std"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __tightbeam_server_protocol_channels_handle {
	($protocol:path, $listener:expr, $error_tx:expr, $ok_tx:expr, $handler:expr) => {{
		let __listener = $listener;
		// Only the tokio loop reports through channels, so the sync expansion
		// evaluates both inputs and drops them.
		let _ = ($error_tx, $ok_tx);
		::std::thread::spawn(move || {
			$crate::server!(@sync_loop $protocol, __listener, $handler,)
		})
	}};
}

#[cfg(not(any(feature = "tokio", feature = "std")))]
#[doc(hidden)]
#[macro_export]
macro_rules! __tightbeam_server_protocol_channels_handle {
	($protocol:path, $listener:expr, $error_tx:expr, $ok_tx:expr, $handler:expr) => {
		// The build stops at the `compile_error!` below, so this line only
		// expands both inputs.
		let _ = ($error_tx, $ok_tx);
		compile_error!(
			"server!(protocol ..., channels: ...) requires tightbeam to be built with either the `tokio` or `std` feature"
		);
	};
}

#[cfg(feature = "tokio")]
#[doc(hidden)]
#[macro_export]
macro_rules! __tightbeam_server_protocol_channels_policies_handle {
	($protocol:path, $listener:expr, $error_tx:expr, $ok_tx:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {{
		let __listener = $listener;
		$crate::macros::server::server_runtime::rt::spawn(async move {
			let __error_tx = Some($error_tx);
			let __ok_tx = Some($ok_tx);
			$crate::server!(@async_loop $protocol, __listener, $handler, __error_tx, __ok_tx, $($policy_name: [ $( $policy_expr ),* ]),*)
		})
	}};
}

#[cfg(all(not(feature = "tokio"), feature = "std"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __tightbeam_server_protocol_channels_policies_handle {
	($protocol:path, $listener:expr, $error_tx:expr, $ok_tx:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {{
		let __listener = $listener;
		// Only the tokio loop reports through channels, so the sync expansion
		// evaluates both inputs and drops them.
		let _ = ($error_tx, $ok_tx);
		::std::thread::spawn(move || {
			$crate::server!(@sync_loop $protocol, __listener, $handler, $($policy_name: [ $( $policy_expr ),* ]),*)
		})
	}};
}

#[cfg(not(any(feature = "tokio", feature = "std")))]
#[doc(hidden)]
#[macro_export]
macro_rules! __tightbeam_server_protocol_channels_policies_handle {
	($protocol:path, $listener:expr, $error_tx:expr, $ok_tx:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {
		// The build stops at the `compile_error!` below, so this line only
		// expands both inputs.
		let _ = ($error_tx, $ok_tx);
		compile_error!(
			"server!(protocol ..., channels: ...) requires tightbeam to be built with either the `tokio` or `std` feature"
		);
	};
}

#[cfg(feature = "tokio")]
#[doc(hidden)]
#[macro_export]
macro_rules! __tightbeam_server_protocol_bind_policies_handle {
	($protocol:path, $addr:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {{
		let (listener, _) = <$protocol as $crate::transport::Protocol>::bind_cleartext($addr).await?;
		let __server = <$protocol>::from(listener);
		$crate::macros::server::server_runtime::rt::spawn(async move {
			let __error_tx = $crate::macros::server::server_runtime::rt::empty_error_channel();
			let __ok_tx = $crate::macros::server::server_runtime::rt::empty_ok_channel();
			$crate::server!(@async_loop $protocol, __server, $handler, __error_tx, __ok_tx, $($policy_name: [ $( $policy_expr ),* ]),*)
		})
	}};
}

#[cfg(all(not(feature = "tokio"), feature = "std"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __tightbeam_server_protocol_bind_policies_handle {
	($protocol:path, $addr:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {{
		let (listener, _) = $crate::macros::server::server_runtime::rt::block_on(<$protocol as $crate::transport::Protocol>::bind_cleartext($addr))?;
		let __server = <$protocol>::from(listener);
		::std::thread::spawn(move || {
			$crate::server!(@sync_loop $protocol, __server, $handler, $($policy_name: [ $( $policy_expr ),* ]),*)
		})
	}};
}

#[cfg(not(any(feature = "tokio", feature = "std")))]
#[doc(hidden)]
#[macro_export]
macro_rules! __tightbeam_server_protocol_bind_policies_handle {
	($protocol:path, $addr:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {
		compile_error!("server!(protocol ..., policies: ...) with `bind_cleartext` requires tightbeam to be built with either the `tokio` or `std` feature");
	};
}

#[cfg(pooled_mux)]
#[doc(hidden)]
#[macro_export]
macro_rules! __tightbeam_server_protocol_service_handle {
	($protocol:path, $listener:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $error_tx:expr, $ok_tx:expr, $service:expr) => {{
		let __listener = $listener;
		$crate::macros::server::server_runtime::rt::spawn(async move {
			let __error_tx = $error_tx;
			let __ok_tx = $ok_tx;
			$crate::server!(@async_service_loop $protocol, __listener, $service, __error_tx, __ok_tx, $($policy_name: [ $( $policy_expr ),* ]),*)
		})
	}};
}

#[cfg(not(pooled_mux))]
#[doc(hidden)]
#[macro_export]
macro_rules! __tightbeam_server_protocol_service_handle {
	($protocol:path, $listener:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $error_tx:expr, $ok_tx:expr, $service:expr) => {
		compile_error!(
			"server!(protocol ..., service: ...) requires the pooled multiplexing feature set that the `pooled_mux` alias in tightbeam's build.rs defines"
		);
	};
}

/// Server-specific runtime extensions.
///
/// The module re-exports the unified runtime and adds server-specific
/// channel helpers.
#[cfg(any(feature = "tokio", feature = "std"))]
#[doc(hidden)]
pub mod server_runtime {
	/// Runtime primitives, re-exported from the unified runtime.
	pub mod rt {
		pub use crate::runtime::rt::*;
		/// The accept-loop connection plane of the async `server!` expansion,
		/// which serves the expansion and sits outside the documented surface.
		#[cfg(feature = "tokio")]
		pub use crate::transport::accept::AcceptPlane;

		use crate::transport::error::TransportError;

		/// The sender half of the error notification channel.
		pub type ErrorSender = crate::runtime::rt::Sender<TransportError>;

		/// The sender half of the success notification channel.
		pub type OkSender = crate::runtime::rt::Sender<()>;

		/// Returns `None`, the error channel of an expansion that names no
		/// channels.
		#[allow(dead_code)]
		pub fn empty_error_channel() -> Option<ErrorSender> {
			None
		}

		/// Returns `None`, the success channel of an expansion that names no
		/// channels.
		#[allow(dead_code)]
		pub fn empty_ok_channel() -> Option<OkSender> {
			None
		}
	}
}

/// Serves a listener: accepts each connection, applies the policies, and
/// runs the handler or service on it.
///
/// # Policies
///
/// - `name: [ expr, .. ]` calls `name(expr)` on every accepted transport.
/// - The accept loop evaluates each expression once per accepted
///   connection, so every connection receives its own value.
/// - An expression that shares one value across connections clones it, as
///   `with_trace: [ trace.share() ]` does.
/// - `max_connections: [ n ]` sets the connection cap of the async accept
///   plane instead. The sync loop ignores it.
#[macro_export]
macro_rules! server {
	(@apply_policy $transport:ident, $policy_name:ident, [ $( $policy_expr:expr ),* $(,)? ]) => {{
		$(
			$transport = $crate::server!(@apply_one_policy $transport, $policy_name, $policy_expr);
		)*
	}};

	// `max_connections` is an accept-loop knob that `@extract_max_connections`
	// consumes, so this arm returns the transport as it is.
	(@apply_one_policy $transport:ident, max_connections, $policy_expr:expr) => {{
		$transport
	}};

	// Fold the policy list down to the accept-loop concurrency cap. The first
	// `max_connections: [ n ]` entry wins, and the default applies otherwise.
	(@extract_max_connections) => {
		$crate::constants::DEFAULT_MAX_SERVER_CONNECTIONS
	};
	(@extract_max_connections max_connections: [ $cap:expr ] $(, $rest_name:ident: [ $( $rest_expr:expr ),* $(,)? ])* $(,)?) => {
		$cap
	};
	(@extract_max_connections $other:ident: [ $( $expr:expr ),* $(,)? ] $(, $rest_name:ident: [ $( $rest_expr:expr ),* $(,)? ])* $(,)?) => {
		$crate::server!(@extract_max_connections $($rest_name: [ $( $rest_expr ),* ]),*)
	};

	// Any other policy name calls the transport method of that name.
	(@apply_one_policy $transport:ident, $other:ident, $policy_expr:expr) => {{
		$transport.$other($policy_expr)
	}};

	// This arm is a fire-and-forget loop. The sync path holds no error channel,
	// so the loop drops each failure: a transport failure ends its connection,
	// an accept failure ends the loop, and a failed handler answers `Internal`.
	// Use the tokio path when operators need to see errors.
	(@sync_loop_body $protocol:path, $listener:ident, $handler:ident, $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?) => {{
		loop {
			match $listener.accept() {
				Ok(mut __transport) => {
					$(
						$(
							__transport = $crate::server!(@apply_one_policy __transport, $policy_name, $policy_expr);
						)*
					)*
					let __handler_clone = ::core::clone::Clone::clone(&$handler);
					#[allow(unused_imports)]
					use $crate::transport::MessageCollector;
					$crate::macros::server::server_runtime::rt::spawn(move || {
						let mut __transport = __transport;
						// The session context fills after the first collected
						// frame, because the lazy handshake is complete by
						// then.
						let mut __session_slot = ::core::option::Option::None;
						loop {
							let __collected = match $crate::macros::server::server_runtime::rt::block_on(__transport.collect_message()) {
								Ok(result) => result,
								Err(_err) => {
									break;
								}
							};

							let __answer = $crate::macros::server::SingleFlightAnswer::of(
								&mut __transport,
								&mut __session_slot,
								__collected,
								|frame, session| __handler_clone.call(frame, session),
							);
							// The loop has no error channel, so it drops the
							// error of a failed handler, and the `Internal`
							// answer tells the peer.
							let $crate::macros::server::SingleFlightAnswer { status, response, .. } =
								$crate::macros::server::server_runtime::rt::block_on(__answer);

							match $crate::macros::server::server_runtime::rt::block_on(__transport.send_response(status, response)) {
								Ok(()) => continue,
								Err(_err) => {
									break;
								}
							}
						}
					});
				}
				Err(_err) => {
					break;
				}
			}
		}
	}};

	(@async_loop_body $protocol:path, $listener:ident, $handler:ident, $serve:path, $error_tx:ident, $ok_tx:ident, $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?) => {{
		// `policies: { max_connections: [ n ] }` overrides the plane's
		// default connection cap.
		let __accept_errors = $error_tx.clone();
		$crate::macros::server::server_runtime::rt::AcceptPlane::new(
			$crate::server!(@extract_max_connections $($policy_name: [ $( $policy_expr ),* ]),*),
			::std::sync::Arc::new($crate::utils::time::SystemClock),
		)
		.accept_on_reporting(
			$listener,
			move |mut __transport| {
				$(
					$(
						__transport = $crate::server!(@apply_one_policy __transport, $policy_name, $policy_expr);
					)*
				)*
				let __service_clone = ::core::clone::Clone::clone(&$handler);
				let __error_channel = $error_tx.clone();
				let __ok_channel = $ok_tx.clone();
				async move {
					$serve(__transport, __service_clone, __error_channel, __ok_channel).await;
				}
			},
			move |__accept_error| {
				// The listener error converts here, before the await, so the
				// async block holds only the reported error across it.
				let __reported = ::core::convert::Into::into(__accept_error);
				let __channel = __accept_errors.clone();
				async move {
					if let Some(tx) = __channel {
						// The error channel belongs to the application, and a
						// receiver that is gone wants no report.
						let _ = tx.send(__reported).await;
					}
				}
			},
		)
		.await;
	}};

	(@sync_loop $protocol:path, $listener:expr, $handler:expr, $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?) => {{
		let mut __listener = $listener;
		let __handler = $crate::macros::server::SharedHandler::from_context_blind($handler);

		$crate::server!(@sync_loop_body $protocol, __listener, __handler, $($policy_name: [ $( $policy_expr ),* ]),*);
	}};

	(@async_loop_assertions $protocol:path, $listener:expr, $assertions:expr, ($param1:ident, $param2:ident, $handler_body:expr), $error_tx:expr, $ok_tx:expr, $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?) => {{
		#[allow(unused_imports)]
		use $crate::trace::TraceCollector;

		let __assertions = ::std::sync::Arc::new($assertions);
		let __handler_with_trace = {
			let __assertions = ::std::sync::Arc::clone(&__assertions);
			move |$param1: $crate::Frame| {
				let $param2: TraceCollector = __assertions.as_ref().share();
				$handler_body
			}
		};

		$crate::server!(@async_loop $protocol, $listener, __handler_with_trace, $error_tx, $ok_tx, $($policy_name: [ $( $policy_expr ),* ]),*);
	}};

	(@async_loop $protocol:path, $listener:expr, $handler:expr, $error_tx:expr, $ok_tx:expr, $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?) => {{
		let mut __listener = $listener;
		let __handler = $crate::macros::server::SharedHandler::from_context_blind($handler);
		let mut __error_tx = $error_tx;
		let mut __ok_tx = $ok_tx;

		$crate::server!(@async_loop_body $protocol, __listener, __handler, $crate::macros::server::serve_connection, __error_tx, __ok_tx, $($policy_name: [ $( $policy_expr ),* ]),*);
	}};

	(@async_session_loop $protocol:path, $listener:expr, $handler:expr, $error_tx:expr, $ok_tx:expr, $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?) => {{
		let mut __listener = $listener;
		let __handler = $crate::macros::server::SharedHandler::from($handler);
		let mut __error_tx = $error_tx;
		let mut __ok_tx = $ok_tx;

		$crate::server!(@async_loop_body $protocol, __listener, __handler, $crate::macros::server::serve_connection, __error_tx, __ok_tx, $($policy_name: [ $( $policy_expr ),* ]),*);
	}};

	// Service form: the caller supplies a full `MuxService`, so streaming
	// and duplex interactions dispatch to it.
	(@async_service_loop $protocol:path, $listener:expr, $service:expr, $error_tx:expr, $ok_tx:expr, $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?) => {{
		let mut __listener = $listener;
		let __service = ::std::sync::Arc::new($service);
		let mut __error_tx = $error_tx;
		let mut __ok_tx = $ok_tx;

		$crate::server!(@async_loop_body $protocol, __listener, __service, $crate::macros::server::serve_connection_service, __error_tx, __ok_tx, $($policy_name: [ $( $policy_expr ),* ]),*);
	}};

	($protocol:path: $listener:expr, handle: $handler:expr) => {{
		$crate::__tb_require_std!({
			let __listener = $listener;
			$crate::server!(@sync_loop $protocol, __listener, $handler,)
		})
	}};

	($protocol:path: bind_cleartext $addr:expr, handle: $handler:expr) => {{
		$crate::__tb_require_std!({
			let (listener, _) = $crate::macros::server::server_runtime::rt::block_on(<$protocol as $crate::transport::Protocol>::bind_cleartext($addr))?;
			let __server = <$protocol>::from(listener);
			$crate::server!(@sync_loop $protocol, __server, $handler,)
		})
	}};

	($protocol:path: $listener:expr, policies: { $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)? }, handle: $handler:expr) => {{
		$crate::__tb_require_std!({
			let __listener = $listener;
			$crate::server!(@sync_loop $protocol, __listener, $handler, $($policy_name: [ $( $policy_expr ),* ]),*);
		})
	}};

	($protocol:path: bind_cleartext $addr:expr, policies: { $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)? }, handle: $handler:expr) => {{
		$crate::__tb_require_std!({
			let (listener, _) = $crate::macros::server::server_runtime::rt::block_on(<$protocol as $crate::transport::Protocol>::bind_cleartext($addr))?;
			let __server = <$protocol>::from(listener);
			$crate::server!(@sync_loop $protocol, __server, $handler, $($policy_name: [ $( $policy_expr ),* ]),*);
		})
	}};

	// Session-aware handler: the closure's second parameter receives the
	// connection's authenticated peer context.
	(protocol $protocol:path: $listener:expr, handle: move |$frame:ident $(: $frame_ty:ty)?, $session:ident $(: $session_ty:ty)?| $body:expr) => {{
		$crate::__tightbeam_server_protocol_policies_session_handle!(
			$protocol,
			$listener,
			[],
			move |$frame $(: $frame_ty)?, $session $(: $session_ty)?| $body
		)
	}};

	(protocol $protocol:path: $listener:expr, handle: $handler:expr) => {{
		$crate::__tightbeam_server_protocol_handle!($protocol, $listener, $handler)
	}};

	(protocol $protocol:path: $listener:expr, assertions: $assertions:expr, handle: move |$param1:ident, $param2:ident| $handler_body:expr) => {{
		$crate::__tightbeam_server_protocol_handle!($protocol, $listener, assertions: $assertions, ($param1, $param2, $handler_body))
	}};

	(protocol $protocol:path: $listener:expr, assertions: $assertions:expr, handle: |$param1:ident, $param2:ident| $handler_body:expr) => {{
		$crate::__tightbeam_server_protocol_handle!($protocol, $listener, assertions: $assertions, ($param1, $param2, $handler_body))
	}};

	(protocol $protocol:path: bind_cleartext $addr:expr, handle: $handler:expr) => {{
		$crate::__tightbeam_server_protocol_bind_handle!($protocol, $addr, $handler)
	}};

	// Session-aware handler with policies. This arm matches ahead of the
	// context-blind `handle: $handler:expr` arm.
	(protocol $protocol:path: $listener:expr, policies: { $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)? }, handle: move |$frame:ident $(: $frame_ty:ty)?, $session:ident $(: $session_ty:ty)?| $body:expr) => {{
		$crate::__tightbeam_server_protocol_policies_session_handle!(
			$protocol,
			$listener,
			[ $($policy_name: [ $( $policy_expr ),* ]),* ],
			move |$frame $(: $frame_ty)?, $session $(: $session_ty)?| $body
		)
	}};

	(protocol $protocol:path: $listener:expr, policies: { $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)? }, handle: $handler:expr) => {{
		$crate::__tightbeam_server_protocol_policies_handle!($protocol, $listener, [ $($policy_name: [ $( $policy_expr ),* ]),* ], $handler)
	}};

	(protocol $protocol:path: $listener:expr, policies: { $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)? }, assertions: $assertions:expr, handle: move |$param1:ident, $param2:ident| $handler_body:expr) => {{
		$crate::__tightbeam_server_protocol_policies_assertions_handle!(
			$protocol,
			$listener,
			[ $($policy_name: [ $( $policy_expr ),* ]),* ],
			$assertions,
			($param1, $param2, $handler_body)
		)
	}};

	(protocol $protocol:path: $listener:expr, policies: { $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)? }, assertions: $assertions:expr, handle: |$param1:ident, $param2:ident| $handler_body:expr) => {{
		$crate::__tightbeam_server_protocol_policies_assertions_handle!(
			$protocol,
			$listener,
			[ $($policy_name: [ $( $policy_expr ),* ]),* ],
			$assertions,
			($param1, $param2, $handler_body)
		)
	}};

	(protocol $protocol:path: $listener:expr, assertions: $assertions:expr, policies: { $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)? }, handle: move |$param1:ident, $param2:ident| $handler_body:expr) => {{
		$crate::__tightbeam_server_protocol_policies_assertions_handle!(
			$protocol,
			$listener,
			[ $($policy_name: [ $( $policy_expr ),* ]),* ],
			$assertions,
			($param1, $param2, $handler_body)
		)
	}};

	(protocol $protocol:path: $listener:expr, assertions: $assertions:expr, policies: { $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)? }, handle: |$param1:ident, $param2:ident| $handler_body:expr) => {{
		$crate::__tightbeam_server_protocol_policies_assertions_handle!(
			$protocol,
			$listener,
			[ $($policy_name: [ $( $policy_expr ),* ]),* ],
			$assertions,
			($param1, $param2, $handler_body)
		)
	}};

	// Service forms: `service:` takes a `MuxService` value, so one declaration
	// serves unary, streaming, and duplex interactions. These forms require the
	// pooled multiplexing feature set.
	(protocol $protocol:path: $listener:expr, service: $service:expr) => {{
		$crate::__tightbeam_server_protocol_service_handle!(
			$protocol,
			$listener,
			[],
			$crate::macros::server::server_runtime::rt::empty_error_channel(),
			$crate::macros::server::server_runtime::rt::empty_ok_channel(),
			$service
		)
	}};

	(protocol $protocol:path: $listener:expr, policies: { $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)? }, service: $service:expr) => {{
		$crate::__tightbeam_server_protocol_service_handle!(
			$protocol,
			$listener,
			[ $($policy_name: [ $( $policy_expr ),* ]),* ],
			$crate::macros::server::server_runtime::rt::empty_error_channel(),
			$crate::macros::server::server_runtime::rt::empty_ok_channel(),
			$service
		)
	}};

	(protocol $protocol:path: $listener:expr, channels: { error: $error_tx:expr, ok: $ok_tx:expr }, service: $service:expr) => {{
		$crate::__tightbeam_server_protocol_service_handle!(
			$protocol,
			$listener,
			[],
			Some($error_tx),
			Some($ok_tx),
			$service
		)
	}};

	(protocol $protocol:path: $listener:expr, channels: { error: $error_tx:expr, ok: $ok_tx:expr }, policies: { $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)? }, service: $service:expr) => {{
		$crate::__tightbeam_server_protocol_service_handle!(
			$protocol,
			$listener,
			[ $($policy_name: [ $( $policy_expr ),* ]),* ],
			Some($error_tx),
			Some($ok_tx),
			$service
		)
	}};

	(protocol $protocol:path: $listener:expr, channels: { error: $error_tx:expr, ok: $ok_tx:expr }, handle: $handler:expr) => {{
		$crate::__tightbeam_server_protocol_channels_handle!($protocol, $listener, $error_tx, $ok_tx, $handler)
	}};

	(protocol $protocol:path: $listener:expr, channels: { error: $error_tx:expr, ok: $ok_tx:expr }, policies: { $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)? }, handle: $handler:expr) => {{
		$crate::__tightbeam_server_protocol_channels_policies_handle!($protocol, $listener, $error_tx, $ok_tx, [ $($policy_name: [ $( $policy_expr ),* ]),* ], $handler)
	}};

	(protocol $protocol:path: bind_cleartext $addr:expr, policies: { $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)? }, handle: $handler:expr) => {{
		$crate::__tightbeam_server_protocol_bind_policies_handle!($protocol, $addr, [ $($policy_name: [ $( $policy_expr ),* ]),* ], $handler)
	}};

	(async $($rest:tt)*) => {
		$crate::server!(protocol $($rest)*)
	};
}

#[cfg(all(test, feature = "tokio"))]
mod tests {
	use core::future::ready;
	use core::sync::atomic::{AtomicBool, Ordering};

	use tokio::net::{TcpListener, TcpStream};

	use super::*;
	use crate::testing::TestFrame;
	use crate::transport::tcp::r#async::{TcpTransport, TokioStream};
	use crate::transport::{EndpointConfig, TransportResult};

	/// A cleartext transport over a loopback connection, beside the listener
	/// that holds the other end open.
	async fn loopback_transport() -> TransportResult<(TcpListener, TcpTransport<TokioStream>)> {
		let listener = TcpListener::bind("127.0.0.1:0").await?;
		let stream = TcpStream::connect(listener.local_addr()?).await?;
		let transport = TcpTransport::new(TokioStream::from(stream), EndpointConfig::cleartext());

		Ok((listener, transport))
	}

	/// Run one turn on a frame collected under `status` with a handler that
	/// fails, and return the status the turn answers with and whether the
	/// handler ran.
	async fn failing_turn(status: TransitStatus) -> TransportResult<(TransitStatus, bool)> {
		let (_listener, mut transport) = loopback_transport().await?;
		let ran = AtomicBool::new(false);
		let failing = |_frame, _session| {
			ran.store(true, Ordering::SeqCst);
			ready(Err::<Option<Frame>, _>(TightBeamError::MissingResponse))
		};

		let collected = (Arc::new(TestFrame::v0(None, None)), status);
		let answer = SingleFlightAnswer::of(&mut transport, &mut None, collected, failing).await;
		Ok((answer.status, ran.load(Ordering::SeqCst)))
	}

	/// A turn answers a refused frame with the status that refused it, before
	/// any handler runs.
	#[tokio::test]
	async fn a_turn_answers_a_refused_frame_with_its_status() -> TransportResult<()> {
		let refused = TransitStatus::PermissionDenied;
		assert_eq!(failing_turn(refused).await?, (refused, false));
		Ok(())
	}

	/// A turn answers an admitted frame whose handler fails with `Internal`,
	/// so the peer can tell it apart from an accepted empty reply.
	#[tokio::test]
	async fn a_turn_answers_a_failed_handler_with_internal() -> TransportResult<()> {
		assert_eq!(failing_turn(TransitStatus::Ok).await?, (TransitStatus::Internal, true));
		Ok(())
	}
}
