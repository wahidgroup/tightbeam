#![allow(clippy::type_complexity)]

use core::{future::Future, pin::Pin};

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, sync::Arc};
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::policy::SessionContext;
use crate::Frame;

#[cfg(feature = "tokio")]
use crate::policy::TransitStatus;
#[cfg(feature = "tokio")]
use crate::transport::MessageCollector;
#[cfg(feature = "tokio")]
use crate::TightBeamError;

#[cfg(all(feature = "tokio", feature = "x509"))]
use crate::transport::state::EncryptedProtocolState;

#[cfg(pooled_mux)]
use crate::transport::multiplex::MuxAcceptor;
#[cfg(pooled_mux)]
use crate::transport::multiplex::{ReplySink, StreamBody, StreamRoute};
#[cfg(pooled_mux)]
use crate::transport::serve::{serve_mux, CallContext, MuxService};

#[cfg(feature = "tokio")]
use self::server_runtime::rt::{ErrorSender, OkSender};

pub type HandlerFuture = Pin<Box<dyn Future<Output = Result<Option<Frame>, crate::TightBeamError>> + Send>>;
/// Connection-scoped handler: every invocation carries the session's
/// authenticated peer context alongside the frame.
pub type SharedHandler = Arc<dyn Fn(Frame, SessionContext) -> HandlerFuture + Send + Sync>;

/// Adapt a context-blind handler: the session context is dropped.
pub fn into_shared_handler<F, Fut>(handler: F) -> SharedHandler
where
	F: Fn(Frame) -> Fut + Send + Sync + Clone + 'static,
	Fut: Future<Output = Result<Option<Frame>, crate::TightBeamError>> + Send + 'static,
{
	let handler = Arc::new(handler);
	Arc::new(move |frame: Frame, _session: SessionContext| -> HandlerFuture {
		let handler = Arc::clone(&handler);
		Box::pin(async move { handler(frame).await })
	})
}

/// Share a session-aware handler (`handle: move |frame, session| ...`).
pub fn into_shared_session_handler<F, Fut>(handler: F) -> SharedHandler
where
	F: Fn(Frame, SessionContext) -> Fut + Send + Sync + Clone + 'static,
	Fut: Future<Output = Result<Option<Frame>, crate::TightBeamError>> + Send + 'static,
{
	let handler = Arc::new(handler);
	Arc::new(move |frame: Frame, session: SessionContext| -> HandlerFuture {
		let handler = Arc::clone(&handler);
		Box::pin(async move { handler(frame, session).await })
	})
}

/// Everything one accepted async server connection must already be:
/// message collection for the single-flight loop, mux negotiation for
/// the takeover, and handshake state for session capture. Satisfied
/// blanket-wise; callers never implement this by hand.
#[cfg(pooled_mux)]
pub trait AcceptedConnection: MessageCollector + MuxAcceptor + EncryptedProtocolState + Send {}

#[cfg(pooled_mux)]
impl<T: MessageCollector + MuxAcceptor + EncryptedProtocolState + Send> AcceptedConnection for T {}

#[cfg(all(feature = "tokio", not(pooled_mux), feature = "x509"))]
pub trait AcceptedConnection: MessageCollector + EncryptedProtocolState + Send {}

#[cfg(all(feature = "tokio", not(pooled_mux), feature = "x509"))]
impl<T: MessageCollector + EncryptedProtocolState + Send> AcceptedConnection for T {}

#[cfg(all(feature = "tokio", not(feature = "x509")))]
pub trait AcceptedConnection: MessageCollector + Send {}

#[cfg(all(feature = "tokio", not(feature = "x509")))]
impl<T: MessageCollector + Send> AcceptedConnection for T {}

/// [`SharedHandler`] as a unary-only service: the closure grammar of
/// `server!` serves unary interactions, streaming kinds answer
/// `Unimplemented` through the [`MuxService`] defaults.
#[cfg(pooled_mux)]
struct SharedHandlerService(SharedHandler);

#[cfg(pooled_mux)]
impl MuxService for SharedHandlerService {
	fn unary(
		&self,
		frame: Frame,
		cx: CallContext,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		(self.0)(frame, cx.into_session())
	}
}

/// Report a service failure to the error channel, degrading it to an
/// opaque `Internal` so the peer-visible status never leaks the
/// original error once it has been reported locally.
#[cfg(pooled_mux)]
async fn report_failure(errors: &mut Option<ErrorSender>, err: TightBeamError) -> TightBeamError {
	match errors.as_mut() {
		Some(tx) => {
			let _ = tx.send(err.into()).await;
			TightBeamError::TransportError(crate::transport::TransportError::OperationFailed(
				crate::transport::TransportFailure::Internal,
			))
		}
		None => err,
	}
}

/// [`MuxService`] adapter reporting every handler failure to the
/// server's error channel before the stream closes with its status.
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

/// Serve one accepted connection with a [`MuxService`]: mux takeover
/// when the peer negotiated multiplexing (every stream kind routed by
/// the service), single-flight unary loop otherwise.
///
/// Generic over the accepted transport ([`AcceptedConnection`]), so
/// every protocol's connections serve identically.
#[cfg(pooled_mux)]
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
			match serve_mux(transport, settings, reported, None).await {
				Ok(()) => {
					if let Some(tx) = ok_tx.as_mut() {
						let _ = tx.send(()).await;
					}
				}
				Err(err) => {
					if let Some(tx) = error_tx.as_mut() {
						let _ = tx.send(err).await;
					}
				}
			}
			return;
		}
		Ok(None) => {}
		Err(err) => {
			if let Some(tx) = error_tx.as_mut() {
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

/// Serve one accepted connection with a closure-form handler:
/// [`serve_connection_service`] over the unary-only adapter when the
/// mux plane is compiled in, the single-flight loop alone otherwise.
#[cfg(feature = "tokio")]
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
		let respond = move |frame: Frame, session: SessionContext| handler(frame, session);
		serve_single_flight(transport, respond, error_tx, ok_tx).await;
	}
}

/// Single-flight request/response loop over one connection: collect,
/// answer through `respond`, send. A handler failure answers
/// `Internal` so the peer can tell it apart from an accepted empty
/// reply; the original error goes to the channel.
#[cfg(feature = "tokio")]
async fn serve_single_flight<T, F, Fut>(
	mut transport: T,
	respond: F,
	mut error_tx: Option<ErrorSender>,
	mut ok_tx: Option<OkSender>,
) where
	T: AcceptedConnection,
	F: Fn(Frame, SessionContext) -> Fut,
	Fut: Future<Output = Result<Option<Frame>, TightBeamError>>,
{
	// Session context filled after the first collected frame: the
	// lazy handshake is complete by then.
	let mut session_slot: Option<SessionContext> = None;
	loop {
		let (frame, status) = match transport.collect_message().await {
			Ok(result) => result,
			Err(err) => {
				if let Some(tx) = error_tx.as_mut() {
					let _ = tx.send(err).await;
				}
				break;
			}
		};

		// Prefer moving the frame out of the Arc; deep-copy only when
		// the inbound path still holds a shared reference.
		let frame_owned = Arc::try_unwrap(frame).unwrap_or_else(|arc| (*arc).clone());
		let (status, response) = if status == TransitStatus::Ok {
			let session = session_slot.get_or_insert_with(|| capture_session(&transport)).clone();
			match respond(frame_owned, session).await {
				Ok(response) => (status, response),
				Err(err) => {
					if let Some(tx) = error_tx.as_mut() {
						let _ = tx.send(err.into()).await;
					}
					(TransitStatus::Internal, None)
				}
			}
		} else {
			(status, None)
		};

		match transport.send_response(status, response).await {
			Ok(()) => {
				if let Some(tx) = ok_tx.as_mut() {
					let _ = tx.send(()).await;
				}
			}
			Err(err) => {
				if let Some(tx) = error_tx.as_mut() {
					let _ = tx.send(err).await;
				}
				break;
			}
		}
	}
}

#[cfg(all(feature = "tokio", feature = "x509"))]
fn capture_session<T: EncryptedProtocolState>(transport: &T) -> SessionContext {
	SessionContext::capture(transport)
}

/// Cleartext builds authenticate nothing: empty context.
#[cfg(all(feature = "tokio", not(feature = "x509")))]
fn capture_session<T>(_transport: &T) -> SessionContext {
	SessionContext::default()
}

#[cfg(feature = "tokio")]
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
#[macro_export]
macro_rules! __tightbeam_server_protocol_handle {
	($protocol:path, $listener:expr, $handler:expr) => {
		compile_error!("server!(protocol ...) requires tightbeam to be built with either the `tokio` or `std` feature");
	};
}

#[cfg(feature = "tokio")]
#[macro_export]
macro_rules! __tightbeam_server_protocol_bind_handle {
	($protocol:path, $addr:expr, $handler:expr) => {{
		let (listener, _) = <$protocol as $crate::transport::Protocol>::bind($addr).await?;
		let __server = <$protocol>::from(listener);
		$crate::macros::server::server_runtime::rt::spawn(async move {
			let __error_tx = $crate::macros::server::server_runtime::rt::empty_error_channel();
			let __ok_tx = $crate::macros::server::server_runtime::rt::empty_ok_channel();
			$crate::server!(@async_loop $protocol, __server, $handler, __error_tx, __ok_tx,)
		})
	}};
}

#[cfg(all(not(feature = "tokio"), feature = "std"))]
#[macro_export]
macro_rules! __tightbeam_server_protocol_bind_handle {
	($protocol:path, $addr:expr, $handler:expr) => {{
		let (listener, _) = <$protocol as $crate::transport::Protocol>::bind($addr)?;
		let __server = <$protocol>::from(listener);
		::std::thread::spawn(move || {
			$crate::server!(@sync_loop $protocol, __server, $handler,)
		})
	}};
}

#[cfg(not(any(feature = "tokio", feature = "std")))]
#[macro_export]
macro_rules! __tightbeam_server_protocol_bind_handle {
	($protocol:path, $addr:expr, $handler:expr) => {
		compile_error!(
			"server!(protocol ...) with `bind` requires tightbeam to be built with either the `tokio` or `std` feature"
		);
	};
}

#[cfg(feature = "tokio")]
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
#[macro_export]
macro_rules! __tightbeam_server_protocol_policies_handle {
	($protocol:path, $listener:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {
		compile_error!(
			"server!(protocol ..., policies: ...) requires tightbeam to be built with either the `tokio` or `std` feature"
		);
	};
}

#[cfg(feature = "tokio")]
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
#[macro_export]
macro_rules! __tightbeam_server_protocol_policies_session_handle {
	($protocol:path, $listener:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {
		compile_error!("server!(protocol ..., handle: move |frame, session| ...) requires the `tokio` feature");
	};
}

#[cfg(feature = "tokio")]
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
#[macro_export]
macro_rules! __tightbeam_server_protocol_policies_assertions_handle {
	($protocol:path, $listener:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $assertions:expr, ($param1:ident, $param2:ident, $handler_body:expr)) => {{
		compile_error!("server!(protocol ..., policies: ..., assertions: ...) requires the `tokio` feature");
	}};
}

#[cfg(not(any(feature = "tokio", feature = "std")))]
#[macro_export]
macro_rules! __tightbeam_server_protocol_policies_assertions_handle {
	($protocol:path, $listener:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $assertions:expr, ($param1:ident, $param2:ident, $handler_body:expr)) => {{
		compile_error!(
			"server!(protocol ..., policies: ..., assertions: ...) requires tightbeam to be built with either the `tokio` or `std` feature"
		);
	}};
}

#[cfg(feature = "tokio")]
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
#[macro_export]
macro_rules! __tightbeam_server_protocol_channels_handle {
	($protocol:path, $listener:expr, $error_tx:expr, $ok_tx:expr, $handler:expr) => {{
		let __listener = $listener;
		let _ = ($error_tx, $ok_tx);
		::std::thread::spawn(move || {
			$crate::server!(@sync_loop $protocol, __listener, $handler,)
		})
	}};
}

#[cfg(not(any(feature = "tokio", feature = "std")))]
#[macro_export]
macro_rules! __tightbeam_server_protocol_channels_handle {
	($protocol:path, $listener:expr, $error_tx:expr, $ok_tx:expr, $handler:expr) => {
		let _ = ($error_tx, $ok_tx);
		compile_error!(
			"server!(protocol ..., channels: ...) requires tightbeam to be built with either the `tokio` or `std` feature"
		);
	};
}

#[cfg(feature = "tokio")]
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
#[macro_export]
macro_rules! __tightbeam_server_protocol_channels_policies_handle {
	($protocol:path, $listener:expr, $error_tx:expr, $ok_tx:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {{
		let __listener = $listener;
		let _ = ($error_tx, $ok_tx);
		::std::thread::spawn(move || {
			$crate::server!(@sync_loop $protocol, __listener, $handler, $($policy_name: [ $( $policy_expr ),* ]),*)
		})
	}};
}

#[cfg(not(any(feature = "tokio", feature = "std")))]
#[macro_export]
macro_rules! __tightbeam_server_protocol_channels_policies_handle {
	($protocol:path, $listener:expr, $error_tx:expr, $ok_tx:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {
		let _ = ($error_tx, $ok_tx);
		compile_error!(
			"server!(protocol ..., channels: ...) requires tightbeam to be built with either the `tokio` or `std` feature"
		);
	};
}

#[cfg(feature = "tokio")]
#[macro_export]
macro_rules! __tightbeam_server_protocol_bind_policies_handle {
	($protocol:path, $addr:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {{
		let (listener, _) = <$protocol as $crate::transport::Protocol>::bind($addr).await?;
		let __server = <$protocol>::from(listener);
		$crate::macros::server::server_runtime::rt::spawn(async move {
			let __error_tx = $crate::macros::server::server_runtime::rt::empty_error_channel();
			let __ok_tx = $crate::macros::server::server_runtime::rt::empty_ok_channel();
			$crate::server!(@async_loop $protocol, __server, $handler, __error_tx, __ok_tx, $($policy_name: [ $( $policy_expr ),* ]),*)
		})
	}};
}

#[cfg(all(not(feature = "tokio"), feature = "std"))]
#[macro_export]
macro_rules! __tightbeam_server_protocol_bind_policies_handle {
	($protocol:path, $addr:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {{
		let (listener, _) = <$protocol as $crate::transport::Protocol>::bind($addr)?;
		let __server = <$protocol>::from(listener);
		::std::thread::spawn(move || {
			$crate::server!(@sync_loop $protocol, __server, $handler, $($policy_name: [ $( $policy_expr ),* ]),*)
		})
	}};
}

#[cfg(not(any(feature = "tokio", feature = "std")))]
#[macro_export]
macro_rules! __tightbeam_server_protocol_bind_policies_handle {
	($protocol:path, $addr:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {
		compile_error!("server!(protocol ..., policies: ...) with `bind` requires tightbeam to be built with either the `tokio` or `std` feature");
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
			"server!(protocol ..., service: ...) requires the pooled multiplexing feature set (`tokio`, `x509`, `transport-policy`, `transport-multiplex`, and a handshake protocol)"
		);
	};
}

/// Server-specific runtime extensions
///
/// Re-exports unified runtime and adds server-specific channel helpers.
#[cfg(any(feature = "tokio", feature = "std"))]
pub mod server_runtime {
	/// Runtime primitives (re-exported from unified runtime)
	pub mod rt {
		pub use crate::runtime::rt::*;
		/// Accept-loop concurrency primitive for the async `server!`
		/// expansion (macro plumbing, not part of the public surface).
		#[cfg(feature = "tokio")]
		pub use tokio::sync::Semaphore;

		use crate::transport::error::TransportError;

		/// Error notification channel sender type
		pub type ErrorSender = crate::runtime::rt::Sender<TransportError>;

		/// Success notification channel sender type
		pub type OkSender = crate::runtime::rt::Sender<()>;

		/// Returns None for optional error channel
		#[allow(dead_code)]
		pub fn empty_error_channel() -> Option<ErrorSender> {
			None
		}

		/// Returns None for optional success channel
		#[allow(dead_code)]
		pub fn empty_ok_channel() -> Option<OkSender> {
			None
		}
	}
}

#[macro_export]
macro_rules! server {
	(@apply_policy $transport:ident, $policy_name:ident, [ $( $policy_expr:expr ),* $(,)? ]) => {{
		$(
			$transport = $crate::server!(@apply_one_policy $transport, $policy_name, $policy_expr);
		)*
	}};

	// Accept-loop knob, not a transport policy: consumed by
	// `@extract_max_connections`, so application is a no-op here.
	(@apply_one_policy $transport:ident, max_connections, $policy_expr:expr) => {{
		$transport
	}};

	// Fold the policy list down to the accept-loop concurrency cap:
	// a `max_connections: [ n ]` entry wins, otherwise the default.
	(@extract_max_connections) => {
		$crate::constants::DEFAULT_MAX_SERVER_CONNECTIONS
	};
	(@extract_max_connections max_connections: [ $cap:expr ] $(, $rest_name:ident: [ $( $rest_expr:expr ),* $(,)? ])* $(,)?) => {
		$cap
	};
	(@extract_max_connections $other:ident: [ $( $expr:expr ),* $(,)? ] $(, $rest_name:ident: [ $( $rest_expr:expr ),* $(,)? ])* $(,)?) => {
		$crate::server!(@extract_max_connections $($rest_name: [ $( $rest_expr ),* ]),*)
	};

	// Generic fallback
	(@apply_one_policy $transport:ident, $other:ident, $policy_expr:expr) => {{
		$transport.$other($policy_expr)
	}};

	// Fire-and-forget loop: the sync path has no error channel, so transport
	// and handler failures terminate or skip the affected connection without
	// reporting. Use the tokio path when operators need error visibility.
	(@sync_loop_body $protocol:path, $listener:ident, $handler:ident, $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?) => {{
		loop {
			match $listener.accept() {
				Ok(mut __transport) => {
					$(
						$(
							__transport = $crate::server!(@apply_one_policy __transport, $policy_name, $policy_expr);
						)*
					)*
					let __handler_clone = ::std::sync::Arc::clone(&$handler);
					#[allow(unused_imports)]
					use $crate::transport::MessageCollector;
					$crate::macros::server::server_runtime::rt::spawn(move || {
						let mut __transport = __transport;
						// Session context filled after the first collected
						// frame: the lazy handshake is complete by then.
						let mut __session_slot = ::core::option::Option::None;
						loop {
							// Read message
							let (frame, status) = match $crate::macros::server::server_runtime::rt::block_on(__transport.collect_message()) {
								Ok(result) => result,
								Err(_err) => {
									break;
								}
							};

							// Unwrap Arc<Frame> to Frame for handler (clone only if Arc has multiple owners)
							let frame_owned = ::std::sync::Arc::try_unwrap(frame)
								.unwrap_or_else(|arc| (*arc).clone());
							let (status, response) = if status == $crate::policy::TransitStatus::Ok {
								let __session = ::core::clone::Clone::clone(
									__session_slot.get_or_insert_with(|| $crate::policy::SessionContext::capture(&__transport)),
								);
								match $crate::macros::server::server_runtime::rt::block_on((__handler_clone)(frame_owned, __session)) {
									Ok(opt) => (status, opt),
									// A handler failure answers a distinct
									// status so the peer can tell it apart
									// from an accepted empty reply. The sync
									// loop has no error channel to report to.
									Err(_err) => ($crate::policy::TransitStatus::Internal, ::core::option::Option::None),
								}
							} else {
								(status, ::core::option::Option::None)
							};

							// Send response
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
		// Concurrency cap (CWE-400): accepting pauses while that many
		// connection tasks are alive, so a connection flood queues in the
		// listener backlog instead of pinning unbounded tasks and file
		// descriptors. `policies: { max_connections: [ n ] }` overrides
		// the default.
		let __connection_permits = ::std::sync::Arc::new(
			$crate::macros::server::server_runtime::rt::Semaphore::new(
				$crate::server!(@extract_max_connections $($policy_name: [ $( $policy_expr ),* ]),*),
			),
		);
		loop {
			let ::core::result::Result::Ok(__connection_permit) =
				::std::sync::Arc::clone(&__connection_permits).acquire_owned().await
			else {
				// Unreachable in practice: the semaphore is never closed.
				break;
			};
			match $listener.accept().await {
				Ok((mut __transport, _addr)) => {
					$(
						$(
							__transport = $crate::server!(@apply_one_policy __transport, $policy_name, $policy_expr);
						)*
					)*
					let __service_clone = ::std::sync::Arc::clone(&$handler);
					let __error_channel = $error_tx.clone();
					let __ok_channel = $ok_tx.clone();
					$crate::macros::server::server_runtime::rt::spawn(async move {
						// The permit lives as long as the connection task,
						// releasing its accept slot on any exit path.
						let _connection_permit = __connection_permit;
						$serve(__transport, __service_clone, __error_channel, __ok_channel).await;
					});
				}
				Err(e) => {
					if let Some(tx) = $error_tx.as_mut() {
						let _ = tx.send(e.into()).await;
					}

					break;
				}
			}
		}
	}};

	(@sync_loop $protocol:path, $listener:expr, $handler:expr, $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?) => {{
		let mut __listener = $listener;
		let __handler = $crate::macros::server::into_shared_handler($handler);

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
		let __handler = $crate::macros::server::into_shared_handler($handler);
		let mut __error_tx = $error_tx;
		let mut __ok_tx = $ok_tx;

		$crate::server!(@async_loop_body $protocol, __listener, __handler, $crate::macros::server::serve_connection, __error_tx, __ok_tx, $($policy_name: [ $( $policy_expr ),* ]),*);
	}};

	(@async_session_loop $protocol:path, $listener:expr, $handler:expr, $error_tx:expr, $ok_tx:expr, $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?) => {{
		let mut __listener = $listener;
		let __handler = $crate::macros::server::into_shared_session_handler($handler);
		let mut __error_tx = $error_tx;
		let mut __ok_tx = $ok_tx;

		$crate::server!(@async_loop_body $protocol, __listener, __handler, $crate::macros::server::serve_connection, __error_tx, __ok_tx, $($policy_name: [ $( $policy_expr ),* ]),*);
	}};

	// Service form: the caller supplies a full `MuxService`, so streaming
	// and duplex interactions dispatch to it instead of being refused.
	(@async_service_loop $protocol:path, $listener:expr, $service:expr, $error_tx:expr, $ok_tx:expr, $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?) => {{
		let mut __listener = $listener;
		let __service = ::std::sync::Arc::new($service);
		let mut __error_tx = $error_tx;
		let mut __ok_tx = $ok_tx;

		$crate::server!(@async_loop_body $protocol, __listener, __service, $crate::macros::server::serve_connection_service, __error_tx, __ok_tx, $($policy_name: [ $( $policy_expr ),* ]),*);
	}};

	($protocol:path: $listener:expr, handle: $handler:expr) => {{
		$crate::__tb_if_std!({
			let __listener = $listener;
			$crate::server!(@sync_loop $protocol, __listener, $handler,)
		})
	}};

	($protocol:path: bind $addr:expr, handle: $handler:expr) => {{
		$crate::__tb_if_std!({
			let (listener, _) = <$protocol as $crate::transport::Protocol>::bind($addr)?;
			let __server = <$protocol>::from(listener);
			$crate::server!(@sync_loop $protocol, __server, $handler,)
		})
	}};

	($protocol:path: $listener:expr, policies: { $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)? }, handle: $handler:expr) => {{
		$crate::__tb_if_std!({
			let __listener = $listener;
			$crate::server!(@sync_loop $protocol, __listener, $handler, $($policy_name: [ $( $policy_expr ),* ]),*);
		})
	}};

	($protocol:path: bind $addr:expr, policies: { $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)? }, handle: $handler:expr) => {{
		$crate::__tb_if_std!({
			let (listener, _) = <$protocol as $crate::transport::Protocol>::bind($addr)?;
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

	(protocol $protocol:path: bind $addr:expr, handle: $handler:expr) => {{
		$crate::__tightbeam_server_protocol_bind_handle!($protocol, $addr, $handler)
	}};

	// Session-aware handler with policies; must match ahead of the
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

	// Service forms: `service:` takes a `MuxService` value, so one server
	// answers unary, streaming, and duplex interactions without separate
	// declarations. Requires the pooled multiplexing feature set.
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

	(protocol $protocol:path: bind $addr:expr, policies: { $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)? }, handle: $handler:expr) => {{
		$crate::__tightbeam_server_protocol_bind_policies_handle!($protocol, $addr, [ $($policy_name: [ $( $policy_expr ),* ]),* ], $handler)
	}};

	(async $($rest:tt)*) => {
		$crate::server!(protocol $($rest)*)
	};
}
