//! The transport fixtures that the transport suite alone calls: loopback
//! listeners and clients, split handshakes, the HPKE pair and the key purposes
//! of the materials, task joins, signals, and the frames and offers of a
//! multiplexed exchange.

use core::time::Duration;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use tightbeam::crypto::profiles::SecurityProfileDesc;
use tightbeam::crypto::x509::KeyPurposes;
use tightbeam::der::asn1::ObjectIdentifier;
use tightbeam::testing::{TestCertificate, TestFrame};
use tightbeam::transport::handshake::negotiation::{SecurityOffer, TransportOffer};
use tightbeam::transport::handshake::{Client, Handshake, HandshakeProvider, Hpke, Server};
use tightbeam::transport::tcp::r#async::{SplitTransport, TcpTransport, TokioListener, TokioStream};
use tightbeam::transport::{EncryptedMessageIO, TransportEncryptionConfig, TransportLimits};
use tightbeam::x509::Certificate;
use tightbeam::{Frame, TightBeamError};

#[cfg(feature = "transport-multiplex")]
use core::future::IntoFuture;
#[cfg(feature = "transport-multiplex")]
use tokio::sync::Notify;

use crate::common::security::{
	expectation_failure, hpke_client_config, pinning_validator, ClientMaterials, ServerMaterials,
};
use crate::common::transport::{accept_handshaken, bind_on_loopback, connect_mutual_client_under, pinned_client};

#[cfg(feature = "transport-multiplex")]
use crate::common::poll::within_hang_guard;
#[cfg(feature = "transport-cms")]
use crate::common::transport::TestCmsServerExt;

/// Awaits `work`, and panics with `expectation` when [`HANG_GUARD`] passes
/// first, so a stalled server ends its scenario at the guard. The answer is
/// `Ok`, the form of the scenarios that call it.
///
/// [`HANG_GUARD`]: crate::common::poll::HANG_GUARD
#[cfg(feature = "transport-multiplex")]
pub async fn await_within_deadline<F: IntoFuture>(
	work: F,
	expectation: &'static str,
) -> Result<F::Output, TightBeamError> {
	let finished = within_hang_guard(work, expectation).await;
	Ok(finished)
}

/// A signal that a handler or a server task raises, which a test awaits only
/// within [`HANG_GUARD`].
///
/// [`HANG_GUARD`]: crate::common::poll::HANG_GUARD
#[cfg(feature = "transport-multiplex")]
#[derive(Default)]
pub struct HandlerSignal(Notify);

#[cfg(feature = "transport-multiplex")]
impl HandlerSignal {
	/// Raises the signal for one wait. A raise before the wait stores a
	/// permit, so the wait that follows returns at once.
	pub fn raise(&self) {
		self.0.notify_one();
	}

	/// Awaits the raise, and panics with `expectation` when the guard passes
	/// first. The answer is `Ok`, the form of the scenarios that call it.
	pub async fn wait(&self, expectation: &'static str) -> Result<(), TightBeamError> {
		await_within_deadline(self.0.notified(), expectation).await
	}

	/// Awaits the raise, and panics when the guard passes first.
	pub async fn raised(&self) {
		within_hang_guard(self.0.notified(), "a task raises the signal within the hang guard").await;
	}
}

/// A small labeled frame for multiplexed exchanges.
pub fn mux_frame(label: impl AsRef<str>) -> Frame {
	let label = label.as_ref();
	TestFrame::v0(Some(label), None)
}

/// A multiplexing offer that advertises `cap` peer-initiated streams.
pub fn mux_offer(cap: u32) -> TransportOffer {
	TransportOffer::mux(cap)
}

/// The value that `task` returns in its `Ok`, or its error as a
/// [`TightBeamError`]. A panicked task fails with `panic_msg`.
pub async fn await_ok<T, E>(task: JoinHandle<Result<T, E>>, panic_msg: &'static str) -> Result<T, TightBeamError>
where
	E: Into<TightBeamError>,
{
	let joined = task.await.map_err(|_| expectation_failure(panic_msg))?;
	let value = joined.map_err(Into::into)?;
	Ok(value)
}

/// The output of `task`. A panicked task fails with `panic_msg`.
pub async fn join_task<T>(task: JoinHandle<T>, panic_msg: &'static str) -> Result<T, TightBeamError> {
	let value = task.await.map_err(|_| expectation_failure(panic_msg))?;
	Ok(value)
}

/// A connected pair of TCP streams on a free loopback port: the client end,
/// then the end the listener accepts.
pub async fn loopback_streams() -> (TcpStream, TcpStream) {
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("a loopback port binds");
	let addr = listener.local_addr().expect("a bound listener has an address");

	let client = TcpStream::connect(addr).await.expect("the client reaches the listener");
	let (server, _) = listener.accept().await.expect("the listener accepts the client");
	(client, server)
}

/// Binds a listener on a free loopback port that presents the server identity
/// of `materials`, beside its address.
pub async fn bind_encrypted_listener(
	materials: &ServerMaterials,
) -> Result<(TokioListener, SocketAddr), TightBeamError> {
	let config = TransportEncryptionConfig::new(materials.identity());
	bind_on_loopback(config).await
}

/// Binds a listener as [`bind_encrypted_listener`] does, whose handshakes time
/// out after `handshake_timeout`.
pub async fn bind_encrypted_listener_with_timeout(
	materials: &ServerMaterials,
	handshake_timeout: Duration,
) -> Result<(TokioListener, SocketAddr), TightBeamError> {
	let limits = TransportLimits { handshake_timeout, ..TransportLimits::default() };
	let config = TransportEncryptionConfig::new(materials.identity()).with_limits(limits)?;
	bind_on_loopback(config).await
}

impl ServerMaterials {
	/// Binds a listener that presents the CMS server of these materials, its
	/// signing identity paired with its key-agreement identity, and pins
	/// `client_certificate` as its one client.
	#[cfg(feature = "transport-cms")]
	pub async fn bind_cms_mutual_listener(
		&self,
		client_certificate: &Certificate,
	) -> Result<(TokioListener, SocketAddr), TightBeamError> {
		let validators = vec![pinning_validator(client_certificate)];
		let config = self.cms.encryption_config();
		bind_on_loopback(config.with_client_validators(validators)).await
	}

	/// These materials with a certificate whose `extendedKeyUsage` names
	/// `purpose` alone.
	pub fn with_key_purpose(mut self, purpose: ObjectIdentifier) -> Self {
		let certificate = self.certificate.as_ref().to_owned();
		self.certificate = Arc::new(TestCertificate::with_key_purposes(certificate, [purpose]));
		self
	}

	/// An HPKE client and server over these materials, ready to drive by
	/// hand.
	///
	/// - The client pins the server certificate of these materials and offers `client_profiles`.
	/// - The server presents these materials and runs `server_profiles` in preference order.
	pub fn hpke_pair<P: HandshakeProvider>(
		&self,
		client_profiles: impl IntoIterator<Item = SecurityProfileDesc>,
		server_profiles: impl IntoIterator<Item = SecurityProfileDesc>,
	) -> (Handshake<Client, Hpke, P>, Handshake<Server, Hpke, P>) {
		let validator = pinning_validator(&self.certificate);
		let mut client = hpke_client_config::<P>(validator);
		client.security_offer = Some(SecurityOffer::new(client_profiles));

		let server = self.hpke_server_config::<P>(server_profiles);
		(Handshake::client(client), Handshake::server(server))
	}
}

impl ClientMaterials {
	/// These materials with a certificate whose `extendedKeyUsage` names
	/// `purpose` alone.
	pub fn with_key_purpose(mut self, purpose: ObjectIdentifier) -> Self {
		let certificate = self.certificate.as_ref().to_owned();
		self.certificate = Arc::new(TestCertificate::with_key_purposes(certificate, [purpose]));
		self
	}
}

/// Connects a client that presents `client`, pins `server_certificate`, and
/// admits each role under the house purposes.
pub async fn connect_mutual_client(
	addr: SocketAddr,
	server_certificate: &Certificate,
	client: &ClientMaterials,
) -> Result<TcpTransport<TokioStream>, TightBeamError> {
	connect_mutual_client_under(addr, server_certificate, client, KeyPurposes::HOUSE).await
}

/// Accepts one connection on `listener`, serves its handshake, and splits the
/// encrypted transport into its halves.
pub async fn accept_handshaken_split(listener: TokioListener) -> Result<SplitTransport<TokioStream>, TightBeamError> {
	let transport = accept_handshaken(listener, |transport| transport).await?;
	let halves = transport.into_split()?;
	Ok(halves)
}

/// Connects a client to `addr` that pins `server_certificate`, runs its
/// handshake, and splits the encrypted transport into its halves.
pub async fn connect_handshaken_split(
	addr: SocketAddr,
	server_certificate: &Certificate,
) -> Result<SplitTransport<TokioStream>, TightBeamError> {
	let mut client = connect_pinned_client(addr, server_certificate).await?;
	client.perform_client_handshake().await?;

	let halves = client.into_split()?;
	Ok(halves)
}

/// Connects an anonymous client to `addr` that pins `server_certificate`.
pub async fn connect_pinned_client(
	addr: SocketAddr,
	server_certificate: &Certificate,
) -> Result<TcpTransport<TokioStream>, TightBeamError> {
	let builder = pinned_client(server_certificate);
	let stream = TcpStream::connect(addr).await?;

	let adopted = builder.adopt(TokioStream::from(stream))?;
	Ok(adopted.into_transport())
}
