use core::any::TypeId;
use core::marker::PhantomData;
use std::collections::HashMap;
use std::sync::Arc;

use crate::cms::signed_data::SignerIdentifier;
use crate::colony::hive::HiveContext;
use crate::colony::servlet::runtime;
use crate::colony::servlet::tracking::SharedGauge;
use crate::colony::servlet::{UtilizationGauge, WorkerBox};
use crate::colony::worker::Worker;
use crate::core::{Inflator, Message};
use crate::crypto::aead::Decryptor;
use crate::policy::GatePolicy;
use crate::transport::handshake::negotiation::TransportOffer;
use crate::transport::multiplex::IntoMuxOffer;
use crate::transport::{EncryptedProtocol, Protocol};
use crate::utils::time::{Clock, SystemClock};
use crate::TightBeamError;

use crate::crypto::key::SigningKeyProvider;
use crate::crypto::profiles::{CryptoProvider, DefaultCryptoProvider};
use crate::crypto::sign::SigningIdentity;
use crate::crypto::x509::policy::CertificateValidation;
use crate::crypto::x509::CertificateSpec;
use crate::transport::TransportEncryptionConfig;

/// How a servlet accepts connections.
///
/// The handshake binds a multiplexing advertisement into its transcript, so
/// only the encrypted arm carries one. A cleartext servlet that advertises
/// multiplexing is unrepresentable.
pub(crate) enum ServletAccept<C: CryptoProvider> {
	/// The servlet accepts cleartext connections without multiplexing.
	Cleartext,
	/// The servlet presents a certificate and may advertise multiplexing.
	Encrypted {
		/// The certificate, keys, and peer checks for the handshake.
		encryption: Box<TransportEncryptionConfig<C>>,
		/// The multiplexing offer advertised to accepted connections.
		mux_offer: Option<Arc<TransportOffer>>,
	},
}

impl<C: CryptoProvider> ServletAccept<C> {
	/// The [`SignerIdentifier`] that names the certificate this servlet
	/// presents in its handshake (RFC 5652 §5.3), or [`None`] in the clear.
	pub(crate) fn signer(&self) -> Option<&SignerIdentifier> {
		match self {
			Self::Cleartext => None,
			Self::Encrypted { encryption, .. } => Some(encryption.identity.signing().signer_identifier()),
		}
	}

	/// Bind a listener of `P` on `addr` the way this servlet accepts: under
	/// its transport encryption, or in the clear.
	///
	/// # Errors
	///
	/// - `P::Error` -- the protocol fails to bind the listener.
	pub(crate) async fn bind<P>(self, addr: P::Address) -> Result<(P::Listener, P::Address), P::Error>
	where
		P: EncryptedProtocol<CryptoProvider = C>,
	{
		match self {
			Self::Cleartext => P::bind_cleartext(addr).await,
			Self::Encrypted { encryption, .. } => P::bind_with(addr, *encryption).await,
		}
	}
}

/// Servlet bind and handler configuration, transport encryption included.
///
/// `Env` is the application configuration the handlers read. It is a type
/// parameter, not an erased value, so the config a servlet starts with and the
/// env its handlers name are one type by construction.
pub struct ServletConfig<P, M, C: CryptoProvider = DefaultCryptoProvider, Env = ()>
where
	P: Protocol,
	M: Message,
{
	pub(crate) _protocol: PhantomData<P>,
	pub(crate) _message: PhantomData<M>,
	pub(crate) _crypto: PhantomData<C>,
	pub(crate) accept: ServletAccept<C>,
	pub(crate) servlet_config: Arc<Env>,
	pub(crate) hive_context: Option<Arc<dyn HiveContext>>,
	pub(crate) workers: HashMap<TypeId, Box<dyn WorkerBox>>,
	pub(crate) collector_gates: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	pub(crate) message_decryptor: Option<Arc<dyn Decryptor + Send + Sync>>,
	pub(crate) message_inflator: Option<Arc<dyn Inflator + Send + Sync>>,
	pub(crate) utilization: Option<Box<dyn UtilizationGauge>>,
	pub(crate) clock: Arc<dyn Clock>,
}

pub(crate) mod sealed {
	use super::{CryptoProvider, Message, Protocol, ServletConfig, ServletConfigBuilder};

	/// Closes [`AcceptState`](super::AcceptState) to the two states this
	/// module defines, so no outside type can claim a third, and keeps the
	/// accept shape itself off the public surface.
	pub trait Sealed<C: CryptoProvider>: Sized {
		/// Finishes `builder`, which holds this state, into a configuration
		/// that accepts the way this state names.
		fn finish<P, M, Env>(builder: ServletConfigBuilder<P, M, C, Env, Self>) -> ServletConfig<P, M, C, Env>
		where
			P: Protocol,
			M: Message;
	}
}

/// One of the two accept states a [`ServletConfigBuilder`] builds from:
/// [`Cleartext`] and [`WithCertificate`].
///
/// The state carries the accept material, so the builder holds the
/// certificate and the mux offer in one place, which
/// [`ServletConfigBuilder::build`] reads.
pub trait AcceptState<C: CryptoProvider>: sealed::Sealed<C> {}

/// The state of a fresh builder, before it names a certificate or cleartext.
/// [`ServletConfigBuilder::build`] exists on the two [`AcceptState`] types
/// alone, so the compiler refuses a configuration that names neither.
#[derive(Default)]
pub struct NoAcceptState;

/// The builder state of a servlet that serves in the clear, which
/// [`ServletConfigBuilder::allow_cleartext`] names.
/// [`ServletConfigBuilder::with_mux_offer`] exists in [`WithCertificate`]
/// alone, where a handshake binds the offer.
pub struct Cleartext;

/// The builder state with a certificate set, in which the servlet may also
/// advertise multiplexing.
pub struct WithCertificate<C: CryptoProvider> {
	encryption: TransportEncryptionConfig<C>,
	mux_offer: Option<Arc<TransportOffer>>,
}

impl<C: CryptoProvider> sealed::Sealed<C> for Cleartext {
	fn finish<P, M, Env>(builder: ServletConfigBuilder<P, M, C, Env, Self>) -> ServletConfig<P, M, C, Env>
	where
		P: Protocol,
		M: Message,
	{
		builder.into_config(|Self| ServletAccept::Cleartext)
	}
}

impl<C: CryptoProvider> sealed::Sealed<C> for WithCertificate<C> {
	fn finish<P, M, Env>(builder: ServletConfigBuilder<P, M, C, Env, Self>) -> ServletConfig<P, M, C, Env>
	where
		P: Protocol,
		M: Message,
	{
		builder.into_config(|Self { encryption, mux_offer }| ServletAccept::Encrypted {
			encryption: Box::new(encryption),
			mux_offer,
		})
	}
}

impl<C: CryptoProvider> AcceptState<C> for Cleartext {}
impl<C: CryptoProvider> AcceptState<C> for WithCertificate<C> {}

/// Builder for [`ServletConfig`].
///
/// `A` is the accept state, which holds the accept material. A fresh builder
/// is in [`NoAcceptState`], and one of three calls moves it to a state that
/// builds:
///
/// - [`ServletConfigBuilder::with_certificate`] or
///   [`ServletConfigBuilder::with_identity`] moves it to [`WithCertificate`],
///   where [`ServletConfigBuilder::with_mux_offer`] exists.
/// - [`ServletConfigBuilder::allow_cleartext`] moves it to [`Cleartext`].
///
/// A servlet serves in the clear only where its configuration says so
/// (CWE-319).
pub struct ServletConfigBuilder<P, M, C: CryptoProvider = DefaultCryptoProvider, Env = (), A = NoAcceptState>
where
	P: Protocol,
	M: Message,
{
	accept: A,
	servlet_config: Arc<Env>,
	hive_context: Option<Arc<dyn HiveContext>>,
	workers: HashMap<TypeId, Box<dyn WorkerBox>>,
	collector_gates: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	message_decryptor: Option<Arc<dyn Decryptor + Send + Sync>>,
	message_inflator: Option<Arc<dyn Inflator + Send + Sync>>,
	utilization: Option<Box<dyn UtilizationGauge>>,
	clock: Arc<dyn Clock>,
	_phantom: PhantomData<(P, M, C)>,
}

impl<P, M, C, Env> crate::colony::servlet::ServletConf for ServletConfig<P, M, C, Env>
where
	P: Protocol,
	M: Message,
	C: CryptoProvider,
{
	type Env = Env;
}

impl<P, M, C, Env> ServletConfig<P, M, C, Env>
where
	P: Protocol,
	M: Message,
	C: CryptoProvider + Send + Sync + 'static,
{
	/// Starts a [`ServletConfigBuilder`] over the unit env `()`, which
	/// [`ServletConfigBuilder::with_config`] replaces.
	pub fn builder() -> ServletConfigBuilder<P, M, C, (), NoAcceptState> {
		ServletConfigBuilder::default()
	}

	/// A configuration in the accept state
	/// [`ServletConfigBuilder::allow_cleartext`] names, over the default env
	/// and the empty defaults of a fresh builder.
	///
	/// [`Self::builder`] takes any other env.
	pub fn cleartext() -> Self
	where
		Env: Default,
	{
		let env = Arc::new(Env::default());
		let builder = ServletConfigBuilder::<P, M, C>::default().with_config(env);
		let cleartext = builder.allow_cleartext();
		cleartext.build()
	}

	/// Returns the worker of type `W` that this config registers, if it
	/// registers one.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::servlet::ServletConfig;
	/// use tightbeam::testing::TestMessage;
	/// use tightbeam::transport::tcp::r#async::TokioListener;
	/// use tightbeam::worker;
	///
	/// worker! {
	///     name: Echo<TestMessage, usize>,
	///     handle: |message, _trace| async move { message.content.len() }
	/// }
	///
	/// let builder = ServletConfig::<TokioListener, TestMessage>::builder().with_worker(Echo::new(()));
	/// let config = builder.allow_cleartext().build();
	///
	/// assert!(config.worker::<Echo>().is_some());
	/// ```
	pub fn worker<W: 'static>(&self) -> Option<&W> {
		let key = TypeId::of::<W>();
		self.workers.get(&key)?.downcast_ref()
	}

	/// Returns the transport encryption config when this servlet presents a
	/// certificate.
	pub fn to_encryption_config_ref(&self) -> Option<&TransportEncryptionConfig<C>> {
		match &self.accept {
			ServletAccept::Cleartext => None,
			ServletAccept::Encrypted { encryption, .. } => Some(encryption),
		}
	}

	/// Returns the multiplexing advertisement applied to accepted connections.
	/// It is always [`None`] on a cleartext servlet, which has no handshake to
	/// bind an offer into.
	pub fn mux_offer(&self) -> Option<Arc<TransportOffer>> {
		match &self.accept {
			ServletAccept::Cleartext => None,
			ServletAccept::Encrypted { mux_offer, .. } => mux_offer.as_ref().map(Arc::clone),
		}
	}

	/// Returns the application env config this servlet serves.
	#[must_use]
	pub fn env_config(&self) -> &Arc<Env> {
		&self.servlet_config
	}

	/// Takes ownership of the registered workers for servlet startup, one of
	/// each type.
	///
	/// [`ServletContext::new`] takes them and keys each by its type.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::colony::servlet::{ServletConfig, ServletContext};
	/// use tightbeam::testing::TestMessage;
	/// use tightbeam::trace::TraceCollector;
	/// use tightbeam::transport::tcp::r#async::TokioListener;
	/// use tightbeam::worker;
	///
	/// worker! {
	///     name: Echo<TestMessage, usize>,
	///     handle: |message, _trace| async move { message.content.len() }
	/// }
	///
	/// let builder = ServletConfig::<TokioListener, TestMessage>::builder().with_worker(Echo::new(()));
	/// let workers = builder.allow_cleartext().build().to_workers();
	/// let ctx: ServletContext = ServletContext::new(Arc::new(TraceCollector::new()), Arc::new(()), workers, None);
	///
	/// assert!(ctx.worker::<Echo>().is_some());
	/// ```
	///
	/// [`ServletContext::new`]: crate::colony::servlet::ServletContext::new
	pub fn to_workers(self) -> impl Iterator<Item = Box<dyn WorkerBox>> {
		self.workers.into_values()
	}

	/// Takes ownership of the collector gates for the accept loop.
	pub fn to_collector_gates(self) -> Vec<Arc<dyn GatePolicy + Send + Sync>> {
		self.collector_gates
	}

	/// Borrows the collector gates.
	pub fn collector_gates_ref(&self) -> &[Arc<dyn GatePolicy + Send + Sync>] {
		&self.collector_gates
	}

	/// Returns the intra-hive communication handle, when one is set.
	pub fn hive_context(&self) -> Option<&Arc<dyn HiveContext>> {
		self.hive_context.as_ref()
	}

	/// Returns a clone of the frame-body decryptor, when one is configured.
	pub fn to_message_decryptor(&self) -> Option<Arc<dyn Decryptor + Send + Sync>> {
		self.message_decryptor.as_ref().map(Arc::clone)
	}

	/// Returns a clone of the frame-body inflator, when one is configured.
	pub fn to_message_inflator(&self) -> Option<Arc<dyn Inflator + Send + Sync>> {
		self.message_inflator.as_ref().map(Arc::clone)
	}

	/// Splits the config into the accept state, which binds the listener, and
	/// the parts the accept loop keeps, the signer the listener presents
	/// among them.
	///
	/// The split happens once, so the encryption and the offer it was paired
	/// with always leave together.
	pub(crate) fn into_bind_parts(self) -> (ServletAccept<C>, runtime::ServletRuntimeParts<Env>) {
		let mux_offer = self.mux_offer();
		let signer = self.accept.signer().cloned();
		let parts = runtime::ServletRuntimeParts {
			signer,
			env_config: self.servlet_config,
			collector_gates: self.collector_gates,
			mux_offer,
			hive_context: self.hive_context,
			message_decryptor: self.message_decryptor,
			message_inflator: self.message_inflator,
			workers: self.workers,
			utilization: self.utilization,
			clock: self.clock,
		};

		(self.accept, parts)
	}
}

/// A fresh builder serves the unit env and is in [`NoAcceptState`]. Four calls
/// leave these defaults:
///
/// - [`ServletConfigBuilder::with_config`] for the env.
/// - [`ServletConfigBuilder::with_certificate`],
///   [`ServletConfigBuilder::with_identity`], or
///   [`ServletConfigBuilder::allow_cleartext`] for the accept state.
impl<P, M, C> Default for ServletConfigBuilder<P, M, C, (), NoAcceptState>
where
	P: Protocol,
	M: Message,
	C: CryptoProvider + Send + Sync + 'static,
{
	fn default() -> Self {
		Self {
			accept: NoAcceptState,
			servlet_config: Arc::new(()),
			hive_context: None,
			workers: HashMap::new(),
			collector_gates: Vec::new(),
			message_decryptor: None,
			message_inflator: None,
			utilization: None,
			clock: Arc::new(SystemClock),
			_phantom: PhantomData,
		}
	}
}

impl<P, M, C, Env, A> ServletConfigBuilder<P, M, C, Env, A>
where
	P: Protocol,
	M: Message,
	C: CryptoProvider + Send + Sync + 'static,
{
	/// Sets the application env config, which names the servlet's env type, so
	/// the compiler checks the handlers that read it against the config.
	#[must_use]
	pub fn with_config<NewEnv>(self, config: Arc<NewEnv>) -> ServletConfigBuilder<P, M, C, NewEnv, A> {
		ServletConfigBuilder {
			accept: self.accept,
			servlet_config: config,
			hive_context: self.hive_context,
			workers: self.workers,
			collector_gates: self.collector_gates,
			message_decryptor: self.message_decryptor,
			message_inflator: self.message_inflator,
			utilization: self.utilization,
			clock: self.clock,
			_phantom: PhantomData,
		}
	}

	/// Sets the clock the servlet's accept loop paces its retries on,
	/// [`SystemClock`] by default.
	#[must_use]
	pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
		self.clock = clock;
		self
	}

	/// Registers `worker` under its type, so a handler reaches it as
	/// `ctx.relay::<W>(..)`. A second worker of one type replaces the first.
	pub fn with_worker<W>(mut self, worker: W) -> Self
	where
		W: Worker + 'static,
	{
		let worker: Box<dyn WorkerBox> = Box::new(worker);
		self.workers.insert(worker.type_key(), worker);
		self
	}

	/// Appends a collector gate policy.
	pub fn with_collector_gate<G>(mut self, gate: G) -> Self
	where
		G: GatePolicy + Send + Sync + 'static,
	{
		self.collector_gates.push(Arc::new(gate));
		self
	}

	/// Attaches the hive context for intra-hive calls.
	#[must_use]
	pub fn with_hive_context(mut self, ctx: Arc<dyn HiveContext>) -> Self {
		self.hive_context = Some(ctx);
		self
	}

	/// Enables typed delivery of encrypted frame bodies.
	pub fn with_message_decryptor<D>(mut self, decryptor: D) -> Self
	where
		D: Decryptor + Send + Sync + 'static,
	{
		self.message_decryptor = Some(Arc::new(decryptor));
		self
	}

	/// Enables typed delivery of compressed frame bodies.
	pub fn with_message_inflator<I>(mut self, inflator: I) -> Self
	where
		I: Inflator + Send + Sync + 'static,
	{
		self.message_inflator = Some(Arc::new(inflator));
		self
	}

	/// Installs `gauge` as the load the hive reads for this servlet when it
	/// scales.
	///
	/// The servlet's handlers keep their own handle on the gauge to record
	/// into, so the gauge arrives shared. `G` may be the erased
	/// `dyn UtilizationGauge`.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::colony::servlet::{ServletConfig, UtilizationReporter};
	/// use tightbeam::der::Sequence;
	/// use tightbeam::transport::tcp::r#async::TokioListener;
	/// use tightbeam::Beamable;
	///
	/// /// The request the servlet serves.
	/// #[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
	/// struct Ping {
	///     n: u64,
	/// }
	///
	/// let reporter = Arc::new(UtilizationReporter::default());
	/// let builder = ServletConfig::<TokioListener, Ping>::builder().with_utilization(Arc::clone(&reporter));
	/// let config: ServletConfig<TokioListener, Ping> = builder.allow_cleartext().build();
	/// # drop(config);
	/// ```
	#[must_use]
	pub fn with_utilization<G>(mut self, gauge: Arc<G>) -> Self
	where
		G: UtilizationGauge + ?Sized + 'static,
	{
		self.utilization = Some(Box::new(SharedGauge(gauge)));
		self
	}

	/// This builder in the accept state `accept`, with everything else it
	/// holds.
	fn with_accept<B>(self, accept: B) -> ServletConfigBuilder<P, M, C, Env, B> {
		ServletConfigBuilder {
			accept,
			servlet_config: self.servlet_config,
			hive_context: self.hive_context,
			workers: self.workers,
			collector_gates: self.collector_gates,
			message_decryptor: self.message_decryptor,
			message_inflator: self.message_inflator,
			utilization: self.utilization,
			clock: self.clock,
			_phantom: PhantomData,
		}
	}

	/// Finishes the builder into a [`ServletConfig`].
	///
	/// The accept state carries the certificate and the offer, so the type of
	/// that state picks the accept shape this builds.
	pub fn build(self) -> ServletConfig<P, M, C, Env>
	where
		A: AcceptState<C>,
	{
		A::finish(self)
	}
}

impl<P, M, C, Env, A> ServletConfigBuilder<P, M, C, Env, A>
where
	P: Protocol,
	M: Message,
	C: CryptoProvider,
{
	/// The configuration this builder holds, which accepts by the shape that
	/// `accept` makes of the builder's state.
	fn into_config(self, accept: impl FnOnce(A) -> ServletAccept<C>) -> ServletConfig<P, M, C, Env> {
		ServletConfig {
			_protocol: PhantomData,
			_message: PhantomData,
			_crypto: PhantomData,
			accept: accept(self.accept),
			servlet_config: self.servlet_config,
			hive_context: self.hive_context,
			workers: self.workers,
			collector_gates: self.collector_gates,
			message_decryptor: self.message_decryptor,
			message_inflator: self.message_inflator,
			utilization: self.utilization,
			clock: self.clock,
		}
	}
}

impl<P, M, C, Env> ServletConfigBuilder<P, M, C, Env, NoAcceptState>
where
	P: Protocol,
	M: Message,
	C: CryptoProvider + Send + Sync + 'static,
{
	/// Names cleartext as the intent of this servlet.
	///
	/// - Its frames travel in the clear, and it accepts every client that connects.
	/// - It suits a loopback fixture or a link a lower layer already secures.
	/// - It names no signer, so its hive gives it no route ([`ServletBox::signer`]).
	///
	/// `build` exists after this call, after [`Self::with_certificate`], or
	/// after [`Self::with_identity`].
	///
	/// [`ServletBox::signer`]: crate::colony::hive::ServletBox::signer
	#[must_use]
	pub fn allow_cleartext(self) -> ServletConfigBuilder<P, M, C, Env, Cleartext> {
		self.with_accept(Cleartext)
	}

	/// Enables encrypted transport with the given server certificate, under
	/// the house provider.
	///
	/// - A non-empty `validators` turns on mutual authentication, and every
	///   validator must accept the client certificate.
	/// - An empty `validators` turns off client authentication.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the certificate or key does not decode, as
	///   [`SigningIdentity::from_spec`] reports it, or the key differs from
	///   the certificate's public key.
	pub fn with_certificate(
		self,
		cert: CertificateSpec,
		key: Arc<dyn SigningKeyProvider>,
		validators: impl IntoIterator<Item = Arc<dyn CertificateValidation>>,
	) -> Result<ServletConfigBuilder<P, M, C, Env, WithCertificate<C>>, TightBeamError> {
		let identity = SigningIdentity::from_spec(cert, key)?;
		let with_certificate = self.with_identity(identity, validators);

		Ok(with_certificate)
	}

	/// Enables encrypted transport under `identity`, whose key signs under the
	/// [`SigningProvider`](crate::crypto::profiles::SigningProvider) it was
	/// paired under. `validators` acts as in [`Self::with_certificate`].
	#[must_use]
	pub fn with_identity(
		self,
		identity: SigningIdentity,
		validators: impl IntoIterator<Item = Arc<dyn CertificateValidation>>,
	) -> ServletConfigBuilder<P, M, C, Env, WithCertificate<C>> {
		let encryption = TransportEncryptionConfig::new(identity).with_client_validators(validators);

		self.with_accept(WithCertificate { encryption, mux_offer: None })
	}
}

impl<P, M, C, Env> ServletConfigBuilder<P, M, C, Env, WithCertificate<C>>
where
	P: Protocol,
	M: Message,
	C: CryptoProvider + Send + Sync + 'static,
{
	/// Advertises multiplexing on accepted connections.
	///
	/// The handshake binds the offer into its transcript, so this exists only
	/// in the [`WithCertificate`] state, beside the certificate it binds to.
	#[must_use]
	pub fn with_mux_offer(mut self, offer: impl IntoMuxOffer) -> Self {
		self.accept.mux_offer = offer.into_mux_offer();
		self
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::der::Sequence;
	use crate::transport::tcp::r#async::TokioListener;
	use crate::Beamable;

	#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
	struct Ping {
		content: String,
	}

	/// The move into an accept state keeps what the builder holds, so a clock
	/// set ahead of `allow_cleartext` is the clock the servlet paces on.
	#[test]
	fn the_cleartext_state_keeps_the_clock_of_the_builder() {
		let clock: Arc<dyn Clock> = Arc::new(SystemClock);
		let builder = ServletConfig::<TokioListener, Ping>::builder().with_clock(Arc::clone(&clock));

		let config: ServletConfig<TokioListener, Ping> = builder.allow_cleartext().build();
		assert!(Arc::ptr_eq(&config.clock, &clock));
	}

	/// The explicit cleartext configuration is in the accept state that binds
	/// in the clear, which holds no encryption and no multiplexing offer.
	#[test]
	fn the_cleartext_configuration_holds_no_encryption() {
		let config: ServletConfig<TokioListener, Ping> = ServletConfig::cleartext();
		assert!(config.to_encryption_config_ref().is_none());
		assert!(config.mux_offer().is_none());
	}
}
