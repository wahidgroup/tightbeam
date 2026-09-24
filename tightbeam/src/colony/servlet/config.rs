use core::marker::PhantomData;
use std::collections::HashMap;
use std::sync::Arc;

use crate::colony::hive::HiveContext;
use crate::colony::servlet::runtime;
use crate::colony::servlet::WorkerBox;
use crate::colony::worker::{Worker, WorkerMetadata};
use crate::core::{Inflator, Message};
use crate::crypto::aead::Decryptor;
use crate::policy::GatePolicy;
use crate::transport::handshake::negotiation::TransportOffer;
use crate::transport::multiplex::IntoMuxOffer;
use crate::transport::Protocol;
use crate::utils::time::{Clock, SystemClock};
use crate::TightBeamError;

use crate::crypto::key::SigningKeyProvider;
use crate::crypto::profiles::{CryptoProvider, DefaultCryptoProvider};
use crate::crypto::x509::policy::CertificateValidation;
use crate::crypto::x509::CertificateSpec;
use crate::transport::state::ClientIdentity;
use crate::transport::TransportEncryptionConfig;

/// How a servlet accepts connections.
///
/// A multiplexing advertisement is bound into the handshake transcript, so
/// it exists only where there is a handshake. The encrypted arm carries it,
/// so a cleartext servlet that advertises multiplexing is unrepresentable
/// rather than silently ignored.
pub enum ServletAccept<C: CryptoProvider> {
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

/// Servlet bind and handler configuration, transport encryption included.
///
/// `Env` is the application configuration the handlers read. It is a type
/// parameter rather than an erased value, so the config a servlet is
/// started with and the env its handlers name are the same type by
/// construction.
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
	pub(crate) workers: HashMap<String, Box<dyn WorkerBox>>,
	pub(crate) collector_gates: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	pub(crate) message_decryptor: Option<Arc<dyn Decryptor + Send + Sync>>,
	pub(crate) message_inflator: Option<Arc<dyn Inflator + Send + Sync>>,
	pub(crate) clock: Arc<dyn Clock>,
}

pub(crate) mod sealed {
	use super::{CryptoProvider, ServletAccept};

	/// Closes [`AcceptState`](super::AcceptState) to the two states this
	/// module defines, so no outside type can claim a third, and keeps the
	/// accept shape itself off the public surface.
	pub trait Sealed<C: CryptoProvider> {
		/// The accept shape this state builds.
		fn into_accept(self) -> ServletAccept<C>;
	}
}

/// One of the two accept states a [`ServletConfigBuilder`] can be in.
///
/// The state carries the accept material itself, so the builder holds the
/// certificate and the mux offer in exactly one place and `build` reads
/// the state rather than re-deriving it.
pub trait AcceptState<C: CryptoProvider>: sealed::Sealed<C> {}

/// The builder state with no certificate, and so with no handshake to bind
/// an offer to.
#[derive(Default)]
pub struct NoCertificate;

/// The builder state with a certificate set, in which the servlet may also
/// advertise multiplexing.
pub struct WithCertificate<C: CryptoProvider> {
	encryption: TransportEncryptionConfig<C>,
	mux_offer: Option<Arc<TransportOffer>>,
}

impl<C: CryptoProvider> sealed::Sealed<C> for NoCertificate {
	fn into_accept(self) -> ServletAccept<C> {
		ServletAccept::Cleartext
	}
}

impl<C: CryptoProvider> sealed::Sealed<C> for WithCertificate<C> {
	fn into_accept(self) -> ServletAccept<C> {
		ServletAccept::Encrypted { encryption: Box::new(self.encryption), mux_offer: self.mux_offer }
	}
}

impl<C: CryptoProvider> AcceptState<C> for NoCertificate {}
impl<C: CryptoProvider> AcceptState<C> for WithCertificate<C> {}

/// Builder for [`ServletConfig`] with transport encryption.
///
/// `A` is the accept state, and it holds the accept material.
/// [`ServletConfigBuilder::with_certificate`] moves the builder from
/// [`NoCertificate`] to [`WithCertificate`], and
/// [`ServletConfigBuilder::with_mux_offer`] exists only in that state. A
/// builder with no certificate has nowhere to put an offer, so the pair
/// cannot come apart.
pub struct ServletConfigBuilder<P, M, C: CryptoProvider = DefaultCryptoProvider, Env = (), A = NoCertificate>
where
	P: Protocol,
	M: Message,
{
	accept: A,
	servlet_config: Arc<Env>,
	hive_context: Option<Arc<dyn HiveContext>>,
	workers: HashMap<String, Box<dyn WorkerBox>>,
	collector_gates: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	message_decryptor: Option<Arc<dyn Decryptor + Send + Sync>>,
	message_inflator: Option<Arc<dyn Inflator + Send + Sync>>,
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
	/// Starts a [`ServletConfigBuilder`].
	pub fn builder() -> ServletConfigBuilder<P, M, C, (), NoCertificate> {
		ServletConfigBuilder::default()
	}

	/// Returns the worker registered under `name`, downcast to `W`.
	pub fn worker<W: 'static>(&self, name: impl AsRef<str>) -> Option<&W> {
		let name = name.as_ref();
		self.workers.get(name)?.downcast_ref()
	}

	/// Returns the transport encryption config when this servlet presents a
	/// certificate.
	pub fn to_encryption_config_ref(&self) -> Option<&TransportEncryptionConfig<C>> {
		match &self.accept {
			ServletAccept::Cleartext => None,
			ServletAccept::Encrypted { encryption, .. } => Some(encryption),
		}
	}

	/// Returns the multiplexing advertisement applied to accepted
	/// connections.
	///
	/// It is always [`None`] on a cleartext servlet, which has no handshake
	/// to bind an offer into.
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

	/// Takes ownership of the registered workers for servlet startup.
	pub fn to_workers(self) -> HashMap<String, Box<dyn WorkerBox>> {
		self.workers
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

	/// Splits the config into the material `bind` needs and the parts the
	/// accept loop keeps.
	///
	/// The split happens once, so the encryption and the offer it was paired
	/// with always leave together.
	pub(crate) fn into_bind_parts(self) -> (Option<TransportEncryptionConfig<C>>, runtime::ServletRuntimeParts<Env>) {
		let (encryption, mux_offer) = match self.accept {
			ServletAccept::Cleartext => (None, None),
			ServletAccept::Encrypted { encryption, mux_offer } => (Some(*encryption), mux_offer),
		};

		let parts = runtime::ServletRuntimeParts {
			env_config: self.servlet_config,
			collector_gates: self.collector_gates,
			mux_offer,
			hive_context: self.hive_context,
			message_decryptor: self.message_decryptor,
			message_inflator: self.message_inflator,
			workers: self.workers,
			clock: self.clock,
		};

		(encryption, parts)
	}
}

/// A servlet with an env that has a default needs no configuration to
/// start. An env without one must be supplied, which is what makes the
/// pairing between a servlet and its env a compile-time fact.
impl<P, M, C, Env> Default for ServletConfig<P, M, C, Env>
where
	P: Protocol,
	M: Message,
	C: CryptoProvider + Send + Sync + 'static,
	Env: Default,
{
	fn default() -> Self {
		Self {
			_protocol: PhantomData,
			_message: PhantomData,
			_crypto: PhantomData,
			accept: ServletAccept::Cleartext,
			servlet_config: Arc::new(Env::default()),
			hive_context: None,
			workers: HashMap::new(),
			collector_gates: Vec::new(),
			message_decryptor: None,
			message_inflator: None,
			clock: Arc::new(SystemClock),
		}
	}
}

/// A fresh builder serves the unit env and presents no certificate. These
/// are the only states the builder can supply on its own, and
/// [`ServletConfigBuilder::with_config`] and
/// [`ServletConfigBuilder::with_certificate`] are the way to leave them.
impl<P, M, C> Default for ServletConfigBuilder<P, M, C, (), NoCertificate>
where
	P: Protocol,
	M: Message,
	C: CryptoProvider + Send + Sync + 'static,
{
	fn default() -> Self {
		Self {
			accept: NoCertificate,
			servlet_config: Arc::new(()),
			hive_context: None,
			workers: HashMap::new(),
			collector_gates: Vec::new(),
			message_decryptor: None,
			message_inflator: None,
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
	/// Sets the application env config.
	///
	/// This names the servlet's env type, so the handlers that read it and
	/// the config that carries it are checked against each other.
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
			clock: self.clock,
			_phantom: PhantomData,
		}
	}

	/// Sets the clock the servlet's accept loop paces its retries on.
	///
	/// A builder that never sets one uses [`SystemClock`].
	#[must_use]
	pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
		self.clock = clock;
		self
	}

	/// Registers a worker under its [`WorkerMetadata`] name.
	pub fn with_worker<W>(mut self, worker: W) -> Self
	where
		W: Worker + WorkerMetadata + 'static,
	{
		self.workers
			.insert(W::name().to_string(), Box::new(worker) as Box<dyn WorkerBox>);
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

	/// Finishes the builder into a [`ServletConfig`].
	///
	/// The accept state carries the certificate and the offer, so this
	/// reads the state rather than re-deriving which one the builder is in.
	pub fn build(self) -> ServletConfig<P, M, C, Env>
	where
		A: AcceptState<C>,
	{
		ServletConfig {
			_protocol: PhantomData,
			_message: PhantomData,
			_crypto: PhantomData,
			accept: sealed::Sealed::into_accept(self.accept),
			servlet_config: self.servlet_config,
			hive_context: self.hive_context,
			workers: self.workers,
			collector_gates: self.collector_gates,
			message_decryptor: self.message_decryptor,
			message_inflator: self.message_inflator,
			clock: self.clock,
		}
	}
}

impl<P, M, C, Env> ServletConfigBuilder<P, M, C, Env, NoCertificate>
where
	P: Protocol,
	M: Message,
	C: CryptoProvider + Send + Sync + 'static,
{
	/// Enables encrypted transport with the given server certificate.
	///
	/// - A non-empty `validators` turns on mutual authentication, and every
	///   validator must accept the client certificate.
	/// - An empty `validators` turns off client authentication.
	///
	/// `validators` accepts any iterator of shared [`CertificateValidation`]
	/// values.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the certificate or key does not decode, as
	///   [`ClientIdentity::from_spec`] reports it.
	pub fn with_certificate(
		self,
		cert: CertificateSpec,
		key: Arc<dyn SigningKeyProvider>,
		validators: impl IntoIterator<Item = Arc<dyn CertificateValidation>>,
	) -> Result<ServletConfigBuilder<P, M, C, Env, WithCertificate<C>>, TightBeamError> {
		let (certificate, key_manager) = ClientIdentity::<C>::from_spec(cert, key)?.parts();
		let encryption = TransportEncryptionConfig::new(certificate, key_manager).with_client_validators(validators);

		Ok(ServletConfigBuilder {
			accept: WithCertificate { encryption, mux_offer: None },
			servlet_config: self.servlet_config,
			hive_context: self.hive_context,
			workers: self.workers,
			collector_gates: self.collector_gates,
			message_decryptor: self.message_decryptor,
			message_inflator: self.message_inflator,
			clock: self.clock,
			_phantom: PhantomData,
		})
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
	/// The offer is bound into the handshake transcript, so this exists
	/// only after [`ServletConfigBuilder::with_certificate`] has put the
	/// builder in the [`WithCertificate`] state, and it lands beside the
	/// certificate it binds to.
	#[must_use]
	pub fn with_mux_offer(mut self, offer: impl IntoMuxOffer) -> Self {
		self.accept.mux_offer = offer.into_mux_offer();
		self
	}
}
