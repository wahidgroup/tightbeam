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

impl<C: CryptoProvider> ServletAccept<C> {
	/// Bind a listener of `P` on `addr` the way this servlet accepts: under
	/// its transport encryption, or in the clear.
	///
	/// # Errors
	///
	/// The protocol's error when the bind fails.
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

/// One of the two accept states a [`ServletConfigBuilder`] builds from:
/// [`Cleartext`] and [`WithCertificate`].
///
/// The state carries the accept material itself, so the builder holds the
/// certificate and the mux offer in exactly one place and `build` reads
/// the state rather than re-deriving it.
pub trait AcceptState<C: CryptoProvider>: sealed::Sealed<C> {}

/// The state of a fresh builder, ahead of a certificate or the word for
/// cleartext. `build` exists on the two [`AcceptState`] types alone, so the
/// compiler refuses a configuration that names neither.
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
	fn into_accept(self) -> ServletAccept<C> {
		ServletAccept::Cleartext
	}
}

impl<C: CryptoProvider> sealed::Sealed<C> for WithCertificate<C> {
	fn into_accept(self) -> ServletAccept<C> {
		ServletAccept::Encrypted { encryption: Box::new(self.encryption), mux_offer: self.mux_offer }
	}
}

impl<C: CryptoProvider> AcceptState<C> for Cleartext {}
impl<C: CryptoProvider> AcceptState<C> for WithCertificate<C> {}

/// Builder for [`ServletConfig`].
///
/// `A` is the accept state, and it holds the accept material. A fresh builder
/// is in [`NoAcceptState`], and one of three calls moves it to a state that
/// builds:
///
/// - [`ServletConfigBuilder::with_certificate`] or
///   [`ServletConfigBuilder::with_identity`] moves it to [`WithCertificate`],
///   where [`ServletConfigBuilder::with_mux_offer`] exists. The offer has its
///   one place beside the certificate, so the pair stays together.
/// - [`ServletConfigBuilder::allow_cleartext`] moves it to [`Cleartext`].
///
/// A servlet therefore serves in the clear only where its configuration says
/// so (CWE-319).
pub struct ServletConfigBuilder<P, M, C: CryptoProvider = DefaultCryptoProvider, Env = (), A = NoAcceptState>
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

	/// Splits the config into the accept state, which binds the listener, and
	/// the parts the accept loop keeps.
	///
	/// The split happens once, so the encryption and the offer it was paired
	/// with always leave together.
	pub(crate) fn into_bind_parts(self) -> (ServletAccept<C>, runtime::ServletRuntimeParts<Env>) {
		let mux_offer = self.mux_offer();
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

		(self.accept, parts)
	}
}

/// A fresh builder serves the unit env and is in [`NoAcceptState`]. These are
/// the states the builder supplies on its own, and four calls leave them:
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
			clock: self.clock,
			_phantom: PhantomData,
		}
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

impl<P, M, C, Env> ServletConfigBuilder<P, M, C, Env, NoAcceptState>
where
	P: Protocol,
	M: Message,
	C: CryptoProvider + Send + Sync + 'static,
{
	/// Names cleartext as the intent of this servlet.
	///
	/// Its frames then travel in the clear and it accepts every client that
	/// connects, which suits a loopback fixture or a link a lower layer
	/// already secures. `build` exists after this call, after
	/// [`Self::with_certificate`], or after [`Self::with_identity`].
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
	/// `validators` accepts any iterator of shared [`CertificateValidation`]
	/// values.
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
	/// The offer is bound into the handshake transcript, so this exists
	/// only after [`ServletConfigBuilder::with_certificate`] or
	/// [`ServletConfigBuilder::with_identity`] has put the builder in the
	/// [`WithCertificate`] state, and it lands beside the certificate it binds
	/// to.
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
