/// Client macro - creates a configured transport for multiple emit calls
#[macro_export]
macro_rules! client {
	// With identity only (mutual auth without policies)
	(connect $protocol:path: $addr:expr, identity: ($cert:expr, $key:expr)) => {{
		#[cfg(feature = "std")]
		{
			#[cfg(feature = "builder")]
			{
				$crate::macros::client::builder::ClientBuilder::<$protocol>::connect($addr)
					.await?
					.with_client_identity($cert, $key)?
					.build()?
			}
			#[cfg(not(feature = "builder"))]
			{
				let stream = <$protocol as $crate::transport::Protocol>::connect($addr).await?;
				<$protocol as $crate::transport::Protocol>::create_transport(stream)
					.with_client_identity($cert, $key)
			}
		}
	}};

	// With identity AND policies (mutual auth with policies)
	(connect $protocol:path: $addr:expr, identity: ($cert:expr, $key:expr), policies: { $($tt:tt)* }) => {{
		#[cfg(feature = "std")]
		{
			#[cfg(feature = "builder")]
			{
				let __builder = $crate::macros::client::builder::ClientBuilder::<$protocol>::connect($addr).await?;
				let __builder = $crate::client!(@apply_policies_to_builder __builder, { $($tt)* });
				__builder.with_client_identity($cert, $key)?.build()?
			}
			#[cfg(not(feature = "builder"))]
			{
				let stream = <$protocol as $crate::transport::Protocol>::connect($addr).await?;
				let mut __transport = <$protocol as $crate::transport::Protocol>::create_transport(stream)
					.with_client_identity($cert, $key);
				__transport = $crate::client!(@apply_policies __transport, { $($tt)* });
				__transport
			}
		}
	}};

	// Generic sync: protocol: stream
	($protocol:path: $stream:expr) => {{
		let __transport = <$protocol as Protocol>::create_transport($stream);
		#[cfg(feature = "builder")]
		{ $crate::macros::client::builder::GenericClient::<$protocol>::from_transport(__transport) }
		#[cfg(not(feature = "builder"))]
		{ __transport }
	}};

	// Generic sync: connect protocol: addr
	(connect $protocol:path: $addr:expr) => {{
		#[cfg(feature = "std")]
		{
			let stream = <$protocol as $crate::transport::Protocol>::connect($addr).await?;
			let __transport = <$protocol as $crate::transport::Protocol>::create_transport(stream);
			#[cfg(feature = "builder")]
			{ $crate::macros::client::builder::GenericClient::<$protocol>::from_transport(__transport) }
			#[cfg(not(feature = "builder"))]
			{ __transport }
		}
	}};

	// Generic sync: protocol: stream, policies: {...}
	($protocol:path: $stream:expr, policies: { $($tt:tt)* }) => {{
		let mut __transport = <$protocol as $crate::transport::Protocol>::create_transport($stream);
		__transport = $crate::client!(@apply_policies __transport, { $($tt)* });
		#[cfg(feature = "builder")]
		{ $crate::macros::client::builder::GenericClient::<$protocol>::from_transport(__transport) }
		#[cfg(not(feature = "builder"))]
		{ __transport }
	}};

	// Generic sync: connect protocol: addr, policies: {...}
	(connect $protocol:path: $addr:expr, policies: { $($tt:tt)* }) => {{
		#[cfg(feature = "std")]
		{
			let stream = <$protocol as $crate::transport::Protocol>::connect($addr).await?;
			let mut __transport = <$protocol as $crate::transport::Protocol>::create_transport(stream);
			__transport = $crate::client!(@apply_policies __transport, { $($tt)* });
			#[cfg(feature = "builder")]
			{ $crate::macros::client::builder::GenericClient::<$protocol>::from_transport(__transport) }
			#[cfg(not(feature = "builder"))]
			{ __transport }
		}
	}};

	// Generic async: async protocol: stream
	(async $protocol:path: $stream:expr) => {{
		async {
			let __transport = <$protocol as $crate::transport::Protocol>::create_transport($stream);
			#[cfg(feature = "builder")]
			{ Ok::<_, $crate::transport::error::TransportError>($crate::macros::client::builder::GenericClient::<$protocol>::from_transport(__transport)) }
			#[cfg(not(feature = "builder"))]
			{ Ok::<_, $crate::transport::error::TransportError>(__transport) }
		}
	}};

	// Generic async: async connect protocol: addr
	(async connect $protocol:path: $addr:expr) => {{
		#[cfg(feature = "tokio")]
		async {
			let stream = <$protocol as $crate::transport::Protocol>::connect($addr).await
				.map_err(|e| $crate::transport::error::TransportError::from(e))?;
			let __transport = <$protocol as Protocol>::create_transport(stream);
			#[cfg(feature = "builder")]
			{ Ok::<_, $crate::transport::error::TransportError>($crate::macros::client::__client_policies::GenericClient::<$protocol>::from_transport(__transport)) }
			#[cfg(not(feature = "builder"))]
			{ Ok::<_, $crate::transport::error::TransportError>(__transport) }
		}
	}};

	// Generic async: async protocol: stream, policies: {...}
	(async $protocol:path: $stream:expr, policies: { $($tt:tt)* }) => {{
		async {
			let mut __transport = <$protocol as $crate::transport::Protocol>::create_transport($stream);
			__transport = $crate::client!(@apply_policies __transport, { $($tt)* });
			#[cfg(feature = "builder")]
			{ Ok::<_, $crate::transport::error::TransportError>($crate::macros::client::builder::GenericClient::<$protocol>::from_transport(__transport)) }
			#[cfg(not(feature = "builder"))]
			{ Ok::<_, $crate::transport::error::TransportError>(__transport) }
		}
	}};

	// Generic async: async connect protocol: addr, policies: {...}
	(async connect $protocol:path: $addr:expr, policies: { $($tt:tt)* }) => {{
		#[cfg(feature = "tokio")]
		async {
			let stream = <$protocol as $crate::transport::Protocol>::connect($addr).await
				.map_err(|e| $crate::transport::error::TransportError::from(e))?;
			let mut __transport = <$protocol as $crate::transport::Protocol>::create_transport(stream);
			__transport = $crate::client!(@apply_policies __transport, { $($tt)* });
			#[cfg(feature = "builder")]
			{ Ok::<_, $crate::transport::error::TransportError>($crate::macros::client::__client_policies::GenericClient::<$protocol>::from_transport(__transport)) }
			#[cfg(not(feature = "builder"))]
			{ Ok::<_, $crate::transport::error::TransportError>(__transport) }
		}
	}};

	// Policy application helper - processes mixed singular and plural policies
	(@apply_policies $transport:expr, { $($tt:tt)* }) => {{
		let mut __t = $transport;
		$crate::client!(@process_policy __t, $($tt)*);
		__t
	}};

	// Policy application helper for ClientBuilder - processes policies for builder pattern
	(@apply_policies_to_builder $builder:expr, { $($tt:tt)* }) => {{
		#[cfg(feature = "builder")]
		{
			let mut __b = $builder;
			$crate::client!(@process_policy_builder __b, $($tt)*);
			__b
		}
	}};

	// Process individual policies recursively
	(@process_policy $transport:expr, restart_policy: $value:expr, $($rest:tt)*) => {
		$transport = $transport.with_restart($value);
		$crate::client!(@process_policy $transport, $($rest)*);
	};
	(@process_policy $transport:expr, restart: $value:expr, $($rest:tt)*) => {
		$transport = $transport.with_restart($value);
		$crate::client!(@process_policy $transport, $($rest)*);
	};
	// emitter_gate can be singular or array
	(@process_policy $transport:expr, emitter_gate: [ $( $value:expr ),* $(,)? ], $($rest:tt)*) => {
		$(
			$transport = $transport.with_emitter_gate($value);
		)*
		$crate::client!(@process_policy $transport, $($rest)*);
	};
	(@process_policy $transport:expr, emitter_gate: [ $( $value:expr ),* $(,)? ] $(,)?) => {
		$(
			$transport = $transport.with_emitter_gate($value);
		)*
	};
	(@process_policy $transport:expr, emitter_gate: $value:expr, $($rest:tt)*) => {
		$transport = $transport.with_emitter_gate($value);
		$crate::client!(@process_policy $transport, $($rest)*);
	};
	(@process_policy $transport:expr, emitter_gate: $value:expr $(,)?) => {
		$transport = $transport.with_emitter_gate($value);
	};
	// gate (shorthand for emitter_gate) can be singular or array
	(@process_policy $transport:expr, gate: [ $( $value:expr ),* $(,)? ], $($rest:tt)*) => {
		$(
			$transport = $transport.with_emitter_gate($value);
		)*
		$crate::client!(@process_policy $transport, $($rest)*);
	};
	(@process_policy $transport:expr, gate: [ $( $value:expr ),* $(,)? ] $(,)?) => {
		$(
			$transport = $transport.with_emitter_gate($value);
		)*
	};
	(@process_policy $transport:expr, gate: $value:expr, $($rest:tt)*) => {
		$transport = $transport.with_emitter_gate($value);
		$crate::client!(@process_policy $transport, $($rest)*);
	};
	(@process_policy $transport:expr, gate: $value:expr $(,)?) => {
		$transport = $transport.with_emitter_gate($value);
	};
	// collector_gate can be singular or array
	(@process_policy $transport:expr, collector_gate: [ $( $value:expr ),* $(,)? ], $($rest:tt)*) => {
		$(
			$transport = $transport.with_collector_gate($value);
		)*
		$crate::client!(@process_policy $transport, $($rest)*);
	};
	(@process_policy $transport:expr, collector_gate: [ $( $value:expr ),* $(,)? ] $(,)?) => {
		$(
			$transport = $transport.with_collector_gate($value);
		)*
	};
	(@process_policy $transport:expr, collector_gate: $value:expr, $($rest:tt)*) => {
		$transport = $transport.with_collector_gate($value);
		$crate::client!(@process_policy $transport, $($rest)*);
	};
	(@process_policy $transport:expr, collector_gate: $value:expr $(,)?) => {
		$transport = $transport.with_collector_gate($value);
	};
	// timeout accepts Duration
	(@process_policy $transport:expr, timeout: $value:expr, $($rest:tt)*) => {
		#[cfg(feature = "std")]
		{ $transport = $transport.with_timeout($value); }
		$crate::client!(@process_policy $transport, $($rest)*);
	};
	(@process_policy $transport:expr, timeout: $value:expr $(,)?) => {
		#[cfg(feature = "std")]
		{ $transport = $transport.with_timeout($value); }
	};
	// x509_gate accepts array of validators
	(@process_policy $transport:expr, x509_gate: [ $( $validator:expr ),* $(,)? ], $($rest:tt)*) => {
		$(
			#[cfg(all(feature = "x509", feature = "signature", feature = "secp256k1"))]
			{ $transport = $transport.with_x509_gate($validator); }
		)*
		$crate::client!(@process_policy $transport, $($rest)*);
	};
	(@process_policy $transport:expr, x509_gate: [ $( $validator:expr ),* $(,)? ] $(,)?) => {
		$(
			#[cfg(all(feature = "x509", feature = "signature", feature = "secp256k1"))]
			{ $transport = $transport.with_x509_gate($validator); }
		)*
	};
	(@process_policy $transport:expr, with_x509_gate: [ $( $validator:expr ),* $(,)? ], $($rest:tt)*) => {
		$(
			#[cfg(all(feature = "x509", feature = "signature", feature = "secp256k1"))]
			{ $transport = $transport.with_x509_gate($validator); }
		)*
		$crate::client!(@process_policy $transport, $($rest)*);
	};
	(@process_policy $transport:expr, with_x509_gate: [ $( $validator:expr ),* $(,)? ] $(,)?) => {
		$(
			#[cfg(all(feature = "x509", feature = "signature", feature = "secp256k1"))]
			{ $transport = $transport.with_x509_gate($validator); }
		)*
	};
	// Base case: no more policies
	(@process_policy $transport:expr,) => {};
	(@process_policy $transport:expr) => {};

	// Process policies for ClientBuilder - similar to process_policy but works with builder methods
	(@process_policy_builder $builder:expr, restart_policy: $value:expr, $($rest:tt)*) => {
		$builder = $builder.with_restart($value);
		$crate::client!(@process_policy_builder $builder, $($rest)*);
	};
	(@process_policy_builder $builder:expr, restart: $value:expr, $($rest:tt)*) => {
		$builder = $builder.with_restart($value);
		$crate::client!(@process_policy_builder $builder, $($rest)*);
	};
	(@process_policy_builder $builder:expr, emitter_gate: [ $( $value:expr ),* $(,)? ], $($rest:tt)*) => {
		$(
			$builder = $builder.with_emitter_gate($value);
		)*
		$crate::client!(@process_policy_builder $builder, $($rest)*);
	};
	(@process_policy_builder $builder:expr, emitter_gate: $value:expr, $($rest:tt)*) => {
		$builder = $builder.with_emitter_gate($value);
		$crate::client!(@process_policy_builder $builder, $($rest)*);
	};
	(@process_policy_builder $builder:expr, gate: [ $( $value:expr ),* $(,)? ], $($rest:tt)*) => {
		$(
			$builder = $builder.with_emitter_gate($value);
		)*
		$crate::client!(@process_policy_builder $builder, $($rest)*);
	};
	(@process_policy_builder $builder:expr, gate: $value:expr, $($rest:tt)*) => {
		$builder = $builder.with_emitter_gate($value);
		$crate::client!(@process_policy_builder $builder, $($rest)*);
	};
	(@process_policy_builder $builder:expr, collector_gate: [ $( $value:expr ),* $(,)? ], $($rest:tt)*) => {
		$(
			$builder = $builder.with_collector_gate($value);
		)*
		$crate::client!(@process_policy_builder $builder, $($rest)*);
	};
	(@process_policy_builder $builder:expr, collector_gate: $value:expr, $($rest:tt)*) => {
		$builder = $builder.with_collector_gate($value);
		$crate::client!(@process_policy_builder $builder, $($rest)*);
	};
	(@process_policy_builder $builder:expr, timeout: $value:expr, $($rest:tt)*) => {
		#[cfg(feature = "std")]
		{
			$builder = $builder.with_timeout($value);
		}
		$crate::client!(@process_policy_builder $builder, $($rest)*);
	};
	(@process_policy_builder $builder:expr, x509_gate: [ $( $validator:expr ),* $(,)? ], $($rest:tt)*) => {
		#[cfg(all(feature = "x509", feature = "signature", feature = "secp256k1"))]
		{
			$(
				$builder = $builder.with_x509_gate($validator);
			)*
		}
		$crate::client!(@process_policy_builder $builder, $($rest)*);
	};
	(@process_policy_builder $builder:expr, x509_gate: [ $( $validator:expr ),* $(,)? ] $(,)?) => {
		#[cfg(all(feature = "x509", feature = "signature", feature = "secp256k1"))]
		{
			$(
				$builder = $builder.with_x509_gate($validator);
			)*
		}
	};
	(@process_policy_builder $builder:expr,) => {};
	(@process_policy_builder $builder:expr) => {};
}

// Programmatic client policy system (non-macro) enabling external implementors to apply
// policies without invoking the `client!` macro.
#[cfg(feature = "builder")]
pub mod builder {
	#[cfg(not(feature = "std"))]
	extern crate alloc;

	#[cfg(not(feature = "std"))]
	use alloc::{boxed::Box, sync::Arc, vec::Vec};

	#[cfg(feature = "std")]
	use std::sync::Arc;

	use core::time::Duration;

	use crate::asn1::Frame;
	use crate::policy::{GatePolicy, TransitStatus};
	use crate::transport::error::{TransportError, TransportFailure};
	use crate::transport::{MessageCollector, MessageEmitter, Protocol, TransportResult};

	#[cfg(feature = "x509")]
	mod x509 {
		pub use crate::crypto::key::KeySpec;
		pub use crate::crypto::x509::error::CertificateValidationError;
		pub use crate::crypto::x509::policy::CertificateValidation;
		pub use crate::crypto::x509::CertificateSpec;
		pub use crate::transport::handshake::HandshakeKeyManager;
		pub use crate::transport::X509ClientConfig;
		pub use crate::x509::Certificate;
	}

	#[cfg(feature = "x509")]
	use x509::*;

	#[cfg(feature = "transport-policy")]
	mod policy {
		pub use crate::transport::policy::{PolicyConf, RestartPolicy, RetryAction};
	}

	#[cfg(feature = "transport-policy")]
	use policy::*;

	#[derive(Default)]
	pub struct ClientPolicies {
		restart: Option<DynRestart>,
		emitter_gates: Vec<DynGate>,
		collector_gates: Vec<DynGate>,
		#[cfg(all(feature = "x509", feature = "signature", feature = "secp256k1"))]
		validators: Vec<DynCertValidator>,
		timeout: Option<Duration>,
	}

	pub struct DynRestart(pub Box<dyn RestartPolicy + Send + Sync>);
	impl RestartPolicy for DynRestart {
		fn evaluate(&self, frame: Box<Frame>, failure: &TransportFailure, attempt: usize) -> RetryAction {
			self.0.evaluate(frame, failure, attempt)
		}
	}

	pub struct DynGate(pub Arc<dyn GatePolicy + Send + Sync>);
	impl GatePolicy for DynGate {
		fn evaluate(&self, message: &Frame) -> TransitStatus {
			self.0.evaluate(message)
		}
	}

	#[cfg(all(feature = "x509", feature = "signature", feature = "secp256k1"))]
	pub struct DynCertValidator(pub Arc<dyn CertificateValidation + Send + Sync>);
	#[cfg(all(feature = "x509", feature = "signature", feature = "secp256k1"))]
	impl CertificateValidation for DynCertValidator {
		fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
			self.0.evaluate(cert)
		}
	}

	impl ClientPolicies {
		pub fn with_restart<P>(mut self, policy: P) -> Self
		where
			P: RestartPolicy + Send + Sync + 'static,
		{
			self.restart = Some(DynRestart(Box::new(policy)));
			self
		}

		pub fn with_emitter_gate<G>(mut self, gate: G) -> Self
		where
			G: GatePolicy + Send + Sync + 'static,
		{
			self.emitter_gates.push(DynGate(Arc::new(gate)));
			self
		}

		pub fn with_collector_gate<G>(mut self, gate: G) -> Self
		where
			G: GatePolicy + Send + Sync + 'static,
		{
			self.collector_gates.push(DynGate(Arc::new(gate)));
			self
		}

		#[cfg(all(feature = "x509", feature = "signature", feature = "secp256k1"))]
		pub fn with_x509_gate<V>(mut self, v: V) -> Self
		where
			V: CertificateValidation + Send + Sync + 'static,
		{
			self.validators.push(DynCertValidator(Arc::new(v)));
			self
		}

		pub fn with_timeout(mut self, timeout: Duration) -> Self {
			self.timeout = Some(timeout);
			self
		}

		pub fn apply<P>(self, mut transport: P::Transport) -> P::Transport
		where
			P: Protocol,
			P::Transport: MessageEmitter + MessageCollector + PolicyConf,
		{
			if let Some(r) = self.restart {
				transport = transport.with_restart(r);
			}
			#[cfg(all(feature = "x509", feature = "signature", feature = "secp256k1"))]
			for v in self.validators.into_iter() {
				transport = transport.with_x509_gate(v);
			}
			for g in self.emitter_gates.into_iter() {
				transport = transport.with_emitter_gate(g);
			}
			for g in self.collector_gates.into_iter() {
				transport = transport.with_collector_gate(g);
			}
			if let Some(timeout) = self.timeout {
				transport = transport.with_timeout(timeout);
			}
			transport
		}
	}

	pub struct ClientBuilder<P: Protocol> {
		stream: Option<P::Stream>,
		addr: Option<P::Address>,
		policies: ClientPolicies,
		#[cfg(feature = "x509")]
		server_certificates: Vec<Certificate>,
		#[cfg(feature = "x509")]
		client_certificate: Option<Certificate>,
		#[cfg(feature = "x509")]
		client_key: Option<HandshakeKeyManager>,
		_ph: core::marker::PhantomData<P>,
	}

	impl<P: Protocol> ClientBuilder<P> {
		pub fn from_stream(stream: P::Stream) -> Self {
			Self {
				stream: Some(stream),
				addr: None,
				policies: ClientPolicies::default(),
				#[cfg(feature = "x509")]
				server_certificates: Vec::new(),
				#[cfg(feature = "x509")]
				client_certificate: None,
				#[cfg(feature = "x509")]
				client_key: None,
				_ph: core::marker::PhantomData,
			}
		}

		pub async fn connect(addr: P::Address) -> Result<Self, TransportError> {
			// Cannt avoid clone here because of the async trait bound
			let stream = <P as Protocol>::connect(addr.clone()).await.map_err(|e| e.into())?;
			Ok(Self {
				stream: Some(stream),
				addr: Some(addr),
				policies: ClientPolicies::default(),
				#[cfg(feature = "x509")]
				server_certificates: Vec::new(),
				#[cfg(feature = "x509")]
				client_certificate: None,
				#[cfg(feature = "x509")]
				client_key: None,
				_ph: core::marker::PhantomData,
			})
		}

		pub fn policies(mut self, policies: ClientPolicies) -> Self {
			self.policies = policies;
			self
		}

		pub fn with_restart<R>(mut self, p: R) -> Self
		where
			R: RestartPolicy + Send + Sync + 'static,
		{
			self.policies = self.policies.with_restart(p);
			self
		}

		pub fn with_emitter_gate<G>(mut self, g: G) -> Self
		where
			G: GatePolicy + Send + Sync + 'static,
		{
			self.policies = self.policies.with_emitter_gate(g);
			self
		}

		pub fn with_collector_gate<G>(mut self, g: G) -> Self
		where
			G: GatePolicy + Send + Sync + 'static,
		{
			self.policies = self.policies.with_collector_gate(g);
			self
		}

		#[cfg(all(feature = "x509", feature = "signature", feature = "secp256k1"))]
		pub fn with_x509_gate<V>(mut self, v: V) -> Self
		where
			V: CertificateValidation + Send + Sync + 'static,
		{
			self.policies = self.policies.with_x509_gate(v);
			self
		}

		pub fn with_timeout(mut self, timeout: Duration) -> Self {
			self.policies = self.policies.with_timeout(timeout);
			self
		}

		#[cfg(feature = "x509")]
		pub fn with_server_certificate(mut self, cert: CertificateSpec) -> Result<Self, TransportError> {
			let cert = Certificate::try_from(cert).map_err(|_| TransportError::ConnectionFailed)?;
			self.server_certificates.push(cert);
			Ok(self)
		}

		#[cfg(feature = "x509")]
		pub fn with_server_certificates(mut self, certs: impl IntoIterator<Item = Certificate>) -> Self {
			self.server_certificates.extend(certs);
			self
		}

		#[cfg(feature = "x509")]
		pub fn with_client_identity(mut self, cert: CertificateSpec, key: KeySpec) -> Result<Self, TransportError> {
			let cert = Certificate::try_from(cert).map_err(|_| TransportError::ConnectionFailed)?;
			let key_manager = HandshakeKeyManager::try_from(key).map_err(|_| TransportError::ConnectionFailed)?;
			self.client_certificate = Some(cert);
			self.client_key = Some(key_manager);
			Ok(self)
		}

		/// Build the client. For x509 configuration, call with_server_certificate()
		/// and with_client_identity() before calling build().
		#[cfg(not(feature = "x509"))]
		pub fn build(mut self) -> Result<GenericClient<P>, TransportError>
		where
			P::Transport: MessageEmitter + MessageCollector + PolicyConf,
		{
			let stream = self.stream.take().ok_or(TransportError::ConnectionFailed)?;
			let transport = <P as Protocol>::create_transport(stream);
			let configured = self.policies.apply::<P>(transport);
			Ok(GenericClient {
				transport: Some(configured),
				connection_params: ClientConnectionParams { addr: self.addr },
				_ph: core::marker::PhantomData,
			})
		}

		#[cfg(feature = "x509")]
		pub fn build(mut self) -> Result<GenericClient<P>, TransportError>
		where
			P::Transport: MessageEmitter + MessageCollector + PolicyConf + X509ClientConfig,
		{
			let stream = self.stream.take().ok_or(TransportError::ConnectionFailed)?;
			let mut transport = <P as Protocol>::create_transport(stream);
			if !self.server_certificates.is_empty() {
				transport = transport.with_server_certificates(self.server_certificates);
			}
			if let (Some(cert), Some(key)) = (self.client_certificate, self.client_key) {
				transport = transport.with_client_identity(cert, key);
			}

			let configured = self.policies.apply::<P>(transport);
			Ok(GenericClient {
				transport: Some(configured),
				connection_params: ClientConnectionParams { addr: self.addr },
				_ph: core::marker::PhantomData,
			})
		}
	}

	/// Connection parameters for reconnection
	///
	/// Note: Currently only stores address for basic reconnection.
	/// Policies and x509 configuration are not restored on reconnect.
	struct ClientConnectionParams<P: Protocol> {
		addr: Option<P::Address>,
	}

	pub struct GenericClient<P: Protocol> {
		transport: Option<P::Transport>,
		connection_params: ClientConnectionParams<P>,
		_ph: core::marker::PhantomData<P>,
	}

	impl<P: Protocol> GenericClient<P> {
		pub fn from_transport(transport: P::Transport) -> Self {
			Self {
				transport: Some(transport),
				connection_params: ClientConnectionParams { addr: None },
				_ph: core::marker::PhantomData,
			}
		}

		pub fn transport(&self) -> Option<&P::Transport> {
			self.transport.as_ref()
		}

		pub fn into_transport(self) -> Option<P::Transport> {
			self.transport
		}

		#[allow(async_fn_in_trait)]
		pub async fn emit(&mut self, frame: Frame, attempt: Option<usize>) -> TransportResult<Option<Frame>>
		where
			P::Transport: MessageEmitter,
		{
			// Delegate to transport if available
			if let Some(transport) = &mut self.transport {
				transport.emit(frame, attempt).await
			} else {
				// No transport available
				Err(TransportError::ConnectionFailed)
			}
		}

		/// Check if transport is available
		pub fn is_connected(&self) -> bool {
			self.transport.is_some()
		}

		/// Reconnect using stored parameters
		///
		/// Note: Currently does not restore policies or x509 configuration.
		/// Reconnection creates a basic transport.
		///
		/// Zero-copy consideration: Address is small (IP + port) and required by
		/// Protocol::connect which takes ownership. The alternative (store address
		/// by value, consume on reconnect) would prevent multiple reconnects.
		pub async fn reconnect(&mut self) -> TransportResult<()>
		where
			P::Address: Clone, // Required by Protocol::connect signature
		{
			let addr = self
				.connection_params
				.addr
				.as_ref()
				.ok_or(TransportError::ConnectionFailed)?
				.clone();

			let stream = P::connect(addr).await.map_err(|e| e.into())?;
			let transport = P::create_transport(stream);

			self.transport = Some(transport);
			Ok(())
		}
	}

	// Conversions
	#[cfg(not(feature = "x509"))]
	impl<P: Protocol> TryFrom<ClientBuilder<P>> for GenericClient<P>
	where
		P::Transport: MessageEmitter + MessageCollector + PolicyConf,
	{
		type Error = TransportError;

		fn try_from(builder: ClientBuilder<P>) -> Result<Self, Self::Error> {
			builder.build()
		}
	}

	#[cfg(feature = "x509")]
	impl<P: Protocol> TryFrom<ClientBuilder<P>> for GenericClient<P>
	where
		P::Transport: MessageEmitter + MessageCollector + PolicyConf + X509ClientConfig,
	{
		type Error = TransportError;

		fn try_from(builder: ClientBuilder<P>) -> Result<Self, Self::Error> {
			builder.build()
		}
	}

	impl GatePolicy for Arc<dyn GatePolicy + Send + Sync> {
		fn evaluate(&self, message: &Frame) -> TransitStatus {
			(**self).evaluate(message)
		}
	}
}
