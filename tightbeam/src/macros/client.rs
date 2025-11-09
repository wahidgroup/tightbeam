/// Client macro - creates a configured transport for multiple emit calls
#[macro_export]
macro_rules! client {
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
	($protocol:path: $stream:expr, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }) => {{
		let mut __transport = <$protocol as $crate::transport::Protocol>::create_transport($stream);
		$( __transport = $crate::client!(@set_policy __transport, $policy_name, $policy_value); )*
		#[cfg(feature = "builder")]
		{ $crate::macros::client::builder::GenericClient::<$protocol>::from_transport(__transport) }
		#[cfg(not(feature = "builder"))]
		{ __transport }
	}};

	// Generic sync: connect protocol: addr, policies: {...}
	(connect $protocol:path: $addr:expr, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }) => {{
		#[cfg(feature = "std")]
		{
			let stream = <$protocol as $crate::transport::Protocol>::connect($addr).await?;
			let mut __transport = <$protocol as $crate::transport::Protocol>::create_transport(stream);
			$( __transport = $crate::client!(@set_policy __transport, $policy_name, $policy_value); )*
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
	(async $protocol:path: $stream:expr, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }) => {{
		async {
			let mut __transport = <$protocol as $crate::transport::Protocol>::create_transport($stream);
			$( __transport = $crate::client!(@set_policy __transport, $policy_name, $policy_value); )*
			#[cfg(feature = "builder")]
			{ Ok::<_, $crate::transport::error::TransportError>($crate::macros::client::builder::GenericClient::<$protocol>::from_transport(__transport)) }
			#[cfg(not(feature = "builder"))]
			{ Ok::<_, $crate::transport::error::TransportError>(__transport) }
		}
	}};

	// Generic async: async connect protocol: addr, policies: {...}
	(async connect $protocol:path: $addr:expr, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }) => {{
		#[cfg(feature = "tokio")]
		async {
			let stream = <$protocol as $crate::transport::Protocol>::connect($addr).await
				.map_err(|e| $crate::transport::error::TransportError::from(e))?;
			let mut __transport = <$protocol as $crate::transport::Protocol>::create_transport(stream);
			$( __transport = $crate::client!(@set_policy __transport, $policy_name, $policy_value); )*
			#[cfg(feature = "builder")]
			{ Ok::<_, $crate::transport::error::TransportError>($crate::macros::client::__client_policies::GenericClient::<$protocol>::from_transport(__transport)) }
			#[cfg(not(feature = "builder"))]
			{ Ok::<_, $crate::transport::error::TransportError>(__transport) }
		}
	}};

	// Internal helper to set policies
	(@set_policy $transport:expr, restart_policy, $value:expr) => {
		$transport.with_restart($value)
	};
	// Shorthand: restart -> with_restart(...)
	(@set_policy $transport:expr, restart, $value:expr) => {
		$transport.with_restart($value)
	};
	(@set_policy $transport:expr, emitter_gate, $value:expr) => {
		$transport.with_emitter_gate($value)
	};
	// Shorthand: gate (client-side) -> with_emitter_gate(...)
	(@set_policy $transport:expr, gate, $value:expr) => {
		$transport.with_emitter_gate($value)
	};
	(@set_policy $transport:expr, collector_gate, $value:expr) => {
		$transport.with_collector_gate($value)
	};
	// X.509 certificate validation gate (single validator form)
	(@set_policy $transport:expr, with_x509_gate, $validator:expr) => {{
		#[cfg(all(feature = "x509", feature = "signature", feature = "secp256k1"))]
		{ $transport.with_x509_gate($validator) }
		#[cfg(not(all(feature = "x509", feature = "signature", feature = "secp256k1")))]
		{ $transport }
	}};
	// Shorthand alias: x509_gate
	(@set_policy $transport:expr, x509_gate, $validator:expr) => {{
		#[cfg(all(feature = "x509", feature = "signature", feature = "secp256k1"))]
		{ $transport.with_x509_gate($validator) }
		#[cfg(not(all(feature = "x509", feature = "signature", feature = "secp256k1")))]
		{ $transport }
	}};
	// Multi-validator list form: with_x509_gate: [ValidatorA, ValidatorB, ...]
	(@set_policy $transport:expr, with_x509_gate, [$($validator:expr),* $(,)?]) => {{
		#[cfg(all(feature = "x509", feature = "signature", feature = "secp256k1"))]
		{
			let mut __t = $transport;
			$( __t = __t.with_x509_gate($validator); )*
			__t
		}
		#[cfg(not(all(feature = "x509", feature = "signature", feature = "secp256k1")))]
		{ $transport }
	}};
	// Multi-validator list shorthand: x509_gate: [..]
	(@set_policy $transport:expr, x509_gate, [$($validator:expr),* $(,)?]) => {{
		#[cfg(all(feature = "x509", feature = "signature", feature = "secp256k1"))]
		{
			let mut __t = $transport;
			$( __t = __t.with_x509_gate($validator); )*
			__t
		}
		#[cfg(not(all(feature = "x509", feature = "signature", feature = "secp256k1")))]
		{ $transport }
	}};
}

// Programmatic client policy system (non-macro) enabling external implementors to apply
// policies without invoking the `client!` macro.
#[cfg(feature = "builder")]
#[allow(dead_code)]
pub mod builder {
	use crate::asn1::Frame;
	use crate::transport::error::TransportError;
	#[cfg(feature = "transport-policy")]
	use crate::transport::policy::PolicyConf;
	use crate::transport::{MessageCollector, MessageEmitter, Protocol, TransportResult};

	#[derive(Default)]
	pub struct ClientPolicies {
		restart: Option<DynRestart>,
		emitter_gates: Vec<DynGate>,
		collector_gates: Vec<DynGate>,
		#[cfg(all(feature = "x509", feature = "signature", feature = "secp256k1"))]
		validators: Vec<DynCertValidator>,
	}

	pub struct DynRestart(pub Box<dyn crate::transport::policy::RestartPolicy + Send + Sync>);
	impl crate::transport::policy::RestartPolicy for DynRestart {
		fn evaluate(
			&self,
			message: crate::Frame,
			result: crate::transport::TransportResult<&crate::Frame>,
			attempt: usize,
		) -> Option<crate::Frame> {
			self.0.evaluate(message, result, attempt)
		}
	}

	pub struct DynGate(pub std::sync::Arc<dyn crate::policy::GatePolicy + Send + Sync>);
	impl crate::policy::GatePolicy for DynGate {
		fn evaluate(&self, message: &crate::Frame) -> crate::policy::TransitStatus {
			self.0.evaluate(message)
		}
	}

	#[cfg(all(feature = "x509", feature = "signature", feature = "secp256k1"))]
	pub struct DynCertValidator(
		pub std::sync::Arc<dyn crate::crypto::x509::policy::CertificateValidation + Send + Sync>,
	);
	#[cfg(all(feature = "x509", feature = "signature", feature = "secp256k1"))]
	impl crate::crypto::x509::policy::CertificateValidation for DynCertValidator {
		fn evaluate(
			&self,
			cert: &crate::x509::Certificate,
		) -> core::result::Result<(), crate::crypto::x509::error::CertificateValidationError> {
			self.0.evaluate(cert)
		}
	}

	impl ClientPolicies {
		pub fn new() -> Self {
			Self::default()
		}
		pub fn with_restart<P>(mut self, policy: P) -> Self
		where
			P: crate::transport::policy::RestartPolicy + Send + Sync + 'static,
		{
			self.restart = Some(DynRestart(Box::new(policy)));
			self
		}
		pub fn with_emitter_gate<G>(mut self, gate: G) -> Self
		where
			G: crate::policy::GatePolicy + Send + Sync + 'static,
		{
			self.emitter_gates.push(DynGate(std::sync::Arc::new(gate)));
			self
		}
		pub fn with_collector_gate<G>(mut self, gate: G) -> Self
		where
			G: crate::policy::GatePolicy + Send + Sync + 'static,
		{
			self.collector_gates.push(DynGate(std::sync::Arc::new(gate)));
			self
		}
		#[cfg(all(feature = "x509", feature = "signature", feature = "secp256k1"))]
		pub fn with_x509_gate<V>(mut self, v: V) -> Self
		where
			V: crate::crypto::x509::policy::CertificateValidation + Send + Sync + 'static,
		{
			self.validators.push(DynCertValidator(std::sync::Arc::new(v)));
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
			transport
		}
	}

	pub struct ClientBuilder<P: Protocol> {
		addr: Option<P::Address>,
		stream: Option<P::Stream>,
		policies: ClientPolicies,
		_ph: core::marker::PhantomData<P>,
	}

	impl<P: Protocol> ClientBuilder<P> {
		pub fn from_stream(stream: P::Stream) -> Self {
			Self {
				addr: None,
				stream: Some(stream),
				policies: ClientPolicies::new(),
				_ph: core::marker::PhantomData,
			}
		}
		pub async fn connect(addr: P::Address) -> Result<Self, TransportError> {
			let stream = <P as Protocol>::connect(addr.clone()).await.map_err(|e| e.into())?;
			Ok(Self {
				addr: Some(addr),
				stream: Some(stream),
				policies: ClientPolicies::new(),
				_ph: core::marker::PhantomData,
			})
		}
		pub fn policies(mut self, policies: ClientPolicies) -> Self {
			self.policies = policies;
			self
		}
		pub fn with_restart<R>(mut self, p: R) -> Self
		where
			R: crate::transport::policy::RestartPolicy + Send + Sync + 'static,
		{
			self.policies = self.policies.with_restart(p);
			self
		}
		pub fn with_emitter_gate<G>(mut self, g: G) -> Self
		where
			G: crate::policy::GatePolicy + Send + Sync + 'static,
		{
			self.policies = self.policies.with_emitter_gate(g);
			self
		}
		pub fn with_collector_gate<G>(mut self, g: G) -> Self
		where
			G: crate::policy::GatePolicy + Send + Sync + 'static,
		{
			self.policies = self.policies.with_collector_gate(g);
			self
		}
		#[cfg(all(feature = "x509", feature = "signature", feature = "secp256k1"))]
		pub fn with_x509_gate<V>(mut self, v: V) -> Self
		where
			V: crate::crypto::x509::policy::CertificateValidation + Send + Sync + 'static,
		{
			self.policies = self.policies.with_x509_gate(v);
			self
		}
		pub fn build(self) -> Result<GenericClient<P>, TransportError>
		where
			P::Transport: MessageEmitter + MessageCollector + PolicyConf,
		{
			let stream = self.stream.expect("stream must be present");
			let transport = <P as Protocol>::create_transport(stream);
			let configured = self.policies.apply::<P>(transport);
			Ok(GenericClient::from_transport(configured))
		}
	}

	pub struct GenericClient<P: Protocol> {
		transport: P::Transport,
		_ph: core::marker::PhantomData<P>,
	}
	impl<P: Protocol> GenericClient<P> {
		pub fn from_transport(transport: P::Transport) -> Self {
			Self { transport, _ph: core::marker::PhantomData }
		}
		pub fn transport(&self) -> &P::Transport {
			&self.transport
		}
		pub fn into_transport(self) -> P::Transport {
			self.transport
		}
		#[allow(async_fn_in_trait)]
		pub async fn emit(&mut self, frame: Frame, attempt: Option<usize>) -> TransportResult<Option<Frame>>
		where
			P::Transport: crate::transport::MessageEmitter,
		{
			self.transport.emit(frame, attempt).await
		}
	}

	// Conversions
	impl<P: Protocol> From<ClientBuilder<P>> for GenericClient<P>
	where
		P::Transport: MessageEmitter + MessageCollector + PolicyConf,
	{
		fn from(builder: ClientBuilder<P>) -> Self {
			builder.build().expect("client builder failed")
		}
	}
	impl crate::policy::GatePolicy for std::sync::Arc<dyn crate::policy::GatePolicy + Send + Sync> {
		fn evaluate(&self, message: &crate::Frame) -> crate::policy::TransitStatus {
			(**self).evaluate(message)
		}
	}
}
