/// Client macro - creates a configured transport for multiple emit calls
#[macro_export]
macro_rules! client {
	// With identity only (mutual auth without policies)
	(connect $protocol:path: $addr:expr, identity: ($cert:expr, $key:expr)) => {{
		#[cfg(feature = "std")]
		{
			#[cfg(feature = "builder")]
			{
				use $crate::transport::ConnectionBuilder;
				let builder = $crate::transport::client::ClientBuilder::<$protocol>::builder();
				let builder = ConnectionBuilder::with_client_identity(builder, $cert, $key)?;
				let builder = ConnectionBuilder::build(builder);
				builder.connect($addr).await?
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
				use $crate::transport::ConnectionBuilder;
				let __builder = $crate::transport::client::ClientBuilder::<$protocol>::builder();
				let __builder = $crate::client!(@apply_policies_to_builder __builder, { $($tt)* });
				let __builder = ConnectionBuilder::with_client_identity(__builder, $cert, $key)?;
				let __builder = ConnectionBuilder::build(__builder);
				__builder.connect($addr).await?
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
		let __transport = <$protocol as $crate::transport::Protocol>::create_transport($stream);
		#[cfg(feature = "builder")]
		{ $crate::transport::client::GenericClient::<$protocol>::from_transport(__transport) }
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
			{ $crate::transport::client::GenericClient::<$protocol>::from_transport(__transport) }
			#[cfg(not(feature = "builder"))]
			{ __transport }
		}
	}};

	// Generic sync: protocol: stream, policies: {...}
	($protocol:path: $stream:expr, policies: { $($tt:tt)* }) => {{
		let mut __transport = <$protocol as $crate::transport::Protocol>::create_transport($stream);
		__transport = $crate::client!(@apply_policies __transport, { $($tt)* });
		#[cfg(feature = "builder")]
		{ $crate::transport::client::GenericClient::<$protocol>::from_transport(__transport) }
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
			{ $crate::transport::client::GenericClient::<$protocol>::from_transport(__transport) }
			#[cfg(not(feature = "builder"))]
			{ __transport }
		}
	}};

	// Generic async: async protocol: stream
	(async $protocol:path: $stream:expr) => {{
		async {
			let __transport = <$protocol as $crate::transport::Protocol>::create_transport($stream);
			#[cfg(feature = "builder")]
			{ Ok::<_, $crate::transport::error::TransportError>($crate::transport::client::GenericClient::<$protocol>::from_transport(__transport)) }
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
			let __transport = <$protocol as $crate::transport::Protocol>::create_transport(stream);
			#[cfg(feature = "builder")]
			{ Ok::<_, $crate::transport::error::TransportError>($crate::transport::client::GenericClient::<$protocol>::from_transport(__transport)) }
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
			{ Ok::<_, $crate::transport::error::TransportError>($crate::transport::client::GenericClient::<$protocol>::from_transport(__transport)) }
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
			{ Ok::<_, $crate::transport::error::TransportError>($crate::transport::client::GenericClient::<$protocol>::from_transport(__transport)) }
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
