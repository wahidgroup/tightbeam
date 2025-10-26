/// Client macro - creates a configured transport for multiple emit calls
#[macro_export]
macro_rules! client {
	// Generic sync: protocol: stream
	($protocol:path: $stream:expr) => {{
		<$protocol as Protocol>::create_transport($stream)
	}};

	// Generic sync: connect protocol: addr
	(connect $protocol:path: $addr:expr) => {{
		#[cfg(feature = "std")]
		{
			let stream = <$protocol as $crate::transport::Protocol>::connect($addr).await?;
			<$protocol as $crate::transport::Protocol>::create_transport(stream)
		}
	}};

	// Generic sync: protocol: stream, policies: {...}
	($protocol:path: $stream:expr, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }) => {{
		let mut transport = <$protocol as $crate::transport::Protocol>::create_transport($stream);
		$(
			transport = $crate::client!(@set_policy transport, $policy_name, $policy_value);
		)*
		transport
	}};

	// Generic sync: connect protocol: addr, policies: {...}
	(connect $protocol:path: $addr:expr, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }) => {{
		#[cfg(feature = "std")]
		{
			let stream = <$protocol as $crate::transport::Protocol>::connect($addr).await?;
			let mut transport = <$protocol as $crate::transport::Protocol>::create_transport(stream);
			$(
				transport = $crate::client!(@set_policy transport, $policy_name, $policy_value);
			)*
			transport
		}
	}};

	// Generic async: async protocol: stream
	(async $protocol:path: $stream:expr) => {{
		async {
			let transport = <$protocol as $crate::transport::Protocol>::create_transport($stream);
			Ok::<_, $crate::transport::error::TransportError>(transport)
		}
	}};

	// Generic async: async connect protocol: addr
	(async connect $protocol:path: $addr:expr) => {{
		#[cfg(feature = "tokio")]
		async {
			let stream = <$protocol as $crate::transport::Protocol>::connect($addr).await
				.map_err(|e| $crate::transport::error::TransportError::from(e))?;
			let transport = <$protocol as Protocol>::create_transport(stream);
			Ok::<_, $crate::transport::error::TransportError>(transport)
		}
	}};

	// Generic async: async protocol: stream, policies: {...}
	(async $protocol:path: $stream:expr, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }) => {{
		async {
			let mut transport = <$protocol as $crate::transport::Protocol>::create_transport($stream);
			$(
				transport = $crate::client!(@set_policy transport, $policy_name, $policy_value);
			)*
			Ok::<_, $crate::transport::error::TransportError>(transport)
		}
	}};

	// Generic async: async connect protocol: addr, policies: {...}
	(async connect $protocol:path: $addr:expr, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }) => {{
		#[cfg(feature = "tokio")]
		async {
			let stream = <$protocol as $crate::transport::Protocol>::connect($addr).await
				.map_err(|e| $crate::transport::error::TransportError::from(e))?;
			let mut transport = <$protocol as $crate::transport::Protocol>::create_transport(stream);
			$(
				transport = $crate::client!(@set_policy transport, $policy_name, $policy_value);
			)*
			Ok::<_, $crate::transport::error::TransportError>(transport)
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
}
