/// Client macro: builds a client through
/// [`ClientBuilder`](crate::transport::client::ClientBuilder), so every
/// client answers the dialer rule before it writes.
///
/// A client names how it knows its peer with `trust_store:`, or names
/// `cleartext`. With neither, the client is refused with a
/// `PeerAuthenticationUnconfigured` error.
///
/// # Options
///
/// The options follow the address or stream in any order.
///
/// - `cleartext`: accept any peer, and travel with no confidentiality.
/// - `trust_store: <expr>`: validate the server against these anchors.
/// - `identity: (<cert>, <key>)`: present a client certificate.
/// - `policies: { ... }`: restart, gate, and timeout policies.
#[macro_export]
macro_rules! client {
	// Dial `addr`, then yield the client or return the error.
	(connect $protocol:path: $addr:expr $(, $($options:tt)*)?) => {{
		$crate::__tb_require_std!({
			let __builder = $crate::transport::client::ClientBuilder::<$protocol>::builder();
			let __builder = $crate::client!(@options __builder $(, $($options)*)?);
			__builder.connect($addr).await?
		})
	}};

	// Dial `addr` inside a future that yields the client or the error.
	(async connect $protocol:path: $addr:expr $(, $($options:tt)*)?) => {{
		$crate::__tb_if_tokio!({
			async {
				let __builder = $crate::transport::client::ClientBuilder::<$protocol>::builder();
				let __builder = $crate::client!(@options __builder $(, $($options)*)?);
				__builder.connect($addr).await
			}
		})
	}};

	// Adopt an open stream inside a future that yields the client or the
	// error.
	(async $protocol:path: $stream:expr $(, $($options:tt)*)?) => {{
		async {
			let __builder = $crate::transport::client::ClientBuilder::<$protocol>::builder();
			let __builder = $crate::client!(@options __builder $(, $($options)*)?);
			__builder.adopt($stream)
		}
	}};

	// Adopt an open stream, yielding the client or the error.
	($protocol:path: $stream:expr $(, $($options:tt)*)?) => {{
		let __builder = $crate::transport::client::ClientBuilder::<$protocol>::builder();
		let __builder = $crate::client!(@options __builder $(, $($options)*)?);
		__builder.adopt($stream)
	}};

	// One arm per option. The trailing comma is optional and the tail may be
	// empty, so an option needs no second arm for the last position.
	(@options $builder:expr $(,)?) => { $builder };
	(@options $builder:expr, cleartext $(, $($rest:tt)*)?) => {
		$crate::client!(@options $builder.allow_cleartext() $(, $($rest)*)?)
	};
	(@options $builder:expr, trust_store: $store:expr $(, $($rest:tt)*)?) => {
		$crate::client!(@options $builder.with_trust_store($store) $(, $($rest)*)?)
	};
	(@options $builder:expr, identity: ($cert:expr, $key:expr) $(, $($rest:tt)*)?) => {
		$crate::client!(
			@options $crate::transport::ConnectionBuilder::with_client_identity(
				$builder,
				$crate::transport::state::ClientIdentity::from_spec($cert, $key)?,
			)
			$(, $($rest)*)?
		)
	};
	(@options $builder:expr, policies: { $($policies:tt)* } $(, $($rest:tt)*)?) => {
		$crate::client!(
			@options $crate::client!(@apply_policies_to_builder $builder, { $($policies)* })
			$(, $($rest)*)?
		)
	};

	// Policy application helper for ClientBuilder - processes policies for builder pattern
	(@apply_policies_to_builder $builder:expr, { $($tt:tt)* }) => {{
		$crate::__tb_if_builder!({
			let mut __b = $builder;
			$crate::client!(@process_policy_builder __b, $($tt)*);
			__b
		})
	}};

	// One arm per policy key. The trailing comma is optional and the tail may
	// be empty, so a key needs no second arm for the last position in the list;
	// `gate` is the shorthand for `emitter_gate`.
	(@process_policy $transport:expr, restart_policy: $value:expr $(, $($rest:tt)*)?) => {
		$transport = $transport.with_restart($value);
		$($crate::client!(@process_policy $transport, $($rest)*);)?
	};
	(@process_policy $transport:expr, restart: $value:expr $(, $($rest:tt)*)?) => {
		$transport = $transport.with_restart($value);
		$($crate::client!(@process_policy $transport, $($rest)*);)?
	};
	(@process_policy $transport:expr, emitter_gate: [ $( $value:expr ),* $(,)? ] $(, $($rest:tt)*)?) => {
		$(
			$transport = $transport.with_emitter_gate($value);
		)*
		$($crate::client!(@process_policy $transport, $($rest)*);)?
	};
	(@process_policy $transport:expr, emitter_gate: $value:expr $(, $($rest:tt)*)?) => {
		$transport = $transport.with_emitter_gate($value);
		$($crate::client!(@process_policy $transport, $($rest)*);)?
	};
	(@process_policy $transport:expr, gate: [ $( $value:expr ),* $(,)? ] $(, $($rest:tt)*)?) => {
		$(
			$transport = $transport.with_emitter_gate($value);
		)*
		$($crate::client!(@process_policy $transport, $($rest)*);)?
	};
	(@process_policy $transport:expr, gate: $value:expr $(, $($rest:tt)*)?) => {
		$transport = $transport.with_emitter_gate($value);
		$($crate::client!(@process_policy $transport, $($rest)*);)?
	};
	(@process_policy $transport:expr, collector_gate: [ $( $value:expr ),* $(,)? ] $(, $($rest:tt)*)?) => {
		$(
			$transport = $transport.with_collector_gate($value);
		)*
		$($crate::client!(@process_policy $transport, $($rest)*);)?
	};
	(@process_policy $transport:expr, collector_gate: $value:expr $(, $($rest:tt)*)?) => {
		$transport = $transport.with_collector_gate($value);
		$($crate::client!(@process_policy $transport, $($rest)*);)?
	};
	(@process_policy $transport:expr, timeout: $value:expr $(, $($rest:tt)*)?) => {
		$transport = $transport.with_timeout($value);
		$($crate::client!(@process_policy $transport, $($rest)*);)?
	};
	(@process_policy $transport:expr,) => {};
	(@process_policy $transport:expr) => {};

	// The same keys against `ClientBuilder`, whose setters take the builder.
	(@process_policy_builder $builder:expr, restart_policy: $value:expr $(, $($rest:tt)*)?) => {
		$builder = $builder.with_restart($value);
		$($crate::client!(@process_policy_builder $builder, $($rest)*);)?
	};
	(@process_policy_builder $builder:expr, restart: $value:expr $(, $($rest:tt)*)?) => {
		$builder = $builder.with_restart($value);
		$($crate::client!(@process_policy_builder $builder, $($rest)*);)?
	};
	(@process_policy_builder $builder:expr, emitter_gate: [ $( $value:expr ),* $(,)? ] $(, $($rest:tt)*)?) => {
		$(
			$builder = $builder.with_emitter_gate($value);
		)*
		$($crate::client!(@process_policy_builder $builder, $($rest)*);)?
	};
	(@process_policy_builder $builder:expr, emitter_gate: $value:expr $(, $($rest:tt)*)?) => {
		$builder = $builder.with_emitter_gate($value);
		$($crate::client!(@process_policy_builder $builder, $($rest)*);)?
	};
	(@process_policy_builder $builder:expr, gate: [ $( $value:expr ),* $(,)? ] $(, $($rest:tt)*)?) => {
		$(
			$builder = $builder.with_emitter_gate($value);
		)*
		$($crate::client!(@process_policy_builder $builder, $($rest)*);)?
	};
	(@process_policy_builder $builder:expr, gate: $value:expr $(, $($rest:tt)*)?) => {
		$builder = $builder.with_emitter_gate($value);
		$($crate::client!(@process_policy_builder $builder, $($rest)*);)?
	};
	(@process_policy_builder $builder:expr, collector_gate: [ $( $value:expr ),* $(,)? ] $(, $($rest:tt)*)?) => {
		$(
			$builder = $builder.with_collector_gate($value);
		)*
		$($crate::client!(@process_policy_builder $builder, $($rest)*);)?
	};
	(@process_policy_builder $builder:expr, collector_gate: $value:expr $(, $($rest:tt)*)?) => {
		$builder = $builder.with_collector_gate($value);
		$($crate::client!(@process_policy_builder $builder, $($rest)*);)?
	};
	(@process_policy_builder $builder:expr, timeout: $value:expr $(, $($rest:tt)*)?) => {
		$builder = $crate::transport::ConnectionBuilder::with_timeout($builder, $value);
		$($crate::client!(@process_policy_builder $builder, $($rest)*);)?
	};
	(@process_policy_builder $builder:expr,) => {};
	(@process_policy_builder $builder:expr) => {};
}
