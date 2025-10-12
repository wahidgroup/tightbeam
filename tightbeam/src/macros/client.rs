/// Client macro - creates a configured transport for multiple emit calls
#[macro_export]
macro_rules! client {
    // Sync: tcp: stream
    (tcp: $stream:expr) => {{
        $crate::transport::tcp::sync::TcpTransport::from($stream)
    }};

    // Sync: tcp: connect "addr"
    (tcp: connect $addr:expr) => {{
        #[cfg(feature = "std")]
        {
            let stream = std::net::TcpStream::connect($addr)?;
            $crate::transport::tcp::sync::TcpTransport::from(stream)
        }
    }};

    // Sync: tcp: stream, policies: {...}
    (tcp: $stream:expr, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }) => {{
        let mut transport = $crate::transport::tcp::sync::TcpTransport::from($stream);
        $(
            transport = $crate::client!(@set_policy transport, $policy_name, $policy_value);
        )*
        transport
    }};

    // Sync: tcp: connect "addr", policies: {...}
    (tcp: connect $addr:expr, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }) => {{
        #[cfg(feature = "std")]
        {
            let stream = std::net::TcpStream::connect($addr)?;
            let mut transport = $crate::transport::tcp::sync::TcpTransport::from(stream);
            $(
                transport = $crate::client!(@set_policy transport, $policy_name, $policy_value);
            )*
            transport
        }
    }};

    // Async: async tcp: stream
    (async tcp: $stream:expr) => {{
        $crate::transport::tcp::r#async::TcpTransportAsync::from($stream)
    }};

	// Async: async tcp: connect "addr"
    (async tcp: connect $addr:expr) => {{
        #[cfg(feature = "tokio")]
        {
            let stream = tokio::net::TcpStream::connect($addr).await?;
            let tokio_stream = $crate::transport::tcp::r#async::TokioStream::from(stream);
            $crate::transport::tcp::r#async::TcpTransportAsync::from(tokio_stream)
        }
    }};

    // Async: async tcp: stream, policies: {...}
    (async tcp: $stream:expr, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }) => {{
        let mut transport = $crate::transport::tcp::r#async::TcpTransportAsync::from($stream);
        $(
            transport = $crate::client!(@set_policy transport, $policy_name, $policy_value);
        )*
        transport
    }};

    // Async: async tcp: connect "addr", policies: {...}
    (async tcp: connect $addr:expr, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }) => {{
        #[cfg(feature = "tokio")]
        async {
            let stream = tokio::net::TcpStream::connect($addr).await
                .map_err(|e| $crate::transport::error::TransportError::from(e))?;
            let tokio_stream = $crate::transport::tcp::r#async::TokioStream::from(stream);
            let transport = $crate::transport::tcp::r#async::TcpTransportAsync::from(tokio_stream);
            $(
                let transport = $crate::client!(@set_policy transport, $policy_name, $policy_value);
            )*
            Ok::<_, $crate::transport::error::TransportError>(transport)
        }
    }};

    // Internal helper to set policies
    (@set_policy $transport:expr, restart_policy, $value:expr) => {
        $transport.with_restart_policy($value)
    };
    // Shorthand: restart -> with_restart_policy(...)
    (@set_policy $transport:expr, restart, $value:expr) => {
        $transport.with_restart_policy($value)
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
