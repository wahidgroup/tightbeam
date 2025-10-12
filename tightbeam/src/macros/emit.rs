/// Emit macro - one-shot message send
#[macro_export]
macro_rules! emit {
	// Basic: tcp: stream, message: expr
	(tcp: $stream:expr, message: $message:expr) => {{
		async {
			let mut transport = $crate::transport::tcp::TcpTransport::from($stream);
			transport.emit($message, None).await
		}
	}};
}
