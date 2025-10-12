#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

pub mod sync;

#[cfg(feature = "tokio")]
pub mod r#async;

use crate::transport::TransportError;

#[cfg(feature = "tokio")]
pub use crate::transport::tcp::r#async::*;

/// Abstract TCP stream trait for different networking backends
pub trait TcpStreamTrait: Send {
	type Error: Into<TransportError>;

	fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error>;
	fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error>;
}

/// Abstract TCP listener trait for different networking backends
pub trait TcpListenerTrait: Send {
	type Stream: TcpStreamTrait;
	type Error: Into<TransportError>;

	#[cfg(feature = "std")]
	fn accept(&self) -> Result<(Self::Stream, std::net::SocketAddr), Self::Error>;

	#[cfg(not(feature = "std"))]
	fn accept(&self) -> Result<(Self::Stream, SocketAddr), Self::Error>;
}

/// Socket address abstraction for no_std environments
#[cfg(not(feature = "std"))]
#[derive(Debug, Clone)]
pub enum SocketAddr {
	V4 { ip: [u8; 4], port: u16 },
	V6 { ip: [u8; 16], port: u16 },
}

/// Macro to generate common transport implementation for both sync and async.
#[macro_export]
macro_rules! impl_tcp_common {
    ($transport:ident, $stream_trait:path) => {
        #[cfg(not(feature = "transport-policy"))]
        impl<S: $stream_trait> From<S> for $transport<S>
        where
            TransportError: From<S::Error>,
        {
            fn from(stream: S) -> Self {
                Self {
                    stream,
                    handler: None,
                }
            }
        }

        #[cfg(feature = "transport-policy")]
        impl<S: $stream_trait> From<S> for $transport<S>
        where
            TransportError: From<S::Error>,
        {
            fn from(stream: S) -> Self {
				use $crate::policy::AcceptAllGate;
                use $crate::transport::policy::NoRestart;
                Self {
                    stream,
                    restart_policy: Box::new(NoRestart),
                    emitter_gate: Box::new(AcceptAllGate),
                    collector_gate: Box::new(AcceptAllGate),
                    handler: None,
                }
            }
        }

        impl<S: $stream_trait> $crate::transport::ResponseHandler for $transport<S>
        where
            TransportError: From<S::Error>,
        {
            fn with_handler<F>(mut self, handler: F) -> Self
            where
                F: Fn($crate::Frame) -> Option<$crate::Frame> + Send + 'static,
            {
                self.handler = Some(Box::new(handler));
                self
            }

            fn handler(&self) -> Option<&(dyn Fn($crate::Frame) -> Option<$crate::Frame> + Send)> {
                self.handler.as_ref().map(|h| h.as_ref())
            }
        }

        #[cfg(feature = "transport-policy")]
        impl<S: $stream_trait> $crate::transport::policy::PolicyConfiguration for $transport<S>
        where
            TransportError: From<S::Error>,
        {
            fn with_restart_policy<P: RestartPolicy + 'static>(mut self, policy: P) -> Self {
                self.restart_policy = Box::new(policy);
                self
            }

            fn with_emitter_gate<G: GatePolicy + 'static>(mut self, gate: G) -> Self {
                self.emitter_gate = Box::new(gate);
                self
            }

            fn with_collector_gate<G: GatePolicy + 'static>(mut self, gate: G) -> Self {
                self.collector_gate = Box::new(gate);
                self
            }
        }

        #[cfg(feature = "transport-policy")]
        impl<S: $stream_trait> $crate::transport::MessageEmitter for $transport<S>
        where
            TransportError: From<S::Error>,
        {
            type EmitterGate = dyn GatePolicy;
            type RestartPolicy = dyn RestartPolicy;

            fn get_restart_policy(&self) -> &Self::RestartPolicy {
                self.restart_policy.as_ref()
            }

            fn get_emitter_gate_policy(&self) -> &Self::EmitterGate {
                self.emitter_gate.as_ref()
            }
        }

        #[cfg(feature = "transport-policy")]
        impl<S: $stream_trait> $crate::transport::MessageCollector for $transport<S>
        where
            TransportError: From<S::Error>,
        {
            type CollectorGate = dyn GatePolicy;

            fn collector_gate(&self) -> &Self::CollectorGate {
                self.collector_gate.as_ref()
            }
        }

        #[cfg(not(feature = "transport-policy"))]
        impl<S: $stream_trait> $crate::transport::MessageEmitter for $transport<S>
        where
            TransportError: From<S::Error>
        {}

        #[cfg(not(feature = "transport-policy"))]
        impl<S: $stream_trait> $crate::transport::MessageCollector for $transport<S>
        where
            TransportError: From<S::Error>
        {}
    };
}
