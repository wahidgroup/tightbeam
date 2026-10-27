//! The internals of the stream router, split by plane: the connection-wide
//! shared state, the reader and writer drivers, the client handle, the
//! responder loop, the producer sinks, the incremental bodies, and flow
//! control.

mod body;
mod flow;
mod handle;
mod link;
mod outbound;
mod pending;
mod reader;
mod reassembly;
mod responder;
mod shared;
mod sink;
mod transport;
mod writer;

#[cfg(test)]
mod testing;

pub use body::StreamBody;
pub use flow::BufferedGrantor;
pub use handle::MuxHandle;
pub use reader::MuxReaderDriver;
pub use responder::MuxResponder;
pub use sink::{ReplySink, RequestSink};
pub use transport::MuxTransport;
pub use writer::MuxWriterDriver;

#[cfg(feature = "tokio")]
pub use transport::SpawnedMux;
