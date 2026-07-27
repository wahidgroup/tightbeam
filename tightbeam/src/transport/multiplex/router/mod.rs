//! Stream router internals, split by plane: connection-wide shared
//! state, the reader and writer drivers, the client handle, the
//! responder loop, producer sinks, incremental bodies, and flow
//! control.

mod body;
mod flow;
mod handle;
mod outbound;
mod reader;
mod responder;
mod shared;
mod sink;
mod transport;
mod writer;

#[cfg(test)]
mod testing;

pub use body::StreamBody;
pub use flow::{BufferedGrantor, CreditGrantor};
pub use handle::MuxHandle;
pub use reader::MuxReaderDriver;
pub use responder::MuxResponder;
pub use sink::{ReplySink, RequestSink};
pub use transport::MuxTransport;
pub use writer::MuxWriterDriver;

#[cfg(feature = "tokio")]
pub use transport::SpawnedMux;
