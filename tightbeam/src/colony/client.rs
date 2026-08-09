//! Client-side submission of cluster work.
//!
//! The unary work plane is request-reply. The client nests its complete
//! end-to-end [`Frame`] in a [`ClusterWorkRequest`], the gateway delivers
//! those bytes to the servlet unmodified, and the servlet's complete
//! response frame comes back the same way. [`SubmitWork`] hides the
//! hop-local transport wrapper and the response envelope, so a caller
//! sends one frame and receives one frame.
//!
//! The returned frame is the servlet's end-to-end envelope. Verify its
//! signature with [`Frame::verify`] before trusting the message body.

use crate::asn1::{Frame, Metadata, Version};
use crate::colony::common::messages::{ClusterRequest, ClusterWorkRequest, ClusterWorkResponse};
use crate::error::TightBeamError;
use crate::transport::client::GenericClient;
use crate::transport::protocols::Protocol;
use crate::transport::MessageEmitter;
use crate::utils::urn::Urn;
use crate::utils::{decode, encode};

// Pooled clients only expose `emit` on the multiplexed build (the
// `pooled_mux` cfg alias), which the `colony` feature always satisfies.
#[cfg(pooled_mux)]
mod mux {
	pub use core::hash::Hash;

	pub use crate::crypto::profiles::CryptoProvider;
	pub use crate::transport::client::PooledClient;
	pub use crate::transport::multiplex::MuxConnector;
	pub use crate::transport::policy::PolicyConfig;
	pub use crate::transport::protocols::PersistentConnection;
	pub use crate::transport::{MessageCollector, X509ClientConfig};
}

#[cfg(pooled_mux)]
use mux::*;

/// Submit unary work to a cluster gateway and receive the servlet's
/// complete response frame.
///
/// Implemented by the transport clients, so work submission is one
/// method call on an established connection. A refusal surfaces as
/// [`TightBeamError::WorkRefused`] with the gateway's transit status.
pub trait SubmitWork {
	/// Send `work` (the client's complete end-to-end frame) to the
	/// servlet type addressed by `servlet_type` and return the
	/// servlet's complete response frame.
	///
	/// The gateway forwards `work` byte-for-byte, so its signature,
	/// integrity, and previous-frame linkage stay verifiable at the
	/// servlet. The returned frame is the servlet's envelope with the
	/// same fidelity in the other direction. Verify it with
	/// [`Frame::verify`] before decoding the message body.
	#[allow(async_fn_in_trait)]
	async fn submit_work_to(&mut self, servlet_type: Urn<'static>, work: &Frame) -> Result<Frame, TightBeamError>;
}

/// Wrap `work` in the hop-local transport frame the gateway expects.
///
/// The wrapper is routing plumbing only. It reuses the work frame's id
/// for correlation and carries the encoded [`ClusterRequest::Work`]
/// envelope as its message.
fn work_transport(servlet_type: Urn<'static>, work: &Frame) -> Result<Frame, TightBeamError> {
	let request = ClusterRequest::Work(ClusterWorkRequest::new(servlet_type, work)?);

	let mut metadata = Metadata::default();
	metadata.id = work.metadata.id.clone();

	Ok(Frame {
		version: Version::V0,
		metadata,
		message: encode(&request)?,
		integrity: None,
		nonrepudiation: None,
	})
}

/// Unwrap the gateway's reply down to the servlet's response frame.
fn served_reply(reply: Option<Frame>) -> Result<Frame, TightBeamError> {
	let reply = reply.ok_or(TightBeamError::MissingResponse)?;
	let response: ClusterWorkResponse = decode(&reply.message)?;

	response.served()
}

impl<P> SubmitWork for GenericClient<P>
where
	P: Protocol,
	P::Transport: MessageEmitter,
{
	async fn submit_work_to(&mut self, servlet_type: Urn<'static>, work: &Frame) -> Result<Frame, TightBeamError> {
		let reply = self.emit(work_transport(servlet_type, work)?, None).await?;
		served_reply(reply)
	}
}

#[cfg(pooled_mux)]
impl<P, C> SubmitWork for PooledClient<P, C>
where
	P: Protocol + PersistentConnection + Send + Sync,
	C: CryptoProvider + Send + Sync + 'static,
	P::Address: Hash + Eq + Clone + Send + Sync,
	P::Transport: MessageEmitter
		+ MessageCollector
		+ PolicyConfig
		+ X509ClientConfig<CryptoProvider = C>
		+ MuxConnector
		+ Send
		+ Sync,
{
	async fn submit_work_to(&mut self, servlet_type: Urn<'static>, work: &Frame) -> Result<Frame, TightBeamError> {
		let reply = self.emit(work_transport(servlet_type, work)?, None).await?;
		served_reply(reply)
	}
}
