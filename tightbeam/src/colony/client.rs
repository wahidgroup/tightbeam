//! Client-side submission of cluster work.
//!
//! The unary work plane is request-reply. [`SubmitWork`] nests the client's
//! complete end-to-end [`Frame`] in a hop-local [`ClusterWorkRequest`] and
//! unwraps the [`ClusterWorkResponse`] envelope of the reply. A caller sends
//! one frame and receives the servlet's complete response frame.
//!
//! The returned frame is the servlet's end-to-end envelope. Verify its
//! signature with [`Frame::verify`] before you trust the message body.

use crate::asn1::Frame;
use crate::colony::protocol::{ClusterWorkRequest, ClusterWorkResponse};
use crate::error::TightBeamError;
use crate::transport::client::GenericClient;
use crate::transport::protocols::Protocol;
use crate::transport::MessageEmitter;
use crate::urn::Urn;

use core::hash::Hash;

use crate::transport::client::PooledClient;
use crate::transport::multiplex::MuxConnector;
use crate::transport::policy::PolicyConfig;
use crate::transport::protocols::PersistentConnection;
use crate::transport::MessageCollector;

/// Submit unary work to a cluster gateway and receive the servlet's
/// complete response frame.
///
/// The transport clients implement it, so work submission is one method
/// call on an established connection. A refusal surfaces as
/// [`TightBeamError::WorkRefused`] with the gateway's transit status.
pub trait SubmitWork {
	/// Sends `work`, the client's complete end-to-end frame, to the servlet
	/// type `servlet_type` and returns the servlet's complete response frame.
	///
	/// The gateway forwards `work` and the servlet's reply byte-for-byte, so
	/// the signature, integrity, and previous-frame linkage of each frame stay
	/// verifiable at its receiver. Verify the reply with [`Frame::verify`]
	/// before you decode the message body.
	#[allow(async_fn_in_trait)]
	async fn submit_work_to(&mut self, servlet_type: Urn<'static>, work: &Frame) -> Result<Frame, TightBeamError>;
}

impl<P> SubmitWork for GenericClient<P>
where
	P: Protocol,
	P::Transport: MessageEmitter,
{
	async fn submit_work_to(&mut self, servlet_type: Urn<'static>, work: &Frame) -> Result<Frame, TightBeamError> {
		let frame = ClusterWorkRequest::transport_frame(servlet_type, work)?;
		let reply = self.emit(frame, None).await?;
		ClusterWorkResponse::served_reply(reply)
	}
}

impl<P> SubmitWork for PooledClient<P>
where
	P: Protocol + PersistentConnection + Send + Sync,
	P::Address: Hash + Eq + Clone + Send + Sync,
	P::Transport: MessageEmitter + MessageCollector + PolicyConfig + MuxConnector + Send + Sync,
{
	async fn submit_work_to(&mut self, servlet_type: Urn<'static>, work: &Frame) -> Result<Frame, TightBeamError> {
		let frame = ClusterWorkRequest::transport_frame(servlet_type, work)?;
		let reply = self.emit(frame, None).await?;
		ClusterWorkResponse::served_reply(reply)
	}
}
