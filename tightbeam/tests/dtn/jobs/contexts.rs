use std::sync::Arc;

use tightbeam::{
	crypto::sign::ecdsa::Secp256k1SigningKey,
	transport::{tcp::r#async::TokioListener, ConnectionPool},
};

use crate::dtn::{certs::SharedCipher, frame_builder::FrameBuilderHelper};

/// The shared state of the gap recovery jobs, which build a frame request and
/// send it to the upstream hop.
#[derive(Clone)]
pub struct GapRecoveryContext {
	/// The frame builder that builds the frame request.
	pub frame_builder: Arc<FrameBuilderHelper>,
	/// The key that signs the frame request.
	pub signing_key: Arc<Secp256k1SigningKey>,
	/// The cipher that seals the frame request.
	pub cipher: Arc<SharedCipher>,
	/// The pool that dials the upstream hop.
	pub pool: Arc<ConnectionPool<TokioListener>>,
}
