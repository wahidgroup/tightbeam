use std::sync::Arc;

use tightbeam::{
	crypto::sign::ecdsa::Secp256k1SigningKey,
	transport::{tcp::r#async::TokioListener, ConnectionPool},
};

use crate::dtn::{certs::SharedCipher, frame_builder::FrameBuilderHelper};

/// The shared state of the gap recovery jobs.
///
/// It holds what the jobs need to build and send a gap recovery frame.
#[derive(Clone)]
pub struct GapRecoveryContext {
	pub frame_builder: Arc<FrameBuilderHelper>,
	pub signing_key: Arc<Secp256k1SigningKey>,
	pub cipher: Arc<SharedCipher>,
	pub pool: Arc<ConnectionPool<TokioListener>>,
}
