use std::sync::Arc;

use tightbeam::{
	crypto::{aead::Aes256Gcm, sign::ecdsa::Secp256k1SigningKey},
	transport::{tcp::r#async::TokioListener, ConnectionPool},
};

use crate::dtn::{chain_processor::ChainProcessor, frame_builder::FrameBuilderHelper};

/// Context for gap recovery operations.
///
/// Contains all dependencies needed for building and sending gap recovery frames.
#[derive(Clone)]
pub struct GapRecoveryContext {
	pub chain_processor: Arc<ChainProcessor>,
	pub frame_builder: Arc<FrameBuilderHelper>,
	pub signing_key: Arc<Secp256k1SigningKey>,
	pub cipher: Arc<Aes256Gcm>,
	pub pool: Arc<ConnectionPool<TokioListener, 3>>,
}
