#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::cms::enveloped_data::EnvelopedData;
use crate::der::{Decode, Encode, Enumerated};
use crate::zeroize::Zeroizing;
use k256::{PublicKey, SecretKey};

/// Handshake phase enumeration
#[repr(u8)]
#[derive(Enumerated, Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakePhase {
	#[default]
	ClientHello = 0,
	ServerHello = 1,
	ClientAck = 2,
	ServerAck = 3,
}

/// Handshake message containing phase and encrypted payload
#[derive(der::Sequence, Debug, Clone, PartialEq)]
pub struct HandshakeMessage {
	pub phase: HandshakePhase,
	pub enveloped_data: EnvelopedData,
}

/// Session state tracking handshake progress
#[derive(Debug, Default, Clone)]
pub struct HandshakeState {
	pub phase: HandshakePhase,
	pub client_pubkey: Option<PublicKey>,
	pub server_pubkey: Option<PublicKey>,
	pub shared_key: Option<Zeroizing<Vec<u8>>>,
	pub completed: bool,
}

impl HandshakeState {
	/// Check if handshake is complete
	pub fn is_complete(&self) -> bool {
		self.completed
	}

	/// Get the shared key (only available after handshake completion)
	pub fn shared_key(&self) -> Option<&[u8]> {
		self.shared_key.as_deref().map(Vec::as_slice)
	}
}

/// Handshake initiator (client-side)
pub struct HandshakeClient {
	secret_key: SecretKey,
	state: HandshakeState,
}
