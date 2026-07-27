//! Writer-queue command protocol: the one vocabulary every producer
//! (handle, sinks, reader, responder) shares with the writer driver.

use futures::channel::mpsc;

use crate::transport::envelopes::TransportEnvelope;

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::aead::SendCipher;

pub(super) enum Outbound {
	Envelope(TransportEnvelope),
	/// Write the envelope, then switch the send direction to the new
	/// epoch cipher (client `RekeyAck` / server `RekeyDone` boundary,
	/// [RFC 9846 § 4.7.3](https://datatracker.ietf.org/doc/html/rfc9846#section-4.7.3)).
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	EnvelopeThenInstall(TransportEnvelope, Box<SendCipher>),
	/// Budget-watermark renewal trigger from a handle: the writer
	/// opens the exchange.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	StartRenewal,
	Close,
}

/// Exclusive outbound handle for `SinkExt::send` / `try_send`.
/// `mpsc::Sender` is Arc-backed so this is a refcount bump.
pub(super) fn outbound_handle(outbound: &mpsc::Sender<Outbound>) -> mpsc::Sender<Outbound> {
	outbound.clone()
}
