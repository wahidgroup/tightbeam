//! Writer-queue command protocol: the one vocabulary every producer
//! (handle, sinks, reader, responder) shares with the writer driver.

use futures::channel::mpsc;

use crate::transport::envelopes::{MuxEnvelope, TransportEnvelope};

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::aead::SendCipher;

pub enum Outbound {
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

impl Outbound {
	/// Whether this command is a buffered credit grant for `stream_id`.
	pub(crate) fn is_credit_grant_for(&self, stream_id: u32) -> bool {
		matches!(
			self,
			Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Credit(package)))
				if package.stream_id() == stream_id
		)
	}

	/// Whether this command is a buffered ping ack.
	pub(crate) fn is_ping_ack(&self) -> bool {
		matches!(self, Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Ping(_))))
	}
}

/// Exclusive outbound handle for `SinkExt::send` / `try_send`.
/// `mpsc::Sender` is Arc-backed so this is a refcount bump.
pub fn outbound_handle(outbound: &mpsc::Sender<Outbound>) -> mpsc::Sender<Outbound> {
	outbound.clone()
}
