//! Multiplexed transport integration tests.
//!
//! Drives ECIES handshakes with transport negotiation over TCP,
//! assembles `MuxTransport` routers from the split halves, and verifies
//! stream concurrency, lifecycle, cleartext parity, ping, and credit.

#![cfg(all(
	feature = "transport-ecies",
	feature = "transport-policy",
	feature = "tcp",
	feature = "tokio",
	feature = "testing",
	feature = "testing-csp"
))]

/// DER of `Mux(Open { stream_id: 1, last: true, payload: [] })`.
///
/// Pins the wire format from both sides: mux build asserts the encoder
/// produces exactly these bytes, non-mux build asserts they fail to
/// decode.
const MUX_OPEN_WIRE_DER: [u8; 14] = [
	0xA4, 0x0C, 0xA0, 0x0A, 0x30, 0x08, 0x02, 0x01, 0x01, 0x01, 0x01, 0xFF, 0x04, 0x00,
];

#[cfg(feature = "transport-multiplex")]
mod common;

#[cfg(feature = "transport-multiplex")]
mod streams;

#[cfg(feature = "transport-multiplex")]
mod lifecycle;

#[cfg(feature = "transport-multiplex")]
mod cleartext;

#[cfg(feature = "transport-multiplex")]
mod ping;

#[cfg(feature = "transport-multiplex")]
mod credit;

mod wire;
