//! Multiplexed transport integration tests over ECIES/TCP.

#![cfg(all(
	feature = "transport-ecies",
	feature = "transport-policy",
	feature = "tcp",
	feature = "tokio",
	feature = "testing",
	feature = "testing-csp",
	feature = "instrument"
))]

/// Golden DER for `Mux(Open { stream_id: 1, last: true, kind: Unary, payload: [] })`.
const MUX_OPEN_WIRE_DER: [u8; 17] = [
	0xA4, 0x0F, 0xA0, 0x0D, 0x30, 0x0B, 0x02, 0x01, 0x01, 0x01, 0x01, 0xFF, 0x0A, 0x01, 0x00, 0x04, 0x00,
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

#[cfg(feature = "transport-multiplex")]
mod rekey;

#[cfg(feature = "transport-multiplex")]
mod streaming;

mod wire;
