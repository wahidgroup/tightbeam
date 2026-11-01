//! `TransportEnvelope::from_der` against arbitrary bytes.
//!
//! The transport envelope wraps every frame on the wire, so it is decoded
//! before the frame inside it is. Its contract is the same as the frame
//! decoder's: malformed input produces a typed error, and a decoded envelope
//! has one encoding, the octets it came from.
//!
//! Run with:
//!   cargo afl build --bin fuzz_envelope_der --features "std,testing-fuzz,transport"
//!   cargo afl fuzz -i tightbeam/fuzz/envelope_der/seeds -o fuzz_out \
//!     target/debug/fuzz_envelope_der

#![allow(unexpected_cfgs)]
#![cfg(all(feature = "std", feature = "testing-fuzz", feature = "transport"))]

use tightbeam::tb_scenario;
use tightbeam::testing::fuzz::assert_one_encoding;
use tightbeam::transport::TransportEnvelope;

tb_scenario! {
	fuzz: afl,
	raw: |data: &[u8]| {
		assert_one_encoding::<TransportEnvelope>(data);
	}
}
