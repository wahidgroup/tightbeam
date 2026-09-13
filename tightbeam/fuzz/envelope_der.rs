//! `TransportEnvelope::from_der` against arbitrary bytes.
//!
//! The transport envelope wraps every frame on the wire, so it is decoded
//! before the frame inside it is. Its contract is the same as the frame
//! decoder's: malformed input produces a typed error.
//!
//! Run with:
//!   cargo afl build --bin fuzz_envelope_der --features "std,testing-fuzz,transport"
//!   cargo afl fuzz -i fuzz_in -o fuzz_out target/debug/fuzz_envelope_der

#![allow(unexpected_cfgs)]
#![cfg(all(feature = "std", feature = "testing-fuzz", feature = "transport"))]

use tightbeam::der::Decode;
use tightbeam::tb_scenario;
use tightbeam::transport::TransportEnvelope;

tb_scenario! {
	fuzz: afl,
	raw: |data: &[u8]| {
		// Either answer is correct. The target is the absence of a third
		// outcome, so the decoded value has no reader.
		let _decoded = TransportEnvelope::from_der(data);
	}
}
