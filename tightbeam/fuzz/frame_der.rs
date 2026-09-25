//! `Frame::from_der` against arbitrary bytes.
//!
//! The wire decoder is the widest untrusted-input boundary the library has:
//! every byte a peer sends reaches it before any policy runs. Its contract is
//! that malformed input produces a typed error, so this target holds the
//! decoder to that contract rather than to any particular parse.
//!
//! Run with:
//!   cargo afl build --bin fuzz_frame_der --features "std,testing-fuzz"
//!   cargo afl fuzz -i fuzz_in -o fuzz_out target/debug/fuzz_frame_der

#![allow(unexpected_cfgs)]
#![cfg(all(feature = "std", feature = "testing-fuzz"))]

use tightbeam::asn1::Frame;
use tightbeam::der::Decode;
use tightbeam::tb_scenario;

tb_scenario! {
	fuzz: afl,
	raw: |data: &[u8]| {
		// Either answer is correct. The target is the absence of a third
		// outcome, so the decoded value has no reader.
		let _decoded = Frame::from_der(data);
	}
}
