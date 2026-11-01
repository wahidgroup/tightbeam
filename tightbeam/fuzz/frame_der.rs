//! `Frame::from_der` against arbitrary bytes.
//!
//! The wire decoder is the widest untrusted-input boundary the library has:
//! every byte a peer sends reaches it before any policy runs. Its contract is
//! that malformed input produces a typed error, and that a decoded frame has
//! one encoding, the octets it came from.
//!
//! Run with:
//!   cargo afl build --bin fuzz_frame_der --features "std,testing-fuzz"
//!   cargo afl fuzz -i tightbeam/fuzz/frame_der/seeds -o fuzz_out \
//!     target/debug/fuzz_frame_der

#![allow(unexpected_cfgs)]
#![cfg(all(feature = "std", feature = "testing-fuzz"))]

use tightbeam::asn1::Frame;
use tightbeam::tb_scenario;
use tightbeam::testing::fuzz::assert_one_encoding;

tb_scenario! {
	fuzz: afl,
	raw: |data: &[u8]| {
		assert_one_encoding::<Frame>(data);
	}
}
