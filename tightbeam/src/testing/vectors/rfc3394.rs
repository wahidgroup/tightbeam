//! The test vectors of RFC 3394 §4: the AES key wrap of 128, 192, and 256 bits
//! of key data under each KEK at least as wide.
//!
//! Each KEK of §4 is the leading octets of `000102...1f`, and each key data is
//! the leading octets of `00112233...0f`.
//!
//! # Sources
//!
//! - RFC 3394 (September 2002), §4.1 to §4.6:
//!   <https://www.rfc-editor.org/rfc/rfc3394#section-4>

/// One key wrap of RFC 3394 §4, each octet string in hex.
pub struct KeyWrapVector {
	/// The key-encryption key, `KEK`.
	pub kek: &'static str,
	/// The key data that the wrap takes.
	pub key_data: &'static str,
	/// The wrap of [`Self::key_data`] under [`Self::kek`].
	pub ciphertext: &'static str,
}

/// RFC 3394 §4.1: 128 bits of key data under a 128-bit KEK.
pub const RFC_3394_4_1: KeyWrapVector = KeyWrapVector {
	kek: "000102030405060708090a0b0c0d0e0f",
	key_data: "00112233445566778899aabbccddeeff",
	ciphertext: "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5",
};

/// RFC 3394 §4.2: 128 bits of key data under a 192-bit KEK.
pub const RFC_3394_4_2: KeyWrapVector = KeyWrapVector {
	kek: "000102030405060708090a0b0c0d0e0f1011121314151617",
	key_data: "00112233445566778899aabbccddeeff",
	ciphertext: "96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d",
};

/// RFC 3394 §4.3: 128 bits of key data under a 256-bit KEK.
pub const RFC_3394_4_3: KeyWrapVector = KeyWrapVector {
	kek: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	key_data: "00112233445566778899aabbccddeeff",
	ciphertext: "64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7",
};

/// RFC 3394 §4.4: 192 bits of key data under a 192-bit KEK.
pub const RFC_3394_4_4: KeyWrapVector = KeyWrapVector {
	kek: "000102030405060708090a0b0c0d0e0f1011121314151617",
	key_data: "00112233445566778899aabbccddeeff0001020304050607",
	ciphertext: "031d33264e15d33268f24ec260743edce1c6c7ddee725a936ba814915c6762d2",
};

/// RFC 3394 §4.5: 192 bits of key data under a 256-bit KEK.
pub const RFC_3394_4_5: KeyWrapVector = KeyWrapVector {
	kek: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	key_data: "00112233445566778899aabbccddeeff0001020304050607",
	ciphertext: "a8f9bc1612c68b3ff6e6f4fbe30e71e4769c8b80a32cb8958cd5d17d6b254da1",
};

/// RFC 3394 §4.6: 256 bits of key data under a 256-bit KEK.
pub const RFC_3394_4_6: KeyWrapVector = KeyWrapVector {
	kek: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	key_data: "00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f",
	ciphertext: "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21",
};
