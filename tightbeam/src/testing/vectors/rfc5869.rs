//! The test cases of RFC 5869 Appendix A that run HKDF over SHA-256.
//!
//! # Sources
//!
//! - RFC 5869 (May 2010), Appendix A, test cases A.1 to A.3:
//!   <https://www.rfc-editor.org/rfc/rfc5869#appendix-A>

/// One HKDF-SHA-256 test case of RFC 5869 Appendix A, each octet string in
/// hex.
pub struct HkdfVector {
	/// The input keying material, `IKM`.
	pub ikm: &'static str,
	/// The salt of the extract step. An empty string is a salt of no octets.
	pub salt: &'static str,
	/// The context and application specific information of the expand step,
	/// `info`.
	pub info: &'static str,
	/// The length of the output keying material, `L`, in octets.
	pub length: usize,
	/// The pseudorandom key that the extract step outputs, `PRK`.
	pub prk: &'static str,
	/// The output keying material, `OKM`, of [`Self::length`] octets.
	pub okm: &'static str,
}

/// RFC 5869 A.1, the basic test case.
pub const RFC_5869_A_1: HkdfVector = HkdfVector {
	ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
	salt: "000102030405060708090a0b0c",
	info: "f0f1f2f3f4f5f6f7f8f9",
	length: 42,
	prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
	okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
};

/// RFC 5869 A.2, longer inputs and outputs.
pub const RFC_5869_A_2: HkdfVector = HkdfVector {
	ikm: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
		202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
	salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
		808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
	info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
		d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
	length: 82,
	prk: "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
	okm: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
		59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
};

/// RFC 5869 A.3, a salt and an `info` of no octets.
pub const RFC_5869_A_3: HkdfVector = HkdfVector {
	ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
	salt: "",
	info: "",
	length: 42,
	prk: "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
	okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
};
