use crate::{
	cms::{content_info::CmsVersion, signed_data::EncapsulatedContentInfo},
	error::CompressionResult,
	spki::AlgorithmIdentifierOwned,
	CompressedData,
};

/// Trait for compressing data
pub trait Compressor {
	/// Compress data and return the compressed bytes along with compression metadata
	fn compress(
		&self,
		data: &[u8],
		content_info: Option<EncapsulatedContentInfo>,
	) -> CompressionResult<(Vec<u8>, CompressedData)>;
}

/// Trait for decompressing data
pub trait Inflator {
	/// Decompress data and return the decompressed bytes along with compression metadata
	fn decompress(&self, data: &[u8]) -> CompressionResult<Vec<u8>>;
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZstdCompression;

impl Compressor for ZstdCompression {
	fn compress(
		&self,
		data: &[u8],
		content_info: Option<EncapsulatedContentInfo>,
	) -> CompressionResult<(Vec<u8>, CompressedData)> {
		use std::io::Cursor;

		let mut output: Vec<u8> = vec![];
		let mut encoder = zeekstd::Encoder::new(&mut output)?;
		std::io::copy(&mut Cursor::new(data), &mut encoder)?;
		encoder.finish()?;

		let compression_alg = AlgorithmIdentifierOwned::from(ZstdCompression);
		let encap_content_info = content_info
			.unwrap_or(EncapsulatedContentInfo { econtent_type: crate::asn1::COMPRESSION_CONTENT_OID, econtent: None });
		let compressed_data = CompressedData { version: CmsVersion::V0, compression_alg, encap_content_info };

		Ok((output, compressed_data))
	}
}

impl Inflator for ZstdCompression {
	fn decompress(&self, data: &[u8]) -> CompressionResult<Vec<u8>> {
		use std::io::Cursor;

		let cursor = Cursor::new(data);
		let mut decoder = zeekstd::Decoder::new(cursor)?;
		let mut out: Vec<u8> = Vec::new();

		std::io::copy(&mut decoder, &mut out)?;
		Ok(out)
	}
}

impl From<&ZstdCompression> for AlgorithmIdentifierOwned {
	fn from(_: &ZstdCompression) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: crate::asn1::COMPRESSION_ZSTD_OID, parameters: None }
	}
}

impl From<ZstdCompression> for AlgorithmIdentifierOwned {
	fn from(_: ZstdCompression) -> AlgorithmIdentifierOwned {
		(&ZstdCompression).into()
	}
}
