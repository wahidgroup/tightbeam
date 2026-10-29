use tightbeam::crypto::aead::DecryptContent;
use tightbeam::crypto::cms::AuthEnvelopedData;
use tightbeam::marker::MaybeSendFuture;
use tightbeam::TightBeamError;

/// The decryption of `envelope` beside `arrived`, two values that no decode
/// binds.
fn split<'a>(
	decryptor: &'a impl DecryptContent,
	envelope: &'a AuthEnvelopedData,
	arrived: &'a [u8],
	content: &'a mut [u8],
) -> MaybeSendFuture<'a, Result<(), TightBeamError>> {
	// `decrypt_content` takes the envelope beside the encoding that carries
	// it, as one `WireDer`, so the read of the encoding covers the envelope
	// that the decryptor opens. A call that hands the two apart may not
	// compile.
	decryptor.decrypt_content(envelope, arrived, content)
}

fn main() {}
