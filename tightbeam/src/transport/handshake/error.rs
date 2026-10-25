#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

use crate::Errorizable;

#[cfg(all(
	feature = "instrument",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
use crate::instrumentation::events;
#[cfg(all(
	feature = "instrument",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
use crate::urn::Urn;

/// Errors that a handshake operation returns.
///
/// The handshake reports an invariant violation through one of these variants
/// instead of a panic.
#[derive(Debug, Errorizable)]
#[non_exhaustive]
pub enum HandshakeError {
	/// A public key in the handshake is invalid.
	#[error("Invalid public key in handshake: {0}")]
	#[from]
	InvalidPublicKey(crate::crypto::sign::ecdsa::k256::elliptic_curve::Error),

	/// The server sent its static key, or the negation of it, as its
	/// ephemeral. The agreement would then collapse into the static one, which
	/// the server's key recovers, so the client refuses it.
	#[error("Server ephemeral equals the server static key")]
	ServerEphemeralIsStatic,

	/// The client sent its static key, or the negation of it, as an ephemeral
	/// of the handshake or of a rekey. The agreement would then collapse into
	/// the static one, which the client's key recovers, so the server refuses
	/// it.
	#[error("Client ephemeral equals the client static key")]
	ClientEphemeralIsStatic,

	/// The peer certificate failed validation.
	#[error("Invalid certificate: {0}")]
	#[from]
	CertificateValidationError(crate::crypto::x509::error::CertificateValidationError),

	/// The handshake signature failed verification.
	#[error("Handshake signature verification failed")]
	SignatureVerificationFailed,

	/// A signature failed to parse or to verify.
	#[error("Signature error: {0}")]
	#[from]
	SignatureError(crate::crypto::sign::Error),

	/// The underlying DER encoding or decoding failed.
	#[error("DER error: {0}")]
	#[from]
	DerError(crate::der::Error),

	/// A SubjectPublicKeyInfo (SPKI) value is invalid.
	#[error("SPKI error: {0}")]
	#[from]
	SpkiError(crate::spki::Error),

	/// The key provider failed.
	#[error("Key provider error: {0}")]
	#[from]
	KeyError(crate::crypto::key::KeyError),

	/// The handshake state is invalid for this operation.
	#[error("Invalid handshake state")]
	InvalidState,

	/// The peer sent the other CMS container for this handshake step.
	#[error("Unexpected handshake container for this step")]
	UnexpectedContainer,

	/// No trust store or certificate validator is configured, so the handshake
	/// refuses to validate a peer certificate by its expiry alone.
	#[error("Trust store required: refusing expiry-only peer certificate validation")]
	MissingTrustStore,

	/// The server certificate is missing.
	#[error("Missing server certificate")]
	MissingServerCertificate,

	/// The client certificate is missing.
	#[error("Missing client certificate")]
	MissingClientCertificate,

	/// The signing and the key-agreement certificate of a CMS server name
	/// two subjects.
	#[error("The two server certificates name two subjects")]
	SubjectMismatch,

	/// The signing certificate a CMS server's Finished carries and the
	/// key-agreement certificate its client pins chain to two trust anchors.
	#[error("The two server certificates chain to two trust anchors")]
	AnchorMismatch,

	/// The signing and the key-agreement certificate of a CMS server hold one
	/// key, which would serve two purposes (NIST SP 800-57 Part 1 Rev. 5 §5.2).
	#[error("The two server certificates hold one key")]
	KeyReuse,

	/// A digest output lies outside the widths the handshake admits for a
	/// transcript hash and a key-confirmation tag, `min` to `max` bytes.
	/// `received` is the width of the output, in bytes.
	#[error("Transcript digest length invalid: {received} bytes, outside {min} to {max}")]
	TranscriptDigestLength { min: usize, max: usize, received: usize },

	/// The server requires mutual authentication, and the client has no
	/// identity configured.
	#[error("Server requires mutual authentication but client has no identity")]
	MutualAuthRequired,

	/// A budget-bearing session requires a session receipt, and none arrived.
	#[error("Session receipt required for budget-bearing session but missing")]
	ReceiptMissing,

	/// The session receipt disagrees with the negotiated session parameters.
	#[error("Session receipt does not match the negotiated session")]
	ReceiptMismatch,

	/// A budget-bearing session requires the client countersignature, and it
	/// is missing.
	#[error("Receipt countersignature required for budget-bearing session but missing")]
	CountersignatureMissing,

	/// The client's receipt approver refused the session receipt. `code` is
	/// the refusal code the approver returned.
	#[error("Session receipt refused by approver: code {code}")]
	ApprovalRefused { code: u32 },

	/// The server's authorizer rejected the settlement answer. `code` is the
	/// rejection code the authorizer returned.
	#[error("Settlement rejected: code {code}")]
	SettlementRejected { code: u32 },

	/// The envelope refused to seal or open the receipt acknowledgement under
	/// the key the handshake secret derives. On the opening side the
	/// acknowledgement was sealed under another handshake secret or another
	/// transcript, or altered in flight. The payload is the envelope's refusal.
	#[cfg(feature = "hpke")]
	#[error("Receipt acknowledgement envelope refused: {0}")]
	ReceiptAckCipher(crate::crypto::cms::EnvelopeError),

	/// The envelope refused to seal or open the closing under the key the
	/// handshake secret derives. The closing was sealed under another
	/// handshake secret or another transcript, or altered in flight. The
	/// payload is the envelope's refusal.
	#[cfg(feature = "hpke")]
	#[error("Sealed closing refused: {0}")]
	SealedClosing(crate::crypto::cms::EnvelopeError),

	/// The closing exceeds the padded frame it seals in, or an opened frame
	/// carries a length past its end, a non-zero padding byte, or another
	/// padded length.
	#[error("Sealed frame malformed")]
	SealedFrame,

	/// A key-confirmation tag differs from the tag its receiver derived: the
	/// client's tag in the closing, or the server Finished of the HPKE reply.
	/// The peer holds another handshake secret, or it confirmed another
	/// transcript.
	#[error("Key confirmation failed")]
	KeyConfirmationFailed,

	/// The KDF salt of a traffic-key derivation is below the minimum entropy
	/// requirement. `actual` is the salt length and `minimum` is the required
	/// length, both in bytes.
	#[error("KDF salt too short: {actual} bytes (minimum {minimum} required)")]
	InsufficientSaltEntropy { actual: usize, minimum: usize },

	/// The peer sent an abort alert during the handshake.
	#[error("Handshake aborted by peer: {0:?}")]
	AbortReceived(crate::transport::handshake::HandshakeAlert),

	/// The server selected no profile, or one that the client did not offer.
	#[error("Server selected no profile, or one outside the client's offer")]
	InvalidProfileSelection,

	/// Profile negotiation failed.
	#[error("Profile negotiation failed: {0}")]
	#[from]
	NegotiationError(crate::transport::handshake::negotiation::NegotiationError),

	/// The server has no supported profile configured, so it can select none.
	#[error("No supported profiles configured on server")]
	NoSupportedProfiles,

	/// An attribute holds more or fewer than one value.
	#[error("Attribute must contain exactly one value")]
	InvalidAttributeArity,
	/// An attribute appears more than once.
	#[error("Duplicate attribute present")]
	DuplicateAttribute,
	/// A required attribute is missing.
	#[error("Required attribute missing")]
	MissingAttribute,
	/// An OCTET STRING has the wrong length.
	#[error("OCTET STRING length mismatch: {0}")]
	OctetStringLengthError(crate::error::ReceivedExpectedError<usize, usize>),
	/// A version or alert value is not a valid INTEGER.
	#[error("Version/alert value not valid INTEGER")]
	InvalidIntegerEncoding,
	/// An INTEGER is out of range.
	#[error("INTEGER out of range")]
	IntegerOutOfRange,
	/// The alert code is unknown.
	#[error("Unknown alert code: {0:?}")]
	UnknownAlertCode(u8),

	/// An HPKE operation failed.
	#[cfg(feature = "hpke")]
	#[error("HPKE operation failed: {0}")]
	#[from]
	HpkeError(crate::crypto::hpke::HpkeError),
	/// The authenticated envelope of a CMS opening fails to open, or an
	/// envelope fails to seal.
	#[cfg(feature = "hpke")]
	#[error("Authenticated envelope refused: {0}")]
	#[from]
	Envelope(crate::crypto::cms::EnvelopeError),

	/// A KDF operation failed.
	#[error("KDF operation failed: {0}")]
	#[from]
	KdfError(crate::crypto::kdf::KdfError),
	/// A key has an invalid size. `expected` and `received` are the required
	/// and the actual key length in bytes.
	#[error("Invalid key size: expected {expected}, got {received}")]
	InvalidKeySize { expected: usize, received: usize },

	/// Random generation failed.
	#[error("Random generation failed")]
	RandomGenerationFailed,

	/// Cryptographic key or nonce material has the wrong length.
	#[error("Invalid key material length: {0}")]
	#[from]
	InvalidKeyMaterialLength(crypto_common::InvalidLength),

	/// A crate error that names no handshake fault, kept whole.
	/// [`Error::source`](core::error::Error::source) returns it as the cause.
	#[error("Crate error during the handshake")]
	#[source]
	Other(Box<crate::error::TightBeamError>),
}

#[cfg(all(
	feature = "instrument",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
impl HandshakeError {
	/// Returns the audit event a failed handshake records for this error, when
	/// the error names one.
	///
	/// - A receipt approval or settlement refusal records
	///   [`SESSION_RECEIPT_REFUSED`](events::SESSION_RECEIPT_REFUSED).
	/// - A refused peer certificate or client Finished, including a
	///   certificate the peer did not present and a closing or frame that
	///   fails to open, records
	///   [`SESSION_CERT_REJECTED`](events::SESSION_CERT_REJECTED).
	/// - A crate error that names no handshake fault records [`ERROR`](events::ERROR).
	pub(crate) fn audit_event(&self) -> Option<Urn<'static>> {
		match self {
			Self::ApprovalRefused { .. } | Self::SettlementRejected { .. } => Some(events::SESSION_RECEIPT_REFUSED),
			Self::CertificateValidationError(_)
			| Self::SignatureVerificationFailed
			| Self::MissingClientCertificate
			| Self::SealedClosing(_)
			| Self::SealedFrame
			| Self::MutualAuthRequired => Some(events::SESSION_CERT_REJECTED),
			Self::Other(_) => Some(events::ERROR),
			_ => None,
		}
	}
}

/// Narrows [`TightBeamError`](crate::error::TightBeamError) into
/// [`HandshakeError`].
///
/// A variant with a handshake counterpart becomes that counterpart. Any other
/// variant becomes [`HandshakeError::Other`], which keeps it as the source, so
/// the conversion reports a handshake fault only when the error names one.
impl From<crate::error::TightBeamError> for HandshakeError {
	fn from(err: crate::error::TightBeamError) -> Self {
		use crate::error::TightBeamError;
		match err {
			TightBeamError::HandshakeError(h) => h,
			TightBeamError::SerializationError(e) => HandshakeError::DerError(e),
			TightBeamError::SpkiError(e) => HandshakeError::SpkiError(e),
			TightBeamError::CertificateValidationError(e) => HandshakeError::CertificateValidationError(e),
			TightBeamError::KeyError(e) => HandshakeError::KeyError(e),
			TightBeamError::SignatureError(e) => HandshakeError::SignatureError(e),
			TightBeamError::SignatureEncodingError => HandshakeError::SignatureVerificationFailed,
			TightBeamError::Signer(e) => HandshakeError::from(e),
			TightBeamError::EllipticCurveError(e) => HandshakeError::InvalidPublicKey(e),
			TightBeamError::KeyDerivationError(e) => HandshakeError::KdfError(e),
			TightBeamError::InvalidKeyLength(e) => HandshakeError::InvalidKeyMaterialLength(e),
			#[cfg(feature = "hpke")]
			TightBeamError::HpkeError(e) => HandshakeError::HpkeError(e),
			#[cfg(feature = "hpke")]
			TightBeamError::EnvelopeError(e) => HandshakeError::Envelope(e),
			TightBeamError::OsRngError(_) => HandshakeError::RandomGenerationFailed,
			other => HandshakeError::Other(Box::new(other)),
		}
	}
}

/// Narrows a CMS signer error into [`HandshakeError`].
///
/// An encoding, key, or certificate failure keeps its variant. Every other
/// refusal of a signature, its signer, its version, or its signed attributes
/// is [`HandshakeError::SignatureVerificationFailed`], the one verdict both
/// flows report for a signature they refuse.
impl From<crate::crypto::sign::SignerError> for HandshakeError {
	fn from(err: crate::crypto::sign::SignerError) -> Self {
		use crate::crypto::sign::SignerError;

		match err {
			SignerError::Encoding(e) => HandshakeError::DerError(e),
			SignerError::PublicKey(e) => HandshakeError::SpkiError(e),
			SignerError::Key(e) => HandshakeError::KeyError(e),
			SignerError::Certificate(e) => HandshakeError::CertificateValidationError(e),
			_ => HandshakeError::SignatureVerificationFailed,
		}
	}
}

#[cfg(all(
	test,
	feature = "instrument",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
mod tests {
	use super::*;
	use crate::crypto::cms::EnvelopeError;
	use crate::crypto::kdf::KdfError;
	use crate::crypto::sign::{elliptic_curve, SignerError};
	use crate::error::ReceivedExpectedError;
	use crate::TightBeamError;

	#[test]
	fn a_missing_client_certificate_is_a_certificate_rejection() {
		let event = HandshakeError::MissingClientCertificate.audit_event();
		assert_eq!(event, Some(events::SESSION_CERT_REJECTED));
	}

	/// A closing that fails to open names no certificate the server could
	/// check, so it records the refusal of an unproven identity.
	#[test]
	fn a_sealed_identity_that_fails_to_open_is_a_certificate_rejection() {
		let event = HandshakeError::SealedClosing(EnvelopeError::Authentication).audit_event();
		assert_eq!(event, Some(events::SESSION_CERT_REJECTED));
	}

	#[test]
	fn a_refused_approval_is_a_receipt_refusal() {
		let event = HandshakeError::ApprovalRefused { code: 7 }.audit_event();
		assert_eq!(event, Some(events::SESSION_RECEIPT_REFUSED));
	}

	#[test]
	fn a_state_error_records_no_audit_event() {
		assert_eq!(HandshakeError::InvalidState.audit_event(), None);
	}

	/// A crate error with no handshake counterpart keeps its cause, so the
	/// conversion reports no state fault.
	#[test]
	fn an_unmapped_crate_error_reads_back_through_its_source() -> Result<(), Box<dyn core::error::Error>> {
		let error = HandshakeError::from(TightBeamError::MissingEncryptionInfo);
		let source = core::error::Error::source(&error).ok_or("the conversion keeps the cause")?;

		let downcast = source.downcast_ref::<Box<TightBeamError>>();
		let cause = downcast.ok_or("the cause is the crate error")?;
		assert!(matches!(**cause, TightBeamError::MissingEncryptionInfo));
		Ok(())
	}

	/// The widths that a shared-secret length error of the KDF holds, or
	/// `None` for every other error.
	fn held_width(error: HandshakeError) -> Option<ReceivedExpectedError<usize, usize>> {
		match error {
			HandshakeError::KdfError(KdfError::InvalidSharedSecretLength(held)) => Some(held),
			_ => None,
		}
	}

	/// A key derivation failure has a handshake counterpart, so it keeps its
	/// kind.
	#[test]
	fn a_key_derivation_failure_converts_to_its_counterpart() {
		let width = ReceivedExpectedError { received: 16, expected: 32 };
		let failure = KdfError::InvalidSharedSecretLength(width.clone());
		let error = HandshakeError::from(TightBeamError::KeyDerivationError(failure));
		assert_eq!(held_width(error), Some(width));
	}

	/// A signature that fails to encode is a signature the handshake refuses.
	#[test]
	fn a_signature_encoding_failure_is_a_failed_verification() {
		let error = HandshakeError::from(TightBeamError::SignatureEncodingError);
		assert!(matches!(error, HandshakeError::SignatureVerificationFailed));
	}

	/// A signer error that the crate error carries whole converts as the
	/// signer conversion converts it.
	#[test]
	fn a_carried_signer_error_converts_as_a_signer_refusal() {
		let error = HandshakeError::from(TightBeamError::Signer(SignerError::SignerIdentifier));
		assert!(matches!(error, HandshakeError::SignatureVerificationFailed));
	}

	/// A curve failure is an invalid public key.
	#[test]
	fn a_curve_failure_is_an_invalid_public_key() {
		let error = HandshakeError::from(TightBeamError::EllipticCurveError(elliptic_curve::Error));
		assert!(matches!(error, HandshakeError::InvalidPublicKey(_)));
	}

	/// Key material of the wrong length keeps its kind.
	#[test]
	fn an_invalid_key_length_converts_to_its_counterpart() {
		let error = HandshakeError::from(TightBeamError::InvalidKeyLength(crypto_common::InvalidLength));
		assert!(matches!(error, HandshakeError::InvalidKeyMaterialLength(_)));
	}

	#[test]
	fn an_unmapped_crate_error_records_the_generic_failure() {
		let event = HandshakeError::from(TightBeamError::MissingEncryptionInfo).audit_event();
		assert_eq!(event, Some(events::ERROR));
	}
}
