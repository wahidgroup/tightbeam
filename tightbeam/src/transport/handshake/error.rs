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
use crate::trace::TraceCollector;
#[cfg(all(
	feature = "instrument",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
use crate::transport::handshake::negotiation::NegotiationError;
#[cfg(all(
	feature = "instrument",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
use crate::TightBeamError;

/// The errors that a handshake operation returns.
///
/// An invariant violation returns one of these variants, not a panic.
#[derive(Debug, Errorizable)]
#[non_exhaustive]
pub enum HandshakeError {
	/// A public key in the handshake is invalid.
	#[error("Invalid public key in handshake: {0}")]
	#[from]
	InvalidPublicKey(crate::crypto::sign::ecdsa::k256::elliptic_curve::Error),

	/// The exchange refuses a key share for its width, its encoding, or its
	/// algorithm, or refuses it as it runs.
	#[error("Key share refused: {0}")]
	#[from]
	KeyExchange(crate::crypto::exchange::KeyExchangeError),

	/// The server sent a share that collapses into its static key. The
	/// agreement would collapse into the static one, which the server's key
	/// recovers, so the client refuses it.
	#[error("Server ephemeral equals the server static key")]
	ServerEphemeralIsStatic,

	/// The client sent a share that collapses into its static key, in the
	/// handshake or in a rekey. The agreement would collapse into the static
	/// one, which the client's key recovers, so the server refuses it.
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

	/// The DER encoding or decoding failed.
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
	/// key for two purposes (NIST SP 800-57 Part 1 Rev. 5 §5.2).
	#[error("The two server certificates hold one key")]
	KeyReuse,

	/// A digest output of `received` bytes lies outside the `min` to `max`
	/// bytes the handshake admits for a transcript hash and a key-confirmation
	/// tag.
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

	/// The client's receipt approver refused the session receipt with the
	/// refusal code `code`.
	#[error("Session receipt refused by approver: code {code}")]
	ApprovalRefused { code: u32 },

	/// The server's authorizer rejected the settlement answer with the
	/// rejection code `code`.
	#[error("Settlement rejected: code {code}")]
	SettlementRejected { code: u32 },

	/// The envelope refused to seal or open the receipt acknowledgement under
	/// the key the handshake secret derives. An open fails when another
	/// handshake secret or transcript sealed it, or when it changed in flight.
	/// The payload is the envelope's refusal.
	#[cfg(feature = "hpke")]
	#[error("Receipt acknowledgement envelope refused: {0}")]
	ReceiptAckCipher(crate::crypto::cms::EnvelopeError),

	/// The envelope refused to seal or open the closing under the key the
	/// handshake secret derives. An open fails when another handshake secret
	/// or transcript sealed it, or when it changed in flight. The payload is
	/// the envelope's refusal.
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

	/// The KDF salt of a derivation is `actual` bytes, below the `minimum`
	/// bytes that [`KdfSalt`](crate::crypto::kdf::KdfSalt) admits.
	#[error("KDF salt too short: {actual} bytes (minimum {minimum} required)")]
	InsufficientSaltEntropy { actual: usize, minimum: usize },

	/// The peer sent an abort alert during the handshake.
	#[error("Handshake aborted by peer: {0:?}")]
	AbortReceived(crate::transport::handshake::HandshakeAlert),

	/// The server selected no profile, or one that the client did not offer.
	#[error("Server selected no profile, or one outside the client's offer")]
	InvalidProfileSelection,

	/// The profile negotiation failed.
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
	#[source]
	KdfError(crate::crypto::kdf::KdfError),
	/// A key has an invalid size: `received` bytes, not the `expected` bytes.
	#[error("Invalid key size: expected {expected}, got {received}")]
	InvalidKeySize { expected: usize, received: usize },

	/// The generation of random bytes failed.
	#[error("Random generation failed")]
	RandomGenerationFailed,

	/// The material of a cryptographic key or a nonce has the wrong length.
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
	/// Returns the record a failed handshake files in its audit trail for this
	/// error, when the error names one.
	///
	/// - A receipt that the approver refuses, the authorizer rejects, or that
	///   is missing, mismatched, or not countersigned files a receipt refusal
	///   for its reason, with the code of a refusal that carries one.
	/// - A refused proof or identity of the peer files an identity refusal for
	///   its reason: a peer certificate that fails validation or is absent, a
	///   signature or key confirmation that fails, a closing or frame that
	///   fails to open, two server certificates that conflict, and an ephemeral
	///   that equals its static key.
	/// - A refusal of the transport authorizer files the code it returned.
	/// - A crate error that names no handshake fault files the generic failure.
	/// - A local fault, a malformed message, and a negotiation outcome other
	///   than an authorizer refusal name no record.
	pub(crate) fn audit(&self) -> Option<HandshakeAudit> {
		let audit = match self {
			Self::ApprovalRefused { code } => {
				HandshakeAudit::ReceiptRefused { reason: "approval-refused", code: Some(*code) }
			}
			Self::SettlementRejected { code } => {
				HandshakeAudit::ReceiptRefused { reason: "settlement-rejected", code: Some(*code) }
			}
			Self::ReceiptMissing => HandshakeAudit::ReceiptRefused { reason: "receipt-missing", code: None },
			Self::ReceiptMismatch => HandshakeAudit::ReceiptRefused { reason: "receipt-mismatch", code: None },
			Self::CountersignatureMissing => {
				HandshakeAudit::ReceiptRefused { reason: "countersignature-missing", code: None }
			}
			Self::CertificateValidationError(cause) => HandshakeAudit::IdentityRefused(cause.refusal_label()),
			Self::SignatureVerificationFailed | Self::SignatureError(_) => HandshakeAudit::IdentityRefused("signature"),
			Self::MissingClientCertificate => HandshakeAudit::IdentityRefused("missing-client-certificate"),
			Self::MissingServerCertificate => HandshakeAudit::IdentityRefused("missing-server-certificate"),
			Self::MutualAuthRequired => HandshakeAudit::IdentityRefused("mutual-auth-required"),
			Self::SealedFrame => HandshakeAudit::IdentityRefused("sealed-frame"),
			#[cfg(feature = "hpke")]
			Self::SealedClosing(cause) => HandshakeAudit::IdentityRefused(cause.sealed_closing_label()),
			Self::KeyConfirmationFailed => HandshakeAudit::IdentityRefused("key-confirmation"),
			Self::SubjectMismatch => HandshakeAudit::IdentityRefused("subject-mismatch"),
			Self::AnchorMismatch => HandshakeAudit::IdentityRefused("anchor-mismatch"),
			Self::KeyReuse => HandshakeAudit::IdentityRefused("key-reuse"),
			Self::ServerEphemeralIsStatic => HandshakeAudit::IdentityRefused("server-ephemeral-is-static"),
			Self::ClientEphemeralIsStatic => HandshakeAudit::IdentityRefused("client-ephemeral-is-static"),
			Self::NegotiationError(NegotiationError::AuthorizationRefused { code }) => {
				HandshakeAudit::AuthorizationRefused(*code)
			}
			Self::Other(_) => HandshakeAudit::Failed,
			Self::NegotiationError(_)
			| Self::InvalidPublicKey(_)
			| Self::KeyExchange(_)
			| Self::DerError(_)
			| Self::SpkiError(_)
			| Self::KeyError(_)
			| Self::InvalidState
			| Self::UnexpectedContainer
			| Self::MissingTrustStore
			| Self::TranscriptDigestLength { .. }
			| Self::InsufficientSaltEntropy { .. }
			| Self::AbortReceived(_)
			| Self::InvalidProfileSelection
			| Self::NoSupportedProfiles
			| Self::InvalidAttributeArity
			| Self::DuplicateAttribute
			| Self::MissingAttribute
			| Self::OctetStringLengthError(_)
			| Self::InvalidIntegerEncoding
			| Self::IntegerOutOfRange
			| Self::UnknownAlertCode(_)
			| Self::KdfError(_)
			| Self::InvalidKeySize { .. }
			| Self::RandomGenerationFailed
			| Self::InvalidKeyMaterialLength(_) => return None,
			#[cfg(feature = "hpke")]
			Self::ReceiptAckCipher(_) | Self::HpkeError(_) | Self::Envelope(_) => return None,
		};

		Some(audit)
	}
}

/// The record that a failed handshake files in the audit trail of its
/// endpoint, at the record of the handshake outcome.
#[cfg(all(
	feature = "instrument",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HandshakeAudit {
	/// The receipt failed for `reason`, with the code of a refusal that
	/// carries one. It files [`SESSION_RECEIPT_REFUSED`].
	///
	/// [`SESSION_RECEIPT_REFUSED`]: events::SESSION_RECEIPT_REFUSED
	ReceiptRefused {
		/// Why the receipt failed, such as `approval-refused`.
		reason: &'static str,
		/// The code that the approver or the authorizer returned.
		code: Option<u32>,
	},
	/// The handshake refused the identity of its peer for the reason it holds,
	/// such as `signature`. It files [`SESSION_CERT_REJECTED`].
	///
	/// [`SESSION_CERT_REJECTED`]: events::SESSION_CERT_REJECTED
	IdentityRefused(&'static str),
	/// The transport authorizer refused the session with the code it holds. It
	/// files [`SESSION_AUTHORIZATION_REFUSED`].
	///
	/// [`SESSION_AUTHORIZATION_REFUSED`]: events::SESSION_AUTHORIZATION_REFUSED
	AuthorizationRefused(u32),
	/// A deadline ended the handshake. It files [`SESSION_HANDSHAKE_EXPIRED`].
	///
	/// [`SESSION_HANDSHAKE_EXPIRED`]: events::SESSION_HANDSHAKE_EXPIRED
	Expired,
	/// A crate error that names no handshake fault ended the handshake. It
	/// files [`ERROR`](events::ERROR).
	Failed,
}

#[cfg(all(
	feature = "instrument",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
impl HandshakeAudit {
	/// Files this record in `trace`.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at the event of this record.
	pub(crate) fn file(&self, trace: &TraceCollector) -> Result<(), TightBeamError> {
		match self {
			Self::ReceiptRefused { reason, code: Some(code) } => {
				trace.emit_event_with_value(events::SESSION_RECEIPT_REFUSED, *reason, *code)
			}
			Self::ReceiptRefused { reason, code: None } => {
				trace.emit_event_with_value(events::SESSION_RECEIPT_REFUSED, *reason, ())
			}
			Self::IdentityRefused(reason) => {
				trace.emit_event_with_value(events::SESSION_CERT_REJECTED, *reason, *reason)
			}
			Self::AuthorizationRefused(code) => {
				// The trace renders the digits for a record its sink keeps.
				let label = || code.to_string();
				trace.emit_event_with_value_and_rendered_label(events::SESSION_AUTHORIZATION_REFUSED, label, *code)
			}
			Self::Expired => trace.emit_event(events::SESSION_HANDSHAKE_EXPIRED),
			Self::Failed => trace.emit_event(events::ERROR),
		}
	}
}

/// Narrows [`TightBeamError`](crate::error::TightBeamError) into
/// [`HandshakeError`].
///
/// A variant with a handshake counterpart becomes that counterpart. Any other
/// becomes [`HandshakeError::Other`], which keeps it as the source, so the
/// conversion reports a handshake fault only when the error names one.
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
			TightBeamError::KeyDerivationError(e) => HandshakeError::from(e),
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

/// Narrows a KDF error into [`HandshakeError`].
///
/// A salt under the floor is [`HandshakeError::InsufficientSaltEntropy`], the
/// name the handshake gives that refusal. Every other refusal is
/// [`HandshakeError::KdfError`].
impl From<crate::crypto::kdf::KdfError> for HandshakeError {
	fn from(err: crate::crypto::kdf::KdfError) -> Self {
		use crate::crypto::kdf::KdfError;

		match err {
			KdfError::SaltTooShort { actual, minimum } => HandshakeError::InsufficientSaltEntropy { actual, minimum },
			other => HandshakeError::KdfError(other),
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
	use crate::crypto::x509::error::CertificateValidationError;
	use crate::error::ReceivedExpectedError;
	use crate::testing::fixtures::TestTrace;
	use crate::testing::TestResult;
	use crate::TightBeamError;

	// Each refusal files the reason it names, and the code of a refusal that
	// carries one, so a spec tells one refusal from another. A local fault
	// files no record.
	crate::tb_cases! {
		fn a_refusal_files_its_reason((error, expected): (HandshakeError, Option<HandshakeAudit>)) {
			assert_eq!(error.audit(), expected);
		}
		cases {
			/// A missing client certificate is the refusal of an identity.
			missing_client_certificate => (
				HandshakeError::MissingClientCertificate,
				Some(HandshakeAudit::IdentityRefused("missing-client-certificate")),
			),
			/// A closing that fails to open names no certificate the server
			/// could check, so it records the refusal of an unproven identity.
			sealed_closing_authentication => (
				HandshakeError::SealedClosing(EnvelopeError::Authentication),
				Some(HandshakeAudit::IdentityRefused("sealed-closing/authentication")),
			),
			/// A refused approval is the refusal of a receipt.
			approval_refused => (
				HandshakeError::ApprovalRefused { code: 7 },
				Some(HandshakeAudit::ReceiptRefused { reason: "approval-refused", code: Some(7) }),
			),
			settlement_rejected => (
				HandshakeError::SettlementRejected { code: 9 },
				Some(HandshakeAudit::ReceiptRefused { reason: "settlement-rejected", code: Some(9) }),
			),
			receipt_missing => (
				HandshakeError::ReceiptMissing,
				Some(HandshakeAudit::ReceiptRefused { reason: "receipt-missing", code: None }),
			),
			receipt_mismatch => (
				HandshakeError::ReceiptMismatch,
				Some(HandshakeAudit::ReceiptRefused { reason: "receipt-mismatch", code: None }),
			),
			countersignature_missing => (
				HandshakeError::CountersignatureMissing,
				Some(HandshakeAudit::ReceiptRefused { reason: "countersignature-missing", code: None }),
			),
			certificate_cause => (
				HandshakeError::CertificateValidationError(CertificateValidationError::CertificateDenied),
				Some(HandshakeAudit::IdentityRefused("certificate/certificate-denied")),
			),
			signature => (
				HandshakeError::SignatureVerificationFailed,
				Some(HandshakeAudit::IdentityRefused("signature")),
			),
			mutual_auth_required => (
				HandshakeError::MutualAuthRequired,
				Some(HandshakeAudit::IdentityRefused("mutual-auth-required")),
			),
			sealed_frame => (HandshakeError::SealedFrame, Some(HandshakeAudit::IdentityRefused("sealed-frame"))),
			authorization_refused => (
				HandshakeError::NegotiationError(NegotiationError::AuthorizationRefused { code: 11 }),
				Some(HandshakeAudit::AuthorizationRefused(11)),
			),
			key_confirmation_failed => (
				HandshakeError::KeyConfirmationFailed,
				Some(HandshakeAudit::IdentityRefused("key-confirmation")),
			),
			subject_mismatch => (
				HandshakeError::SubjectMismatch,
				Some(HandshakeAudit::IdentityRefused("subject-mismatch")),
			),
			anchor_mismatch => (
				HandshakeError::AnchorMismatch,
				Some(HandshakeAudit::IdentityRefused("anchor-mismatch")),
			),
			key_reuse => (HandshakeError::KeyReuse, Some(HandshakeAudit::IdentityRefused("key-reuse"))),
			missing_server_certificate => (
				HandshakeError::MissingServerCertificate,
				Some(HandshakeAudit::IdentityRefused("missing-server-certificate")),
			),
			server_ephemeral_is_static => (
				HandshakeError::ServerEphemeralIsStatic,
				Some(HandshakeAudit::IdentityRefused("server-ephemeral-is-static")),
			),
			client_ephemeral_is_static => (
				HandshakeError::ClientEphemeralIsStatic,
				Some(HandshakeAudit::IdentityRefused("client-ephemeral-is-static")),
			),
			signature_error => (
				HandshakeError::SignatureError(crate::crypto::sign::Error::new()),
				Some(HandshakeAudit::IdentityRefused("signature")),
			),
			/// A local fault files no record.
			invalid_state => (HandshakeError::InvalidState, None),
			/// A crate error with no handshake counterpart files the generic
			/// failure.
			unmapped_crate_error => (
				HandshakeError::from(TightBeamError::MissingEncryptionInfo),
				Some(HandshakeAudit::Failed),
			),
		}
	}

	// The label of a refused authorization holds the decimal digits of its
	// code, from one digit to the ten of `u32::MAX`.
	crate::tb_cases! {
		fn a_refusal_code_labels_its_record_in_decimal((code, label): (u32, &str)) -> TestResult {
			let trace = TraceCollector::new();
			HandshakeAudit::AuthorizationRefused(code).file(&trace)?;

			let labels = TestTrace::labels(&trace, events::SESSION_AUTHORIZATION_REFUSED);
			assert_eq!(labels, [Some(label.to_owned())]);
			Ok(())
		}
		cases {
			zero => (0, "0"),
			two_digits => (11, "11"),
			the_largest_code => (u32::MAX, "4294967295"),
		}
	}

	/// A crate error with no handshake counterpart keeps its cause, so the
	/// conversion reports no state fault.
	#[test]
	fn an_unmapped_crate_error_reads_back_through_its_source() -> TestResult {
		let error = HandshakeError::from(TightBeamError::MissingEncryptionInfo);
		let source = core::error::Error::source(&error).ok_or("the conversion keeps the cause")?;

		let downcast = source.downcast_ref::<Box<TightBeamError>>();
		let cause = downcast.ok_or("the cause is the crate error")?;
		assert!(matches!(**cause, TightBeamError::MissingEncryptionInfo));
		Ok(())
	}

	/// A key derivation failure has a handshake counterpart, so it keeps its
	/// kind and the widths it holds.
	#[test]
	fn a_key_derivation_failure_converts_to_its_counterpart() {
		let width = ReceivedExpectedError { received: 16, expected: 32 };
		let failure = KdfError::InvalidSharedSecretLength(width.clone());
		let error = HandshakeError::from(TightBeamError::KeyDerivationError(failure));
		assert!(matches!(error, HandshakeError::KdfError(KdfError::InvalidSharedSecretLength(held)) if held == width));
	}

	// A crate error whose cause is a signature the handshake cannot read
	// converts to a failed verification.
	crate::tb_cases! {
		fn a_crate_error_converts_to_a_failed_verification(error: TightBeamError) {
			let converted = HandshakeError::from(error);
			assert!(matches!(converted, HandshakeError::SignatureVerificationFailed));
		}
		cases {
			/// A signature that fails to encode is a signature the handshake
			/// refuses.
			signature_encoding => TightBeamError::SignatureEncodingError,
			/// A signer error that the crate error carries whole converts as
			/// the signer conversion converts it.
			carried_signer => TightBeamError::Signer(SignerError::SignerIdentifier),
		}
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
}
