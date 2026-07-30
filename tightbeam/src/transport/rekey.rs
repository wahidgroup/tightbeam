//! In-band rekey exchange logic.
//!
//! Pure message-level build/verify for the three-leg renewal:
//! - `RekeyRequest`
//! - `RekeyResponse`
//! - `RekeyAck`
//!
//! # Exchange
//!
//! ```text
//! client                                server
//!   RekeyRequest(client_random)  ---->
//!                                <----  RekeyResponse(server_random, epoch receipt)
//!   RekeyAck(countersignature)   ---->
//!                                <----  RekeyDone
//! ```
//!
//! Fresh keys per direction from the epoch KDF chain
//! ([RFC 9846 § 4.7.3](https://datatracker.ietf.org/doc/html/rfc9846#section-4.7.3)
//! with an explicit exchange); the prior epoch secret drops the
//! moment the next one installs
//! ([RFC 9846 § 7.2](https://datatracker.ietf.org/doc/html/rfc9846#section-7.2)).
//!
//! # Bindings
//!
//! - The epoch receipt's `transcript_hash` pins the exchange:
//!   `H(hash_prev || request_der || server_random)`.
//! - The chain root advances over the full exchange:
//!   `hash_next = H(hash_prev || request_der || response_der || ack_der)`,
//!   so every epoch receipt transitively commits to the whole session
//!   history back to the handshake transcript.
//! - Credit-match invariant: epoch receipt budgets and credit unit must
//!   equal the initial receipt terms byte-for-byte; only the settlement
//!   challenge may vary per epoch.

use std::sync::Arc;

use futures::lock::Mutex as FuturesMutex;

use crate::cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use crate::constants::TIGHTBEAM_EPOCH_KDF_INFO;
use crate::crypto::aead::{KeyInit, RecvCipher, SendCipher, SessionKeys};
use crate::crypto::hash::Digest;
use crate::crypto::key::SigningKeyProvider;
use crate::crypto::profiles::CryptoProvider;
use crate::der::asn1::{ObjectIdentifier, OctetString};
use crate::der::Encode;
use crate::random::generate_nonce;
use crate::transport::envelopes::{MuxRekeyAckPackage, MuxRekeyRequestPackage, MuxRekeyResponsePackage};
use crate::transport::handshake::negotiation::TransportAuthorizer;
use crate::transport::handshake::primitives::kdf_chain;
use crate::transport::handshake::receipt::{
	approve_or_fail_closed, complete_receipt_artifact, countersign_receipt, receipt_from_artifact,
	record_receipt_outcome, settle_receipt_ack, sign_receipt, signer_for_role, transcript_digest_info,
	verify_receipt_signer, ReceiptApprover, ReceiptRole, SessionObserver, SessionOutcome, SessionReceipt,
	SessionVerdict, StoredReceipt,
};
use crate::transport::handshake::{
	compute_transcript_digest, derive_directional_from_oid, octet_string_to_32_byte_array, EpochMaterials,
	HandshakeError,
};
use crate::transport::multiplex::MuxRole;
use crate::utils::marker::{MaybeSend, MaybeSendFuture};
use crate::x509::Certificate;

/// Shared epoch state and identities for one session's rekey exchanges.
///
/// Both roles hold one: the epoch secret chain, the negotiated AEAD
/// OID, the initial receipt terms (the credit-match reference), the
/// local signing identity, and the peer's verified receipt identity.
pub(crate) struct RekeyMaterials<P>
where
	P: CryptoProvider,
{
	epoch: EpochMaterials,
	aead_oid: ObjectIdentifier,
	reference: SessionReceipt,
	signing_provider: Arc<dyn SigningKeyProvider>,
	peer_verifying_key: P::VerifyingKey,
	peer_sid: SignerIdentifier,
}

/// Fresh per-direction state produced by a completed exchange.
///
/// The mux driver installs each cipher at its wire boundary:
/// - client: send at `RekeyAck`, receive at `RekeyDone`
/// - server: receive after a verified `RekeyAck`, send at `RekeyDone`
pub(crate) struct EpochInstall {
	/// Send-direction cipher for the new epoch (fresh counter).
	pub(crate) send_cipher: SendCipher,
	/// Receive-direction cipher for the new epoch (fresh counter).
	pub(crate) recv_cipher: RecvCipher,
	/// The new epoch's dual-signed receipt.
	pub(crate) receipt: StoredReceipt,
	/// Epoch number the install activates. Read by unit tests; the
	/// driver installs positionally at the wire boundary.
	#[cfg_attr(not(test), allow(dead_code))]
	pub(crate) epoch: u32,
}

impl<P> RekeyMaterials<P>
where
	P: CryptoProvider,
	P::AeadCipher: KeyInit + 'static,
{
	pub(crate) fn new(
		epoch: EpochMaterials,
		aead_oid: ObjectIdentifier,
		reference: SessionReceipt,
		signing_provider: Arc<dyn SigningKeyProvider>,
		peer_verifying_key: P::VerifyingKey,
		peer_sid: SignerIdentifier,
	) -> Self {
		Self { epoch, aead_oid, reference, signing_provider, peer_verifying_key, peer_sid }
	}

	/// Current epoch number.
	pub(crate) fn epoch(&self) -> u32 {
		self.epoch.epoch
	}

	/// Rotate the epoch chain and derive the new directional ciphers.
	///
	/// `secret_next = KDF(secret_prev, epoch-label, salt = client_random || server_random)`,
	/// traffic keys from `secret_next` under the directional labels the
	/// handshake finalization uses. Assigning the next secret drops the
	/// prior one (zeroized on drop, RFC 9846 § 7.2).
	fn rotate(
		&mut self,
		role: MuxRole,
		client_random: &[u8; 32],
		server_random: &[u8; 32],
		next_hash: [u8; 32],
	) -> Result<(SendCipher, RecvCipher), HandshakeError> {
		let mut salt = [0u8; 64];
		salt[..32].copy_from_slice(client_random);
		salt[32..].copy_from_slice(server_random);

		let stage = (self.epoch.secret.as_slice(), TIGHTBEAM_EPOCH_KDF_INFO);
		let next_secret = kdf_chain::<P>(&[stage], &salt)?;
		let directional = derive_directional_from_oid::<P>(&next_secret, &salt, self.aead_oid)?;

		let next_epoch = self.epoch.epoch.checked_add(1).ok_or(HandshakeError::IntegerOutOfRange)?;
		self.epoch.secret = next_secret;
		self.epoch.epoch = next_epoch;
		self.epoch.transcript_hash = next_hash;

		let keys = match role {
			MuxRole::Client => {
				SessionKeys::for_client(directional.client_to_server, directional.server_to_client, self.aead_oid)
			}
			MuxRole::Server => {
				SessionKeys::for_server(directional.client_to_server, directional.server_to_client, self.aead_oid)
			}
		};
		Ok(keys.into_parts())
	}
}

/// Exchange pin the epoch receipt commits to:
/// `H(hash_prev || request_der || server_random)`.
///
/// Computable before the receipt exists, so the receipt's
/// `transcript_hash` can commit to the exchange without circularity.
fn exchange_challenge_hash<D>(
	chain_hash: &[u8; 32],
	request_der: &[u8],
	server_random: &[u8; 32],
) -> Result<[u8; 32], HandshakeError>
where
	D: Digest,
{
	let capacity = chain_hash.len() + request_der.len() + server_random.len();
	let mut transcript = Vec::with_capacity(capacity);
	transcript.extend_from_slice(chain_hash);
	transcript.extend_from_slice(request_der);
	transcript.extend_from_slice(server_random);
	compute_transcript_digest::<D>(&transcript)
}

/// Advance the chain root over the completed exchange:
/// `hash_next = H(hash_prev || request_der || response_der || ack_der)`.
fn advance_chain_hash<D>(
	chain_hash: &[u8; 32],
	request_der: &[u8],
	response_der: &[u8],
	ack_der: &[u8],
) -> Result<[u8; 32], HandshakeError>
where
	D: Digest,
{
	let capacity = chain_hash.len() + request_der.len() + response_der.len() + ack_der.len();
	let mut transcript = Vec::with_capacity(capacity);
	transcript.extend_from_slice(chain_hash);
	transcript.extend_from_slice(request_der);
	transcript.extend_from_slice(response_der);
	transcript.extend_from_slice(ack_der);
	compute_transcript_digest::<D>(&transcript)
}

/// Client randomness and request DER retained between the request and
/// the server's response.
struct PendingRenewal {
	client_random: [u8; 32],
	request_der: Vec<u8>,
}

/// Client half of the rekey exchange: opens renewals, verifies and
/// countersigns epoch receipts, rotates the chain.
pub(crate) struct ClientRekey<P>
where
	P: CryptoProvider,
{
	materials: RekeyMaterials<P>,
	approver: Option<Arc<dyn ReceiptApprover>>,
	pending: Option<PendingRenewal>,
}

impl<P> ClientRekey<P>
where
	P: CryptoProvider,
	for<'a> P::Signature: TryFrom<&'a [u8]>,
	P::AeadCipher: KeyInit + 'static,
{
	pub(crate) fn new(materials: RekeyMaterials<P>, approver: Option<Arc<dyn ReceiptApprover>>) -> Self {
		Self { materials, approver, pending: None }
	}

	/// Current epoch number (unit-test observability).
	#[cfg(test)]
	pub(crate) fn epoch(&self) -> u32 {
		self.materials.epoch()
	}

	/// Whether a renewal is awaiting the server's response
	/// (unit-test observability).
	#[cfg(test)]
	pub(crate) fn renewal_in_flight(&self) -> bool {
		self.pending.is_some()
	}

	/// Open a renewal: fresh client randomness, first leg on the wire.
	///
	/// # Errors
	/// - A renewal already in flight: [`HandshakeError::InvalidState`]
	pub(crate) fn start_renewal(&mut self) -> Result<MuxRekeyRequestPackage, HandshakeError> {
		if self.pending.is_some() {
			return Err(HandshakeError::InvalidState);
		}

		let client_random = generate_nonce::<32>(None)?;
		let request = MuxRekeyRequestPackage::new(client_random)?;
		let request_der = request.to_der()?;
		self.pending = Some(PendingRenewal { client_random, request_der });
		Ok(request)
	}

	/// Verify the server's epoch receipt, approve and countersign it,
	/// and rotate the epoch chain.
	///
	/// # Fail closed
	/// - No renewal in flight: [`HandshakeError::InvalidState`]
	/// - Response without an epoch receipt: [`HandshakeError::ReceiptMissing`]
	/// - Exchange pin or credit-match violation: [`HandshakeError::ReceiptMismatch`]
	/// - Server `SignerInfo` invalid: [`HandshakeError::SignatureVerificationFailed`]
	/// - The approver refused the renewal: [`HandshakeError::ApprovalRefused`]
	pub(crate) async fn process_response(
		&mut self,
		response: MuxRekeyResponsePackage,
	) -> Result<(MuxRekeyAckPackage, EpochInstall), HandshakeError> {
		let pending = self.pending.take().ok_or(HandshakeError::InvalidState)?;
		let response_der = response.to_der()?;
		let MuxRekeyResponsePackage { server_random, epoch_receipt } = response;
		let server_random = octet_string_to_32_byte_array(&server_random)?;
		let epoch_receipt = epoch_receipt.ok_or(HandshakeError::ReceiptMissing)?;
		let artifact = *epoch_receipt;

		let receipt = receipt_from_artifact(&artifact)?;
		let receipt_der = receipt.to_der()?;
		let server_role = ReceiptRole::Server;
		let server_signer = signer_for_role(&artifact, server_role)?.ok_or(HandshakeError::ReceiptMissing)?;
		verify_receipt_signer::<P::Digest, P::Signature, _>(
			&receipt_der,
			server_signer,
			server_role,
			&self.materials.peer_sid,
			&self.materials.peer_verifying_key,
		)?;

		let challenge_hash = exchange_challenge_hash::<P::Digest>(
			&self.materials.epoch.transcript_hash,
			&pending.request_der,
			&server_random,
		)?;
		let expected_pin = transcript_digest_info::<P::Digest>(challenge_hash)?;
		let pin_matches = receipt.transcript_hash == expected_pin;
		let budgets_match = receipt.budgets == self.materials.reference.budgets;
		let unit_matches = receipt.credit_unit == self.materials.reference.credit_unit;
		if !pin_matches || !budgets_match || !unit_matches {
			return Err(HandshakeError::ReceiptMismatch);
		}

		let answer = approve_or_fail_closed(self.approver.as_deref(), &receipt).await?;
		let answer_bytes = answer.as_ref().map(OctetString::as_bytes);
		let provider = self.materials.signing_provider.as_ref();
		let countersignature = countersign_receipt::<P::Digest>(&receipt, answer_bytes, provider).await?;

		// Dual ownership by design: one copy folds into the retained
		// artifact, the other is DER-encoded onto the wire in the ack.
		let completed = complete_receipt_artifact(artifact, countersignature.clone())?;
		let stored = StoredReceipt::try_from(completed)?;

		let ack = MuxRekeyAckPackage::new(Some(countersignature));
		let ack_der = ack.to_der()?;
		let next_hash = advance_chain_hash::<P::Digest>(
			&self.materials.epoch.transcript_hash,
			&pending.request_der,
			&response_der,
			&ack_der,
		)?;

		let (send_cipher, recv_cipher) =
			self.materials
				.rotate(MuxRole::Client, &pending.client_random, &server_random, next_hash)?;
		let install = EpochInstall { send_cipher, recv_cipher, receipt: stored, epoch: self.materials.epoch() };
		Ok((ack, install))
	}
}

/// Receipt, artifact, randoms, and exchange DERs retained between the
/// response and the client's acknowledgement.
struct PendingSettlement {
	receipt: SessionReceipt,
	artifact: SignedData,
	request_der: Vec<u8>,
	response_der: Vec<u8>,
	client_random: [u8; 32],
	server_random: [u8; 32],
}

/// Server half of the rekey exchange: issues epoch receipts, settles
/// countersignatures, records outcomes, rotates the chain.
pub(crate) struct ServerRekey<P>
where
	P: CryptoProvider,
{
	materials: RekeyMaterials<P>,
	authorizer: Option<Arc<dyn TransportAuthorizer>>,
	observer: Option<Arc<dyn SessionObserver>>,
	client_certificate: Option<Arc<Certificate>>,
	pending: Option<PendingSettlement>,
}

impl<P> ServerRekey<P>
where
	P: CryptoProvider,
	for<'a> P::Signature: TryFrom<&'a [u8]>,
	P::AeadCipher: KeyInit + 'static,
{
	pub(crate) fn new(
		materials: RekeyMaterials<P>,
		authorizer: Option<Arc<dyn TransportAuthorizer>>,
		observer: Option<Arc<dyn SessionObserver>>,
		client_certificate: Option<Arc<Certificate>>,
	) -> Self {
		Self { materials, authorizer, observer, client_certificate, pending: None }
	}

	/// Current epoch number (unit-test observability).
	#[cfg(test)]
	pub(crate) fn epoch(&self) -> u32 {
		self.materials.epoch()
	}

	/// Whether an exchange is awaiting the client's acknowledgement.
	pub(crate) fn exchange_in_flight(&self) -> bool {
		self.pending.is_some()
	}

	/// Issue the epoch receipt for a renewal request: second leg on the wire.
	///
	/// The receipt inherits the initial budgets and credit unit. The
	/// authorizer may attach a fresh settlement challenge for the epoch.
	///
	/// # Fail closed
	/// - An exchange already in flight (the mux driver bounds request
	///   flooding before this): [`HandshakeError::InvalidState`]
	/// - The authorizer refused the renewal: [`HandshakeError::SettlementRejected`]
	pub(crate) async fn process_request(
		&mut self,
		request: &MuxRekeyRequestPackage,
	) -> Result<MuxRekeyResponsePackage, HandshakeError> {
		if self.pending.is_some() {
			return Err(HandshakeError::InvalidState);
		}

		let request_der = request.to_der()?;
		let client_random = octet_string_to_32_byte_array(&request.client_random)?;
		let server_random = generate_nonce::<32>(None)?;

		let challenge_hash =
			exchange_challenge_hash::<P::Digest>(&self.materials.epoch.transcript_hash, &request_der, &server_random)?;

		let challenge = match self.authorizer.as_deref() {
			Some(authorizer) => {
				let renewal = authorizer.challenge_renewal(&self.materials.reference).await;
				renewal.map_err(|refusal| HandshakeError::SettlementRejected { code: refusal.code })?
			}
			None => None,
		};

		let (receipt, artifact) = sign_receipt::<P::Digest>(
			challenge_hash,
			self.materials.reference.budgets,
			self.materials.reference.credit_unit,
			challenge,
			self.materials.signing_provider.as_ref(),
		)
		.await?;

		// Dual ownership by design: this copy is DER-encoded onto the
		// wire and dropped; the retained artifact absorbs the client
		// SignerInfo at settlement.
		let response = MuxRekeyResponsePackage::new(server_random, Some(artifact.clone()))?;
		let response_der = response.to_der()?;
		self.pending =
			Some(PendingSettlement { receipt, artifact, request_der, response_der, client_random, server_random });
		Ok(response)
	}

	/// Settle the client's countersignature, record the outcome, and
	/// rotate the epoch chain.
	///
	/// A verified countersignature rotates the chain **even when the
	/// authorizer refuses settlement**: the client switched its send
	/// cipher at the Ack boundary, so the server must install the new
	/// receive cipher to keep the refusal's GoAway drain decryptable.
	/// The refusal code surfaces in [`ServerAckOutcome::rejection`]
	/// for the driver to drain on.
	///
	/// # Fail closed (after the observer records the evidence)
	/// - No exchange in flight: [`HandshakeError::InvalidState`]
	/// - Absent countersignature: [`HandshakeError::CountersignatureMissing`]
	/// - Invalid countersignature: [`HandshakeError::SignatureVerificationFailed`]
	pub(crate) async fn process_ack(&mut self, ack: MuxRekeyAckPackage) -> Result<ServerAckOutcome, HandshakeError> {
		let pending = self.pending.take().ok_or(HandshakeError::InvalidState)?;
		let ack_der = ack.to_der()?;
		let MuxRekeyAckPackage { countersignature } = ack;
		let countersignature = countersignature.map(|boxed| *boxed);

		let (verdict, ancillary_response) = settle_receipt_ack::<P::Digest, P::Signature, _>(
			&pending.receipt,
			countersignature.as_ref(),
			&self.materials.peer_sid,
			&self.materials.peer_verifying_key,
			self.authorizer.as_deref(),
		)
		.await?;

		let countersignature_der = countersignature.as_ref().map(SignerInfo::to_der).transpose()?;

		// A verified countersignature completes the artifact; a failed
		// one stays out of it but its DER remains in the outcome as
		// evidence.
		let artifact = match (verdict, countersignature) {
			(SessionVerdict::Activated | SessionVerdict::SettlementRejected { .. }, Some(signer)) => {
				complete_receipt_artifact(pending.artifact, signer)?
			}
			(_, _) => pending.artifact,
		};

		// The refusal path still needs the dual-signed view after the
		// outcome consumes the artifact (dual ownership by design).
		let refused_artifact = match verdict {
			SessionVerdict::SettlementRejected { .. } => Some(artifact.clone()),
			_ => None,
		};

		let countersignature_octet = countersignature_der.map(OctetString::new).transpose()?;
		let client_certificate = self.client_certificate.as_ref().map(Arc::clone);
		let outcome = SessionOutcome {
			receipt: pending.receipt,
			artifact,
			countersignature: countersignature_octet,
			ancillary_response,
			client_certificate,
			verdict,
		};
		let recorded = record_receipt_outcome(self.observer.as_deref(), outcome).await;
		let (stored, rejection) = match (recorded, refused_artifact) {
			(Ok(stored), _) => (stored, None),
			(Err(HandshakeError::SettlementRejected { code }), Some(refused)) => {
				(StoredReceipt::try_from(refused)?, Some(code))
			}
			(Err(err), _) => return Err(err),
		};

		let next_hash = advance_chain_hash::<P::Digest>(
			&self.materials.epoch.transcript_hash,
			&pending.request_der,
			&pending.response_der,
			&ack_der,
		)?;
		let (send_cipher, recv_cipher) =
			self.materials
				.rotate(MuxRole::Server, &pending.client_random, &pending.server_random, next_hash)?;
		let install = EpochInstall { send_cipher, recv_cipher, receipt: stored, epoch: self.materials.epoch() };
		Ok(ServerAckOutcome { install, rejection })
	}
}

/// Server verdict on a settled acknowledgement: fresh epoch state plus
/// the settlement refusal code when the authorizer said no.
///
/// The install is unconditional for a verified countersignature (the
/// chain already advanced on both endpoints).
pub(crate) struct ServerAckOutcome {
	/// Fresh per-direction state for the new epoch.
	pub(crate) install: EpochInstall,
	/// Application refusal code when settlement was rejected.
	pub(crate) rejection: Option<u32>,
}

/// Object-safe client half of the rekey exchange, erasing the crypto
/// provider so the mux driver stays non-generic.
pub(crate) trait ClientRekeyExchange: MaybeSend {
	/// Open a renewal: first leg on the wire.
	fn start_renewal(&mut self) -> Result<MuxRekeyRequestPackage, HandshakeError>;

	/// Verify, countersign, and rotate on the server's response.
	fn process_response<'a>(
		&'a mut self,
		response: MuxRekeyResponsePackage,
	) -> MaybeSendFuture<'a, Result<(MuxRekeyAckPackage, EpochInstall), HandshakeError>>;
}

impl<P> ClientRekeyExchange for ClientRekey<P>
where
	P: CryptoProvider,
	for<'a> P::Signature: TryFrom<&'a [u8]>,
	P::AeadCipher: KeyInit + 'static,
{
	fn start_renewal(&mut self) -> Result<MuxRekeyRequestPackage, HandshakeError> {
		ClientRekey::start_renewal(self)
	}

	fn process_response<'a>(
		&'a mut self,
		response: MuxRekeyResponsePackage,
	) -> MaybeSendFuture<'a, Result<(MuxRekeyAckPackage, EpochInstall), HandshakeError>> {
		Box::pin(ClientRekey::process_response(self, response))
	}
}

/// Object-safe server half of the rekey exchange, erasing the crypto
/// provider so the mux driver stays non-generic.
pub(crate) trait ServerRekeyExchange: MaybeSend {
	/// Whether an exchange is awaiting the client's acknowledgement.
	fn exchange_in_flight(&self) -> bool;

	/// Second leg on the wire.
	fn process_request<'a>(
		&'a mut self,
		request: &'a MuxRekeyRequestPackage,
	) -> MaybeSendFuture<'a, Result<MuxRekeyResponsePackage, HandshakeError>>;

	/// Settle countersignature, record outcome, rotate chain.
	fn process_ack<'a>(
		&'a mut self,
		ack: MuxRekeyAckPackage,
	) -> MaybeSendFuture<'a, Result<ServerAckOutcome, HandshakeError>>;
}

impl<P> ServerRekeyExchange for ServerRekey<P>
where
	P: CryptoProvider,
	for<'a> P::Signature: TryFrom<&'a [u8]>,
	P::AeadCipher: KeyInit + 'static,
{
	fn exchange_in_flight(&self) -> bool {
		ServerRekey::exchange_in_flight(self)
	}

	fn process_request<'a>(
		&'a mut self,
		request: &'a MuxRekeyRequestPackage,
	) -> MaybeSendFuture<'a, Result<MuxRekeyResponsePackage, HandshakeError>> {
		Box::pin(ServerRekey::process_request(self, request))
	}

	fn process_ack<'a>(
		&'a mut self,
		ack: MuxRekeyAckPackage,
	) -> MaybeSendFuture<'a, Result<ServerAckOutcome, HandshakeError>> {
		Box::pin(ServerRekey::process_ack(self, ack))
	}
}

/// Role-fixed rekey exchange handed to the mux plane.
///
/// The client half sits behind an async mutex: the reader driver holds
/// it across the exchange's hook awaits, while the trigger paths
/// (writer record watermark, emit budget watermark) `try_lock` for the
/// synchronous [`ClientRekeyExchange::start_renewal`] only. A contended
/// try-lock means an exchange is already being processed, which makes
/// initiation moot.
pub(crate) enum RekeyDriver {
	/// Renewal initiator (mux client role).
	Client(Arc<FuturesMutex<Box<dyn ClientRekeyExchange>>>),
	/// Receipt issuer (mux server role).
	Server(Box<dyn ServerRekeyExchange>),
}

impl RekeyDriver {
	/// Type-erased wrapper for the mux driver.
	pub(crate) fn client<P>(rekey: ClientRekey<P>) -> Self
	where
		P: CryptoProvider + 'static,
		for<'a> P::Signature: TryFrom<&'a [u8]>,
		P::AeadCipher: KeyInit + 'static,
	{
		RekeyDriver::Client(Arc::new(FuturesMutex::new(Box::new(rekey))))
	}

	/// Type-erased wrapper for the mux driver.
	pub(crate) fn server<P>(rekey: ServerRekey<P>) -> Self
	where
		P: CryptoProvider + 'static,
		for<'a> P::Signature: TryFrom<&'a [u8]>,
		P::AeadCipher: KeyInit + 'static,
	{
		RekeyDriver::Server(Box::new(rekey))
	}
}

#[cfg(all(test, feature = "secp256k1", feature = "aes-gcm"))]
mod tests {
	use super::*;
	use crate::crypto::aead::Decryptor;
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::key::{InMemorySigningKeyProvider, Secp256k1Provider};
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::crypto::sign::ecdsa::{Secp256k1SigningKey, Secp256k1VerifyingKey};
	use crate::crypto::x509::utils::compute_signer_identifier;
	use crate::oids::AES_256_GCM;
	use crate::random::OsRng;
	use crate::transport::handshake::negotiation::MuxBudgets;
	use crate::zeroize::Zeroizing;

	const SAMPLE_SECRET: [u8; 32] = [0x42u8; 32];
	const SAMPLE_CHAIN_ROOT: [u8; 32] = [0x07u8; 32];
	const SAMPLE_BUDGETS: MuxBudgets = MuxBudgets { client_to_server: 64, server_to_client: 1024 };
	const SAMPLE_CREDIT_UNIT: u32 = 1024;
	const PLAINTEXT: &[u8] = b"epoch traffic";

	struct Identity {
		provider: Arc<dyn SigningKeyProvider>,
		verifying_key: Secp256k1VerifyingKey,
		sid: SignerIdentifier,
	}

	fn test_identity() -> Result<Identity, HandshakeError> {
		let signing_key = Secp256k1SigningKey::random(&mut OsRng);
		let verifying_key = *signing_key.verifying_key();
		let sid = compute_signer_identifier::<Sha3_256, _>(&verifying_key)?;
		let provider: Secp256k1Provider = InMemorySigningKeyProvider::from(signing_key);
		Ok(Identity { provider: Arc::new(provider), verifying_key, sid })
	}

	fn sample_epoch() -> EpochMaterials {
		EpochMaterials {
			secret: Zeroizing::new(SAMPLE_SECRET.to_vec()),
			epoch: 0,
			transcript_hash: SAMPLE_CHAIN_ROOT,
		}
	}

	fn sample_reference(credit_unit: u32) -> Result<SessionReceipt, HandshakeError> {
		Ok(SessionReceipt {
			transcript_hash: transcript_digest_info::<Sha3_256>(SAMPLE_CHAIN_ROOT)?,
			budgets: SAMPLE_BUDGETS,
			credit_unit,
			ancillary: None,
		})
	}

	fn rekey_pair() -> Result<(ClientRekey<DefaultCryptoProvider>, ServerRekey<DefaultCryptoProvider>), HandshakeError>
	{
		let client_identity = test_identity()?;
		let server_identity = test_identity()?;
		let reference = sample_reference(SAMPLE_CREDIT_UNIT)?;

		let client_materials = RekeyMaterials::new(
			sample_epoch(),
			AES_256_GCM,
			reference.to_owned(),
			client_identity.provider,
			server_identity.verifying_key,
			server_identity.sid,
		);
		let server_materials = RekeyMaterials::new(
			sample_epoch(),
			AES_256_GCM,
			reference,
			server_identity.provider,
			client_identity.verifying_key,
			client_identity.sid,
		);

		let client = ClientRekey::new(client_materials, None);
		let server = ServerRekey::new(server_materials, None, None, None);
		Ok((client, server))
	}

	async fn run_exchange(
		client: &mut ClientRekey<DefaultCryptoProvider>,
		server: &mut ServerRekey<DefaultCryptoProvider>,
	) -> Result<(EpochInstall, EpochInstall), HandshakeError> {
		let request = client.start_renewal()?;
		let response = server.process_request(&request).await?;
		let (ack, client_install) = client.process_response(response).await?;
		let outcome = server.process_ack(ack).await?;
		assert!(outcome.rejection.is_none());
		Ok((client_install, outcome.install))
	}

	#[tokio::test]
	async fn exchange_rotates_both_endpoints() -> Result<(), Box<dyn std::error::Error>> {
		let (mut client, mut server) = rekey_pair()?;
		let (client_install, server_install) = run_exchange(&mut client, &mut server).await?;

		assert_eq!(client_install.epoch, 1);
		assert_eq!(server_install.epoch, 1);
		assert_eq!(client.epoch(), 1);
		assert_eq!(server.epoch(), 1);
		assert_eq!(client_install.receipt, server_install.receipt);
		assert!(!client.renewal_in_flight());
		assert!(!server.exchange_in_flight());

		let uplink = client_install.send_cipher.encrypt_next(PLAINTEXT, None)?;
		let received = server_install.recv_cipher.decrypt_content(&uplink)?;
		assert!(received.with(|plain| plain == PLAINTEXT)?);

		let downlink = server_install.send_cipher.encrypt_next(PLAINTEXT, None)?;
		let received = client_install.recv_cipher.decrypt_content(&downlink)?;
		assert!(received.with(|plain| plain == PLAINTEXT)?);
		Ok(())
	}

	#[tokio::test]
	async fn chained_exchanges_stay_in_step() -> Result<(), Box<dyn std::error::Error>> {
		let (mut client, mut server) = rekey_pair()?;
		run_exchange(&mut client, &mut server).await?;
		let (client_install, server_install) = run_exchange(&mut client, &mut server).await?;

		assert_eq!(client_install.epoch, 2);
		assert_eq!(server_install.epoch, 2);

		let uplink = client_install.send_cipher.encrypt_next(PLAINTEXT, None)?;
		let received = server_install.recv_cipher.decrypt_content(&uplink)?;
		assert!(received.with(|plain| plain == PLAINTEXT)?);
		Ok(())
	}

	#[tokio::test]
	async fn epoch_receipt_pins_the_exchange() -> Result<(), HandshakeError> {
		let (mut client, mut server) = rekey_pair()?;
		let request = client.start_renewal()?;
		let response = server.process_request(&request).await?;

		let epoch_receipt = response.epoch_receipt().ok_or(HandshakeError::ReceiptMissing)?;
		let receipt = receipt_from_artifact(epoch_receipt)?;
		assert_eq!(receipt.budgets, SAMPLE_BUDGETS);
		assert_eq!(receipt.credit_unit, SAMPLE_CREDIT_UNIT);
		let chain_root = transcript_digest_info::<Sha3_256>(SAMPLE_CHAIN_ROOT)?;
		assert_ne!(receipt.transcript_hash, chain_root);
		Ok(())
	}

	#[tokio::test]
	async fn renewal_already_in_flight_fails_closed() -> Result<(), HandshakeError> {
		let (mut client, mut server) = rekey_pair()?;
		let request = client.start_renewal()?;

		let duplicate_start = client.start_renewal();
		assert!(matches!(duplicate_start, Err(HandshakeError::InvalidState)));

		server.process_request(&request).await?;
		let duplicate = server.process_request(&request).await;
		assert!(matches!(duplicate, Err(HandshakeError::InvalidState)));
		Ok(())
	}

	#[tokio::test]
	async fn unsolicited_legs_fail_closed() -> Result<(), HandshakeError> {
		let (mut client, mut server) = rekey_pair()?;
		let request = MuxRekeyRequestPackage::new([1u8; 32])?;
		let response = server.process_request(&request).await?;

		let unsolicited = client.process_response(response).await;
		assert!(matches!(unsolicited, Err(HandshakeError::InvalidState)));

		server.pending = None;
		let bare_ack = server.process_ack(MuxRekeyAckPackage::new(None)).await;
		assert!(matches!(bare_ack, Err(HandshakeError::InvalidState)));
		Ok(())
	}

	#[tokio::test]
	async fn missing_epoch_receipt_fails_closed() -> Result<(), HandshakeError> {
		let (mut client, _) = rekey_pair()?;
		client.start_renewal()?;

		let bare = MuxRekeyResponsePackage::new([9u8; 32], None)?;
		let missing_receipt = client.process_response(bare).await;
		assert!(matches!(missing_receipt, Err(HandshakeError::ReceiptMissing)));
		Ok(())
	}

	#[tokio::test]
	async fn credit_drift_fails_closed() -> Result<(), HandshakeError> {
		let (mut client, mut server) = rekey_pair()?;
		client.materials.reference = sample_reference(SAMPLE_CREDIT_UNIT + 1)?;

		let request = client.start_renewal()?;
		let response = server.process_request(&request).await?;
		let drift = client.process_response(response).await;
		assert!(matches!(drift, Err(HandshakeError::ReceiptMismatch)));
		Ok(())
	}

	#[tokio::test]
	async fn replayed_response_fails_closed() -> Result<(), HandshakeError> {
		let (mut client, mut server) = rekey_pair()?;
		let request = client.start_renewal()?;
		let response = server.process_request(&request).await?;
		let replay = response.to_owned();

		client.process_response(response).await.map(|_| ())?;

		// A replay targets the advanced chain: the pin no longer matches.
		client.pending = Some(PendingRenewal { client_random: [3u8; 32], request_der: request.to_der()? });
		let replayed = client.process_response(replay).await;
		assert!(matches!(replayed, Err(HandshakeError::ReceiptMismatch)));
		Ok(())
	}

	#[tokio::test]
	async fn missing_countersignature_fails_closed() -> Result<(), HandshakeError> {
		let (mut client, mut server) = rekey_pair()?;
		let request = client.start_renewal()?;

		server.process_request(&request).await?;

		let missing = server.process_ack(MuxRekeyAckPackage::new(None)).await;
		assert!(matches!(missing, Err(HandshakeError::CountersignatureMissing)));
		Ok(())
	}

	#[tokio::test]
	async fn foreign_countersignature_fails_closed() -> Result<(), HandshakeError> {
		let (mut client, mut server) = rekey_pair()?;
		let request = client.start_renewal()?;
		let response = server.process_request(&request).await?;
		let epoch_receipt = response.epoch_receipt().ok_or(HandshakeError::ReceiptMissing)?;
		let receipt = receipt_from_artifact(epoch_receipt)?;
		client.process_response(response).await.map(|_| ())?;

		let intruder = test_identity()?;
		let forged = countersign_receipt::<Sha3_256>(&receipt, None, intruder.provider.as_ref()).await?;
		let foreign_ack = MuxRekeyAckPackage::new(Some(forged));
		let foreign = server.process_ack(foreign_ack).await;
		assert!(matches!(foreign, Err(HandshakeError::SignatureVerificationFailed)));
		Ok(())
	}
}
