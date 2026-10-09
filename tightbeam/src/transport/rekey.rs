//! In-band rekey exchange logic.
//!
//! This module builds and verifies the messages of the three-leg renewal:
//! - `RekeyRequest`
//! - `RekeyResponse`
//! - `RekeyAck`
//!
//! # Exchange
//!
//! ```text
//! client                                   server
//!   RekeyRequest(client_random, C)  ---->
//!                                   <----  RekeyResponse(server_random, S, epoch receipt)
//!   RekeyAck(countersignature)      ---->
//!                                   <----  RekeyDone
//! ```
//!
//! Each direction takes fresh keys from the epoch KDF chain, which follows
//! [RFC 9846 § 4.7.3][rfc9846-4.7.3] with an explicit exchange. The prior
//! epoch secret drops the moment the next one installs
//! ([RFC 9846 § 7.2][rfc9846-7.2]).
//!
//! # Fresh agreement
//!
//! `C` and `S` are ephemeral public keys, drawn for one renewal. The next
//! epoch secret takes the previous one and the agreement between them:
//!
//! ```text
//! epoch_next = HKDF(u32be(32) || epoch || u32be(32) || ee, salt = client_random || server_random)
//! ```
//!
//! A holder of one epoch secret who records the renewal therefore derives
//! nothing of the next epoch. Each side refuses a peer ephemeral that is off
//! the curve or equal to the peer's static key.
//!
//! # Bindings
//!
//! - The epoch receipt's `transcript_hash` pins the exchange: `H(hash_prev || request_der || sr || S)`.
//! - `sr` is the server randomness. The request carries `C`, so the server's
//!   signature over the receipt and the client's countersignature both cover
//!   the two ephemerals.
//! - The chain root advances over the full exchange: `hash_next = H(hash_prev
//!   || request_der || response_der || ack_der)`, so every epoch receipt
//!   transitively commits to the whole session history back to the handshake
//!   transcript.
//! - Credit-match invariant: the epoch receipt budgets and credit unit MUST
//!   equal the initial receipt terms byte for byte. Only the settlement
//!   challenge MAY vary per epoch.
//!
//! [rfc9846-4.7.3]: https://datatracker.ietf.org/doc/html/rfc9846#section-4.7.3
//! [rfc9846-7.2]: https://datatracker.ietf.org/doc/html/rfc9846#section-7.2

use std::sync::Arc;

use futures::lock::Mutex as FuturesMutex;

use crate::cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use crate::constants::EC_PUBKEY_COMPRESSED_SIZE;
use crate::crypto::aead::{DirectionalCiphers, RecvCipher, SendCipher, SessionKeys};
use crate::crypto::key::SigningKeyProvider;
use crate::crypto::sign::elliptic_curve::ecdh::EphemeralSecret;
use crate::crypto::sign::elliptic_curve::PublicKey;
use crate::der::asn1::OctetString;
use crate::der::Encode;
use crate::random::{generate_nonce, OsRng};
use crate::transport::envelopes::{MuxRekeyAckPackage, MuxRekeyRequestPackage, MuxRekeyResponsePackage};
use crate::transport::handshake::negotiation::TransportAuthorizer;
use crate::transport::handshake::primitives::RandomsSalt;
use crate::transport::handshake::receipt::ReceiptArtifact;
use crate::transport::handshake::receipt::{
	ReceiptApprover, ReceiptRole, SessionObserver, SessionOutcome, SessionReceipt, SessionVerdict, StoredReceipt,
};
use crate::transport::handshake::{
	CompressedPoint, EpochMaterials, EpochSecret, HandshakeCurve, HandshakeError, HandshakeOctets, HandshakeProvider,
	PeerEphemeral,
};
use crate::transport::multiplex::MuxRole;
use crate::utils::marker::{MaybeSend, MaybeSendFuture};
use crate::x509::Certificate;

/// Shared epoch state and identities for one session's rekey exchanges.
///
/// Both roles hold one, and it carries:
///
/// - the epoch secret chain,
/// - the initial receipt terms, which are the credit-match reference,
/// - the local signing identity,
/// - the peer's static key, which each rekey ephemeral is parsed beside, and
/// - the peer's verified receipt identity.
///
/// The provider's cipher type names the AEAD, and its curve the agreement.
pub(crate) struct RekeyMaterials<P>
where
	P: HandshakeProvider,
{
	epoch: EpochMaterials,
	reference: SessionReceipt,
	signing_provider: Arc<dyn SigningKeyProvider>,
	peer_static: PublicKey<P::Curve>,
	peer_verifying_key: P::VerifyingKey,
	peer_sid: SignerIdentifier,
}

/// Fresh per-direction state produced by a completed exchange.
///
/// The mux driver installs each cipher at its message boundary:
///
/// - The client installs send at `RekeyAck` and receive at `RekeyDone`.
/// - The server installs receive after a verified `RekeyAck` and send at `RekeyDone`.
pub(crate) struct EpochInstall {
	/// The send-direction cipher for the new epoch, with a fresh counter.
	pub(crate) send_cipher: SendCipher,
	/// The receive-direction cipher for the new epoch, with a fresh counter.
	pub(crate) recv_cipher: RecvCipher,
	/// The new epoch's dual-signed receipt.
	pub(crate) receipt: StoredReceipt,
	/// The epoch number that the install activates. Unit tests read it, and
	/// the driver installs by position at the message boundary.
	#[cfg_attr(not(test), allow(dead_code))]
	pub(crate) epoch: u32,
}

impl<P> RekeyMaterials<P>
where
	P: HandshakeProvider,
{
	/// Materials for a session whose peer holds the static key `peer_static`.
	///
	/// The key that verifies the peer's receipt signatures comes from the
	/// same point, so the two cannot name different peers.
	pub(crate) fn new(
		epoch: EpochMaterials,
		reference: SessionReceipt,
		signing_provider: Arc<dyn SigningKeyProvider>,
		peer_static: PublicKey<P::Curve>,
		peer_sid: SignerIdentifier,
	) -> Self {
		let peer_verifying_key = P::VerifyingKey::from(peer_static);
		Self { epoch, reference, signing_provider, peer_static, peer_verifying_key, peer_sid }
	}

	/// The current epoch number.
	pub(crate) fn epoch(&self) -> u32 {
		self.epoch.epoch
	}

	/// Install `next_secret` as the current epoch and derive its directional
	/// ciphers under `salt`, the salt that derived it.
	///
	/// The traffic keys come from `next_secret` under the directional labels
	/// that the handshake finalization uses. Assigning the next secret drops
	/// the prior one, which zeroizes on drop (RFC 9846 § 7.2).
	fn rotate(
		&mut self,
		role: MuxRole,
		next_secret: EpochSecret,
		salt: &RandomsSalt,
		next_hash: [u8; 32],
	) -> Result<(SendCipher, RecvCipher), HandshakeError> {
		let directional = DirectionalCiphers::derive::<P, _>(&next_secret, salt.as_kdf_salt())?;

		let next_epoch = self.epoch.epoch.checked_add(1).ok_or(HandshakeError::IntegerOutOfRange)?;
		self.epoch.secret = next_secret;
		self.epoch.epoch = next_epoch;
		self.epoch.transcript_hash = next_hash;

		let keys = match role {
			MuxRole::Client => SessionKeys::for_client(directional),
			MuxRole::Server => SessionKeys::for_server(directional),
		};
		Ok(keys.into_parts())
	}
}

/// The client randomness, the request DER, and the client's rekey ephemeral,
/// held between the request and the server's response.
struct PendingRenewal<C>
where
	C: HandshakeCurve,
{
	client_random: [u8; 32],
	request_der: Vec<u8>,
	/// The scalar of this renewal. It is boxed, so a move copies a pointer
	/// and the scalar is wiped where the box drops.
	ephemeral: Box<EphemeralSecret<C>>,
}

/// The client half of the rekey exchange.
///
/// It opens renewals, verifies and countersigns epoch receipts, and rotates
/// the chain.
pub(crate) struct ClientRekey<P>
where
	P: HandshakeProvider,
{
	materials: RekeyMaterials<P>,
	approver: Option<Arc<dyn ReceiptApprover>>,
	pending: Option<PendingRenewal<P::Curve>>,
}

impl<P> ClientRekey<P>
where
	P: HandshakeProvider,
{
	pub(crate) fn new(materials: RekeyMaterials<P>, approver: Option<Arc<dyn ReceiptApprover>>) -> Self {
		Self { materials, approver, pending: None }
	}

	/// The current epoch number, which unit tests observe.
	#[cfg(test)]
	pub(crate) fn epoch(&self) -> u32 {
		self.materials.epoch()
	}

	/// Whether a renewal awaits the server's response, which unit tests
	/// observe.
	#[cfg(test)]
	pub(crate) fn renewal_in_flight(&self) -> bool {
		self.pending.is_some()
	}

	/// Open a renewal with fresh client randomness and a fresh ephemeral, and
	/// build the first leg.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- a renewal is already in flight.
	pub(crate) fn start_renewal(&mut self) -> Result<MuxRekeyRequestPackage, HandshakeError> {
		if self.pending.is_some() {
			return Err(HandshakeError::InvalidState);
		}

		let client_random = generate_nonce::<32>(None)?;
		let ephemeral = Box::new(EphemeralSecret::<P::Curve>::random(&mut OsRng));
		let client_point = ephemeral.public_key().compressed_point()?;

		let request = MuxRekeyRequestPackage::new(client_random, &client_point)?;
		let request_der = request.to_der()?;
		self.pending = Some(PendingRenewal { client_random, request_der, ephemeral });
		Ok(request)
	}

	/// Verify the server's epoch receipt, agree on the next epoch secret,
	/// approve and countersign the receipt, and rotate the epoch chain.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- no renewal is in flight.
	/// - [`HandshakeError::OctetStringLengthError`] -- the server ephemeral is not a compressed point.
	/// - [`HandshakeError::ReceiptMissing`] -- the response has no epoch receipt.
	/// - [`HandshakeError::ReceiptMismatch`] -- the exchange pin or the credit match fails.
	/// - [`HandshakeError::SignatureVerificationFailed`] -- the server `SignerInfo` is invalid.
	/// - [`HandshakeError::InvalidPublicKey`] -- the server ephemeral is not a point on the curve.
	/// - [`HandshakeError::ServerEphemeralIsStatic`] -- the server ephemeral is the server's static key.
	/// - [`HandshakeError::ApprovalRefused`] -- the approver refuses the renewal.
	pub(crate) async fn process_response(
		&mut self,
		response: MuxRekeyResponsePackage,
	) -> Result<(MuxRekeyAckPackage, EpochInstall), HandshakeError> {
		let pending = self.pending.take().ok_or(HandshakeError::InvalidState)?;
		let PendingRenewal { client_random, request_der, ephemeral } = pending;
		let response_der = response.to_der()?;
		let MuxRekeyResponsePackage { server_random, server_ephemeral, epoch_receipt } = response;
		let server_random = server_random.to_32_byte_array()?;
		let server_point = server_ephemeral.to_byte_array::<EC_PUBKEY_COMPRESSED_SIZE>()?;
		let epoch_receipt = epoch_receipt.ok_or(HandshakeError::ReceiptMissing)?;
		let artifact = *epoch_receipt;

		let receipt = artifact.receipt()?;
		let server_role = ReceiptRole::Server;
		let server_signer = artifact.signer_for_role(server_role)?.ok_or(HandshakeError::ReceiptMissing)?;
		receipt.verify_signer::<P::Digest, P::Signature, _>(
			server_signer,
			server_role,
			&self.materials.peer_sid,
			&self.materials.peer_verifying_key,
		)?;

		let epoch = &self.materials.epoch;
		let challenge_hash = epoch.exchange_pin::<P::Digest>(&request_der, &server_random, &server_point)?;
		let reference_budgets = self.materials.reference.budgets;
		let reference_unit = self.materials.reference.credit_unit;
		receipt.verify_terms::<P::Digest>(&challenge_hash, reference_budgets, reference_unit)?;

		// The receipt the server signed pins its ephemeral, so the point is
		// authenticated here. The agreement takes the scalar by value and runs
		// before the approver is awaited, so no await of this step holds it.
		let server_ephemeral = self.materials.peer_static.server_ephemeral(&server_point)?;
		let salt = RandomsSalt::new(&client_random, &server_random);
		let next_secret = epoch.secret.next::<P>(ephemeral, &server_ephemeral, salt.as_kdf_salt())?;

		let answer = receipt.approve(self.approver.as_deref()).await?;
		let answer_bytes = answer.as_ref().map(OctetString::as_bytes);
		let provider = self.materials.signing_provider.as_ref();
		let countersignature = receipt.countersign::<P::Digest>(answer_bytes, provider).await?;

		// The countersignature has two owners by design. One copy folds into
		// the retained artifact, and the other is DER-encoded into the ack.
		let completed = artifact.complete(countersignature.clone())?;
		let stored = StoredReceipt::try_from(completed)?;

		let ack = MuxRekeyAckPackage::new(Some(countersignature));
		let ack_der = ack.to_der()?;
		let next_hash = self
			.materials
			.epoch
			.advanced::<P::Digest>(&request_der, &response_der, &ack_der)?;
		let rotated = self.materials.rotate(MuxRole::Client, next_secret, &salt, next_hash)?;
		let (send_cipher, recv_cipher) = rotated;

		let install = EpochInstall { send_cipher, recv_cipher, receipt: stored, epoch: self.materials.epoch() };
		Ok((ack, install))
	}
}

/// The receipt, the artifact, the randoms, the exchange DERs, and the next
/// epoch secret, held between the response and the client's acknowledgement.
///
/// The request agrees and drops the server's scalar, so the derived secret is
/// what waits here.
struct PendingSettlement {
	receipt: SessionReceipt,
	artifact: SignedData,
	request_der: Vec<u8>,
	response_der: Vec<u8>,
	client_random: [u8; 32],
	server_random: [u8; 32],
	/// The secret the acknowledgement installs, once the client's
	/// countersignature verifies. It zeroizes if the exchange is dropped
	/// unsettled.
	next_secret: EpochSecret,
}

/// The server half of the rekey exchange.
///
/// It issues epoch receipts, settles countersignatures, records outcomes, and
/// rotates the chain.
pub(crate) struct ServerRekey<P>
where
	P: HandshakeProvider,
{
	materials: RekeyMaterials<P>,
	authorizer: Option<Arc<dyn TransportAuthorizer>>,
	observer: Option<Arc<dyn SessionObserver>>,
	client_certificate: Option<Arc<Certificate>>,
	pending: Option<PendingSettlement>,
}

impl<P> ServerRekey<P>
where
	P: HandshakeProvider,
{
	pub(crate) fn new(
		materials: RekeyMaterials<P>,
		authorizer: Option<Arc<dyn TransportAuthorizer>>,
		observer: Option<Arc<dyn SessionObserver>>,
		client_certificate: Option<Arc<Certificate>>,
	) -> Self {
		Self { materials, authorizer, observer, client_certificate, pending: None }
	}

	/// The current epoch number, which unit tests observe.
	#[cfg(test)]
	pub(crate) fn epoch(&self) -> u32 {
		self.materials.epoch()
	}

	/// Whether an exchange awaits the client's acknowledgement.
	pub(crate) fn exchange_in_flight(&self) -> bool {
		self.pending.is_some()
	}

	/// Agree on the next epoch secret and issue the epoch receipt for a
	/// renewal request, as the second leg.
	///
	/// The receipt inherits the initial budgets and credit unit. The
	/// authorizer may attach a fresh settlement challenge for the epoch.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- an exchange is already in flight.
	///   The mux driver bounds request flooding before this check.
	/// - [`HandshakeError::OctetStringLengthError`] -- the client ephemeral is not a compressed point.
	/// - [`HandshakeError::InvalidPublicKey`] -- the client ephemeral is not a point on the curve.
	/// - [`HandshakeError::ClientEphemeralIsStatic`] -- the client ephemeral is the client's static key.
	/// - [`HandshakeError::SettlementRejected`] -- the authorizer refuses the renewal.
	pub(crate) async fn process_request(
		&mut self,
		request: &MuxRekeyRequestPackage,
	) -> Result<MuxRekeyResponsePackage, HandshakeError> {
		if self.pending.is_some() {
			return Err(HandshakeError::InvalidState);
		}

		let request_der = request.to_der()?;
		let client_random = request.client_random.to_32_byte_array()?;
		let client_point = request.client_ephemeral.to_byte_array::<EC_PUBKEY_COMPRESSED_SIZE>()?;
		let client_ephemeral = self.materials.peer_static.client_ephemeral(&client_point)?;
		let server_random = generate_nonce::<32>(None)?;

		// The agreement takes the scalar by value and runs before the first
		// await, so the server holds the derived secret, and never the scalar,
		// across an await or between two legs.
		let epoch = &self.materials.epoch;
		let salt = RandomsSalt::new(&client_random, &server_random);
		let ephemeral = Box::new(EphemeralSecret::<P::Curve>::random(&mut OsRng));
		let server_point = ephemeral.public_key().compressed_point()?;
		let next_secret = epoch.secret.next::<P>(ephemeral, &client_ephemeral, salt.as_kdf_salt())?;

		let challenge_hash = epoch.exchange_pin::<P::Digest>(&request_der, &server_random, &server_point)?;

		let challenge = match self.authorizer.as_deref() {
			Some(authorizer) => {
				let renewal = authorizer.challenge_renewal(&self.materials.reference).await;
				renewal.map_err(|refusal| HandshakeError::SettlementRejected { code: refusal.code })?
			}
			None => None,
		};

		let (receipt, artifact) = SessionReceipt::issue::<P::Digest>(
			challenge_hash,
			self.materials.reference.budgets,
			self.materials.reference.credit_unit,
			challenge,
			self.materials.signing_provider.as_ref(),
		)
		.await?;

		// The artifact has two owners by design. This copy is DER-encoded into
		// the response and dropped, and the retained artifact absorbs the
		// client SignerInfo at settlement.
		let response = MuxRekeyResponsePackage::new(server_random, &server_point, Some(artifact.clone()))?;
		let response_der = response.to_der()?;
		let pending = PendingSettlement {
			receipt,
			artifact,
			request_der,
			response_der,
			client_random,
			server_random,
			next_secret,
		};

		self.pending = Some(pending);
		Ok(response)
	}

	/// Settle the client's countersignature, record the outcome, and
	/// rotate the epoch chain.
	///
	/// # Refused settlement
	///
	/// A verified countersignature rotates the chain **even when the authorizer
	/// refuses settlement**. The client switched its send cipher at the Ack
	/// boundary, so the server installs the new receive cipher to keep the
	/// refusal's GoAway drain decryptable.
	///
	/// The refusal code surfaces in [`ServerAckOutcome::rejection`] for the
	/// driver to drain on.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- no exchange is in flight.
	/// - [`HandshakeError::CountersignatureMissing`] -- the ack carries no countersignature.
	/// - [`HandshakeError::SignatureVerificationFailed`] -- the countersignature is invalid.
	///
	/// The last two return after the observer records the evidence.
	pub(crate) async fn process_ack(&mut self, ack: MuxRekeyAckPackage) -> Result<ServerAckOutcome, HandshakeError> {
		let pending = self.pending.take().ok_or(HandshakeError::InvalidState)?;
		let ack_der = ack.to_der()?;
		let MuxRekeyAckPackage { countersignature } = ack;
		let countersignature = countersignature.map(|boxed| *boxed);

		let (verdict, ancillary_response) = pending
			.receipt
			.settle_ack::<P::Digest, P::Signature, _>(
				countersignature.as_ref(),
				&self.materials.peer_sid,
				&self.materials.peer_verifying_key,
				self.authorizer.as_deref(),
			)
			.await?;

		let countersignature_der = countersignature.as_ref().map(SignerInfo::to_der).transpose()?;

		// A verified countersignature completes the artifact. A failed one
		// stays out of it, but its DER remains in the outcome as evidence.
		let artifact = match (verdict, countersignature) {
			(SessionVerdict::Activated | SessionVerdict::SettlementRejected { .. }, Some(signer)) => {
				pending.artifact.complete(signer)?
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

		let recorded = outcome.record(self.observer.as_deref()).await;
		let (stored, rejection) = match (recorded, refused_artifact) {
			(Ok(stored), _) => (stored, None),
			(Err(HandshakeError::SettlementRejected { code }), Some(refused)) => {
				(StoredReceipt::try_from(refused)?, Some(code))
			}
			(Err(err), _) => return Err(err),
		};

		let epoch = &self.materials.epoch;
		let next_hash = epoch.advanced::<P::Digest>(&pending.request_der, &pending.response_der, &ack_der)?;
		let salt = RandomsSalt::new(&pending.client_random, &pending.server_random);
		let rotated = self.materials.rotate(MuxRole::Server, pending.next_secret, &salt, next_hash)?;
		let (send_cipher, recv_cipher) = rotated;

		let install = EpochInstall { send_cipher, recv_cipher, receipt: stored, epoch: self.materials.epoch() };
		Ok(ServerAckOutcome { install, rejection })
	}
}

/// The server verdict on a settled acknowledgement.
///
/// It holds the fresh epoch state and, when the authorizer refused, the
/// settlement refusal code. A verified countersignature always installs,
/// because the chain already advanced on both endpoints.
pub(crate) struct ServerAckOutcome {
	/// The fresh per-direction state for the new epoch.
	pub(crate) install: EpochInstall,
	/// The application refusal code when the authorizer rejected settlement.
	pub(crate) rejection: Option<u32>,
}

/// Object-safe client half of the rekey exchange, erasing the crypto
/// provider so the mux driver stays non-generic.
pub(crate) trait ClientRekeyExchange: MaybeSend {
	/// Open a renewal and build the first leg.
	fn start_renewal(&mut self) -> Result<MuxRekeyRequestPackage, HandshakeError>;

	/// Verify, countersign, and rotate on the server's response.
	fn process_response<'a>(
		&'a mut self,
		response: MuxRekeyResponsePackage,
	) -> MaybeSendFuture<'a, Result<(MuxRekeyAckPackage, EpochInstall), HandshakeError>>;
}

impl<P> ClientRekeyExchange for ClientRekey<P>
where
	P: HandshakeProvider,
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
	/// Whether an exchange awaits the client's acknowledgement.
	fn exchange_in_flight(&self) -> bool;

	/// Issue the epoch receipt as the second leg.
	fn process_request<'a>(
		&'a mut self,
		request: &'a MuxRekeyRequestPackage,
	) -> MaybeSendFuture<'a, Result<MuxRekeyResponsePackage, HandshakeError>>;

	/// Settle the countersignature, record the outcome, and rotate the chain.
	fn process_ack<'a>(
		&'a mut self,
		ack: MuxRekeyAckPackage,
	) -> MaybeSendFuture<'a, Result<ServerAckOutcome, HandshakeError>>;
}

impl<P> ServerRekeyExchange for ServerRekey<P>
where
	P: HandshakeProvider,
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
/// # Locking
///
/// The client half sits behind an async mutex. The reader driver holds it
/// across the exchange's hook awaits, while the trigger paths (writer record
/// watermark, emit budget watermark) `try_lock` for the synchronous
/// [`ClientRekeyExchange::start_renewal`] only.
///
/// A contended try-lock means an exchange is already being processed, which
/// makes initiation moot.
pub(crate) enum RekeyDriver {
	/// The renewal initiator, in the mux client role.
	Client(Arc<FuturesMutex<Box<dyn ClientRekeyExchange>>>),
	/// The receipt issuer, in the mux server role.
	Server(Box<dyn ServerRekeyExchange>),
}

impl RekeyDriver {
	/// Wrap a client rekey half, type-erased, for the mux driver.
	pub(crate) fn client<P>(rekey: ClientRekey<P>) -> Self
	where
		P: HandshakeProvider,
	{
		RekeyDriver::Client(Arc::new(FuturesMutex::new(Box::new(rekey))))
	}

	/// Wrap a server rekey half, type-erased, for the mux driver.
	pub(crate) fn server<P>(rekey: ServerRekey<P>) -> Self
	where
		P: HandshakeProvider,
	{
		RekeyDriver::Server(Box::new(rekey))
	}
}

#[cfg(all(test, feature = "secp256k1", feature = "aes-gcm"))]
pub(crate) mod tests {
	use super::*;
	use crate::asn1::{AlgorithmIdentifier, DigestInfo};
	use crate::crypto::aead::DecryptContent;
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::key::Secp256k1KeyProvider;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::crypto::sign::ecdsa::k256::Secp256k1;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::crypto::x509::utils::Skid;
	use crate::oids::HASH_SHA3_256;
	use crate::random::OsRng;
	use crate::spki::EncodePublicKey;
	use crate::transport::handshake::negotiation::MuxBudgets;
	use crate::transport::handshake::primitives::KdfSalt;
	use crate::transport::handshake::tests::{fixture_handshake_secret, off_curve_point};

	/// The provider every rekey test runs under.
	type Provider = DefaultCryptoProvider;

	/// The base-secret fill of the handshake every sample epoch derives from.
	const SAMPLE_BASE: u8 = 0x42;
	const SAMPLE_SALT: [u8; 32] = [0x99u8; 32];
	const SAMPLE_CHAIN_ROOT: [u8; 32] = [0x07u8; 32];
	const SAMPLE_CLIENT_RANDOM: [u8; 32] = [0x01u8; 32];
	const SAMPLE_SERVER_RANDOM: [u8; 32] = [0x02u8; 32];
	const SAMPLE_BUDGETS: MuxBudgets = MuxBudgets { client_to_server: 64, server_to_client: 1024 };
	const SAMPLE_CREDIT_UNIT: u32 = 1024;
	const PLAINTEXT: &[u8] = b"epoch traffic";

	struct Identity {
		provider: Arc<dyn SigningKeyProvider>,
		public_key: PublicKey<Secp256k1>,
		sid: SignerIdentifier,
	}

	fn test_identity() -> Result<Identity, HandshakeError> {
		let signing_key = Secp256k1SigningKey::random(&mut OsRng);
		let verifying_key = *signing_key.verifying_key();
		let sid = SignerIdentifier::try_from(Skid::of_public_key(verifying_key.to_public_key_der()?))?;
		let provider = Secp256k1KeyProvider::from(signing_key);
		Ok(Identity { provider: Arc::new(provider), public_key: PublicKey::from(verifying_key), sid })
	}

	/// A rekey scalar drawn for one test.
	fn fresh_ephemeral() -> EphemeralSecret<Secp256k1> {
		EphemeralSecret::random(&mut OsRng)
	}

	/// The compressed SEC1 bytes of `key`, as a rekey leg carries a point.
	fn point_of(key: &PublicKey<Secp256k1>) -> [u8; EC_PUBKEY_COMPRESSED_SIZE] {
		key.compressed_point().expect("a secp256k1 point compresses to 33 bytes")
	}

	/// A valid compressed point that belongs to no party of the test.
	fn stray_point() -> [u8; EC_PUBKEY_COMPRESSED_SIZE] {
		point_of(&fresh_ephemeral().public_key())
	}

	/// A static key that no point of a test equals, for the parse that admits
	/// a peer point to an agreement.
	fn peer_static() -> PublicKey<Secp256k1> {
		fresh_ephemeral().public_key()
	}

	/// The salt of the sample randoms.
	fn sample_salt() -> RandomsSalt {
		RandomsSalt::new(&SAMPLE_CLIENT_RANDOM, &SAMPLE_SERVER_RANDOM)
	}

	/// The cipher a server would receive on under `secret` and `salt`.
	fn server_recv(secret: &EpochSecret, salt: &RandomsSalt) -> RecvCipher {
		let directional = DirectionalCiphers::derive::<Provider, _>(secret, salt.as_kdf_salt());
		let directional = directional.expect("an epoch secret derives its directional ciphers");
		let (_send, recv) = SessionKeys::for_server(directional).into_parts();
		recv
	}

	/// Epoch 0 of a handshake whose base secret is `fill` bytes, rooted at the
	/// sample chain root.
	fn sample_epoch_from(fill: u8) -> Result<EpochMaterials, HandshakeError> {
		let secret = fixture_handshake_secret(fill);
		EpochMaterials::derive::<DefaultCryptoProvider>(&secret, KdfSalt::new(&SAMPLE_SALT), SAMPLE_CHAIN_ROOT)
	}

	fn sample_epoch() -> Result<EpochMaterials, HandshakeError> {
		sample_epoch_from(SAMPLE_BASE)
	}

	/// Rekey materials over `epoch` for a fresh identity and a fresh peer.
	fn materials_with(epoch: EpochMaterials) -> Result<RekeyMaterials<DefaultCryptoProvider>, HandshakeError> {
		let identity = test_identity()?;
		let peer = test_identity()?;
		let reference = sample_reference(SAMPLE_CREDIT_UNIT)?;
		Ok(RekeyMaterials::new(
			epoch,
			reference,
			identity.provider,
			peer.public_key,
			peer.sid,
		))
	}

	/// The SHA3-256 `DigestInfo` a receipt carries for `hash`.
	fn sha3_digest_info(hash: [u8; 32]) -> Result<DigestInfo, HandshakeError> {
		let algorithm = AlgorithmIdentifier { oid: HASH_SHA3_256, parameters: None };
		let digest = OctetString::new(hash)?;
		Ok(DigestInfo { algorithm, digest })
	}

	fn sample_reference(credit_unit: u32) -> Result<SessionReceipt, HandshakeError> {
		Ok(SessionReceipt {
			transcript_hash: sha3_digest_info(SAMPLE_CHAIN_ROOT)?,
			budgets: SAMPLE_BUDGETS,
			credit_unit,
			ancillary: None,
		})
	}

	/// A client and server holding matched epoch materials, with the identity
	/// each one signs under.
	struct Parties {
		client: ClientRekey<DefaultCryptoProvider>,
		server: ServerRekey<DefaultCryptoProvider>,
		client_identity: Identity,
		server_identity: Identity,
	}

	fn rekey_parties() -> Result<Parties, HandshakeError> {
		let client_identity = test_identity()?;
		let server_identity = test_identity()?;
		let reference = sample_reference(SAMPLE_CREDIT_UNIT)?;

		let client_materials = RekeyMaterials::new(
			sample_epoch()?,
			reference.to_owned(),
			Arc::clone(&client_identity.provider),
			server_identity.public_key,
			server_identity.sid.to_owned(),
		);
		let server_materials = RekeyMaterials::new(
			sample_epoch()?,
			reference,
			Arc::clone(&server_identity.provider),
			client_identity.public_key,
			client_identity.sid.to_owned(),
		);

		let client = ClientRekey::new(client_materials, None);
		let server = ServerRekey::new(server_materials, None, None, None);
		Ok(Parties { client, server, client_identity, server_identity })
	}

	/// A client and server holding matched epoch materials, ready to renew.
	pub(crate) fn rekey_pair(
	) -> Result<(ClientRekey<DefaultCryptoProvider>, ServerRekey<DefaultCryptoProvider>), HandshakeError> {
		let Parties { client, server, .. } = rekey_parties()?;
		Ok((client, server))
	}

	/// Run one renewal to completion and return both endpoints' installs.
	pub(crate) async fn run_exchange(
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
		assert!(received.with(|plain| plain == PLAINTEXT));

		let downlink = server_install.send_cipher.encrypt_next(PLAINTEXT, None)?;
		let received = client_install.recv_cipher.decrypt_content(&downlink)?;
		assert!(received.with(|plain| plain == PLAINTEXT));
		Ok(())
	}

	/// Two chains that share the public chain root, the exchange randoms, and
	/// one agreement, but hold different epoch secrets, derive different
	/// traffic keys. The next epoch therefore depends on the previous epoch
	/// secret as well as on the agreement.
	#[test]
	fn the_next_epoch_depends_on_the_previous_epoch_secret() -> Result<(), Box<dyn std::error::Error>> {
		let mut first = materials_with(sample_epoch_from(SAMPLE_BASE)?)?;
		let mut second = materials_with(sample_epoch_from(SAMPLE_BASE + 1)?)?;
		let (client_scalar, server_scalar) = (Box::new(fresh_ephemeral()), Box::new(fresh_ephemeral()));
		let client_point = peer_static().server_ephemeral(&point_of(&client_scalar.public_key()))?;
		let server_point = peer_static().server_ephemeral(&point_of(&server_scalar.public_key()))?;
		let salt = sample_salt();
		let kdf_salt = salt.as_kdf_salt();
		let first_next = first.epoch.secret.next::<Provider>(client_scalar, &server_point, kdf_salt)?;
		let second_next = second.epoch.secret.next::<Provider>(server_scalar, &client_point, kdf_salt)?;

		let (first_send, _first_recv) = first.rotate(MuxRole::Client, first_next, &salt, SAMPLE_CHAIN_ROOT)?;
		let (_second_send, second_recv) = second.rotate(MuxRole::Server, second_next, &salt, SAMPLE_CHAIN_ROOT)?;

		let frame = first_send.encrypt_next(PLAINTEXT, None)?;
		assert!(second_recv.decrypt_content(&frame).is_err());
		Ok(())
	}

	/// The rotated traffic keys come from the next chain link, so a frame
	/// sealed under the previous epoch secret's directional key does not open
	/// under them.
	#[test]
	fn rotation_leaves_the_previous_epoch_keys_behind() -> Result<(), Box<dyn std::error::Error>> {
		let epoch = sample_epoch()?;
		let salt = sample_salt();
		let previous = DirectionalCiphers::derive::<Provider, _>(&epoch.secret, salt.as_kdf_salt())?;
		let (previous_send, _previous_recv) = SessionKeys::for_client(previous).into_parts();
		let peer = peer_static().server_ephemeral(&stray_point())?;
		let scalar = Box::new(fresh_ephemeral());
		let next = epoch.secret.next::<Provider>(scalar, &peer, salt.as_kdf_salt())?;
		let mut materials = materials_with(epoch)?;

		let (_send, recv) = materials.rotate(MuxRole::Server, next, &salt, SAMPLE_CHAIN_ROOT)?;

		let frame = previous_send.encrypt_next(PLAINTEXT, None)?;
		assert!(recv.decrypt_content(&frame).is_err());
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
		assert!(received.with(|plain| plain == PLAINTEXT));
		Ok(())
	}

	#[tokio::test]
	async fn epoch_receipt_pins_the_exchange() -> Result<(), HandshakeError> {
		let (mut client, mut server) = rekey_pair()?;
		let request = client.start_renewal()?;
		let response = server.process_request(&request).await?;

		let epoch_receipt = response.epoch_receipt().ok_or(HandshakeError::ReceiptMissing)?;
		let receipt = epoch_receipt.receipt()?;
		assert_eq!(receipt.budgets, SAMPLE_BUDGETS);
		assert_eq!(receipt.credit_unit, SAMPLE_CREDIT_UNIT);

		let chain_root = sha3_digest_info(SAMPLE_CHAIN_ROOT)?;
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
		let request = MuxRekeyRequestPackage::new([1u8; 32], &stray_point())?;
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

		let bare = MuxRekeyResponsePackage::new([9u8; 32], &stray_point(), None)?;
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
		// A replay targets the advanced chain, where the pin fails to match.
		let request_der = request.to_der()?;
		let ephemeral = Box::new(fresh_ephemeral());
		client.pending = Some(PendingRenewal { client_random: [3u8; 32], request_der, ephemeral });

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
		let receipt = epoch_receipt.receipt()?;

		client.process_response(response).await.map(|_| ())?;

		let intruder = test_identity()?;
		let forged = receipt.countersign::<Sha3_256>(None, intruder.provider.as_ref()).await?;
		let foreign_ack = MuxRekeyAckPackage::new(Some(forged));
		let foreign = server.process_ack(foreign_ack).await;
		assert!(matches!(foreign, Err(HandshakeError::SignatureVerificationFailed)));
		Ok(())
	}

	/// An observer who holds the current epoch secret and the whole renewal
	/// as it was sent, and no rekey scalar, derives no key of the next epoch.
	///
	/// The observer runs the production derivation with a scalar of its own
	/// against each ephemeral the renewal carried. Neither result opens a
	/// frame of the new epoch.
	#[tokio::test]
	async fn the_next_epoch_needs_a_rekey_scalar() -> Result<(), Box<dyn std::error::Error>> {
		let (mut client, mut server) = rekey_pair()?;
		let request = client.start_renewal()?;
		let response = server.process_request(&request).await?;
		let wire_client = peer_static().server_ephemeral(request.client_ephemeral())?;
		let wire_server = peer_static().server_ephemeral(response.server_ephemeral())?;
		let client_random = request.client_random.to_32_byte_array()?;
		let server_random = response.server_random.to_32_byte_array()?;
		let salt = RandomsSalt::new(&client_random, &server_random);

		let (ack, client_install) = client.process_response(response).await?;
		let server_install = server.process_ack(ack).await?.install;
		let frame = client_install.send_cipher.encrypt_next(PLAINTEXT, None)?;

		// Positive control: the server held a rekey scalar and opens the frame.
		let received = server_install.recv_cipher.decrypt_content(&frame)?;
		assert!(received.with(|plain| plain == PLAINTEXT));

		// The observer starts from the epoch secret both endpoints held, and
		// draws a scalar of its own for each attempt.
		let observed = sample_epoch()?;
		let (first, second) = (Box::new(fresh_ephemeral()), Box::new(fresh_ephemeral()));
		let against_client = observed.secret.next::<Provider>(first, &wire_client, salt.as_kdf_salt())?;
		let against_server = observed.secret.next::<Provider>(second, &wire_server, salt.as_kdf_salt())?;
		assert!(server_recv(&against_client, &salt).decrypt_content(&frame).is_err());
		assert!(server_recv(&against_server, &salt).decrypt_content(&frame).is_err());
		Ok(())
	}

	/// A server ephemeral swapped in transit changes the pin the client
	/// recomputes, so the receipt the server signed fails the match.
	#[tokio::test]
	async fn a_swapped_server_ephemeral_fails_the_pin() -> Result<(), HandshakeError> {
		let (mut client, mut server) = rekey_pair()?;
		let request = client.start_renewal()?;
		let mut response = server.process_request(&request).await?;
		response.server_ephemeral = OctetString::new(stray_point())?;

		let swapped = client.process_response(response).await;
		assert!(matches!(swapped, Err(HandshakeError::ReceiptMismatch)));
		Ok(())
	}

	/// A client ephemeral swapped in transit reaches the server inside the
	/// request the server pins. The client pins the request it sent, so the
	/// receipt fails the match.
	#[tokio::test]
	async fn a_swapped_client_ephemeral_fails_the_pin() -> Result<(), HandshakeError> {
		let (mut client, mut server) = rekey_pair()?;
		let mut request = client.start_renewal()?;
		request.client_ephemeral = OctetString::new(stray_point())?;

		let response = server.process_request(&request).await?;
		let swapped = client.process_response(response).await;
		assert!(matches!(swapped, Err(HandshakeError::ReceiptMismatch)));
		Ok(())
	}

	/// A client ephemeral that names no point on the curve is refused at the
	/// parse, before any agreement runs on it.
	#[tokio::test]
	async fn an_off_curve_client_ephemeral_is_refused() -> Result<(), HandshakeError> {
		let (mut client, mut server) = rekey_pair()?;
		let mut request = client.start_renewal()?;
		request.client_ephemeral = OctetString::new(off_curve_point())?;

		let refused = server.process_request(&request).await;
		assert!(matches!(refused, Err(HandshakeError::InvalidPublicKey(_))));
		assert!(!server.exchange_in_flight());
		Ok(())
	}

	/// A client ephemeral of another width is refused before it is parsed as
	/// a point.
	#[tokio::test]
	async fn a_client_ephemeral_of_another_width_is_refused() -> Result<(), HandshakeError> {
		let (mut client, mut server) = rekey_pair()?;
		let mut request = client.start_renewal()?;
		request.client_ephemeral = OctetString::new([0x02u8; 32])?;

		let refused = server.process_request(&request).await;
		assert!(matches!(refused, Err(HandshakeError::OctetStringLengthError(_))));
		Ok(())
	}

	/// A client ephemeral that is the client's static key is refused, so the
	/// agreement of a renewal cannot collapse into the static one.
	#[tokio::test]
	async fn a_client_ephemeral_equal_to_the_static_key_is_refused() -> Result<(), HandshakeError> {
		let Parties { mut client, mut server, client_identity, .. } = rekey_parties()?;
		let mut request = client.start_renewal()?;
		request.client_ephemeral = OctetString::new(point_of(&client_identity.public_key))?;

		let refused = server.process_request(&request).await;
		assert!(matches!(refused, Err(HandshakeError::ClientEphemeralIsStatic)));
		Ok(())
	}

	/// A server ephemeral that is the server's static key is refused, even
	/// under a receipt the server signed over it.
	#[tokio::test]
	async fn a_server_ephemeral_equal_to_the_static_key_is_refused() -> Result<(), HandshakeError> {
		let Parties { mut client, server_identity, .. } = rekey_parties()?;
		let request = client.start_renewal()?;
		let static_point = point_of(&server_identity.public_key);
		let epoch = sample_epoch()?;
		let pin = epoch.exchange_pin::<Sha3_256>(request.to_der()?, &SAMPLE_SERVER_RANDOM, &static_point)?;
		let signer = server_identity.provider.as_ref();
		let issuing = SessionReceipt::issue::<Sha3_256>(pin, SAMPLE_BUDGETS, SAMPLE_CREDIT_UNIT, None, signer);
		let (_receipt, artifact) = issuing.await?;
		let response = MuxRekeyResponsePackage::new(SAMPLE_SERVER_RANDOM, &static_point, Some(artifact))?;

		let refused = client.process_response(response).await;
		assert!(matches!(refused, Err(HandshakeError::ServerEphemeralIsStatic)));
		Ok(())
	}
}
