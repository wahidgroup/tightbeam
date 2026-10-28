//! The in-band rekey exchange of a multiplexed session.
//!
//! It builds and verifies the messages of the three-leg renewal:
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
//! epoch_next = HKDF(u32be(32) || epoch || u32be(Ndh) || ee, salt = client_random || server_random)
//! ```
//!
//! `Ndh` is the width of `ee`, the field width of the session's curve.
//!
//! So a holder of one epoch secret who records the renewal still needs a rekey
//! scalar to derive the next epoch. Each side refuses a peer ephemeral that is
//! off the curve, or that equals a static key of the peer or its negation: the
//! client's one key, or either key of a CMS server, as the handshake refuses
//! it.
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

use core::marker::PhantomData;
use std::sync::Arc;

use futures::lock::Mutex as FuturesMutex;

use crate::cms::signed_data::SignedData;
use crate::crypto::aead::{RecvCipher, SendCipher, SessionKeys};
use crate::crypto::sign::elliptic_curve::ecdh::EphemeralSecret;
use crate::crypto::sign::elliptic_curve::PublicKey;
use crate::crypto::sign::{Signed, SigningIdentity};
use crate::crypto::x509::{PeerCertificate, Signing};
use crate::der::asn1::{ObjectIdentifier, OctetString};
use crate::der::Encode;
use crate::random::{generate_nonce, OsRng};
use crate::transport::envelopes::{MuxRekeyAckPackage, MuxRekeyRequestPackage, MuxRekeyResponsePackage};
use crate::transport::handshake::negotiation::TransportAuthorizer;
use crate::transport::handshake::primitives::RandomsSalt;
use crate::transport::handshake::receipt::ReceiptArtifact;
use crate::transport::handshake::receipt::{
	ReceiptApprover, ReceiptRole, SessionObserver, SessionOutcome, SessionReceipt, StoredReceipt,
};
use crate::transport::handshake::{
	AgreementCertificate, EpochMaterials, EpochSecret, HandshakeCurve, HandshakeError, HandshakeOctets,
	HandshakeProvider, PeerEphemeral, ServerKeys, SessionPeer,
};
use crate::utils::marker::{MaybeSend, MaybeSendFuture};

/// Shared epoch state and identities for one session's rekey exchanges.
///
/// Both roles hold one, and it carries:
///
/// - the epoch secret chain,
/// - the initial receipt terms, which are the credit-match reference,
/// - the local signing identity, and
/// - the [`RekeyPeer`] the session recorded, whose signing key verifies the peer's receipt signatures.
///
/// The provider's cipher type names the AEAD, and its curve names the
/// agreement.
pub(crate) struct RekeyMaterials<P>
where
	P: HandshakeProvider,
{
	epoch: EpochMaterials,
	reference: SessionReceipt,
	identity: SigningIdentity,
	peer: RekeyPeer<P>,
}

/// The peer a session recorded, once its certificate is admitted for signing
/// under the key purpose of its role, with the key of a CMS server's
/// key-agreement certificate as a point of the handshake curve.
///
/// A rekey's materials take it whole, so each key a rekey reads names the one
/// peer.
pub(crate) struct RekeyPeer<P>
where
	P: HandshakeProvider,
{
	/// The certificate, admitted for signing under the purpose of its role.
	signing: PeerCertificate<Signing<P>>,
	/// The key of a CMS server's key-agreement certificate.
	key_agreement: Option<PublicKey<P::Curve>>,
}

impl<P> RekeyPeer<P>
where
	P: HandshakeProvider,
{
	/// Admit `peer` for signing under `purpose`, the key purpose of the peer's
	/// role.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- the signing use or `purpose` refuses `peer`.
	pub(crate) fn admit(peer: &SessionPeer, purpose: ObjectIdentifier) -> Result<Self, HandshakeError> {
		let signing = PeerCertificate::parse(Arc::clone(peer.certificate()), purpose)?;
		let key_agreement = peer.key_agreement();
		let key_agreement = key_agreement.and_then(|certificate| certificate.agreement_point::<P::Curve>());
		Ok(Self { signing, key_agreement })
	}

	/// The static keys of this peer as the server of its session.
	fn server_keys(&self) -> ServerKeys<'_, P> {
		ServerKeys { signing: &self.signing, key_agreement: self.key_agreement.as_ref() }
	}
}

/// Fresh per-direction state produced by a completed exchange.
///
/// The mux driver installs each cipher at its message boundary:
///
/// - The client installs send at `RekeyAck` and receive at `RekeyDone`.
/// - The server installs receive after a verified `RekeyAck` and send at `RekeyDone`.
pub(crate) struct EpochInstall {
	/// The send-direction cipher for the next epoch, with a fresh counter.
	pub(crate) send_cipher: SendCipher,
	/// The receive-direction cipher for the next epoch, with a fresh counter.
	pub(crate) recv_cipher: RecvCipher,
	/// The dual-signed receipt of the next epoch.
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
	/// Materials for a session whose recorded peer is `peer`.
	pub(crate) fn new(
		epoch: EpochMaterials,
		reference: SessionReceipt,
		identity: SigningIdentity,
		peer: RekeyPeer<P>,
	) -> Self {
		Self { epoch, reference, identity, peer }
	}

	/// The current epoch number.
	pub(crate) fn epoch(&self) -> u32 {
		self.epoch.epoch()
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
	/// The scalar of this renewal. It is boxed, so a move copies a pointer,
	/// and the scalar zeroizes where the box drops.
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
	/// The client half over `materials`, whose peer is the server. Each server
	/// ephemeral must differ from every static key of that server.
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
		let client_point = ephemeral.public_key();

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
	/// - [`HandshakeError::OctetStringLengthError`] -- the server random is not
	///   32 bytes, or the server ephemeral is not the width of a compressed
	///   point.
	/// - [`HandshakeError::ReceiptMissing`] -- the response has no epoch receipt.
	/// - [`HandshakeError::ReceiptMismatch`] -- the exchange pin or the credit match fails.
	/// - [`HandshakeError::SignatureVerificationFailed`] -- the server `SignerInfo` is invalid.
	/// - [`HandshakeError::InvalidPublicKey`] -- the server ephemeral is no
	///   point on the curve in the compressed form.
	/// - [`HandshakeError::ServerEphemeralIsStatic`] -- the server ephemeral is
	///   a static key of the server or its negation.
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
		let server_point = server_ephemeral.to_compressed_point::<P::Curve>()?;
		let epoch_receipt = epoch_receipt.ok_or(HandshakeError::ReceiptMissing)?;
		let artifact = *epoch_receipt;

		// The parse refuses a leg that is a static key of the server or its
		// negation. The signed receipt pins the leg, so the checks below
		// authenticate the point before the agreement runs.
		let keys = self.materials.peer.server_keys();
		let server_ephemeral = keys.server_ephemeral(&server_point)?;

		let receipt = artifact.receipt()?;
		let server_role = ReceiptRole::Server;
		let server_signer = artifact.signer_for_role(server_role)?.ok_or(HandshakeError::ReceiptMissing)?;
		receipt.verify_signer::<P>(server_signer, server_role, &self.materials.peer.signing)?;

		let epoch = &self.materials.epoch;
		let challenge_hash = epoch.exchange_pin::<P::Digest, P::Curve>(&request_der, &server_random, &server_point)?;
		let reference_budgets = self.materials.reference.budgets;
		let reference_unit = self.materials.reference.credit_unit;

		receipt.verify_terms(&challenge_hash, reference_budgets, reference_unit)?;

		// The agreement takes the scalar by value and runs before the client
		// awaits the approver, so the scalar is gone before the first await of
		// this step.
		let salt = RandomsSalt::new(&client_random, &server_random);
		let next_secret = epoch.next_secret::<P>(ephemeral, &server_ephemeral, salt.as_kdf_salt()?)?;

		let answer = receipt.approve(self.approver.as_deref()).await?;
		let answer_bytes = answer.as_ref().map(OctetString::as_bytes);
		let identity = &self.materials.identity;
		let countersignature = receipt.countersign(answer_bytes, identity).await?;

		// The countersignature has two owners: the retained artifact and the
		// ack DER. The artifact holds its own copy of the client's certificate,
		// because a `CertificateSet` owns each certificate it holds.
		let signer = countersignature.signer().clone();
		let completed = artifact.with_certified_signer(countersignature)?;
		let stored = StoredReceipt::try_from(completed)?;

		let ack = MuxRekeyAckPackage::new(Some(signer));
		let ack_der = ack.to_der()?;
		let epoch = &mut self.materials.epoch;
		let next_hash = epoch.advanced::<P::Digest>(&request_der, &response_der, &ack_der)?;

		let rotated = epoch.install::<P>(next_secret, salt.as_kdf_salt()?, next_hash)?;
		let (send_cipher, recv_cipher) = SessionKeys::for_client(rotated).into_parts();

		let install = EpochInstall { send_cipher, recv_cipher, receipt: stored, epoch: self.materials.epoch() };
		Ok((ack, install))
	}
}

/// The receipt, the artifact, the randoms, the exchange DERs, and the next
/// epoch secret, held between the response and the client's acknowledgement.
///
/// The server runs the agreement on the request and drops its scalar there,
/// so the derived secret waits here.
struct PendingSettlement {
	receipt: SessionReceipt,
	artifact: Signed<SignedData>,
	request_der: Vec<u8>,
	response_der: Vec<u8>,
	client_random: [u8; 32],
	server_random: [u8; 32],
	/// The secret the acknowledgement installs, once the client's
	/// countersignature verifies. It zeroizes if the server drops the exchange
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
	pending: Option<PendingSettlement>,
}

impl<P> ServerRekey<P>
where
	P: HandshakeProvider,
{
	/// The server half over `materials`, whose peer is the client, which
	/// each outcome names to `observer`.
	pub(crate) fn new(
		materials: RekeyMaterials<P>,
		authorizer: Option<Arc<dyn TransportAuthorizer>>,
		observer: Option<Arc<dyn SessionObserver>>,
	) -> Self {
		Self { materials, authorizer, observer, pending: None }
	}

	/// The current epoch number, which unit tests observe.
	#[cfg(test)]
	pub(crate) fn epoch(&self) -> u32 {
		self.materials.epoch()
	}

	/// Whether an exchange awaits the client's acknowledgement, which unit
	/// tests observe.
	#[cfg(test)]
	pub(crate) fn exchange_in_flight(&self) -> bool {
		self.pending.is_some()
	}

	/// Answer a renewal request: agree on the next epoch secret and issue the
	/// epoch receipt as the second leg, or refuse the request while an
	/// exchange awaits the client's acknowledgement.
	///
	/// The receipt inherits the initial budgets and credit unit. The
	/// authorizer may attach a fresh settlement challenge for the epoch.
	///
	/// # Errors
	///
	/// - [`HandshakeError::OctetStringLengthError`] -- the client random is not
	///   32 bytes, or the client ephemeral is not the width of a compressed
	///   point.
	/// - [`HandshakeError::InvalidPublicKey`] -- the client ephemeral is no
	///   point on the curve in the compressed form.
	/// - [`HandshakeError::ClientEphemeralIsStatic`] -- the client ephemeral is
	///   the client's static key or its negation.
	/// - [`HandshakeError::SettlementRejected`] -- the authorizer refuses the renewal.
	pub(crate) async fn process_request(
		&mut self,
		request: &MuxRekeyRequestPackage,
	) -> Result<RequestAnswer, HandshakeError> {
		if self.pending.is_some() {
			return Ok(RequestAnswer::InFlight);
		}

		let request_der = request.to_der()?;
		let client_random = request.client_random.to_32_byte_array()?;
		let client_point = request.client_ephemeral.to_compressed_point::<P::Curve>()?;
		let client_ephemeral = self.materials.peer.signing.client_ephemeral(&client_point)?;
		let server_random = generate_nonce::<32>(None)?;

		// The agreement takes the scalar by value and runs before the first
		// await, so the server holds the derived secret alone across an await
		// or between two legs.
		let epoch = &self.materials.epoch;
		let salt = RandomsSalt::new(&client_random, &server_random);
		let ephemeral = Box::new(EphemeralSecret::<P::Curve>::random(&mut OsRng));
		let mut response = MuxRekeyResponsePackage::new(server_random, &ephemeral.public_key(), None)?;
		let next_secret = epoch.next_secret::<P>(ephemeral, &client_ephemeral, salt.as_kdf_salt()?)?;

		// The pin covers the leg as the response carries it, read back with
		// the reader the client runs.
		let server_point = response.server_ephemeral.to_compressed_point::<P::Curve>()?;
		let challenge_hash = epoch.exchange_pin::<P::Digest, P::Curve>(&request_der, &server_random, &server_point)?;

		let challenge = match self.authorizer.as_deref() {
			Some(authorizer) => {
				let renewal = authorizer.challenge_renewal(&self.materials.reference).await;
				renewal.map_err(|refusal| HandshakeError::SettlementRejected { code: refusal.code })?
			}
			None => None,
		};

		let (receipt, artifact) = SessionReceipt::issue(
			challenge_hash,
			self.materials.reference.budgets,
			self.materials.reference.credit_unit,
			challenge,
			&self.materials.identity,
		)
		.await?;

		// The artifact has two owners by design. The response encodes this copy
		// in DER and drops it, and the retained artifact absorbs the client
		// SignerInfo at settlement.
		response.epoch_receipt = Some(Box::new(artifact.clone()));
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
		Ok(RequestAnswer::Issued(response))
	}

	/// Settle the client's countersignature, record the outcome, and
	/// rotate the epoch chain.
	///
	/// # Refused settlement
	///
	/// A verified countersignature rotates the chain **even when the authorizer
	/// refuses settlement**. The client switched its send cipher at the Ack
	/// boundary, so the server installs the receive cipher of the next epoch to
	/// keep the refusal's GoAway drain decryptable.
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
		let countersignature_der = countersignature.as_ref().map(Encode::to_der).transpose()?;

		let (verdict, ancillary_response, countersigner) = pending
			.receipt
			.settle_ack::<P>(countersignature, &self.materials.peer.signing, self.authorizer.as_deref())
			.await?;

		// A verified countersignature completes the artifact, beside the
		// client's certificate it verified under. A failed one leaves the
		// artifact as it is, and its DER remains in the outcome as evidence.
		let artifact = match countersigner {
			Some(countersigner) => pending.artifact.with_certified_signer(countersigner)?,
			None => pending.artifact,
		};

		let countersignature_octet = countersignature_der.map(OctetString::new).transpose()?;
		let client_certificate = Some(Arc::clone(self.materials.peer.signing.certificate()));
		let outcome = SessionOutcome {
			receipt: pending.receipt,
			artifact,
			countersignature: countersignature_octet,
			ancillary_response,
			client_certificate,
			verdict,
		};

		let settled = outcome.record(self.observer.as_deref()).await?;
		let (stored, rejection) = settled.installable();

		let epoch = &mut self.materials.epoch;
		let next_hash = epoch.advanced::<P::Digest>(&pending.request_der, &pending.response_der, &ack_der)?;
		let salt = RandomsSalt::new(&pending.client_random, &pending.server_random);
		let rotated = epoch.install::<P>(pending.next_secret, salt.as_kdf_salt()?, next_hash)?;
		let (send_cipher, recv_cipher) = SessionKeys::for_server(rotated).into_parts();

		let install = EpochInstall { send_cipher, recv_cipher, receipt: stored, epoch: self.materials.epoch() };
		Ok(ServerAckOutcome { install, rejection })
	}
}

/// The server's answer to a renewal request.
///
/// [`ServerRekey::process_request`] is its one source, so the server half
/// alone decides whether a request may open an exchange.
pub(crate) enum RequestAnswer {
	/// The epoch receipt for the request, as the second leg.
	Issued(MuxRekeyResponsePackage),
	/// The refusal of a request that arrived while an exchange awaits the
	/// client's acknowledgement, which the mux reader reads as a protocol
	/// violation (CWE-400).
	InFlight,
}

/// The server verdict on a settled acknowledgement.
///
/// It holds the fresh epoch state and, when the authorizer refused, the
/// settlement refusal code. A verified countersignature always installs,
/// because the chain already advanced on both endpoints.
pub(crate) struct ServerAckOutcome {
	/// The fresh per-direction state for the next epoch.
	pub(crate) install: EpochInstall,
	/// The application refusal code when the authorizer rejected settlement.
	pub(crate) rejection: Option<u32>,
}

/// The object-safe client half of the rekey exchange. It erases the crypto
/// provider, so the mux driver stays non-generic.
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

/// The object-safe server half of the rekey exchange. It erases the crypto
/// provider, so the mux driver stays non-generic.
pub(crate) trait ServerRekeyExchange: MaybeSend {
	/// Answer a renewal request, with the epoch receipt as the second leg.
	fn process_request<'a>(
		&'a mut self,
		request: &'a MuxRekeyRequestPackage,
	) -> MaybeSendFuture<'a, Result<RequestAnswer, HandshakeError>>;

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
	fn process_request<'a>(
		&'a mut self,
		request: &'a MuxRekeyRequestPackage,
	) -> MaybeSendFuture<'a, Result<RequestAnswer, HandshakeError>> {
		Box::pin(ServerRekey::process_request(self, request))
	}

	fn process_ack<'a>(
		&'a mut self,
		ack: MuxRekeyAckPackage,
	) -> MaybeSendFuture<'a, Result<ServerAckOutcome, HandshakeError>> {
		Box::pin(ServerRekey::process_ack(self, ack))
	}
}

/// The rekey exchange of one fixed role, which the mux plane holds.
///
/// The mux reader and writer take each step of the exchange through a method
/// of this type, which returns `None` for a step of the other role.
///
/// # Locking
///
/// The client half sits behind an async mutex. The reader driver holds it
/// across the exchange's hook awaits, while the trigger paths (writer record
/// watermark, emit budget watermark) `try_lock` for the synchronous
/// [`ClientRekeyExchange::start_renewal`] only.
///
/// A contended try-lock means an exchange is in progress already, so the
/// trigger skips its renewal.
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

	/// The half that opens renewals, which the writer shares for its record
	/// trigger: the client's half.
	pub(crate) fn renewal_opener(&self) -> Option<&Arc<FuturesMutex<Box<dyn ClientRekeyExchange>>>> {
		match self {
			RekeyDriver::Client(exchange) => Some(exchange),
			RekeyDriver::Server(_) => None,
		}
	}

	/// Answer `request` through the server's half, the server's step, with
	/// the epoch receipt as the second leg.
	pub(crate) async fn process_request(
		&mut self,
		request: &MuxRekeyRequestPackage,
	) -> Option<Result<RequestAnswer, HandshakeError>> {
		match self {
			RekeyDriver::Server(exchange) => {
				let answered = exchange.process_request(request).await;
				Some(answered)
			}
			RekeyDriver::Client(_) => None,
		}
	}

	/// Verify, countersign, and rotate on the server's `response`, the
	/// client's step.
	///
	/// The receiver is exclusive for a `Send` future: the server's half is
	/// `Send` alone, and a shared borrow across an await needs `Sync`.
	pub(crate) async fn process_response(
		&mut self,
		response: MuxRekeyResponsePackage,
	) -> Option<Result<(MuxRekeyAckPackage, EpochInstall), HandshakeError>> {
		match self {
			RekeyDriver::Client(exchange) => {
				let mut guard = exchange.lock().await;
				let processed = guard.process_response(response).await;
				Some(processed)
			}
			RekeyDriver::Server(_) => None,
		}
	}

	/// Settle the countersignature of `ack`, record the outcome, and rotate
	/// the chain, the server's step.
	pub(crate) async fn process_ack(
		&mut self,
		ack: MuxRekeyAckPackage,
	) -> Option<Result<ServerAckOutcome, HandshakeError>> {
		match self {
			RekeyDriver::Server(exchange) => {
				let settled = exchange.process_ack(ack).await;
				Some(settled)
			}
			RekeyDriver::Client(_) => None,
		}
	}
}

/// What one mux role of a session renews under: the identity it presented in
/// the handshake, the key purpose under which it admitted its peer, and the
/// hooks of its half of the rekey exchange.
///
/// 1. [`Self::client`] or [`Self::server`] builds it for one role, under the
///    provider of the endpoint that lends the parts.
/// 2. The session admits its peer with [`Self::admit`].
/// 3. The session runs the [`AdmittedRenewal`] once it hands over its epoch.
pub(crate) struct Renewal<P> {
	/// The identity that signs this role's epoch receipts.
	identity: SigningIdentity,
	/// The key purpose of the peer's role.
	purpose: ObjectIdentifier,
	/// The hooks of this role's half of the exchange.
	hooks: RenewalHooks,
	/// The provider of the endpoint that built it, which the rekey runs under.
	provider: PhantomData<fn() -> P>,
}

/// A renewal whose peer passed the signing use and the purpose of its role,
/// which runs once the session hands over its epoch.
pub(crate) struct AdmittedRenewal<P: HandshakeProvider> {
	/// The identity that signs this role's epoch receipts.
	identity: SigningIdentity,
	/// The peer the session recorded, admitted for this role's rekey.
	peer: RekeyPeer<P>,
	/// The hooks of this role's half of the exchange.
	hooks: RenewalHooks,
}

/// The hooks of one role's half of the rekey exchange.
enum RenewalHooks {
	/// The client's half, which consults `approver` before it countersigns an
	/// epoch receipt.
	Client { approver: Option<Arc<dyn ReceiptApprover>> },
	/// The server's half, which consults `authorizer` for each renewal and
	/// reports each outcome to `observer`.
	Server {
		authorizer: Option<Arc<dyn TransportAuthorizer>>,
		observer: Option<Arc<dyn SessionObserver>>,
	},
}

impl<P> Renewal<P> {
	/// The renewal of the client role: `identity` countersigns each epoch
	/// receipt, [`Self::admit`] admits the server under `purpose`, and
	/// `approver` decides each receipt before the countersignature.
	pub(crate) fn client(
		identity: SigningIdentity,
		purpose: ObjectIdentifier,
		approver: Option<Arc<dyn ReceiptApprover>>,
	) -> Self {
		let hooks = RenewalHooks::Client { approver };
		Self { identity, purpose, hooks, provider: PhantomData }
	}

	/// The renewal of the server role: `identity` signs each epoch receipt,
	/// [`Self::admit`] admits the client under `purpose`, `authorizer` decides
	/// each renewal, and `observer` records each outcome.
	pub(crate) fn server(
		identity: SigningIdentity,
		purpose: ObjectIdentifier,
		authorizer: Option<Arc<dyn TransportAuthorizer>>,
		observer: Option<Arc<dyn SessionObserver>>,
	) -> Self {
		let hooks = RenewalHooks::Server { authorizer, observer };
		Self { identity, purpose, hooks, provider: PhantomData }
	}
}

impl<P: HandshakeProvider> Renewal<P> {
	/// This renewal with `peer`, the peer the session recorded, admitted for
	/// signing under the purpose of the peer's role.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- the signing use or
	///   the purpose of the peer's role refuses `peer`.
	pub(crate) fn admit(self, peer: &SessionPeer) -> Result<AdmittedRenewal<P>, HandshakeError> {
		let Self { identity, purpose, hooks, provider: _ } = self;
		let peer = RekeyPeer::admit(peer, purpose)?;
		Ok(AdmittedRenewal { identity, peer, hooks })
	}
}

impl<P: HandshakeProvider> AdmittedRenewal<P> {
	/// The rekey driver of this role over the session's `epoch` and the terms
	/// of its `reference` receipt.
	pub(crate) fn driver(self, epoch: EpochMaterials, reference: SessionReceipt) -> RekeyDriver {
		let Self { identity, peer, hooks } = self;
		let materials = RekeyMaterials::new(epoch, reference, identity, peer);
		hooks.driver(materials)
	}
}

impl RenewalHooks {
	/// The driver of this half of the exchange over `materials`.
	fn driver<P: HandshakeProvider>(self, materials: RekeyMaterials<P>) -> RekeyDriver {
		match self {
			Self::Client { approver } => {
				let exchange = ClientRekey::new(materials, approver);
				RekeyDriver::client(exchange)
			}
			Self::Server { authorizer, observer } => {
				let exchange = ServerRekey::new(materials, authorizer, observer);
				RekeyDriver::server(exchange)
			}
		}
	}
}

#[cfg(test)]
pub(crate) mod tests {
	use super::*;
	use crate::asn1::{AlgorithmIdentifier, AuthEnvelopedData, DigestInfo};
	use crate::cms::enveloped_data::RecipientInfo;
	use crate::crypto::aead::DirectionalCiphers;
	use crate::crypto::cms::EnvelopeError;
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::kdf::KdfSalt;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::crypto::sign::ecdsa::k256::Secp256k1;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::crypto::sign::elliptic_curve::sec1::{CompressedPoint as Sec1CompressedPoint, ToEncodedPoint};
	use crate::crypto::sign::elliptic_curve::PublicKey;
	use crate::crypto::x509::KeyPurposes;
	use crate::der::Encode;
	use crate::oids::HASH_SHA3_256;
	use crate::random::OsRng;
	use crate::testing::{TestCertificate, TestIdentity, TestKey};
	use crate::transport::envelopes::MUX_APPLICATION_CODE_FLOOR;
	use crate::transport::handshake::negotiation::{
		AuthorizationGrant, AuthorizationRefusal, MuxBudgets, TransportOffer,
	};
	use crate::transport::handshake::primitives::TranscriptHash;
	use crate::transport::handshake::tests::{fixture_handshake_secret, fixture_transcript, off_curve_point};
	use crate::transport::handshake::{CompressedPoint, EstablishedSession};
	use crate::x509::Certificate;
	use crate::TightBeamError;

	#[cfg(feature = "transport-cms")]
	mod cms_session {
		pub use crate::testing::TestCmsServer;
		pub use crate::transport::multiplex::{MuxRekeyContext, MuxRole};
		pub use crate::transport::state::{EncryptedProtocolState, EncryptionConfig, SessionPhase, SessionState};
		pub use crate::transport::{TransportError, TransportLimits};
	}

	#[cfg(feature = "transport-cms")]
	use cms_session::*;

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

	/// One party of a rekey: its signing identity and its static key.
	struct Identity {
		signing: SigningIdentity,
		public_key: PublicKey<Secp256k1>,
	}

	impl Identity {
		/// The party as its peer's session records it, by the certificate it
		/// presents.
		fn peer(&self) -> Result<SessionPeer, HandshakeError> {
			SessionPeer::try_from(self.signing.certificate_arc())
		}
	}

	fn test_identity() -> Result<Identity, HandshakeError> {
		let signing_key = Secp256k1SigningKey::random(&mut OsRng);
		let verifying_key = *signing_key.verifying_key();
		let signing = TestIdentity::of(&signing_key);
		Ok(Identity { signing, public_key: PublicKey::from(verifying_key) })
	}

	/// A rekey scalar drawn for one test.
	fn fresh_ephemeral() -> EphemeralSecret<Secp256k1> {
		EphemeralSecret::random(&mut OsRng)
	}

	/// The compressed SEC 1 bytes of `key`, as a rekey leg carries a point.
	fn point_of(key: &PublicKey<Secp256k1>) -> Sec1CompressedPoint<Secp256k1> {
		key.compressed_point().expect("a secp256k1 point compresses")
	}

	/// A valid point that belongs to no party of the test.
	fn stray_key() -> PublicKey<Secp256k1> {
		fresh_ephemeral().public_key()
	}

	/// The compressed SEC 1 bytes of a valid point that belongs to no party of
	/// the test.
	fn stray_point() -> Sec1CompressedPoint<Secp256k1> {
		point_of(&stray_key())
	}

	/// A peer certificate with a fresh key, distinct from every point of a
	/// test, for the parse that admits a peer point to an agreement.
	fn peer_static() -> PeerCertificate<Signing<Provider>> {
		let certificate = TestCertificate::self_signed(&Secp256k1SigningKey::random(&mut OsRng));
		let peer = PeerCertificate::parse(certificate, KeyPurposes::HOUSE.server);
		peer.expect("a fresh certificate is admitted for signing")
	}

	/// [`SAMPLE_CHAIN_ROOT`] as the chain hash an epoch holds.
	fn sample_chain_root() -> TranscriptHash {
		fixture_transcript::<Sha3_256>(SAMPLE_CHAIN_ROOT)
	}

	/// The salt of the sample randoms.
	fn sample_salt() -> RandomsSalt {
		RandomsSalt::new(&SAMPLE_CLIENT_RANDOM, &SAMPLE_SERVER_RANDOM)
	}

	/// The cipher a server would receive on under `secret` and `salt`, the
	/// secret of epoch 1.
	fn server_recv(secret: &EpochSecret, salt: &RandomsSalt) -> RecvCipher {
		let kdf_salt = salt.as_kdf_salt().expect("the sample randoms meet the salt floor");
		let directional = DirectionalCiphers::derive::<Provider, _>(secret, kdf_salt, 1);
		let directional = directional.expect("an epoch secret derives its directional ciphers");
		let (_send, recv) = SessionKeys::for_server(directional).into_parts();
		recv
	}

	/// Epoch 0 of a handshake whose base secret is `fill` bytes, rooted at the
	/// sample chain root.
	fn sample_epoch_from(fill: u8) -> Result<EpochMaterials, HandshakeError> {
		let secret = fixture_handshake_secret(fill);
		let salt = KdfSalt::try_from(SAMPLE_SALT.as_slice())?;
		EpochMaterials::derive::<DefaultCryptoProvider>(&secret, salt, sample_chain_root())
	}

	fn sample_epoch() -> Result<EpochMaterials, HandshakeError> {
		sample_epoch_from(SAMPLE_BASE)
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

	/// A client and a server that hold matched epoch materials, with the
	/// identity each one signs under.
	struct Parties {
		client: ClientRekey<DefaultCryptoProvider>,
		server: ServerRekey<DefaultCryptoProvider>,
		client_identity: Identity,
		server_identity: Identity,
	}

	fn rekey_parties() -> Result<Parties, HandshakeError> {
		rekey_parties_with(SessionPeer::try_from, None)
	}

	/// The parties of [`rekey_parties`], whose client renews with the peer
	/// `server` makes of the server's signing certificate, as a CMS client
	/// renews with the server's key-agreement certificate beside it, and
	/// whose server reports each outcome to `observer`.
	fn rekey_parties_with(
		server: impl FnOnce(Arc<Certificate>) -> Result<SessionPeer, HandshakeError>,
		observer: Option<Arc<dyn SessionObserver>>,
	) -> Result<Parties, HandshakeError> {
		let client_identity = test_identity()?;
		let server_identity = test_identity()?;
		let reference = sample_reference(SAMPLE_CREDIT_UNIT)?;

		let server_peer = server(server_identity.signing.certificate_arc())?;
		let server_peer = RekeyPeer::admit(&server_peer, KeyPurposes::HOUSE.server)?;
		let client_peer = RekeyPeer::admit(&client_identity.peer()?, KeyPurposes::HOUSE.client)?;
		let client_materials = RekeyMaterials::new(
			sample_epoch()?,
			reference.to_owned(),
			client_identity.signing.clone(),
			server_peer,
		);
		let server_materials =
			RekeyMaterials::new(sample_epoch()?, reference, server_identity.signing.clone(), client_peer);

		let client = ClientRekey::new(client_materials, None);
		let server = ServerRekey::new(server_materials, None, observer);
		Ok(Parties { client, server, client_identity, server_identity })
	}

	/// A client and a server that hold matched epoch materials, ready to
	/// renew.
	pub(crate) fn rekey_pair(
	) -> Result<(ClientRekey<DefaultCryptoProvider>, ServerRekey<DefaultCryptoProvider>), HandshakeError> {
		let Parties { client, server, .. } = rekey_parties()?;
		Ok((client, server))
	}

	/// The epoch receipt `server` issues for `request`, with no exchange of
	/// `server` in flight.
	async fn issued(
		server: &mut ServerRekey<DefaultCryptoProvider>,
		request: &MuxRekeyRequestPackage,
	) -> Result<MuxRekeyResponsePackage, HandshakeError> {
		match server.process_request(request).await? {
			RequestAnswer::Issued(response) => Ok(response),
			RequestAnswer::InFlight => panic!("a server with no exchange in flight answers a request"),
		}
	}

	/// Run one renewal to completion and return both endpoints' installs.
	pub(crate) async fn run_exchange(
		client: &mut ClientRekey<DefaultCryptoProvider>,
		server: &mut ServerRekey<DefaultCryptoProvider>,
	) -> Result<(EpochInstall, EpochInstall), HandshakeError> {
		let request = client.start_renewal()?;
		let response = issued(server, &request).await?;
		let (ack, client_install) = client.process_response(response).await?;

		let outcome = server.process_ack(ack).await?;
		assert!(outcome.rejection.is_none());
		Ok((client_install, outcome.install))
	}

	/// An observer that records the client certificate each outcome names, as
	/// a server reports the outcome.
	#[derive(Default)]
	struct ClientCertificateObserver(std::sync::Mutex<Vec<Option<Arc<Certificate>>>>);

	impl ClientCertificateObserver {
		/// The client certificates the server reported, in order.
		fn reported(&self) -> Vec<Option<Arc<Certificate>>> {
			let reported = self.0.lock().expect("no observer panicked while holding the record");
			reported.to_owned()
		}
	}

	impl SessionObserver for ClientCertificateObserver {
		fn on_outcome<'a>(&'a self, outcome: &'a SessionOutcome) -> MaybeSendFuture<'a, ()> {
			Box::pin(async move {
				let mut reported = self.0.lock().expect("no observer panicked while holding the record");
				reported.push(outcome.client_certificate.as_ref().map(Arc::clone));
			})
		}
	}

	/// A server rekey names to its observer the client whose certificate its
	/// materials verify the countersignature under.
	#[tokio::test]
	async fn a_server_rekey_reports_the_client_of_its_materials() -> Result<(), Box<dyn std::error::Error>> {
		let observer = Arc::new(ClientCertificateObserver::default());
		let reporting = Arc::clone(&observer) as Arc<dyn SessionObserver>;
		let parties = rekey_parties_with(SessionPeer::try_from, Some(reporting))?;
		let Parties { mut client, mut server, client_identity, .. } = parties;
		run_exchange(&mut client, &mut server).await?;

		let expected = Some(client_identity.signing.certificate_arc());
		assert_eq!(observer.reported(), vec![expected]);
		Ok(())
	}

	#[tokio::test]
	async fn exchange_rotates_both_endpoints() -> Result<(), Box<dyn std::error::Error>> {
		let (mut client, mut server) = rekey_pair()?;
		let (mut client_install, mut server_install) = run_exchange(&mut client, &mut server).await?;
		assert_eq!(client_install.epoch, 1);
		assert_eq!(server_install.epoch, 1);
		assert_eq!(client.epoch(), 1);
		assert_eq!(server.epoch(), 1);
		assert_eq!(client_install.receipt, server_install.receipt);
		assert!(!client.renewal_in_flight());
		assert!(!server.exchange_in_flight());

		let mut uplink = client_install.send_cipher.encrypt_next(PLAINTEXT)?.to_der()?;
		let received = server_install.recv_cipher.open(&mut uplink)?;
		assert_eq!(received, PLAINTEXT);

		let mut downlink = server_install.send_cipher.encrypt_next(PLAINTEXT)?.to_der()?;
		let received = client_install.recv_cipher.open(&mut downlink)?;
		assert_eq!(received, PLAINTEXT);
		Ok(())
	}

	/// Two chains that share the public chain root, the exchange randoms, and
	/// one agreement, but hold different epoch secrets, derive different
	/// traffic keys. The next epoch therefore depends on the previous epoch
	/// secret as well as on the agreement.
	#[test]
	fn the_next_epoch_depends_on_the_previous_epoch_secret() -> Result<(), Box<dyn std::error::Error>> {
		let mut first = sample_epoch_from(SAMPLE_BASE)?;
		let mut second = sample_epoch_from(SAMPLE_BASE + 1)?;
		let (client_scalar, server_scalar) = (Box::new(fresh_ephemeral()), Box::new(fresh_ephemeral()));
		let client_point = peer_static().server_ephemeral(&point_of(&client_scalar.public_key()))?;
		let server_point = peer_static().server_ephemeral(&point_of(&server_scalar.public_key()))?;
		let salt = sample_salt();
		let kdf_salt = salt.as_kdf_salt()?;
		let first_next = first.next_secret::<Provider>(client_scalar, &server_point, kdf_salt)?;
		let second_next = second.next_secret::<Provider>(server_scalar, &client_point, kdf_salt)?;

		let first_rotated = first.install::<Provider>(first_next, kdf_salt, sample_chain_root())?;
		let second_rotated = second.install::<Provider>(second_next, kdf_salt, sample_chain_root())?;
		let (first_send, _first_recv) = SessionKeys::for_client(first_rotated).into_parts();
		let (_second_send, mut second_recv) = SessionKeys::for_server(second_rotated).into_parts();

		let mut record = first_send.encrypt_next(PLAINTEXT)?.to_der()?;
		assert!(second_recv.open(&mut record).is_err());
		Ok(())
	}

	/// The rotated traffic keys come from the next chain link, so a record
	/// sealed under the previous epoch secret's directional key does not open
	/// under them. The record carries the rotated epoch, so the key alone
	/// decides.
	#[test]
	fn rotation_leaves_the_previous_epoch_keys_behind() -> Result<(), Box<dyn std::error::Error>> {
		let mut epoch = sample_epoch()?;
		let salt = sample_salt();
		let rotated_epoch = epoch.epoch() + 1;
		let previous = DirectionalCiphers::derive::<Provider, _>(epoch.secret(), salt.as_kdf_salt()?, rotated_epoch)?;
		let (previous_send, _previous_recv) = SessionKeys::for_client(previous).into_parts();
		let peer = peer_static().server_ephemeral(&stray_point())?;
		let scalar = Box::new(fresh_ephemeral());
		let next = epoch.next_secret::<Provider>(scalar, &peer, salt.as_kdf_salt()?)?;
		let rotated = epoch.install::<Provider>(next, salt.as_kdf_salt()?, sample_chain_root())?;
		let (_send, mut recv) = SessionKeys::for_server(rotated).into_parts();

		let mut record = previous_send.encrypt_next(PLAINTEXT)?.to_der()?;
		let refused = recv.open(&mut record);
		assert!(matches!(refused, Err(TightBeamError::EnvelopeError(EnvelopeError::KeyUnwrap))));
		Ok(())
	}

	/// The rotation carries the next epoch into both ciphers, so the first
	/// rotated record opens on a receive cipher of the next epoch that the
	/// next secret derives.
	#[test]
	fn rotation_carries_the_next_epoch() -> Result<(), Box<dyn std::error::Error>> {
		let mut epoch = sample_epoch()?;
		let salt = sample_salt();
		let next_epoch = epoch.epoch() + 1;
		let peer = peer_static().server_ephemeral(&stray_point())?;
		let scalar = Box::new(fresh_ephemeral());
		let next = epoch.next_secret::<Provider>(scalar, &peer, salt.as_kdf_salt()?)?;
		let expected = DirectionalCiphers::derive::<Provider, _>(&next, salt.as_kdf_salt()?, next_epoch)?;
		let (_peer_send, mut peer_recv) = SessionKeys::for_server(expected).into_parts();
		let rotated = epoch.install::<Provider>(next, salt.as_kdf_salt()?, sample_chain_root())?;
		let (send, _recv) = SessionKeys::for_client(rotated).into_parts();

		let mut record = send.encrypt_next(PLAINTEXT)?.to_der()?;
		let opened = peer_recv.open(&mut record)?;
		assert_eq!(opened, PLAINTEXT);
		Ok(())
	}

	/// The `kekid` of the one `KEKRecipientInfo` of `record`.
	fn key_identifier_of(record: &AuthEnvelopedData) -> Vec<u8> {
		let recipient = match record.recipient_infos.0.as_slice().first() {
			Some(RecipientInfo::Kekri(kek)) => Some(kek),
			_ => None,
		};

		let recipient = recipient.expect("a record carries one KEKRecipientInfo");
		recipient.kek_id.kek_identifier.as_bytes().to_vec()
	}

	/// The first record of the rotated client names the client-to-server key
	/// of the next epoch in its `kekid`: the record domain, the direction
	/// octet `00`, and the next epoch in four octets.
	#[test]
	fn a_rotated_record_names_the_next_epoch() -> Result<(), Box<dyn std::error::Error>> {
		let mut epoch = sample_epoch()?;
		let salt = sample_salt();
		let next_epoch = epoch.epoch() + 1;
		let expected = [b"tb/session/record/kekid/v1".as_slice(), &[0x00], &next_epoch.to_be_bytes()].concat();
		let peer = peer_static().server_ephemeral(&stray_point())?;
		let scalar = Box::new(fresh_ephemeral());
		let next = epoch.next_secret::<Provider>(scalar, &peer, salt.as_kdf_salt()?)?;

		let rotated = epoch.install::<Provider>(next, salt.as_kdf_salt()?, sample_chain_root())?;
		let (send, _recv) = SessionKeys::for_client(rotated).into_parts();
		let record = send.encrypt_next(PLAINTEXT)?;
		assert_eq!(key_identifier_of(&record), expected);
		Ok(())
	}

	#[tokio::test]
	async fn chained_exchanges_stay_in_step() -> Result<(), Box<dyn std::error::Error>> {
		let (mut client, mut server) = rekey_pair()?;
		run_exchange(&mut client, &mut server).await?;

		let (client_install, mut server_install) = run_exchange(&mut client, &mut server).await?;
		assert_eq!(client_install.epoch, 2);
		assert_eq!(server_install.epoch, 2);

		let mut uplink = client_install.send_cipher.encrypt_next(PLAINTEXT)?.to_der()?;
		let received = server_install.recv_cipher.open(&mut uplink)?;
		assert_eq!(received, PLAINTEXT);
		Ok(())
	}

	#[tokio::test]
	async fn epoch_receipt_pins_the_exchange() -> Result<(), HandshakeError> {
		let (mut client, mut server) = rekey_pair()?;
		let request = client.start_renewal()?;
		let response = issued(&mut server, &request).await?;

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

		issued(&mut server, &request).await?;

		let duplicate = server.process_request(&request).await?;
		assert!(matches!(duplicate, RequestAnswer::InFlight));
		Ok(())
	}

	#[tokio::test]
	async fn unsolicited_legs_fail_closed() -> Result<(), HandshakeError> {
		let (mut client, mut server) = rekey_pair()?;
		let request = MuxRekeyRequestPackage::new([1u8; 32], &stray_key())?;
		let response = issued(&mut server, &request).await?;

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

		let bare = MuxRekeyResponsePackage::new([9u8; 32], &stray_key(), None)?;
		let missing_receipt = client.process_response(bare).await;
		assert!(matches!(missing_receipt, Err(HandshakeError::ReceiptMissing)));
		Ok(())
	}

	#[tokio::test]
	async fn credit_drift_fails_closed() -> Result<(), HandshakeError> {
		let (mut client, mut server) = rekey_pair()?;
		client.materials.reference = sample_reference(SAMPLE_CREDIT_UNIT + 1)?;

		let request = client.start_renewal()?;
		let response = issued(&mut server, &request).await?;
		let drift = client.process_response(response).await;
		assert!(matches!(drift, Err(HandshakeError::ReceiptMismatch)));
		Ok(())
	}

	#[tokio::test]
	async fn replayed_response_fails_closed() -> Result<(), HandshakeError> {
		let (mut client, mut server) = rekey_pair()?;
		let request = client.start_renewal()?;
		let response = issued(&mut server, &request).await?;
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

		issued(&mut server, &request).await?;

		let missing = server.process_ack(MuxRekeyAckPackage::new(None)).await;
		assert!(matches!(missing, Err(HandshakeError::CountersignatureMissing)));
		Ok(())
	}

	#[tokio::test]
	async fn foreign_countersignature_fails_closed() -> Result<(), HandshakeError> {
		let (mut client, mut server) = rekey_pair()?;
		let request = client.start_renewal()?;
		let response = issued(&mut server, &request).await?;
		let epoch_receipt = response.epoch_receipt().ok_or(HandshakeError::ReceiptMissing)?;
		let receipt = epoch_receipt.receipt()?;

		client.process_response(response).await.map(|_| ())?;

		let intruder = test_identity()?;
		let forged = receipt.countersign(None, &intruder.signing).await?;
		let foreign_ack = MuxRekeyAckPackage::new(Some(forged.signer().to_owned()));
		let foreign = server.process_ack(foreign_ack).await;
		assert!(matches!(foreign, Err(HandshakeError::SignatureVerificationFailed)));
		Ok(())
	}

	/// The code [`RefusingSettlement`] refuses each settlement with.
	const SETTLEMENT_REFUSAL_CODE: u32 = MUX_APPLICATION_CODE_FLOOR + 1;

	/// An authorizer that refuses every grant and every settlement with
	/// [`SETTLEMENT_REFUSAL_CODE`]. A renewal asks it to settle alone.
	struct RefusingSettlement;

	impl TransportAuthorizer for RefusingSettlement {
		fn authorize<'a>(
			&'a self,
			_offer: &'a TransportOffer,
		) -> MaybeSendFuture<'a, Result<AuthorizationGrant, AuthorizationRefusal>> {
			Box::pin(async move { Err(AuthorizationRefusal { code: SETTLEMENT_REFUSAL_CODE }) })
		}

		fn settle<'a>(
			&'a self,
			_receipt: &'a SessionReceipt,
			_response: Option<&'a [u8]>,
			_client: &'a Certificate,
		) -> MaybeSendFuture<'a, Result<(), AuthorizationRefusal>> {
			Box::pin(async move { Err(AuthorizationRefusal { code: SETTLEMENT_REFUSAL_CODE }) })
		}
	}

	/// A verified countersignature rotates the chain under a refused
	/// settlement, so the server installs the dual-signed receipt the client
	/// holds, beside the code of the refusal.
	#[tokio::test]
	async fn a_refused_settlement_rotates_with_the_dual_signed_receipt_and_its_code(
	) -> Result<(), Box<dyn std::error::Error>> {
		let (mut client, mut server) = rekey_pair()?;

		server.authorizer = Some(Arc::new(RefusingSettlement));

		let request = client.start_renewal()?;
		let response = issued(&mut server, &request).await?;
		let (ack, client_install) = client.process_response(response).await?;

		let outcome = server.process_ack(ack).await?;
		let installed = (outcome.install.receipt, outcome.rejection);
		assert_eq!(installed, (client_install.receipt, Some(SETTLEMENT_REFUSAL_CODE)));
		Ok(())
	}

	/// An observer who holds the current epoch secret and the whole renewal
	/// as the endpoints sent it, and no rekey scalar, derives no key of the
	/// next epoch.
	///
	/// The observer runs the production derivation with a scalar of its own
	/// against each ephemeral the renewal carried. Neither result opens a
	/// frame of the next epoch.
	#[tokio::test]
	async fn the_next_epoch_needs_a_rekey_scalar() -> Result<(), Box<dyn std::error::Error>> {
		let (mut client, mut server) = rekey_pair()?;
		let request = client.start_renewal()?;
		let response = issued(&mut server, &request).await?;
		let wire_client = peer_static().server_ephemeral(request.client_ephemeral())?;
		let wire_server = peer_static().server_ephemeral(response.server_ephemeral())?;
		let client_random = request.client_random.to_32_byte_array()?;
		let server_random = response.server_random.to_32_byte_array()?;
		let salt = RandomsSalt::new(&client_random, &server_random);

		let (ack, client_install) = client.process_response(response).await?;
		let mut server_install = server.process_ack(ack).await?.install;
		let record = client_install.send_cipher.encrypt_next(PLAINTEXT)?.to_der()?;

		// Positive control: the server held a rekey scalar and opens the frame.
		let mut control = record.clone();
		let received = server_install.recv_cipher.open(&mut control)?;
		assert_eq!(received, PLAINTEXT);

		// The observer starts from the epoch secret both endpoints held, and
		// draws a scalar of its own for each attempt.
		let observed = sample_epoch()?;
		let (first, second) = (Box::new(fresh_ephemeral()), Box::new(fresh_ephemeral()));
		let against_client = observed.next_secret::<Provider>(first, &wire_client, salt.as_kdf_salt()?)?;
		let against_server = observed.next_secret::<Provider>(second, &wire_server, salt.as_kdf_salt()?)?;
		assert!(server_recv(&against_client, &salt).open(&mut record.clone()).is_err());
		assert!(server_recv(&against_server, &salt).open(&mut record.clone()).is_err());
		Ok(())
	}

	/// A server ephemeral swapped in transit changes the pin the client
	/// recomputes, so the receipt the server signed fails the match.
	#[tokio::test]
	async fn a_swapped_server_ephemeral_fails_the_pin() -> Result<(), HandshakeError> {
		let (mut client, mut server) = rekey_pair()?;
		let request = client.start_renewal()?;
		let mut response = issued(&mut server, &request).await?;
		response.server_ephemeral = OctetString::new(stray_point().as_slice())?;

		let swapped = client.process_response(response).await;
		assert!(matches!(swapped, Err(HandshakeError::ReceiptMismatch)));
		Ok(())
	}

	/// A server ephemeral in the compact form has the width of the compressed
	/// form, and the client refuses it at the parse, before the pin hashes it.
	#[tokio::test]
	async fn a_compact_server_ephemeral_is_refused_before_the_pin() -> Result<(), HandshakeError> {
		let (mut client, mut server) = rekey_pair()?;
		let request = client.start_renewal()?;
		let mut response = issued(&mut server, &request).await?;
		let mut compact = stray_point();
		compact[0] = 0x05;
		response.server_ephemeral = OctetString::new(compact.as_slice())?;

		let refused = client.process_response(response).await;
		assert!(matches!(refused, Err(HandshakeError::InvalidPublicKey(_))));
		Ok(())
	}

	/// A client ephemeral swapped in transit reaches the server inside the
	/// request the server pins. The client pins the request it sent, so the
	/// receipt fails the match.
	#[tokio::test]
	async fn a_swapped_client_ephemeral_fails_the_pin() -> Result<(), HandshakeError> {
		let (mut client, mut server) = rekey_pair()?;
		let mut request = client.start_renewal()?;
		request.client_ephemeral = OctetString::new(stray_point().as_slice())?;

		let response = issued(&mut server, &request).await?;
		let swapped = client.process_response(response).await;
		assert!(matches!(swapped, Err(HandshakeError::ReceiptMismatch)));
		Ok(())
	}

	/// The server refuses a client ephemeral that names no point on the curve
	/// at the parse, before any agreement runs on it.
	#[tokio::test]
	async fn an_off_curve_client_ephemeral_is_refused() -> Result<(), HandshakeError> {
		let (mut client, mut server) = rekey_pair()?;
		let mut request = client.start_renewal()?;
		request.client_ephemeral = OctetString::new(off_curve_point().as_slice())?;

		let refused = server.process_request(&request).await;
		assert!(matches!(refused, Err(HandshakeError::InvalidPublicKey(_))));
		assert!(!server.exchange_in_flight());
		Ok(())
	}

	/// The server refuses a client ephemeral of another width before it parses
	/// the octets as a point.
	#[tokio::test]
	async fn a_client_ephemeral_of_another_width_is_refused() -> Result<(), HandshakeError> {
		let (mut client, mut server) = rekey_pair()?;
		let mut request = client.start_renewal()?;
		request.client_ephemeral = OctetString::new([0x02u8; 32])?;

		let refused = server.process_request(&request).await;
		assert!(matches!(refused, Err(HandshakeError::OctetStringLengthError(_))));
		Ok(())
	}

	/// A client ephemeral in the uncompressed form names a point of the curve,
	/// and the server refuses it at the width, because a rekey leg carries the
	/// compressed form alone.
	#[tokio::test]
	async fn an_uncompressed_client_ephemeral_is_refused() -> Result<(), HandshakeError> {
		let (mut client, mut server) = rekey_pair()?;
		let mut request = client.start_renewal()?;
		let uncompressed = fresh_ephemeral().public_key().to_encoded_point(false);
		request.client_ephemeral = OctetString::new(uncompressed.as_bytes())?;

		let refused = server.process_request(&request).await;
		assert!(matches!(refused, Err(HandshakeError::OctetStringLengthError(_))));
		Ok(())
	}

	/// A client ephemeral in the compact form `0x05` has the width of the
	/// compressed form and names a point of the curve, and the parse refuses
	/// it, because RFC 5480 §2.2 names no such form.
	#[tokio::test]
	async fn a_compact_client_ephemeral_is_refused() -> Result<(), HandshakeError> {
		let (mut client, mut server) = rekey_pair()?;
		let mut request = client.start_renewal()?;
		let mut compact = stray_point();
		compact[0] = 0x05;
		request.client_ephemeral = OctetString::new(compact.as_slice())?;

		let refused = server.process_request(&request).await;
		assert!(matches!(refused, Err(HandshakeError::InvalidPublicKey(_))));
		Ok(())
	}

	/// The server refuses a client ephemeral that is the client's static key,
	/// so the agreement of a renewal cannot collapse into the static one.
	#[tokio::test]
	async fn a_client_ephemeral_equal_to_the_static_key_is_refused() -> Result<(), HandshakeError> {
		let Parties { mut client, mut server, client_identity, .. } = rekey_parties()?;
		let mut request = client.start_renewal()?;
		request.client_ephemeral = OctetString::new(point_of(&client_identity.public_key).as_slice())?;

		let refused = server.process_request(&request).await;
		assert!(matches!(refused, Err(HandshakeError::ClientEphemeralIsStatic)));
		Ok(())
	}

	/// The client refuses a server ephemeral that is the server's static key,
	/// even under a receipt the server signed over it.
	#[tokio::test]
	async fn a_server_ephemeral_equal_to_the_static_key_is_refused() -> Result<(), HandshakeError> {
		let Parties { mut client, server_identity, .. } = rekey_parties()?;
		let request = client.start_renewal()?;
		let static_point = point_of(&server_identity.public_key);
		let epoch = sample_epoch()?;
		let pin = epoch.exchange_pin::<Sha3_256, Secp256k1>(request.to_der()?, &SAMPLE_SERVER_RANDOM, &static_point)?;
		let signer = &server_identity.signing;
		let issuing = SessionReceipt::issue(pin, SAMPLE_BUDGETS, SAMPLE_CREDIT_UNIT, None, signer);
		let (_receipt, artifact) = issuing.await?;

		let static_key = &server_identity.public_key;
		let response = MuxRekeyResponsePackage::new(SAMPLE_SERVER_RANDOM, static_key, Some(artifact))?;
		let refused = client.process_response(response).await;
		assert!(matches!(refused, Err(HandshakeError::ServerEphemeralIsStatic)));
		Ok(())
	}

	/// The session of a CMS client, as a transport holds it once the
	/// handshake completed.
	#[cfg(feature = "transport-cms")]
	struct CmsClientProbe {
		state: SessionState<DefaultCryptoProvider>,
		limits: TransportLimits,
	}

	#[cfg(feature = "transport-cms")]
	impl crate::transport::state::sealed::Sealed for CmsClientProbe {}

	#[cfg(feature = "transport-cms")]
	impl EncryptedProtocolState for CmsClientProbe {
		type CryptoProvider = DefaultCryptoProvider;

		fn limits(&self) -> &TransportLimits {
			&self.limits
		}

		fn session_state(&self) -> &SessionState<DefaultCryptoProvider> {
			&self.state
		}

		fn session_state_mut(&mut self) -> &mut SessionState<DefaultCryptoProvider> {
			&mut self.state
		}

		// The client probe reads its trail through the default `to_trace_ref`,
		// so `with_trace` drops the collector.
		#[cfg(feature = "instrument")]
		fn with_trace(self, _trace: crate::trace::TraceCollector) -> Self {
			self
		}
	}

	/// The session a client of `server` established with a dual-signed
	/// receipt of the sample terms and the sample epoch. It keeps `server`'s
	/// key-agreement certificate as a CMS client's session keeps it.
	#[cfg(feature = "transport-cms")]
	async fn cms_client_session(server: &TestCmsServer) -> CmsClientProbe {
		let client = TestIdentity::of(&Secp256k1SigningKey::random(&mut OsRng));
		let stored = dual_signed_receipt(&server.signing_identity(), &client).await;

		let keys = SessionKeys::for_client(TestKey::insecure_directional_keys());
		let signing = Arc::new(server.signing.to_owned());
		let key_agreement = Arc::new(server.key_agreement.to_owned());
		let peer = SessionPeer::paired(signing, key_agreement).expect("the pair records its peer");
		let epoch = sample_epoch().expect("the sample epoch derives");
		let session = EstablishedSession::forged(keys, Some(Arc::new(stored)), Some(peer));
		let session = session.with_forged_epoch(epoch);
		let encryption = EncryptionConfig { client_identity: Some(client), ..EncryptionConfig::unconfigured() };

		let state = SessionState::at(encryption, SessionPhase::Encrypted(Box::new(session)));
		CmsClientProbe { state, limits: TransportLimits::default() }
	}

	/// The client half of the rekey `probe`'s session hands over.
	#[cfg(feature = "transport-cms")]
	fn client_exchange(probe: &mut CmsClientProbe) -> Arc<FuturesMutex<Box<dyn ClientRekeyExchange>>> {
		let context = MuxRekeyContext::detach(probe, MuxRole::Client).expect("the session detaches its rekey");
		let context = context.expect("a receipt-bearing session renews");
		let exchange = context.driver.renewal_opener().expect("the client role yields the client half");

		Arc::clone(exchange)
	}

	/// The rekey a CMS client's session hands over compares a server ephemeral
	/// with the key of the server's key-agreement certificate the session
	/// kept, so the client refuses a renewal that names that key.
	#[cfg(feature = "transport-cms")]
	#[tokio::test]
	async fn a_cms_session_hands_its_rekey_the_key_agreement_key() -> Result<(), Box<dyn std::error::Error>> {
		let server = TestCmsServer::generate("tightbeam rekey server");
		let mut probe = cms_client_session(&server).await;
		let exchange = client_exchange(&mut probe);
		let mut exchange = exchange.lock().await;
		let request = exchange.start_renewal()?;
		let key = PublicKey::from(server.key_agreement_key.verifying_key());
		let point = point_of(&key);
		let request_der = request.to_der()?;
		let pin = sample_epoch()?.exchange_pin::<Sha3_256, Secp256k1>(request_der, &SAMPLE_SERVER_RANDOM, &point)?;
		let signer = server.signing_identity();
		let issuing = SessionReceipt::issue(pin, SAMPLE_BUDGETS, SAMPLE_CREDIT_UNIT, None, &signer);
		let (_receipt, artifact) = issuing.await?;

		let response = MuxRekeyResponsePackage::new(SAMPLE_SERVER_RANDOM, &key, Some(artifact))?;
		let refused = exchange.process_response(response).await;
		assert!(matches!(refused, Err(HandshakeError::ServerEphemeralIsStatic)));
		Ok(())
	}

	/// A CMS client's session whose server certificate names the client
	/// purpose alone refuses its rekey under the server purpose. It keeps its
	/// receipt, its peer, and its epoch, because the session detaches the epoch
	/// only after every check that can refuse the rekey.
	#[cfg(feature = "transport-cms")]
	#[tokio::test]
	async fn a_session_refused_its_rekey_keeps_its_epoch() {
		let server = TestCmsServer::generate("tightbeam refused rekey server");
		let server = server.with_key_purposes(&[KeyPurposes::HOUSE.client]);
		let mut probe = cms_client_session(&server).await;
		let refused = MuxRekeyContext::detach(&mut probe, MuxRole::Client);

		let refusal = matches!(
			refused,
			Err(TransportError::HandshakeError(HandshakeError::CertificateValidationError(_)))
		);
		let epoch = probe.state.established().and_then(EstablishedSession::epoch);
		assert!(refusal);
		assert!(probe.state.receipt().is_some());
		assert!(probe.state.session_peer().is_some());
		assert!(epoch.is_some());
	}

	/// A CMS client's session hands its epoch to the rekey it renews into, so
	/// the session holds no epoch once its rekey detaches.
	#[cfg(feature = "transport-cms")]
	#[tokio::test]
	async fn a_renewed_session_hands_over_its_epoch() -> Result<(), Box<dyn std::error::Error>> {
		let server = TestCmsServer::generate("tightbeam renewed rekey server");
		let mut probe = cms_client_session(&server).await;

		let renewed = MuxRekeyContext::detach(&mut probe, MuxRole::Client)?;
		let established = probe.state.established().ok_or("the renewed session stays established")?;
		assert!(renewed.is_some());
		assert!(established.epoch().is_none());
		Ok(())
	}

	/// A receipt of the sample terms, rooted at the sample chain root, that
	/// `server` signed and `client` countersigned.
	async fn dual_signed_receipt(server: &SigningIdentity, client: &SigningIdentity) -> StoredReceipt {
		let issuing = SessionReceipt::issue(sample_chain_root(), SAMPLE_BUDGETS, SAMPLE_CREDIT_UNIT, None, server);
		let (receipt, artifact) = issuing.await.expect("the server signs the receipt");
		let countersignature = receipt.countersign(None, client).await.expect("the client countersigns");

		let completed = artifact.with_certified_signer(countersignature);
		StoredReceipt::try_from(completed.expect("the receipt joins")).expect("the receipt is complete")
	}

	/// A session renews only under a dual-signed receipt, so a session built
	/// without one releases its epoch materials where it is built.
	#[test]
	fn a_session_without_a_receipt_releases_its_epoch() -> Result<(), Box<dyn std::error::Error>> {
		let keys = SessionKeys::for_client(TestKey::insecure_directional_keys());
		let peer = test_identity()?.peer()?;

		let session = EstablishedSession::forged(keys, None, Some(peer));
		let session = session.with_forged_epoch(sample_epoch()?);
		assert!(session.epoch().is_none());
		Ok(())
	}

	/// A session renews only against a recorded peer, so a session built
	/// without one releases its epoch materials where it is built.
	#[tokio::test]
	async fn a_session_without_a_peer_releases_its_epoch() -> Result<(), Box<dyn std::error::Error>> {
		let (server, client) = (test_identity()?, test_identity()?);
		let receipt = dual_signed_receipt(&server.signing, &client.signing).await;
		let keys = SessionKeys::for_client(TestKey::insecure_directional_keys());

		let session = EstablishedSession::forged(keys, Some(Arc::new(receipt)), None);
		let session = session.with_forged_epoch(sample_epoch()?);
		assert!(session.epoch().is_none());
		Ok(())
	}

	/// The client refuses a server ephemeral that is the key of a CMS server's
	/// key-agreement certificate, as the handshake refuses it, even under a
	/// receipt the server signed over it.
	#[tokio::test]
	async fn a_server_ephemeral_equal_to_the_key_agreement_key_is_refused() -> Result<(), HandshakeError> {
		let key_agreement_key = Secp256k1SigningKey::random(&mut OsRng);
		let key_agreement = Arc::new(TestCertificate::self_signed(&key_agreement_key));
		let paired = |signing| SessionPeer::paired(signing, key_agreement);
		let Parties { mut client, server_identity, .. } = rekey_parties_with(paired, None)?;
		let request = client.start_renewal()?;
		let key_agreement_public = PublicKey::from(key_agreement_key.verifying_key());
		let point = point_of(&key_agreement_public);
		let epoch = sample_epoch()?;
		let request_der = request.to_der()?;
		let pin = epoch.exchange_pin::<Sha3_256, Secp256k1>(request_der, &SAMPLE_SERVER_RANDOM, &point)?;
		let signer = &server_identity.signing;
		let issuing = SessionReceipt::issue(pin, SAMPLE_BUDGETS, SAMPLE_CREDIT_UNIT, None, signer);
		let (_receipt, artifact) = issuing.await?;

		let response = MuxRekeyResponsePackage::new(SAMPLE_SERVER_RANDOM, &key_agreement_public, Some(artifact))?;
		let refused = client.process_response(response).await;
		assert!(matches!(refused, Err(HandshakeError::ServerEphemeralIsStatic)));
		Ok(())
	}
}
