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
//! `C` and `S` are the two shares of one renewal's key exchange. The next
//! epoch secret takes the previous one and the secret of that exchange:
//!
//! ```text
//! epoch_next = HKDF(u32be(32) || epoch || u32be(Ndh) || ee, salt = client_random || server_random)
//! ```
//!
//! `Ndh` is the width of `ee`, which the exchange fixes.
//!
//! So a holder of one epoch secret who records the renewal still needs the
//! private half of a rekey share to derive the next epoch. Each side refuses a
//! peer share that fails its parse, or that collapses into a static key of the
//! peer, as the handshake refuses it. The static keys are the client's one
//! key, or either key of a CMS server.
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
use crate::crypto::exchange::{KeyExchange, KeyShare};
use crate::crypto::sign::{Signed, SigningIdentity};
use crate::crypto::x509::{PeerCertificate, Signing};
use crate::der::asn1::{ObjectIdentifier, OctetString};
use crate::der::Encode;
use crate::marker::{MaybeSend, MaybeSendFuture};
use crate::random::{generate_nonce, OsRng};
use crate::transport::envelopes::{MuxRekeyAckPackage, MuxRekeyRequestPackage, MuxRekeyResponsePackage};
use crate::transport::handshake::negotiation::TransportAuthorizer;
use crate::transport::handshake::primitives::RandomsSalt;
use crate::transport::handshake::receipt::ReceiptArtifact;
use crate::transport::handshake::receipt::{
	ReceiptApprover, ReceiptRole, SessionObserver, SessionOutcome, SessionReceipt, StoredReceipt,
};
use crate::transport::handshake::{
	ClientShare, Distinct, EpochMaterials, EpochSecret, Exchange, HandshakeError, HandshakeOctets, HandshakeProvider,
	PeerStatics, ServerShare, SessionPeer,
};

/// Shared epoch state and identities for one session's rekey exchanges.
///
/// Both roles hold one, and it carries:
///
/// - the epoch secret chain,
/// - the initial receipt terms, which are the credit-match reference,
/// - the local signing identity, and
/// - the [`RekeyPeer`] the session recorded, whose signing key verifies the peer's receipt signatures.
///
/// The provider's cipher type names the AEAD, and its key exchange runs the
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
/// under the key purpose of its role, beside the static keys its rekey
/// ephemeral must differ from.
///
/// A rekey's materials take it whole, so each key a rekey reads names the one
/// peer.
pub(crate) struct RekeyPeer<P>
where
	P: HandshakeProvider,
{
	/// The certificate, admitted for signing under the purpose of its role.
	signing: PeerCertificate<Signing<P>>,
	/// The static keys of the peer, read once from its certificates.
	statics: PeerStatics<Exchange<P>>,
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
		let statics = PeerStatics::of(peer.certificate(), peer.key_agreement());
		Ok(Self { signing, statics })
	}

	/// Parses `octets` as the rekey share of this peer as the server of its
	/// session, and checks it against the peer's static keys.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KeyExchange`] -- `octets` is no share of the exchange.
	/// - The errors of [`PeerStatics::server_ephemeral`].
	fn server_ephemeral(&self, octets: impl AsRef<[u8]>) -> Result<Distinct<ServerShare<P>>, HandshakeError> {
		let share = <ServerShare<P> as KeyShare<Exchange<P>>>::from_octets(octets.as_ref())?;
		self.statics.server_ephemeral(share)
	}

	/// Parses `octets` as the rekey share of this peer as the client of its
	/// session, and checks it against the peer's static key.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KeyExchange`] -- `octets` is no share of the exchange.
	/// - The errors of [`PeerStatics::client_ephemeral`].
	fn client_ephemeral(&self, octets: impl AsRef<[u8]>) -> Result<Distinct<ClientShare<P>>, HandshakeError> {
		let share = <ClientShare<P> as KeyShare<Exchange<P>>>::from_octets(octets.as_ref())?;
		self.statics.client_ephemeral(share)
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
struct PendingRenewal<P>
where
	P: HandshakeProvider,
{
	client_random: [u8; 32],
	request_der: Vec<u8>,
	/// The pending half of the exchange of this renewal. It is boxed, so a
	/// move copies a pointer, and it wipes in place where the box drops.
	ephemeral: Box<<Exchange<P> as KeyExchange>::Pending>,
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
	pending: Option<PendingRenewal<P>>,
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
		let (pending, client_share) = Exchange::<P>::offer(&mut OsRng);
		let ephemeral = Box::new(pending);

		let request = MuxRekeyRequestPackage::new(client_random, client_share.to_octets())?;
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
	/// - [`HandshakeError::OctetStringLengthError`] -- the server random is not 32 bytes.
	/// - [`HandshakeError::ReceiptMissing`] -- the response has no epoch receipt.
	/// - [`HandshakeError::ReceiptMismatch`] -- the exchange pin or the credit match fails.
	/// - [`HandshakeError::SignatureVerificationFailed`] -- the server `SignerInfo` is invalid.
	/// - [`HandshakeError::KeyExchange`] -- the server's share has another
	///   width or form, or the exchange refuses it.
	/// - [`HandshakeError::ServerEphemeralIsStatic`] -- the server's share
	///   collapses into a static key of the server.
	/// - [`HandshakeError::ApprovalRefused`] -- the approver refuses the renewal.
	pub(crate) async fn process_response(
		&mut self,
		response: MuxRekeyResponsePackage,
	) -> Result<(MuxRekeyAckPackage, EpochInstall), HandshakeError> {
		let pending = self.pending.take().ok_or(HandshakeError::InvalidState)?;
		let PendingRenewal { client_random, request_der, ephemeral } = pending;
		let response_der = response.to_der()?;
		let MuxRekeyResponsePackage { server_random, server_ephemeral: server_octets, epoch_receipt } = response;
		let server_random = server_random.to_32_byte_array()?;
		let epoch_receipt = epoch_receipt.ok_or(HandshakeError::ReceiptMissing)?;
		let artifact = *epoch_receipt;

		let receipt = artifact.receipt()?;
		let server_role = ReceiptRole::Server;
		let server_signer = artifact.signer_for_role(server_role)?.ok_or(HandshakeError::ReceiptMissing)?;
		receipt.verify_signer::<P>(server_signer, server_role, &self.materials.peer.signing)?;

		let epoch = &self.materials.epoch;
		let challenge_hash = epoch.exchange_pin::<P::Digest>(&request_der, &server_random, server_octets.as_bytes())?;
		let reference_budgets = self.materials.reference.budgets;
		let reference_unit = self.materials.reference.credit_unit;

		receipt.verify_terms(&challenge_hash, reference_budgets, reference_unit)?;

		// The signed receipt pins the leg, so the share parses only after the
		// checks above authenticate it, as the handshake parses its reply. The
		// parse refuses a leg that collapses into a static key of the server.
		let server_ephemeral = self.materials.peer.server_ephemeral(server_octets.as_bytes())?;

		// The exchange completes before the client awaits the approver, and its
		// pending half drops right after, so it is wiped before the first await
		// of this step.
		let salt = RandomsSalt::new(&client_random, &server_random);
		let shared = server_ephemeral.complete::<Exchange<P>>(&ephemeral)?;
		drop(ephemeral);
		let next_secret = epoch.next_secret::<P>(shared, salt.as_kdf_salt()?)?;

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
/// The server answers the exchange on the request, which spends its private
/// half there, so the derived secret waits here.
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
	/// - [`HandshakeError::OctetStringLengthError`] -- the client random is not 32 bytes.
	/// - [`HandshakeError::KeyExchange`] -- the client's share has another
	///   width or form, or the exchange refuses to answer it.
	/// - [`HandshakeError::ClientEphemeralIsStatic`] -- the client's share
	///   collapses into the client's static key.
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
		let client_ephemeral = self.materials.peer.client_ephemeral(request.client_ephemeral.as_bytes())?;
		let server_random = generate_nonce::<32>(None)?;

		// The exchange spends its private half inside `respond` and runs before
		// the first await, so the server holds the derived secret alone across
		// an await or between two legs.
		let epoch = &self.materials.epoch;
		let salt = RandomsSalt::new(&client_random, &server_random);
		let (server_share, shared) = client_ephemeral.respond::<Exchange<P>>(&mut OsRng)?;
		let mut response = MuxRekeyResponsePackage::new(server_random, server_share.to_octets(), None)?;
		let next_secret = epoch.next_secret::<P>(shared, salt.as_kdf_salt()?)?;

		// The pin covers the leg as the response carries it.
		let server_octets = response.server_ephemeral.as_bytes();
		let challenge_hash = epoch.exchange_pin::<P::Digest>(&request_der, &server_random, server_octets)?;

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
mod tests {
	use super::*;
	use crate::asn1::{AlgorithmIdentifier, AuthEnvelopedData, DigestInfo};
	use crate::cms::enveloped_data::RecipientInfo;
	use crate::crypto::aead::DirectionalCiphers;
	use crate::crypto::cms::EnvelopeError;
	use crate::crypto::exchange::{Ecdhe, EcdheShare, KeyExchangeError};
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::kdf::KdfSalt;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::crypto::sign::ecdsa::k256::Secp256k1;
	use crate::crypto::sign::elliptic_curve::sec1::ToEncodedPoint;
	use crate::crypto::sign::elliptic_curve::{PublicKey, SecretKey};
	use crate::crypto::x509::KeyPurposes;
	use crate::der::Encode;
	use crate::oids::HASH_SHA3_256;
	use crate::runtime::rt;
	use crate::testing::{TestCertificate, TestIdentity, TestKey, TestResult};
	use crate::transport::envelopes::MUX_APPLICATION_CODE_FLOOR;
	use crate::transport::handshake::negotiation::{
		AuthorizationGrant, AuthorizationRefusal, MuxBudgets, TransportOffer,
	};
	use crate::transport::handshake::primitives::TranscriptHash;
	use crate::transport::handshake::tests::{fixture_handshake_secret, fixture_transcript, off_curve_point};
	use crate::transport::handshake::{Distinct, EstablishedSession};
	use crate::x509::Certificate;
	use crate::TightBeamError;

	#[cfg(feature = "transport-cms")]
	mod cms_session {
		pub use crate::testing::TestCmsServer;
		pub use crate::transport::multiplex::{MuxRekeyContext, MuxRole};
		pub use crate::transport::state::{EncryptedProtocolState, EncryptionConfig, SessionPhase, SessionState};
		pub use crate::transport::{CheckedLimits, TransportError};
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
	/// The seed of the static key of the client of [`rekey_parties_with`].
	const CLIENT_SEED: u8 = 0x21;
	/// The seed of the static key of the server of [`rekey_parties_with`].
	const SERVER_SEED: u8 = 0x22;
	/// The seed of the key of the key-agreement certificate of
	/// [`key_agreement_parties`].
	const KEY_AGREEMENT_SEED: u8 = 0x32;

	/// One party of a rekey: its signing identity and its static key.
	struct Identity {
		signing: SigningIdentity,
		public_key: PublicKey<Secp256k1>,
	}

	impl Identity {
		/// The party as its peer's session records it, by the certificate it
		/// presents.
		fn peer(&self) -> SessionPeer {
			let peer = SessionPeer::try_from(self.signing.certificate_arc());
			peer.expect("a test certificate records its peer")
		}
	}

	/// The party whose static key is the fixed key of `seed`.
	fn test_identity(seed: u8) -> Identity {
		let signing_key = TestKey::fixed(seed);
		let verifying_key = *signing_key.verifying_key();
		let signing = TestIdentity::of(&signing_key);
		Identity { signing, public_key: PublicKey::from(verifying_key) }
	}

	/// The house exchange of the tests.
	type House = Ecdhe<Secp256k1>;

	/// A rekey scalar: the fixed key of `seed`. A test gives each scalar and
	/// each point its own seed, so no two of its points meet.
	fn ephemeral(seed: u8) -> SecretKey<Secp256k1> {
		SecretKey::from(TestKey::fixed(seed))
	}

	/// The compressed SEC 1 bytes of `key`, as a rekey leg carries a share of
	/// the house exchange.
	fn point_of(key: &PublicKey<Secp256k1>) -> Vec<u8> {
		EcdheShare::from(*key).to_octets()
	}

	/// A valid point that belongs to no party of the test: the public key of
	/// the fixed key of `seed`.
	fn stray_key(seed: u8) -> PublicKey<Secp256k1> {
		ephemeral(seed).public_key()
	}

	/// The compressed SEC 1 bytes of [`stray_key`] of `seed`.
	fn stray_point(seed: u8) -> Vec<u8> {
		point_of(&stray_key(seed))
	}

	/// The bytes of [`stray_point`] of `seed` under the prefix `0x05`. The
	/// compact form has the width of the compressed form and names a point of
	/// the curve, though RFC 5480 §2.2 names no such form.
	fn compact_point(seed: u8) -> Vec<u8> {
		let mut compact = stray_point(seed);
		compact[0] = 0x05;
		compact
	}

	/// The statics of a peer with a fresh key, distinct from every point of a
	/// test, for the parse that admits a peer point to an agreement.
	fn peer_static() -> PeerStatics<House> {
		let certificate = TestCertificate::self_signed(&TestKey::fixed(0x31));
		PeerStatics::of(&certificate, None)
	}

	/// `octets` as a rekey share that [`peer_static`] admits.
	fn distinct(octets: impl AsRef<[u8]>) -> Distinct<EcdheShare<Secp256k1>> {
		let share = <EcdheShare<Secp256k1> as KeyShare<House>>::from_octets(octets.as_ref());
		let share = share.expect("the test octets are a point of the curve");
		peer_static()
			.server_ephemeral(share)
			.expect("the test point is no static key of the peer")
	}

	/// The next link of `epoch` from the exchange of `scalar` with `peer`.
	fn next_of(
		epoch: &EpochMaterials,
		scalar: &SecretKey<Secp256k1>,
		peer: &Distinct<EcdheShare<Secp256k1>>,
		salt: KdfSalt<'_>,
	) -> EpochSecret {
		let shared = peer
			.complete::<House>(scalar)
			.expect("the test scalar agrees with the test point");
		epoch
			.next_secret::<Provider>(shared, salt)
			.expect("an epoch derives its next secret")
	}

	/// The sample epoch, the next secret its exchange of a rekey scalar with a
	/// stray point derives under the sample randoms, and the salt of those
	/// randoms.
	fn next_link() -> (EpochMaterials, EpochSecret, RandomsSalt) {
		let epoch = sample_epoch();
		let salt = sample_salt();
		let kdf_salt = salt.as_kdf_salt().expect("the sample randoms meet the salt floor");
		let next = next_of(&epoch, &ephemeral(0x51), &distinct(stray_point(0x41)), kdf_salt);
		(epoch, next, salt)
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
	fn sample_epoch_from(fill: u8) -> EpochMaterials {
		let secret = fixture_handshake_secret(fill);
		let salt = KdfSalt::try_from(SAMPLE_SALT.as_slice()).expect("the sample salt meets the salt floor");
		let epoch = EpochMaterials::derive::<DefaultCryptoProvider>(&secret, salt, sample_chain_root());
		epoch.expect("the sample secret derives an epoch")
	}

	/// Epoch 0 of the handshake of the sample base secret.
	fn sample_epoch() -> EpochMaterials {
		sample_epoch_from(SAMPLE_BASE)
	}

	/// The SHA3-256 `DigestInfo` a receipt carries for `hash`.
	fn sha3_digest_info(hash: [u8; 32]) -> DigestInfo {
		let algorithm = AlgorithmIdentifier { oid: HASH_SHA3_256, parameters: None };
		let digest = OctetString::new(hash).expect("32 octets fit an OCTET STRING");
		DigestInfo { algorithm, digest }
	}

	/// The receipt of the sample handshake under `credit_unit`.
	fn sample_reference(credit_unit: u32) -> SessionReceipt {
		SessionReceipt {
			transcript_hash: sha3_digest_info(SAMPLE_CHAIN_ROOT),
			budgets: SAMPLE_BUDGETS,
			credit_unit,
			ancillary: None,
		}
	}

	/// A client and a server that hold matched epoch materials, with the
	/// identity each one signs under.
	struct Parties {
		client: ClientRekey<DefaultCryptoProvider>,
		server: ServerRekey<DefaultCryptoProvider>,
		client_identity: Identity,
		server_identity: Identity,
	}

	/// The parties of [`rekey_parties_with`] whose client renews with the
	/// server's signing certificate.
	fn rekey_parties() -> Parties {
		rekey_parties_with(SessionPeer::try_from, None)
	}

	/// The parties of [`rekey_parties`], whose client renews with the peer
	/// `server` makes of the server's signing certificate, as a CMS client
	/// renews with the server's key-agreement certificate beside it, and
	/// whose server reports each outcome to `observer`.
	fn rekey_parties_with(
		server: impl FnOnce(Arc<Certificate>) -> Result<SessionPeer, HandshakeError>,
		observer: Option<Arc<dyn SessionObserver>>,
	) -> Parties {
		let client_identity = test_identity(CLIENT_SEED);
		let server_identity = test_identity(SERVER_SEED);
		let reference = sample_reference(SAMPLE_CREDIT_UNIT);

		let server_peer =
			server(server_identity.signing.certificate_arc()).expect("the server certificate records its peer");
		let server_peer = RekeyPeer::admit(&server_peer, KeyPurposes::HOUSE.server).expect("the server may renew");
		let client_peer =
			RekeyPeer::admit(&client_identity.peer(), KeyPurposes::HOUSE.client).expect("the client may renew");
		let client_materials = RekeyMaterials::new(
			sample_epoch(),
			reference.to_owned(),
			client_identity.signing.clone(),
			server_peer,
		);
		let server_materials =
			RekeyMaterials::new(sample_epoch(), reference, server_identity.signing.clone(), client_peer);

		let client = ClientRekey::new(client_materials, None);
		let server = ServerRekey::new(server_materials, None, observer);
		Parties { client, server, client_identity, server_identity }
	}

	/// The parties of [`rekey_parties_with`] whose client renews as a CMS
	/// client: with the server's signing certificate beside the key-agreement
	/// certificate of the fixed key of [`KEY_AGREEMENT_SEED`].
	fn key_agreement_parties() -> Parties {
		let key_agreement = Arc::new(TestCertificate::self_signed(&TestKey::fixed(KEY_AGREEMENT_SEED)));
		rekey_parties_with(|signing| SessionPeer::paired(signing, key_agreement), None)
	}

	impl ClientRekey<DefaultCryptoProvider> {
		/// A client and a server that hold matched epoch materials, ready to
		/// renew.
		pub(crate) fn fixture_pair() -> (Self, ServerRekey<DefaultCryptoProvider>) {
			let Parties { client, server, .. } = rekey_parties();
			(client, server)
		}

		/// Run one renewal with `server` to completion, and return the install
		/// of this client beside what the server made of its ack.
		pub(crate) async fn exchange_with(
			&mut self,
			server: &mut ServerRekey<DefaultCryptoProvider>,
		) -> (EpochInstall, ServerAckOutcome) {
			let request = self.start_renewal().expect("a client with no exchange in flight starts one");
			let response = issued(server, &request).await;
			let answered = self.process_response(response).await;
			let (ack, client_install) = answered.expect("the client admits the response its server signed");

			let outcome = server.process_ack(ack).await;
			(client_install, outcome.expect("the server admits the ack of its own response"))
		}
	}

	/// The epoch receipt `server` issues for `request`, with no exchange of
	/// `server` in flight.
	async fn issued(
		server: &mut ServerRekey<DefaultCryptoProvider>,
		request: &MuxRekeyRequestPackage,
	) -> MuxRekeyResponsePackage {
		let answer = server
			.process_request(request)
			.await
			.expect("a server admits a request of its own client");
		match answer {
			RequestAnswer::Issued(response) => response,
			RequestAnswer::InFlight => panic!("a server with no exchange in flight answers a request"),
		}
	}

	/// The parties of [`ClientRekey::fixture_pair`] in the middle of one
	/// renewal: the request the client sent and the response the server issued
	/// for it.
	struct Renewal {
		client: ClientRekey<DefaultCryptoProvider>,
		server: ServerRekey<DefaultCryptoProvider>,
		request: MuxRekeyRequestPackage,
		response: MuxRekeyResponsePackage,
	}

	/// The parties of [`ClientRekey::fixture_pair`] once the client sent its
	/// request and the server issued its response.
	async fn renewal() -> Renewal {
		let (mut client, mut server) = ClientRekey::fixture_pair();
		let request = client.start_renewal().expect("a client with no exchange in flight starts one");
		let response = issued(&mut server, &request).await;
		Renewal { client, server, request, response }
	}

	/// The response that `signer` issues for `request` over the server
	/// ephemeral `point`, under a receipt that pins both to the sample epoch.
	async fn signed_response(
		request: &MuxRekeyRequestPackage,
		point: Vec<u8>,
		signer: &SigningIdentity,
	) -> MuxRekeyResponsePackage {
		let request_der = request.to_der().expect("a rekey request encodes");
		let pin = sample_epoch().exchange_pin::<Sha3_256>(request_der, &SAMPLE_SERVER_RANDOM, &point);
		let pin = pin.expect("the sample epoch pins a request and a share");
		let issuing = SessionReceipt::issue(pin, SAMPLE_BUDGETS, SAMPLE_CREDIT_UNIT, None, signer);
		let (_receipt, artifact) = issuing.await.expect("the server signs the receipt");

		let response = MuxRekeyResponsePackage::new(SAMPLE_SERVER_RANDOM, point, Some(artifact));
		response.expect("a response of a share of the house width forms")
	}

	/// An observer that records the client certificate each outcome names, as
	/// a server reports the outcome.
	///
	/// The house observers report outcomes to a trace, so the double records
	/// what crossed the observer boundary for the case to read.
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
	async fn a_server_rekey_reports_the_client_of_its_materials() {
		let observer = Arc::new(ClientCertificateObserver::default());
		let reporting = Arc::clone(&observer) as Arc<dyn SessionObserver>;
		let parties = rekey_parties_with(SessionPeer::try_from, Some(reporting));
		let Parties { mut client, mut server, client_identity, .. } = parties;
		client.exchange_with(&mut server).await;

		let expected = Some(client_identity.signing.certificate_arc());
		assert_eq!(observer.reported(), vec![expected]);
	}

	/// One exchange moves both endpoints to epoch 1 under one receipt, and
	/// leaves no exchange in flight on either.
	#[tokio::test]
	async fn an_exchange_moves_both_endpoints_to_the_next_epoch() {
		let (mut client, mut server) = ClientRekey::fixture_pair();
		let (client_install, outcome) = client.exchange_with(&mut server).await;

		let epochs = (client_install.epoch, outcome.install.epoch, client.epoch(), server.epoch());
		assert_eq!((epochs, outcome.rejection), ((1, 1, 1, 1), None));
		assert_eq!(client_install.receipt, outcome.install.receipt);
		assert_eq!((client.renewal_in_flight(), server.exchange_in_flight()), (false, false));
	}

	/// The server opens the traffic that the client seals under the epoch one
	/// exchange installs, and the client opens the traffic of the server.
	#[tokio::test]
	async fn an_exchange_carries_traffic_both_ways() -> TestResult {
		let (mut client, mut server) = ClientRekey::fixture_pair();
		let (mut client_install, outcome) = client.exchange_with(&mut server).await;
		let mut server_install = outcome.install;
		let mut uplink = client_install.send_cipher.encrypt_next(PLAINTEXT)?.to_der()?;
		let mut downlink = server_install.send_cipher.encrypt_next(PLAINTEXT)?.to_der()?;

		let uplinked = server_install.recv_cipher.open(&mut uplink)?;
		let downlinked = client_install.recv_cipher.open(&mut downlink)?;
		assert_eq!(uplinked, PLAINTEXT);
		assert_eq!(downlinked, PLAINTEXT);
		Ok(())
	}

	/// Two chains that share the public chain root, the exchange randoms, and
	/// one agreement, but hold different epoch secrets, derive different
	/// traffic keys. The next epoch therefore depends on the previous epoch
	/// secret as well as on the agreement.
	#[test]
	fn the_next_epoch_depends_on_the_previous_epoch_secret() -> TestResult {
		let mut first = sample_epoch_from(SAMPLE_BASE);
		let mut second = sample_epoch_from(SAMPLE_BASE + 1);
		let (client_scalar, server_scalar) = (ephemeral(0x51), ephemeral(0x52));
		let client_point = distinct(point_of(&client_scalar.public_key()));
		let server_point = distinct(point_of(&server_scalar.public_key()));
		let salt = sample_salt();
		let kdf_salt = salt.as_kdf_salt()?;
		let first_next = next_of(&first, &client_scalar, &server_point, kdf_salt);
		let second_next = next_of(&second, &server_scalar, &client_point, kdf_salt);

		let first_rotated = first.install::<Provider>(first_next, kdf_salt, sample_chain_root())?;
		let second_rotated = second.install::<Provider>(second_next, kdf_salt, sample_chain_root())?;
		let (first_send, _first_recv) = SessionKeys::for_client(first_rotated).into_parts();
		let (_second_send, mut second_recv) = SessionKeys::for_server(second_rotated).into_parts();

		let mut record = first_send.encrypt_next(PLAINTEXT)?.to_der()?;
		let refused = second_recv.open(&mut record);
		assert!(matches!(refused, Err(TightBeamError::EnvelopeError(EnvelopeError::KeyUnwrap))));
		Ok(())
	}

	/// The rotated traffic keys come from the next chain link, so a record
	/// sealed under the previous epoch secret's directional key does not open
	/// under them. The record carries the rotated epoch, so the key alone
	/// decides.
	#[test]
	fn rotation_leaves_the_previous_epoch_keys_behind() -> TestResult {
		let (mut epoch, next, salt) = next_link();
		let rotated_epoch = epoch.epoch() + 1;
		let previous = DirectionalCiphers::derive::<Provider, _>(epoch.secret(), salt.as_kdf_salt()?, rotated_epoch)?;
		let (previous_send, _previous_recv) = SessionKeys::for_client(previous).into_parts();
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
	fn rotation_carries_the_next_epoch() -> TestResult {
		let (mut epoch, next, salt) = next_link();
		let next_epoch = epoch.epoch() + 1;
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
	fn a_rotated_record_names_the_next_epoch() -> TestResult {
		let (mut epoch, next, salt) = next_link();
		let next_epoch = epoch.epoch() + 1;
		let expected = [b"tb/session/record/kekid/v1".as_slice(), &[0x00], &next_epoch.to_be_bytes()].concat();

		let rotated = epoch.install::<Provider>(next, salt.as_kdf_salt()?, sample_chain_root())?;
		let (send, _recv) = SessionKeys::for_client(rotated).into_parts();
		let record = send.encrypt_next(PLAINTEXT)?;
		assert_eq!(key_identifier_of(&record), expected);
		Ok(())
	}

	/// A second exchange moves both endpoints to epoch 2, and the server opens
	/// the traffic that the client seals under it.
	#[tokio::test]
	async fn chained_exchanges_stay_in_step() -> TestResult {
		let (mut client, mut server) = ClientRekey::fixture_pair();
		client.exchange_with(&mut server).await;

		let (client_install, outcome) = client.exchange_with(&mut server).await;
		let mut server_install = outcome.install;
		assert_eq!(client_install.epoch, 2);
		assert_eq!(server_install.epoch, 2);

		let mut uplink = client_install.send_cipher.encrypt_next(PLAINTEXT)?.to_der()?;
		let received = server_install.recv_cipher.open(&mut uplink)?;
		assert_eq!(received, PLAINTEXT);
		Ok(())
	}

	/// The receipt of an epoch pins the exchange that produced it, so its
	/// transcript hash moves off the chain root.
	#[tokio::test]
	async fn epoch_receipt_pins_the_exchange() -> TestResult {
		let Renewal { response, .. } = renewal().await;

		let epoch_receipt = response.epoch_receipt().ok_or(HandshakeError::ReceiptMissing)?;
		let receipt = epoch_receipt.receipt()?;
		assert_eq!(receipt.budgets, SAMPLE_BUDGETS);
		assert_eq!(receipt.credit_unit, SAMPLE_CREDIT_UNIT);

		let chain_root = sha3_digest_info(SAMPLE_CHAIN_ROOT);
		assert_ne!(receipt.transcript_hash, chain_root);
		Ok(())
	}

	/// A client with a renewal in flight refuses a second start.
	#[test]
	fn a_second_start_of_a_renewal_in_flight_fails_closed() -> TestResult {
		let (mut client, _) = ClientRekey::fixture_pair();
		client.start_renewal()?;

		let duplicate = client.start_renewal();
		assert!(matches!(duplicate, Err(HandshakeError::InvalidState)));
		Ok(())
	}

	/// A server with an exchange in flight answers a second request as in
	/// flight, and issues no second response.
	#[tokio::test]
	async fn a_second_request_of_an_exchange_in_flight_answers_in_flight() -> TestResult {
		let Renewal { mut server, request, .. } = renewal().await;

		let duplicate = server.process_request(&request).await?;
		assert!(matches!(duplicate, RequestAnswer::InFlight));
		Ok(())
	}

	/// A response that no renewal of the client asked for is refused.
	#[tokio::test]
	async fn an_unsolicited_response_fails_closed() -> TestResult {
		let (mut client, mut server) = ClientRekey::fixture_pair();
		let request = MuxRekeyRequestPackage::new([1u8; 32], stray_point(0x41))?;
		let response = issued(&mut server, &request).await;

		let unsolicited = client.process_response(response).await;
		assert!(matches!(unsolicited, Err(HandshakeError::InvalidState)));
		Ok(())
	}

	/// An ack that no exchange of the server asked for is refused.
	#[tokio::test]
	async fn an_unsolicited_ack_fails_closed() {
		let (_, mut server) = ClientRekey::fixture_pair();
		let bare_ack = server.process_ack(MuxRekeyAckPackage::new(None)).await;
		assert!(matches!(bare_ack, Err(HandshakeError::InvalidState)));
	}

	/// A response that carries no epoch receipt is refused as a missing
	/// receipt.
	#[tokio::test]
	async fn missing_epoch_receipt_fails_closed() -> TestResult {
		let (mut client, _) = ClientRekey::fixture_pair();
		client.start_renewal()?;

		let bare = MuxRekeyResponsePackage::new([9u8; 32], stray_point(0x41), None)?;
		let missing_receipt = client.process_response(bare).await;
		assert!(matches!(missing_receipt, Err(HandshakeError::ReceiptMissing)));
		Ok(())
	}

	/// A response whose receipt names other credit terms is refused as a
	/// receipt mismatch.
	#[tokio::test]
	async fn credit_drift_fails_closed() -> TestResult {
		let (mut client, mut server) = ClientRekey::fixture_pair();
		client.materials.reference = sample_reference(SAMPLE_CREDIT_UNIT + 1);

		let request = client.start_renewal()?;
		let response = issued(&mut server, &request).await;
		let drift = client.process_response(response).await;
		assert!(matches!(drift, Err(HandshakeError::ReceiptMismatch)));
		Ok(())
	}

	/// A replayed response is refused as a receipt mismatch.
	#[tokio::test]
	async fn replayed_response_fails_closed() -> TestResult {
		let Renewal { mut client, request, response, .. } = renewal().await;
		let replay = response.to_owned();

		client.process_response(response).await.map(|_| ())?;

		// A replay targets the advanced chain, where the pin fails to match.
		let request_der = request.to_der()?;
		let ephemeral = Box::new(ephemeral(0x51));

		client.pending = Some(PendingRenewal { client_random: [3u8; 32], request_der, ephemeral });

		let replayed = client.process_response(replay).await;
		assert!(matches!(replayed, Err(HandshakeError::ReceiptMismatch)));
		Ok(())
	}

	/// An ack with no countersignature is refused.
	#[tokio::test]
	async fn missing_countersignature_fails_closed() {
		let Renewal { mut server, .. } = renewal().await;

		let missing = server.process_ack(MuxRekeyAckPackage::new(None)).await;
		assert!(matches!(missing, Err(HandshakeError::CountersignatureMissing)));
	}

	/// An ack that a party outside the exchange countersigned fails its
	/// signature check.
	#[tokio::test]
	async fn foreign_countersignature_fails_closed() -> TestResult {
		let Renewal { mut client, mut server, response, .. } = renewal().await;
		let epoch_receipt = response.epoch_receipt().ok_or(HandshakeError::ReceiptMissing)?;
		let receipt = epoch_receipt.receipt()?;

		client.process_response(response).await.map(|_| ())?;

		let intruder = test_identity(0x23);
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
	///
	/// The crate ships no authorizer, and the case needs one that refuses a
	/// settlement.
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
	async fn a_refused_settlement_rotates_with_the_dual_signed_receipt_and_its_code() -> TestResult {
		let Renewal { mut client, mut server, response, .. } = renewal().await;

		server.authorizer = Some(Arc::new(RefusingSettlement));

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
	async fn the_next_epoch_needs_a_rekey_scalar() -> TestResult {
		let Renewal { mut client, mut server, request, response } = renewal().await;
		let wire_client = distinct(request.client_ephemeral());
		let wire_server = distinct(response.server_ephemeral());
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
		// holds a scalar of its own for each attempt.
		let observed = sample_epoch();
		let (first, second) = (ephemeral(0x51), ephemeral(0x52));
		let against_client = next_of(&observed, &first, &wire_client, salt.as_kdf_salt()?);
		let against_server = next_of(&observed, &second, &wire_server, salt.as_kdf_salt()?);
		let mut client_attempt = server_recv(&against_client, &salt);
		let mut server_attempt = server_recv(&against_server, &salt);
		let opened_against_client = client_attempt.open(&mut record.clone()).map(<[u8]>::to_vec);
		let opened_against_server = server_attempt.open(&mut record.clone()).map(<[u8]>::to_vec);
		assert!(matches!(
			opened_against_client,
			Err(TightBeamError::EnvelopeError(EnvelopeError::KeyUnwrap))
		));
		assert!(matches!(
			opened_against_server,
			Err(TightBeamError::EnvelopeError(EnvelopeError::KeyUnwrap))
		));
		Ok(())
	}

	// A server ephemeral swapped in transit changes the pin the client
	// recomputes, so the receipt the server signed fails the match. The client
	// parses the share only after the receipt authenticates it, so a malformed
	// share fails the pin as well.
	crate::tb_cases! {
		async fn a_server_ephemeral_swapped_in_transit_fails_the_pin(swapped: Vec<u8>) -> TestResult {
			let Renewal { mut client, mut response, .. } = renewal().await;
			response.server_ephemeral = OctetString::new(swapped.as_slice())?;

			let refused = client.process_response(response).await;
			assert!(matches!(refused, Err(HandshakeError::ReceiptMismatch)));
			Ok(())
		}
		cases {
			for_a_point_of_the_curve => stray_point(0x41),
			for_a_malformed_point => compact_point(0x41),
		}
	}

	/// The parties of a renewal, the server ephemeral their server signs a
	/// receipt over, and the test of the answer of their client.
	type SignedEphemeral = (
		Parties,
		Vec<u8>,
		fn(&Result<(MuxRekeyAckPackage, EpochInstall), HandshakeError>) -> bool,
	);

	// The client parses a server ephemeral once the receipt authenticates it,
	// and refuses one that is no share of a fresh key, even under a receipt
	// the server signed over it. A compact share has the width of the
	// compressed form and fails the parse. The server's static key and the
	// key of a CMS server's key-agreement certificate fail as static keys, as
	// the handshake refuses them.
	crate::tb_cases! {
		async fn the_client_refuses_a_signed_server_ephemeral(
			(parties, point, refused): SignedEphemeral
		) -> TestResult {
			let Parties { mut client, server_identity, .. } = parties;
			let request = client.start_renewal()?;
			let response = signed_response(&request, point, &server_identity.signing).await;

			let answered = client.process_response(response).await;
			assert!(refused(&answered));
			Ok(())
		}
		cases {
			in_the_compact_form => (
				rekey_parties(),
				compact_point(0x41),
				|answered| matches!(answered, Err(HandshakeError::KeyExchange(KeyExchangeError::Malformed))),
			),
			equal_to_the_static_key => (
				rekey_parties(),
				point_of(&test_identity(SERVER_SEED).public_key),
				|answered| matches!(answered, Err(HandshakeError::ServerEphemeralIsStatic)),
			),
			equal_to_the_key_agreement_key => (
				key_agreement_parties(),
				point_of(&PublicKey::from(TestKey::fixed(KEY_AGREEMENT_SEED).verifying_key())),
				|answered| matches!(answered, Err(HandshakeError::ServerEphemeralIsStatic)),
			),
		}
	}

	/// A client ephemeral swapped in transit reaches the server inside the
	/// request the server pins. The client pins the request it sent, so the
	/// receipt fails the match.
	#[tokio::test]
	async fn a_swapped_client_ephemeral_fails_the_pin() -> TestResult {
		let (mut client, mut server) = ClientRekey::fixture_pair();
		let mut request = client.start_renewal()?;
		request.client_ephemeral = OctetString::new(stray_point(0x41).as_slice())?;

		let response = issued(&mut server, &request).await;
		let swapped = client.process_response(response).await;
		assert!(matches!(swapped, Err(HandshakeError::ReceiptMismatch)));
		Ok(())
	}

	/// A client ephemeral and the test of the answer of the server.
	type ClientEphemeral = (Vec<u8>, fn(&Result<RequestAnswer, HandshakeError>) -> bool);

	// The server refuses a client ephemeral at the parse, before any
	// agreement runs on it and before an exchange goes in flight. A rekey leg
	// carries the compressed form of a point of the curve alone, so the parse
	// refuses another width before it reads a point and the uncompressed form
	// at its width. It refuses a point off the curve, and the compact form
	// `0x05`, because RFC 5480 §2.2 names no such form. The server refuses
	// the client's static key, so the agreement of a renewal cannot collapse
	// into the static one.
	crate::tb_cases! {
		async fn the_server_refuses_a_client_ephemeral(
			(share, refused): ClientEphemeral
		) -> TestResult {
			let (mut client, mut server) = ClientRekey::fixture_pair();
			let mut request = client.start_renewal()?;
			request.client_ephemeral = OctetString::new(share.as_slice())?;

			let answered = server.process_request(&request).await;
			assert!(refused(&answered));
			assert!(!server.exchange_in_flight());
			Ok(())
		}
		cases {
			off_the_curve => (
				off_curve_point().to_vec(),
				|answered| matches!(answered, Err(HandshakeError::KeyExchange(KeyExchangeError::Malformed))),
			),
			of_another_width => (
				vec![0x02u8; 32],
				|answered| {
					matches!(
						answered,
						Err(HandshakeError::KeyExchange(KeyExchangeError::Width { expected: 33, actual: 32 }))
					)
				},
			),
			in_the_uncompressed_form => (
				stray_key(0x41).to_encoded_point(false).as_bytes().to_vec(),
				|answered| {
					matches!(
						answered,
						Err(HandshakeError::KeyExchange(KeyExchangeError::Width { expected: 33, actual: 65 }))
					)
				},
			),
			in_the_compact_form => (
				compact_point(0x41),
				|answered| matches!(answered, Err(HandshakeError::KeyExchange(KeyExchangeError::Malformed))),
			),
			equal_to_the_static_key => (
				point_of(&test_identity(CLIENT_SEED).public_key),
				|answered| matches!(answered, Err(HandshakeError::ClientEphemeralIsStatic)),
			),
		}
	}

	/// The session of a CMS client, as a transport holds it once the
	/// handshake completed.
	///
	/// A transport holds its session behind a socket and a handshake, and the
	/// cases read and detach the session alone.
	#[cfg(feature = "transport-cms")]
	struct CmsClientProbe {
		state: SessionState<DefaultCryptoProvider>,
		limits: CheckedLimits,
	}

	#[cfg(feature = "transport-cms")]
	impl crate::transport::state::sealed::Sealed for CmsClientProbe {}

	#[cfg(feature = "transport-cms")]
	impl EncryptedProtocolState for CmsClientProbe {
		type CryptoProvider = DefaultCryptoProvider;

		fn limits(&self) -> &CheckedLimits {
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
	fn cms_client_session(server: &TestCmsServer) -> CmsClientProbe {
		let client = TestIdentity::of(&TestKey::fixed(0x27));
		let stored = dual_signed_receipt(&server.signing_identity(), &client);

		let keys = SessionKeys::for_client(TestKey::insecure_directional_keys());
		let signing = Arc::new(server.signing.to_owned());
		let key_agreement = Arc::new(server.key_agreement.to_owned());
		let peer = SessionPeer::paired(signing, key_agreement).expect("the pair records its peer");
		let epoch = sample_epoch();
		let session = EstablishedSession::forged(keys, Some(Arc::new(stored)), Some(peer));
		let session = session.with_forged_epoch(epoch);
		let encryption = EncryptionConfig { client_identity: Some(client), ..EncryptionConfig::unconfigured() };

		let state = SessionState::at(encryption, SessionPhase::Encrypted(Box::new(session)));
		CmsClientProbe { state, limits: CheckedLimits::default() }
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
	async fn a_cms_session_hands_its_rekey_the_key_agreement_key() -> TestResult {
		let server = TestCmsServer::generate("tightbeam rekey server");
		let mut probe = cms_client_session(&server);
		let exchange = client_exchange(&mut probe);
		let mut exchange = exchange.lock().await;
		let request = exchange.start_renewal()?;
		let point = point_of(&PublicKey::from(server.key_agreement_key.verifying_key()));
		let response = signed_response(&request, point, &server.signing_identity()).await;

		let refused = exchange.process_response(response).await;
		assert!(matches!(refused, Err(HandshakeError::ServerEphemeralIsStatic)));
		Ok(())
	}

	/// A CMS client's session whose server certificate names the client
	/// purpose alone refuses its rekey under the server purpose. It keeps its
	/// receipt, its peer, and its epoch, because the session detaches the epoch
	/// only after every check that can refuse the rekey.
	#[cfg(feature = "transport-cms")]
	#[test]
	fn a_session_refused_its_rekey_keeps_its_epoch() {
		let server = TestCmsServer::generate("tightbeam refused rekey server");
		let server = server.with_key_purposes(&[KeyPurposes::HOUSE.client]);
		let mut probe = cms_client_session(&server);
		let refused = MuxRekeyContext::detach(&mut probe, MuxRole::Client);

		let epoch = probe.state.established().and_then(EstablishedSession::epoch);
		assert!(matches!(
			refused,
			Err(TransportError::HandshakeError(HandshakeError::CertificateValidationError(_)))
		));
		assert!(probe.state.receipt().is_some());
		assert_eq!(probe.state.peer_certificate(), Some(&server.signing));
		assert!(epoch.is_some());
	}

	/// A CMS client's session hands its epoch to the rekey it renews into, so
	/// the session holds no epoch once its rekey detaches.
	#[cfg(feature = "transport-cms")]
	#[test]
	fn a_renewed_session_hands_over_its_epoch() -> TestResult {
		let server = TestCmsServer::generate("tightbeam renewed rekey server");
		let mut probe = cms_client_session(&server);

		let renewed = MuxRekeyContext::detach(&mut probe, MuxRole::Client)?;
		let established = probe.state.established().ok_or("the renewed session stays established")?;
		assert!(renewed.is_some());
		assert!(established.epoch().is_none());
		Ok(())
	}

	/// A receipt of the sample terms, rooted at the sample chain root, that
	/// `server` signed and `client` countersigned.
	///
	/// [`rt::block_on`] drives the signatures, so a synchronous test reads it
	/// on any thread.
	fn dual_signed_receipt(server: &SigningIdentity, client: &SigningIdentity) -> StoredReceipt {
		let issuing = SessionReceipt::issue(sample_chain_root(), SAMPLE_BUDGETS, SAMPLE_CREDIT_UNIT, None, server);
		let (receipt, artifact) = rt::block_on(issuing).expect("the server signs the receipt");
		let countersignature = rt::block_on(receipt.countersign(None, client)).expect("the client countersigns");

		let completed = artifact.with_certified_signer(countersignature);
		StoredReceipt::try_from(completed.expect("the receipt joins")).expect("the receipt is complete")
	}

	// A session renews only under a dual-signed receipt and against a
	// recorded peer, so a session built without either releases its epoch
	// materials where it is built.
	crate::tb_cases! {
		fn a_session_releases_its_epoch((receipt, peer): (Option<StoredReceipt>, Option<SessionPeer>)) {
			let keys = SessionKeys::for_client(TestKey::insecure_directional_keys());

			let session = EstablishedSession::forged(keys, receipt.map(Arc::new), peer);
			let session = session.with_forged_epoch(sample_epoch());
			assert!(session.epoch().is_none());
		}
		cases {
			without_a_receipt => (None, Some(test_identity(0x24).peer())),
			without_a_peer => {
				(Some(dual_signed_receipt(&test_identity(0x25).signing, &test_identity(0x26).signing)), None)
			},
		}
	}
}
