//! These tests run over both flows and cover the step order, the phases, the
//! key schedule, and the decisions on admission, negotiation, and settlement.
//!
//! Each test body is generic over [`TestFlow`], and [`over_each_flow`] runs
//! it once per protocol. A test of the messages of one protocol sits beside
//! that flow.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::asn1::OctetString;
use crate::cms::cert::IssuerAndSerialNumber;
use crate::crypto::cms::EnvelopeError;
use crate::crypto::key::SigningKeyProvider;
use crate::crypto::sign::ecdsa::k256::Secp256k1;
use crate::crypto::sign::elliptic_curve::sec1::ToEncodedPoint;
use crate::crypto::sign::elliptic_curve::PublicKey;
use crate::crypto::sign::SignedDataSigners;
use crate::crypto::x509::error::CertificateValidationError::{
	AmbiguousIssuer, CertificateNotPinned, CertificateNotTrusted, Expired, PathCycle, PathLenExceeded,
};
use crate::crypto::x509::policy::{CertificateValidation, DirectTrustValidator};
use crate::crypto::x509::utils::Skid;
use crate::der::Encode;
use crate::marker::MaybeSendFuture;
use crate::oids::{HANDSHAKE_KEY_CONFIRMATION, SESSION_RECEIPT};
use crate::testing::fixtures::TestStore;
use crate::testing::{TestCmsServer, TestIdentity, TestKey, TestResult};
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::negotiation::{MuxSettings, NegotiationError, SecurityOffer, TransportOffer};
use crate::transport::handshake::receipt::{ApprovalRefusal, ReceiptApprover, SessionReceipt};
use crate::transport::handshake::tests::*;
use crate::transport::handshake::{Handshake, HandshakeMessage, HandshakePhase, PeerAuthentication};
use crate::x509::Certificate;
use crate::TightBeamError;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::x509::KeyPurposes;
#[cfg(feature = "transport-cms")]
use crate::transport::handshake::Cms;
#[cfg(feature = "transport-hpke")]
use crate::transport::handshake::Hpke;
#[cfg(all(feature = "transport-cms", mux_rekey))]
use crate::transport::handshake::SessionPeer;
#[cfg(feature = "transport-hpke")]
use crate::transport::handshake::{ClientConfig, HpkeClientSettings, LearnedTrust};
#[cfg(feature = "transport-cms")]
use crate::transport::handshake::{CmsServerSettings, ServerConfig, SupportedProfiles};

/// The reply a fresh handshake of flow `F` produces, which every other
/// handshake refuses.
async fn stray_reply<F: TestFlow>() -> HandshakeMessage {
	let (mut client, mut server) = pair::<F>(PeerAuthentication::Anonymous);
	let opening = client.start().expect("a fresh client builds its opening");
	server.reply(opening).await.expect("the server admits the opening")
}

/// Each endpoint moves from `Idle` through `Exchanging` to `Agreed` as its
/// steps run, and both endpoints complete once both agreed.
async fn the_phase_follows_the_steps<F: TestFlow>() -> TestResult {
	let (mut client, mut server) = pair::<F>(PeerAuthentication::mutual_by_expiry());
	assert_eq!(client.phase(), HandshakePhase::Idle);
	assert_eq!(server.phase(), HandshakePhase::Idle);

	let opening = client.start()?;
	assert_eq!(client.phase(), HandshakePhase::Exchanging);

	let reply = server.reply(opening).await?;
	assert_eq!(server.phase(), HandshakePhase::Exchanging);

	let closing = client.respond(reply).await?;
	assert_eq!(client.phase(), HandshakePhase::Agreed);

	server.finish(closing).await?;
	assert_eq!(server.phase(), HandshakePhase::Agreed);

	client.complete()?;
	server.complete()?;
	assert!(client.is_complete());
	assert!(server.is_complete());
	Ok(())
}

/// A client refuses each step out of its order and keeps its phase, so the
/// handshake still runs to its end.
async fn an_illegal_client_step_leaves_the_phase_unchanged<F: TestFlow>() -> TestResult {
	let (mut client, mut server) = pair::<F>(PeerAuthentication::Anonymous);

	// Only the opening runs on an idle client.
	let early = client.respond(stray_reply::<F>().await).await;
	assert!(matches!(early, Err(HandshakeError::InvalidState)));
	assert!(matches!(client.complete(), Err(HandshakeError::InvalidState)));
	assert_eq!(client.phase(), HandshakePhase::Idle);

	// A second opening and an early completion leave the sent opening in place.
	let opening = client.start()?;
	assert!(matches!(client.start(), Err(HandshakeError::InvalidState)));
	assert!(matches!(client.complete(), Err(HandshakeError::InvalidState)));
	assert_eq!(client.phase(), HandshakePhase::Exchanging);

	// The handshake still runs to its end.
	let reply = server.reply(opening).await?;
	client.respond(reply).await?;
	client.complete()?;
	Ok(())
}

/// A server refuses each step out of its order and keeps its phase, so the
/// handshake still runs to its end.
async fn an_illegal_server_step_leaves_the_phase_unchanged<F: TestFlow>() -> TestResult {
	let (mut client, mut server) = pair::<F>(PeerAuthentication::Anonymous);
	let opening = client.start()?;

	// Only the opening runs on an idle server.
	let early = server.finish(opening.to_owned()).await;
	assert!(matches!(early, Err(HandshakeError::InvalidState)));
	assert!(matches!(server.complete(), Err(HandshakeError::InvalidState)));
	assert_eq!(server.phase(), HandshakePhase::Idle);

	// A second opening and an early completion leave the sent reply in place.
	let reply = server.reply(opening.to_owned()).await?;
	let repeated = server.reply(opening).await;
	assert!(matches!(repeated, Err(HandshakeError::InvalidState)));
	assert!(matches!(server.complete(), Err(HandshakeError::InvalidState)));
	assert_eq!(server.phase(), HandshakePhase::Exchanging);

	// The handshake still runs to its end.
	let closing = client.respond(reply).await?;
	server.finish(closing).await?;
	server.complete()?;
	Ok(())
}

/// Whether each step that reads or builds a leg is refused as
/// [`HandshakeError::InvalidState`] when it runs again on the endpoints of
/// `run`, beside those endpoints. The client answers and opens, then the
/// server replies and reads the closing, in that order.
async fn steps_after_the_legs<F: TestFlow>(run: Run<F>) -> ([bool; 4], TestClient<F>, TestServer<F>) {
	let Run { opening, reply, closing, mut client, mut server, .. } = run;
	let answered = client.respond(reply).await;
	let started = client.start();
	let reopened = server.reply(opening).await;
	let reclosed = server.finish(closing).await;

	let refused = [
		matches!(answered, Err(HandshakeError::InvalidState)),
		matches!(started, Err(HandshakeError::InvalidState)),
		matches!(reopened, Err(HandshakeError::InvalidState)),
		matches!(reclosed, Err(HandshakeError::InvalidState)),
	];
	(refused, client, server)
}

/// A handshake that agreed refuses every further step that reads or builds a
/// leg, and each refusal leaves what it agreed in place.
async fn a_step_after_the_agreement_is_refused<F: TestFlow>() -> TestResult {
	let Parties { client, server, .. } = parties::<F>(PeerAuthentication::Anonymous);
	let run = run(client, server).await;

	let (refused, mut client, mut server) = steps_after_the_legs(run).await;
	assert_eq!(refused, [true; 4]);
	assert_eq!(client.phase(), HandshakePhase::Agreed);
	assert_eq!(server.phase(), HandshakePhase::Agreed);

	// Both sides still complete.
	client.complete()?;
	server.complete()?;
	Ok(())
}

/// A completed handshake is terminal: it refuses every step that reads or
/// builds a leg, and each refusal leaves it completed.
async fn a_step_after_completion_is_refused<F: TestFlow>() -> TestResult {
	let Established { run, .. } = established::<F>(PeerAuthentication::Anonymous).await;
	let (refused, client, server) = steps_after_the_legs(run).await;
	assert_eq!(refused, [true; 4]);
	assert_eq!(client.phase(), HandshakePhase::Completed);
	assert_eq!(server.phase(), HandshakePhase::Completed);
	Ok(())
}

/// Completion moves the handshake secret out, so a second completion has
/// nothing to derive from and each accessor answers `None`.
async fn completion_takes_what_the_handshake_agreed<F: TestFlow>() -> TestResult {
	let mutual = PeerAuthentication::mutual_by_expiry();
	let Parties { server_identity, client_identity, client, server } = parties::<F>(mutual);
	let mut run = run(client, server).await;
	assert_eq!(run.client.selected_profile(), Some(create_default_test_profile()));
	assert_eq!(run.client.peer_certificate(), Some(&server_identity.signing));
	assert_eq!(run.server.transcript_hash(), Some(run.transcript_hash));
	assert_eq!(run.server.peer_certificate(), Some(&client_identity.certificate));

	run.client.complete()?;
	run.server.complete()?;
	assert!(matches!(run.client.complete(), Err(HandshakeError::InvalidState)));
	assert!(matches!(run.server.complete(), Err(HandshakeError::InvalidState)));
	assert_eq!(run.client.selected_profile(), None);
	assert_eq!(run.client.peer_certificate(), None);
	assert_eq!(run.server.transcript_hash(), None);
	assert_eq!(run.server.peer_certificate(), None);
	Ok(())
}

/// A reply the same server signed for another handshake fails its signature
/// over this transcript, and the client admits no step after the refusal.
async fn a_refused_reply_leaves_the_client_spent<F: TestFlow>() -> TestResult {
	let Parties { server_identity, client, server, .. } = parties::<F>(PeerAuthentication::Anonymous);
	let mut client = Handshake::client(client);
	let mut server = Handshake::server(server);
	let mut other = Handshake::client(F::client(&server_identity, &create_test_certificate(0xe0)));
	let stray = server.reply(other.start()?).await?;

	client.start()?;

	let refused = client.respond(stray.to_owned()).await;
	assert!(matches!(refused, Err(HandshakeError::SignatureVerificationFailed)));
	assert_eq!(client.phase(), HandshakePhase::Spent);

	let replayed = client.respond(stray).await;
	assert!(matches!(replayed, Err(HandshakeError::InvalidState)));
	assert!(matches!(client.start(), Err(HandshakeError::InvalidState)));
	assert!(matches!(client.complete(), Err(HandshakeError::InvalidState)));
	Ok(())
}

/// The server refuses a closing that another handshake secret sealed, and it
/// admits no step after the refusal.
async fn a_refused_closing_leaves_the_server_spent<F: TestFlow>() -> TestResult {
	let (mut client, mut server) = pair::<F>(PeerAuthentication::Anonymous);
	let other = established::<F>(PeerAuthentication::Anonymous).await;

	server.reply(client.start()?).await?;

	let refused = server.finish(other.run.closing.to_owned()).await;
	assert!(matches!(refused, Err(HandshakeError::SealedClosing(_))));
	assert_eq!(server.phase(), HandshakePhase::Spent);

	let replayed = server.finish(other.run.closing).await;
	assert!(matches!(replayed, Err(HandshakeError::InvalidState)));
	assert!(matches!(server.complete(), Err(HandshakeError::InvalidState)));
	Ok(())
}

/// Both sides of a handshake with an anonymous-client server derive one key
/// schedule: a frame the server seals opens on the client.
async fn both_sides_derive_the_same_keys_anonymously<F: TestFlow>() -> TestResult {
	let Established { client_session, server_session, .. } = established::<F>(PeerAuthentication::Anonymous).await;
	let record = server_session.keys().send().encrypt_next(b"server to client".to_vec())?;
	let mut to_client = record.to_der()?;

	let opened = client_session.into_keys().recv_mut().open(&mut to_client)?;
	assert_eq!(opened, b"server to client");
	Ok(())
}

/// Both sides of a mutually authenticated handshake derive one key schedule:
/// a frame the client seals opens on the server.
async fn both_sides_derive_the_same_keys_under_mutual_authentication<F: TestFlow>() -> TestResult {
	let mutual = PeerAuthentication::mutual_by_expiry();
	let Established { client_session, server_session, .. } = established::<F>(mutual).await;

	let mut record = sealed_record(&client_session);
	let opened = server_session.into_keys().recv_mut().open(&mut record)?;
	assert_eq!(opened, RECORD_PLAINTEXT);
	Ok(())
}

/// A passive observer who records the whole session and later obtains the
/// server's static key recovers the CMS base secret, and the HPKE flow seals
/// nothing to that key. No traffic key the observer derives from what it
/// holds and the recording opens a recorded frame.
async fn a_recorded_session_does_not_open_under_the_server_static_key<F: TestFlow>() -> TestResult {
	let established = established::<F>(PeerAuthentication::Anonymous).await;
	let Established { server_identity, run, client_session, .. } = established;
	let record = sealed_record(&client_session);
	let Recovered { observer, .. } = F::recover(&run, &server_identity).await;

	let attempts = observer.record_attempts(&record);
	let refused: Vec<bool> = attempts
		.iter()
		.map(|attempt| matches!(attempt, Err(TightBeamError::EnvelopeError(EnvelopeError::KeyUnwrap))))
		.collect();
	assert_eq!(refused, vec![true; F::RECORD_ATTEMPTS]);
	Ok(())
}

/// A mutual handshake carries no byte of the client identity in the clear.
/// The wire holds no byte of its certificate, its key identifier, its issuer
/// and serial number, its key, or the signature of its client Finished.
async fn a_mutual_handshake_carries_no_byte_of_the_client_identity<F: TestFlow>() -> TestResult {
	let client_identity = create_issued_test_certificate(0xe1, [0x5a; 16]);
	let recorder = Arc::new(RecordingProvider::new(client_identity.signing_key.to_owned()));
	let run = mutual_run::<F>(&client_identity, Arc::clone(&recorder) as Arc<dyn SigningKeyProvider>).await;
	let certificate = &client_identity.certificate;
	let tbs = &certificate.tbs_certificate;
	let certificate_der = certificate.to_der()?;
	let key_identifier = Skid::of_public_key(&tbs.subject_public_key_info);
	let issuer = tbs.issuer.to_owned();
	let serial_number = tbs.serial_number.to_owned();
	let issuer_and_serial = IssuerAndSerialNumber { issuer, serial_number }.to_der()?;
	let key = tbs.subject_public_key_info.subject_public_key.raw_bytes();
	let parsed_key = PublicKey::<Secp256k1>::from_sec1_bytes(key)?;
	let compressed_key = parsed_key.to_encoded_point(true);
	let signature = recorder.last_signature().ok_or("the client signs its client Finished")?;
	let wire = run.wire_bytes();

	// Positive control: the server read the identity from the closing.
	assert_eq!(run.server.peer_certificate(), Some(certificate));
	assert!(!contains_window(&wire, &certificate_der));
	assert!(!contains_window(&wire, key_identifier.as_bytes()));
	assert!(!contains_window(&wire, &issuer_and_serial));
	assert!(!contains_window(&wire, key));
	assert!(!contains_window(&wire, compressed_key.as_bytes()));
	assert!(!contains_window(&wire, &signature));
	Ok(())
}

/// The identity seals padded, so two certificates whose lengths differ within
/// one padding block close with one length.
async fn two_identities_of_different_lengths_close_with_one_length<F: TestFlow>() -> TestResult {
	let short = create_issued_test_certificate(0xe2, [0x5a]);
	let long = create_issued_test_certificate(0xe3, [0x5a; 20]);
	let short_run = mutual_run::<F>(&short, TestKey::provider(short.signing_key.to_owned())).await;
	let long_run = mutual_run::<F>(&long, TestKey::provider(long.signing_key.to_owned())).await;

	let short_closing = short_run.closing.der();
	let long_closing = long_run.closing.der();
	assert_ne!(short.certificate.to_der()?.len(), long.certificate.to_der()?.len());
	assert_eq!(short_closing.len(), long_closing.len());
	Ok(())
}

/// The length of the padded content the closing of `run` seals.
fn sealed_length<F: TestFlow>(run: &Run<F>) -> usize {
	let closing = run.closing.to_owned().auth_enveloped();
	let closing = closing.expect("a closing is an AuthEnvelopedData");

	let content = closing.value().auth_encrypted_content_info.encrypted_content.as_ref();
	content.expect("the closing carries its content").as_bytes().len()
}

/// The client Finished adds about 440 bytes to the 285-byte test
/// certificate, so an identified closing pads to the 1024-byte floor.
async fn an_identified_closing_pads_to_the_floor<F: TestFlow>() -> TestResult {
	let Parties { client, server, .. } = parties::<F>(PeerAuthentication::mutual_by_expiry());
	let run = run(client, server).await;
	assert_eq!(sealed_length(&run), 1024);
	Ok(())
}

/// A receipt countersignature adds about 620 bytes more, so a budget-bearing
/// identified closing pads past the floor to 1536 bytes.
async fn a_budget_bearing_identified_closing_pads_past_the_floor<F: TestFlow>() -> TestResult {
	let Parties { client, server, .. } = budget_bearing::<F>(ChallengingAuthorizer);
	let run = run(client, server).await;
	assert_eq!(sealed_length(&run), 1536);
	Ok(())
}

/// A recorder that later obtains the server's static key holds no closing
/// key: the closing holds no byte of the certificate, and no closing key the
/// recorder derives opens it. The session is budget-bearing, so the client
/// Finished carries the countersignature inside that seal.
async fn the_client_identity_is_sealed_from_the_server_static_key<F: TestFlow>() -> TestResult {
	let Parties { server_identity, client_identity, client, server } = budget_bearing::<F>(ChallengingAuthorizer);

	let run = run(client, server).await;
	let Recovered { observer, .. } = F::recover(&run, &server_identity).await;
	let sealed = run.closing.der();
	let certificate_der = client_identity.certificate.to_der()?;

	let attempts = observer.closing_attempts(&run.transcript_hash, sealed).await;
	let refused: Vec<bool> = attempts
		.iter()
		.map(|attempt| matches!(attempt, Err(HandshakeError::SealedClosing(_))))
		.collect();
	assert!(!contains_window(sealed, &certificate_der));
	assert_eq!(refused, vec![true; F::CLOSING_ATTEMPTS]);
	Ok(())
}

/// The server of `server` once it replied, beside the closing that a client
/// of `client` answered that reply with.
async fn server_and_closing<F: TestFlow>(
	client: TestClientConfig<F>,
	server: TestServerConfig<F>,
) -> (TestServer<F>, HandshakeMessage) {
	let mut client = Handshake::client(client);
	let mut server = Handshake::server(server);
	let opening = client.start().expect("a fresh client builds its opening");
	let reply = server.reply(opening).await.expect("the server admits the opening");
	let closing = client.respond(reply).await.expect("the client admits the reply");

	(server, closing)
}

/// What the server of `server` answers to the closing of a client of
/// `client`.
async fn closing_outcome<F: TestFlow>(
	client: TestClientConfig<F>,
	server: TestServerConfig<F>,
) -> Result<(), HandshakeError> {
	let (mut server, closing) = server_and_closing::<F>(client, server).await;
	server.finish(closing).await
}

/// Settlement is the last gate of the closing, so a refused settlement drops
/// the handshake secret with the step and leaves nothing to complete or to
/// replay with.
async fn a_refused_settlement_leaves_the_server_spent<F: TestFlow>() -> TestResult {
	let Parties { client, server, .. } = budget_bearing::<F>(RefusingAuthorizer);
	let (mut server, closing) = server_and_closing::<F>(client, server).await;

	let refused = server.finish(closing.to_owned()).await;
	assert!(matches!(refused, Err(HandshakeError::SettlementRejected { .. })));
	assert_eq!(server.phase(), HandshakePhase::Spent);

	let replayed = server.finish(closing).await;
	assert!(matches!(replayed, Err(HandshakeError::InvalidState)));
	assert!(matches!(server.complete(), Err(HandshakeError::InvalidState)));
	Ok(())
}

/// An approver that pays each receipt, as [`PayingApprover`] does, and
/// counts its calls.
///
/// Each embedder supplies its own approver as its payment policy, so a test
/// of when the client consults the approver holds this double.
#[derive(Default)]
struct CountingApprover(AtomicUsize);

impl CountingApprover {
	/// The number of receipts this approver answered.
	fn calls(&self) -> usize {
		self.0.load(Ordering::SeqCst)
	}
}

impl ReceiptApprover for CountingApprover {
	fn approve<'a>(
		&'a self,
		receipt: &'a SessionReceipt,
	) -> MaybeSendFuture<'a, Result<Option<OctetString>, ApprovalRefusal>> {
		self.0.fetch_add(1, Ordering::SeqCst);
		PayingApprover.approve(receipt)
	}
}

/// `reply` with its server Finished replaced by a tag under another secret,
/// as an on-path party would forge it. The signature covers no unsigned
/// attribute, so it still verifies.
fn with_forged_server_finished(reply: HandshakeMessage) -> HandshakeMessage {
	let forged = finished_attribute(&fixture_confirmation());
	reply.with_unsigned(|carried| [without_attribute(carried, HANDSHAKE_KEY_CONFIRMATION), vec![forged]].concat())
}

/// `reply` with the session receipt of `other`, the reply of another
/// session, in place of its own. The signature covers no unsigned attribute,
/// so it still verifies.
fn with_receipt_of(reply: HandshakeMessage, other: HandshakeMessage) -> HandshakeMessage {
	let other = other.signed().expect("a reply is a SignedData").into_value();
	let signer = other.sole_signer().expect("a reply has one signer");
	let mut carried = signer.unsigned_attrs.iter().flat_map(|attributes| attributes.iter());
	let receipt = carried.find(|attribute| attribute.oid == SESSION_RECEIPT);
	let receipt = receipt.expect("a budget-bearing reply carries its receipt").to_owned();

	reply.with_unsigned(|carried| [without_attribute(carried, SESSION_RECEIPT), vec![receipt]].concat())
}

/// A budget-bearing client of flow `F` whose approver is `approver`, and the
/// server it opened to, with that server's reply.
async fn budget_bearing_reply<F: TestFlow>(approver: &Arc<CountingApprover>) -> (TestClient<F>, HandshakeMessage) {
	let authorizer = Arc::new(ChallengingAuthorizer);
	let parties = parties::<F>(PeerAuthentication::mutual_by_expiry());
	let Parties { client, server, .. } = parties.budget_bearing(approver.to_owned(), authorizer);

	let mut client = Handshake::client(client);
	let mut server = Handshake::server(server);
	let opening = client.start().expect("a fresh client builds its opening");
	let reply = server.reply(opening).await.expect("the server admits the opening");

	(client, reply)
}

/// The client confirms the server Finished before it reads the receipt, so
/// it refuses a reply whose Finished fails before the approver runs, and the
/// approver sees no call.
async fn a_reply_whose_server_finished_fails_never_reaches_the_approver<F: TestFlow>() -> TestResult {
	let approver = Arc::new(CountingApprover::default());
	let (mut client, reply) = budget_bearing_reply::<F>(&approver).await;

	let refused = client.respond(with_forged_server_finished(reply)).await;
	assert!(matches!(refused, Err(HandshakeError::KeyConfirmationFailed)));
	assert_eq!(approver.calls(), 0);
	Ok(())
}

/// A control of the test above: the honest reply of the same session reaches
/// the approver once.
async fn an_honest_budget_bearing_reply_reaches_the_approver_once<F: TestFlow>() -> TestResult {
	let approver = Arc::new(CountingApprover::default());
	let (mut client, reply) = budget_bearing_reply::<F>(&approver).await;

	client.respond(reply).await?;
	assert_eq!(approver.calls(), 1);
	Ok(())
}

/// The client confirms the server Finished before it verifies the receipt, so
/// when a reply's Finished fails beside the receipt of another session, the
/// client refuses the reply for its Finished.
async fn a_forged_server_finished_is_refused_before_the_receipt_is_read<F: TestFlow>() -> TestResult {
	let approver = Arc::new(CountingApprover::default());
	let (mut client, reply) = budget_bearing_reply::<F>(&approver).await;
	let (_, other) = budget_bearing_reply::<F>(&approver).await;
	let foreign = with_receipt_of(reply, other);
	let forged = with_forged_server_finished(foreign);

	let refused = client.respond(forged).await;
	assert!(matches!(refused, Err(HandshakeError::KeyConfirmationFailed)));
	Ok(())
}

/// A control of the test above: the receipt check refuses the receipt of
/// another session beside an honest server Finished.
async fn a_reply_beside_the_receipt_of_another_session_is_refused<F: TestFlow>() -> TestResult {
	let approver = Arc::new(CountingApprover::default());
	let (mut client, reply) = budget_bearing_reply::<F>(&approver).await;
	let (_, other) = budget_bearing_reply::<F>(&approver).await;

	let refused = client.respond(with_receipt_of(reply, other)).await;
	assert!(matches!(refused, Err(HandshakeError::ReceiptMismatch)));
	Ok(())
}

/// A server that demands no client certificate verifies the proof of an
/// offered one and records no peer.
async fn an_anonymous_server_records_no_peer<F: TestFlow>() -> TestResult {
	let Established { server_session, .. } = established::<F>(PeerAuthentication::Anonymous).await;
	assert_eq!(server_session.peer(), None);
	Ok(())
}

/// A mutual server records the certificate every validator accepted.
async fn a_mutual_server_records_the_accepted_peer<F: TestFlow>() -> TestResult {
	let Parties { client_identity, client, mut server, .. } = parties::<F>(PeerAuthentication::Anonymous);
	let pinned = DirectTrustValidator::default().with_trust_chain([client_identity.certificate.to_owned()])?;
	server.peer_authentication = PeerAuthentication::mutual_with(pinned);

	let mut run = run(client, server).await;
	let session = run.server.complete()?;
	assert_eq!(session.peer(), Some(&client_identity.certificate));
	Ok(())
}

/// A mutual server refuses a closing whose certificate a validator refuses.
/// A direct-trust validator with no anchor refuses every certificate.
async fn a_mutual_server_refuses_a_refused_certificate<F: TestFlow>() -> TestResult {
	let Parties { client, server, .. } = parties::<F>(PeerAuthentication::mutual_with(DirectTrustValidator::default()));

	let refusal = closing_outcome::<F>(client, server).await;
	assert!(matches!(refusal, Err(HandshakeError::CertificateValidationError(_))));
	Ok(())
}

/// The configuration of a server of flow `F` that holds `identity` and
/// demands a client certificate that `validator` accepts.
fn mutual_server<F: TestFlow>(
	identity: &TestCmsServer,
	validator: Arc<dyn CertificateValidation>,
) -> TestServerConfig<F> {
	let mut server = F::server(identity);
	server.peer_authentication = PeerAuthentication::Anonymous.and(validator);
	server
}

/// A client of flow `F` that presents `client`, beside a mutual server whose
/// one client validator pins `pinned` alone.
fn pinning_mutual<F: TestFlow>(
	client: &HandshakeCertificate,
	pinned: &Certificate,
) -> (TestClientConfig<F>, TestServerConfig<F>) {
	let server_identity = create_test_server();
	let server = mutual_server::<F>(&server_identity, pin_of(pinned));
	(F::client(&server_identity, client), server)
}

/// A pin reads no validity period, so a mutual server reads it itself and
/// refuses an expired certificate that its pin accepts.
async fn a_mutual_server_refuses_an_expired_certificate_its_pin_accepts<F: TestFlow>() -> TestResult {
	let client_identity = create_expired_test_certificate(0xe4);
	let (client, server) = pinning_mutual::<F>(&client_identity, &client_identity.certificate);

	let refusal = closing_outcome::<F>(client, server).await;
	assert!(matches!(refusal, Err(HandshakeError::CertificateValidationError(Expired))));
	Ok(())
}

/// A mutual server reads the validity period of a client certificate on its
/// own clock, so a clock past the end of the period refuses a client that the
/// host clock reads as current.
async fn a_mutual_server_reads_the_validity_period_on_its_own_clock<F: TestFlow>() -> TestResult {
	let client_identity = create_windowed_test_certificate(0xe5);
	let (client, server) = pinning_mutual::<F>(&client_identity, &client_identity.certificate);
	let server = server.with_clock(TestCertificate::clock_past_validity());

	let refusal = closing_outcome::<F>(client, server).await;
	assert!(matches!(refusal, Err(HandshakeError::CertificateValidationError(Expired))));
	Ok(())
}

/// A mutual server reads the validity period before its validators, so it
/// refuses an expired certificate that its pin also refuses as [`Expired`].
async fn a_mutual_server_reads_the_validity_period_before_its_validators<F: TestFlow>() -> TestResult {
	let client_identity = create_expired_test_certificate(0xe6);
	let (client, server) = pinning_mutual::<F>(&client_identity, &create_test_certificate(0xe7).certificate);

	let refusal = closing_outcome::<F>(client, server).await;
	assert!(matches!(refusal, Err(HandshakeError::CertificateValidationError(Expired))));
	Ok(())
}

/// A server takes the first profile it runs that the client also offered,
/// and both sides fix that profile.
async fn both_sides_fix_the_offered_profile_the_server_runs<F: TestFlow>() -> TestResult {
	let Parties { mut client, server, .. } = parties::<F>(PeerAuthentication::Anonymous);
	client.security_offer = Some(SecurityOffer::new(vec![foreign_profile(), create_default_test_profile()]));

	let run = run(client, server).await;
	assert_eq!(run.client.selected_profile(), Some(create_default_test_profile()));
	assert_eq!(run.server.selected_profile(), Some(create_default_test_profile()));
	Ok(())
}

/// A server refuses an offer that names no profile it runs, so it never
/// falls back to its own choice past an offer. The refused opening spends the
/// server.
async fn a_server_refuses_an_offer_that_names_no_profile_it_runs<F: TestFlow>() -> TestResult {
	let Parties { mut client, server, .. } = parties::<F>(PeerAuthentication::Anonymous);
	client.security_offer = Some(SecurityOffer::new(vec![foreign_profile()]));

	let mut client = Handshake::client(client);
	let mut server = Handshake::server(server);

	let refusal = server.reply(client.start()?).await;
	let expected = NegotiationError::NoMutualProfile;
	assert!(matches!(refusal, Err(HandshakeError::NegotiationError(error)) if error == expected));
	assert_eq!(server.phase(), HandshakePhase::Spent);
	Ok(())
}

/// The multiplexing settings that the client and the server of an anonymous
/// handshake of flow `F` fix, in that order, once the client offers
/// `client_offer` and the server advertises `server_offer`.
async fn negotiated_mux<F: TestFlow>(
	client_offer: Option<TransportOffer>,
	server_offer: Option<TransportOffer>,
) -> (Option<MuxSettings>, Option<MuxSettings>) {
	let Parties { mut client, mut server, .. } = parties::<F>(PeerAuthentication::Anonymous);
	client.transport_offer = client_offer;
	server.transport = server_offer;

	let run = run(client, server).await;
	(run.client.negotiated_mux(), run.server.negotiated_mux())
}

/// Multiplexing negotiates when the client offers it and the server enables
/// it, and the cap each side advertises bounds the streams its peer initiates.
async fn multiplexing_negotiates_when_offered_and_enabled<F: TestFlow>() -> TestResult {
	let (offer, advertisement) = (TransportOffer::mux(8), TransportOffer::mux(4));
	let (client, server) = negotiated_mux::<F>(Some(offer), Some(advertisement)).await;

	let caps = |mux: MuxSettings| (mux.local_initiated_cap(), mux.peer_initiated_cap());
	assert_eq!(server.map(caps), Some((8, 4)));
	assert_eq!(client.map(caps), Some((4, 8)));
	Ok(())
}

/// A session stays single-flight when the client offers multiplexing and the
/// server leaves it disabled.
async fn an_offer_alone_stays_single_flight<F: TestFlow>() -> TestResult {
	let negotiated = negotiated_mux::<F>(Some(TransportOffer::mux(8)), None).await;
	assert_eq!(negotiated, (None, None));
	Ok(())
}

/// A session stays single-flight when the server enables multiplexing and
/// the client leaves it out of its offer.
async fn a_local_advertisement_alone_stays_single_flight<F: TestFlow>() -> TestResult {
	let negotiated = negotiated_mux::<F>(None, Some(TransportOffer::mux(4))).await;
	assert_eq!(negotiated, (None, None));
	Ok(())
}

/// A client of flow `F` that admits the server of `chained`, beside that
/// server, which presents its intermediate. The CMS client's store holds the
/// root alone.
fn chained_pair<F: TestFlow>(chained: &ChainedTestServer) -> (TestClient<F>, TestServer<F>) {
	let client = F::client(&chained.identity, &create_test_certificate(0xe8));
	let server = F::server_presenting(&chained.identity, chained.signing_identity());
	(Handshake::client(client), Handshake::server(server))
}

/// A reply carries the intermediate its server presents beside the signing
/// certificate (RFC 5652 §5.1).
async fn a_reply_carries_the_intermediate_its_server_presents<F: TestFlow>() -> TestResult {
	let chained = ChainedTestServer::fixed();
	let (mut client, mut server) = chained_pair::<F>(&chained);
	let reply = server.reply(client.start()?).await?;
	assert!(reply.presented_certificates().contains(&chained.intermediate));
	Ok(())
}

/// What a client of flow `F` answers to the reply of the server of `chained`
/// once that reply presents `issuers` above the signing certificate, in place
/// of the path the server sent.
async fn answer_presenting<F: TestFlow>(
	chained: &ChainedTestServer,
	issuers: impl IntoIterator<Item = Certificate>,
) -> Result<HandshakeMessage, HandshakeError> {
	let (mut client, mut server) = chained_pair::<F>(chained);
	let opening = client.start().expect("a fresh client builds its opening");
	let reply = server.reply(opening).await.expect("the server admits the opening");
	let leaf = chained.identity.signing.to_owned();

	client.respond(reply.with_presented([leaf].into_iter().chain(issuers))).await
}

/// A reply whose intermediate was swapped for its twin of one subject and one
/// key still holds a valid path, and the transcript binds the `certificates`
/// field the server sent, so the reply's signature fails.
async fn a_reply_whose_intermediate_was_swapped_is_refused<F: TestFlow>() -> TestResult {
	let chained = ChainedTestServer::fixed();
	let issuers = [chained.intermediate_twin()];

	let refused = answer_presenting::<F>(&chained, issuers).await;
	assert!(matches!(refused, Err(HandshakeError::SignatureVerificationFailed)));
	Ok(())
}

/// The client refuses a reply of nine certificates before it reads any
/// certificate of the reply or checks any signature (CWE-770).
async fn a_reply_of_nine_certificates_is_refused<F: TestFlow>() -> TestResult {
	let chained = ChainedTestServer::fixed();
	let issuers = [vec![chained.intermediate.to_owned()], TestCertificate::strangers(7)].concat();

	let refused = answer_presenting::<F>(&chained, issuers).await;
	assert!(matches!(
		refused,
		Err(HandshakeError::CertificateValidationError(PathLenExceeded))
	));
	Ok(())
}

/// The client refuses a reply whose issuers lead the walk back to a
/// certificate of its path, before it reads the reply's signature.
async fn a_reply_whose_path_returns_to_itself_is_refused<F: TestFlow>() -> TestResult {
	let chained = ChainedTestServer::fixed();
	let issuers = TestCertificate::looping_issuers(&chained.intermediate);

	let refused = answer_presenting::<F>(&chained, issuers).await;
	assert!(matches!(
		refused,
		Err(HandshakeError::CertificateValidationError(PathCycle { .. }))
	));
	Ok(())
}

/// The client refuses a reply that carries two certificates of the subject
/// of the signing certificate's issuer, because the walk cannot tell which
/// one issued it.
async fn a_reply_with_two_issuers_of_one_subject_is_refused<F: TestFlow>() -> TestResult {
	let chained = ChainedTestServer::fixed();
	let issuers = [chained.intermediate.to_owned(), chained.intermediate_twin()];

	let refused = answer_presenting::<F>(&chained, issuers).await;
	assert!(matches!(
		refused,
		Err(HandshakeError::CertificateValidationError(AmbiguousIssuer { .. }))
	));
	Ok(())
}

/// A client of flow `F` that presents the leaf of `chain` with `issuers`
/// above it, beside a mutual server whose one client validator is a store
/// that holds the root of `chain` alone.
fn root_anchored_mutual<F: TestFlow>(
	chain: &TestCertificateChain,
	issuers: [Certificate; 1],
) -> (TestClientConfig<F>, TestServerConfig<F>) {
	let identity = TestIdentity::presenting(chain.leaf.to_owned(), &chain.leaf_key).with_chain(issuers);
	let identity = identity.expect("the leaf names the issuer above it");
	let server_identity = create_test_server();
	let client = F::client_presenting(&server_identity, identity);

	let store = TestStore::holding([chain.root.to_owned()]);
	let server = mutual_server::<F>(&server_identity, Arc::new(store));
	(client, server)
}

/// A mutual server whose store holds the root alone admits a client whose
/// certificate an intermediate issued, because the client Finished presents
/// the intermediate and the server validates that path to the root
/// (RFC 5280 §6.1).
async fn a_root_only_server_admits_a_presented_intermediate<F: TestFlow>() -> TestResult {
	let chain = TestCertificate::insecure_fixed_chain()?;
	let (client, server) = root_anchored_mutual::<F>(&chain, [chain.intermediate.to_owned()]);

	let mut run = run(client, server).await;
	let session = run.server.complete()?;
	assert_eq!(session.peer(), Some(&chain.leaf));
	Ok(())
}

/// A mutual server whose store holds the root alone refuses a client whose
/// Finished presents another authority of the intermediate's name in its
/// place, because that path reaches no anchor of the store.
async fn a_root_only_server_refuses_a_swapped_intermediate<F: TestFlow>() -> TestResult {
	let chain = TestCertificate::insecure_fixed_chain()?;
	let impostor = TestCertificate::authority(&TestKey::fixed(0x24), "Intermediate")?;
	let (client, server) = root_anchored_mutual::<F>(&chain, [impostor]);

	let refused = closing_outcome::<F>(client, server).await;
	assert!(matches!(
		refused,
		Err(HandshakeError::CertificateValidationError(CertificateNotTrusted))
	));
	Ok(())
}

over_each_flow! {
	the_phase_follows_the_steps,
	an_illegal_client_step_leaves_the_phase_unchanged,
	an_illegal_server_step_leaves_the_phase_unchanged,
	a_step_after_the_agreement_is_refused,
	a_step_after_completion_is_refused,
	completion_takes_what_the_handshake_agreed,
	a_refused_reply_leaves_the_client_spent,
	a_refused_closing_leaves_the_server_spent,
	both_sides_derive_the_same_keys_anonymously,
	both_sides_derive_the_same_keys_under_mutual_authentication,
	a_recorded_session_does_not_open_under_the_server_static_key,
	a_mutual_handshake_carries_no_byte_of_the_client_identity,
	two_identities_of_different_lengths_close_with_one_length,
	an_identified_closing_pads_to_the_floor,
	a_budget_bearing_identified_closing_pads_past_the_floor,
	the_client_identity_is_sealed_from_the_server_static_key,
	a_refused_settlement_leaves_the_server_spent,
	a_reply_whose_server_finished_fails_never_reaches_the_approver,
	an_honest_budget_bearing_reply_reaches_the_approver_once,
	a_forged_server_finished_is_refused_before_the_receipt_is_read,
	a_reply_beside_the_receipt_of_another_session_is_refused,
	an_anonymous_server_records_no_peer,
	a_mutual_server_records_the_accepted_peer,
	a_mutual_server_refuses_a_refused_certificate,
	a_mutual_server_refuses_an_expired_certificate_its_pin_accepts,
	a_mutual_server_reads_the_validity_period_on_its_own_clock,
	a_mutual_server_reads_the_validity_period_before_its_validators,
	both_sides_fix_the_offered_profile_the_server_runs,
	a_server_refuses_an_offer_that_names_no_profile_it_runs,
	multiplexing_negotiates_when_offered_and_enabled,
	an_offer_alone_stays_single_flight,
	a_local_advertisement_alone_stays_single_flight,
	a_reply_carries_the_intermediate_its_server_presents,
	a_reply_whose_intermediate_was_swapped_is_refused,
	a_reply_of_nine_certificates_is_refused,
	a_reply_whose_path_returns_to_itself_is_refused,
	a_reply_with_two_issuers_of_one_subject_is_refused,
	a_root_only_server_admits_a_presented_intermediate,
	a_root_only_server_refuses_a_swapped_intermediate,
}

/// A CMS client whose store holds the root alone admits a signing certificate
/// under an intermediate the reply presents, because it validates the
/// presented path to that root (RFC 5280 §6.1).
#[cfg(feature = "transport-cms")]
#[tokio::test]
async fn a_cms_client_of_the_root_alone_admits_a_presented_intermediate() -> TestResult {
	let chained = ChainedTestServer::fixed();
	let (mut client, mut server) = chained_pair::<Cms>(&chained);

	let reply = server.reply(client.start()?).await?;
	client.respond(reply).await?;
	assert_eq!(client.peer_certificate(), Some(&chained.identity.signing));
	Ok(())
}

/// An HPKE client whose trust validates each presented path to the root of
/// `chained` alone.
#[cfg(feature = "transport-hpke")]
fn root_anchored_hpke_client(chained: &ChainedTestServer) -> TestClient<Hpke> {
	let trust = LearnedTrust::anchored(Arc::new(chained.identity.store()));
	let config = ClientConfig::new(HpkeClientSettings::new(trust), KeyPurposes::HOUSE);
	Handshake::client(config.expect("an anonymous client serves the client role"))
}

/// An HPKE client whose store holds the root alone completes a handshake with
/// a server whose signing certificate an intermediate issued, because it
/// validates the path the reply presents to that root (RFC 5280 §6.1).
#[cfg(feature = "transport-hpke")]
#[tokio::test]
async fn an_hpke_client_of_the_root_alone_completes_under_a_presented_intermediate() -> TestResult {
	let chained = ChainedTestServer::fixed();
	let mut client = root_anchored_hpke_client(&chained);
	let mut server = Handshake::server(Hpke::server_presenting(&chained.identity, chained.signing_identity()));

	let reply = server.reply(client.start()?).await?;
	let closing = client.respond(reply).await?;
	let admitted = client.peer_certificate().cloned();
	server.finish(closing).await?;
	client.complete()?;
	server.complete()?;
	assert_eq!(admitted.as_ref(), Some(&chained.identity.signing));
	Ok(())
}

/// An HPKE client whose store holds the root alone refuses a server that
/// presents its signing certificate without the intermediate, because that
/// path stops below its anchor.
#[cfg(feature = "transport-hpke")]
#[tokio::test]
async fn an_hpke_client_of_the_root_alone_refuses_a_path_short_of_its_anchor() -> TestResult {
	let chained = ChainedTestServer::fixed();
	let mut client = root_anchored_hpke_client(&chained);
	let mut server = Handshake::server(Hpke::server(&chained.identity));

	let reply = server.reply(client.start()?).await?;
	let refused = client.respond(reply).await;
	assert!(matches!(
		refused,
		Err(HandshakeError::CertificateValidationError(CertificateNotTrusted))
	));
	Ok(())
}

/// A CMS client's session keeps the key-agreement certificate its opening
/// sealed to, which a rekey compares the server ephemeral with.
#[cfg(all(feature = "transport-cms", mux_rekey))]
#[tokio::test]
async fn a_cms_client_session_keeps_the_key_agreement_certificate() {
	let established = established::<Cms>(PeerAuthentication::Anonymous).await;
	let session_peer = established.client_session.session_peer();
	let kept = session_peer.map(Arc::as_ref).and_then(SessionPeer::key_agreement);
	assert_eq!(kept, Some(&established.server_identity.key_agreement));
}

/// The base secret of the CMS opening crosses the wire only sealed, so no
/// leg carries its bytes in the clear (CWE-311).
#[cfg(feature = "transport-cms")]
#[tokio::test]
async fn the_base_secret_crosses_the_wire_only_sealed() -> TestResult {
	let Parties { server_identity, client, server, .. } = parties::<Cms>(PeerAuthentication::Anonymous);
	let run = run(client, server).await;

	let Recovered { base, .. } = Cms::recover(&run, &server_identity).await;
	let base = base.ok_or("the CMS opening carries a base secret")?;
	assert!(!contains_window(run.wire_bytes(), &base));
	Ok(())
}

/// Two CMS handshakes draw two base secrets, so no session shares its key
/// schedule input with another (CWE-321).
#[cfg(feature = "transport-cms")]
#[tokio::test]
async fn two_handshakes_draw_different_base_secrets() {
	let first = established::<Cms>(PeerAuthentication::Anonymous).await;
	let second = established::<Cms>(PeerAuthentication::Anonymous).await;

	let first = Cms::recover(&first.run, &first.server_identity).await;
	let second = Cms::recover(&second.run, &second.server_identity).await;
	assert_ne!(first.base, second.base);
}

/// The configuration of the CMS server of `server_identity` after its
/// authority issued its signing certificate again, to the same subject, for a
/// fresh key, beside that certificate.
#[cfg(feature = "transport-cms")]
fn rotated_cms_server(server_identity: &TestCmsServer) -> (TestServerConfig<Cms>, Certificate) {
	let (pair, rotated) = server_identity.rotated_pair();
	let profiles = SupportedProfiles::from(create_default_test_profile());
	let config = ServerConfig::new(CmsServerSettings, pair, profiles, KeyPurposes::HOUSE);
	(config.expect("a rotated test server pair serves the server role"), rotated)
}

/// A CMS server policy reads the pinned key-agreement certificate, so a pin
/// of it admits the server after the server rotates its signing certificate.
#[cfg(feature = "transport-cms")]
#[tokio::test]
async fn a_cms_key_agreement_pin_admits_a_rotated_signing_certificate() -> TestResult {
	let server_identity = create_test_server();
	let pin = pin_of(&server_identity.key_agreement);
	let client = Cms::client(&server_identity, &create_test_certificate(0xe9)).with_server_policy([pin]);
	let (server, rotated) = rotated_cms_server(&server_identity);

	let mut client = Handshake::client(client);
	let mut server = Handshake::server(server);
	let reply = server.reply(client.start()?).await?;
	client.respond(reply).await?;
	assert_eq!(client.peer_certificate(), Some(&rotated));
	Ok(())
}

/// A CMS server policy that refuses the pinned key-agreement certificate
/// refuses the server before the client seals its opening to it.
#[cfg(feature = "transport-cms")]
#[test]
fn a_cms_policy_that_refuses_the_pinned_certificate_builds_no_opening() {
	let Parties { server_identity, client, .. } = parties::<Cms>(PeerAuthentication::Anonymous);
	let pin = pin_of(&server_identity.signing);
	let mut client = Handshake::client(client.with_server_policy([pin]));

	let refused = client.start();
	assert!(matches!(
		refused,
		Err(HandshakeError::CertificateValidationError(CertificateNotPinned))
	));
}

/// An HPKE server policy that pins another server refuses the server the
/// reply names, though the client's trust admits it.
#[cfg(feature = "transport-hpke")]
#[tokio::test]
async fn an_hpke_pin_refuses_another_server() -> TestResult {
	let Parties { client, server, .. } = parties::<Hpke>(PeerAuthentication::Anonymous);
	let pin = pin_of(&create_test_certificate(0xea).certificate);
	let mut client = Handshake::client(client.with_server_policy([pin]));
	let mut server = Handshake::server(server);

	let reply = server.reply(client.start()?).await?;
	let refused = client.respond(reply).await;
	assert!(matches!(
		refused,
		Err(HandshakeError::CertificateValidationError(CertificateNotPinned))
	));
	Ok(())
}
