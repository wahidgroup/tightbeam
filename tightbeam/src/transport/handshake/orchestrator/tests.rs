//! These tests run over both flows and cover the step order, the phases, the
//! key schedule, and the decisions on admission, negotiation, and settlement.
//!
//! Each test body is generic over [`TestFlow`], and [`over_each_flow`] runs
//! it once per protocol. A test of the messages of one protocol sits beside
//! that flow.

use std::error::Error;
use std::sync::Arc;

use crate::cms::cert::IssuerAndSerialNumber;
use crate::crypto::cms::EnvelopeError;
use crate::crypto::hash::Sha3_256;
use crate::crypto::key::SigningKeyProvider;
use crate::crypto::profiles::SecurityProfileDesc;
use crate::crypto::sign::ecdsa::k256::Secp256k1;
use crate::crypto::sign::elliptic_curve::sec1::ToEncodedPoint;
use crate::crypto::sign::elliptic_curve::PublicKey;
use crate::crypto::x509::error::CertificateValidationError::Expired;
use crate::crypto::x509::policy::{DirectTrustValidator, ExpiryValidator, RuntimeCertificatePinning};
use crate::crypto::x509::utils::Skid;
use crate::der::Encode;
use crate::oids::AES_128_GCM;
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::negotiation::{MuxSettings, NegotiationError, SecurityOffer, TransportOffer};
use crate::transport::handshake::tests::*;
use crate::transport::handshake::{Handshake, HandshakeMessage, HandshakePhase, PeerAuthentication};
use crate::TightBeamError;

#[cfg(feature = "transport-cms")]
use crate::transport::handshake::Cms;
#[cfg(feature = "transport-hpke")]
use crate::transport::handshake::Hpke;

/// The reply a fresh handshake of flow `F` produces, which no other handshake
/// admits.
async fn stray_reply<F: TestFlow>() -> HandshakeMessage {
	let (mut client, mut server) = pair::<F>(PeerAuthentication::Anonymous);
	let opening = client.start().expect("a fresh client builds its opening");
	server.reply(opening).await.expect("the server admits the opening")
}

/// A descriptor that names an AEAD the default provider does not run.
fn foreign_profile() -> SecurityProfileDesc {
	SecurityProfileDesc { aead: Some(AES_128_GCM), ..create_default_test_profile() }
}

async fn the_phase_follows_the_steps<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let (mut client, mut server) = pair::<F>(mutual_with(ExpiryValidator));
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

async fn an_illegal_client_step_leaves_the_phase_unchanged<F: TestFlow>() -> Result<(), Box<dyn Error>> {
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

async fn an_illegal_server_step_leaves_the_phase_unchanged<F: TestFlow>() -> Result<(), Box<dyn Error>> {
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

/// A handshake that agreed refuses every further step that reads or builds a
/// leg, and each refusal leaves what it agreed in place.
async fn a_step_after_the_agreement_is_refused<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let Parties { client, server, .. } = parties::<F>(PeerAuthentication::Anonymous);
	let Run { opening, reply, closing, mut client, mut server, .. } = run(client, server).await;

	let answered = client.respond(reply).await;
	assert!(matches!(client.start(), Err(HandshakeError::InvalidState)));
	assert!(matches!(answered, Err(HandshakeError::InvalidState)));
	assert_eq!(client.phase(), HandshakePhase::Agreed);

	let reopened = server.reply(opening).await;
	let reclosed = server.finish(closing).await;
	assert!(matches!(reopened, Err(HandshakeError::InvalidState)));
	assert!(matches!(reclosed, Err(HandshakeError::InvalidState)));
	assert_eq!(server.phase(), HandshakePhase::Agreed);

	// Both sides still complete.
	client.complete()?;
	server.complete()?;
	Ok(())
}

/// A completed handshake is terminal: it refuses every step that reads or
/// builds a leg, and each refusal leaves it completed.
async fn a_step_after_completion_is_refused<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let Established { run, .. } = established::<F>(PeerAuthentication::Anonymous).await;
	let Run { opening, reply, closing, mut client, mut server, .. } = run;

	let answered = client.respond(reply).await;
	assert!(matches!(client.start(), Err(HandshakeError::InvalidState)));
	assert!(matches!(answered, Err(HandshakeError::InvalidState)));
	assert_eq!(client.phase(), HandshakePhase::Completed);

	let reopened = server.reply(opening).await;
	let reclosed = server.finish(closing).await;
	assert!(matches!(reopened, Err(HandshakeError::InvalidState)));
	assert!(matches!(reclosed, Err(HandshakeError::InvalidState)));
	assert_eq!(server.phase(), HandshakePhase::Completed);
	Ok(())
}

/// Completion moves the handshake secret out, so a second completion has
/// nothing to derive from and the accessors answer nothing.
async fn completion_takes_what_the_handshake_agreed<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let Parties { client, server, .. } = parties::<F>(mutual_with(ExpiryValidator));
	let mut run = run(client, server).await;
	assert!(run.client.selected_profile().is_some());
	assert!(run.client.peer_certificate().is_some());
	assert!(run.server.transcript_hash().is_some());
	assert!(run.server.peer_certificate().is_some());

	run.client.complete()?;
	run.server.complete()?;
	assert!(matches!(run.client.complete(), Err(HandshakeError::InvalidState)));
	assert!(matches!(run.server.complete(), Err(HandshakeError::InvalidState)));
	assert!(run.client.selected_profile().is_none());
	assert!(run.client.peer_certificate().is_none());
	assert!(run.server.transcript_hash().is_none());
	assert!(run.server.peer_certificate().is_none());
	Ok(())
}

/// A reply the same server signed for another handshake fails its signature
/// over this transcript, and the client admits no step after the refusal.
async fn a_refused_reply_leaves_the_client_spent<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let Parties { server_identity, client, server, .. } = parties::<F>(PeerAuthentication::Anonymous);
	let mut client = Handshake::client(client);
	let mut server = Handshake::server(server);
	let mut other = Handshake::client(F::client(&server_identity, &create_test_certificate()));
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

/// A closing from another handshake is refused, and the server admits no
/// step after the refusal: another handshake secret sealed it.
async fn a_refused_closing_leaves_the_server_spent<F: TestFlow>() -> Result<(), Box<dyn Error>> {
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
async fn both_sides_derive_the_same_keys_anonymously<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let Established { client_session, server_session, .. } = established::<F>(PeerAuthentication::Anonymous).await;

	let record = server_session.keys().send().encrypt_next(b"server to client".to_vec())?;
	let mut to_client = record.to_der()?;
	let opened = client_session.keys().recv().open(&mut to_client)?;
	assert_eq!(opened, b"server to client");
	Ok(())
}

/// Both sides of a mutually authenticated handshake derive one key schedule:
/// a frame the client seals opens on the server.
async fn both_sides_derive_the_same_keys_under_mutual_authentication<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let Established { client_session, server_session, .. } = established::<F>(mutual_with(ExpiryValidator)).await;

	let mut record = sealed_record(&client_session)?;
	let opened = server_session.keys().recv().open(&mut record)?;
	assert_eq!(opened, RECORD_PLAINTEXT);
	Ok(())
}

/// A passive observer who records the whole session and later obtains the
/// server's static key recovers the CMS base secret, and the HPKE flow seals
/// nothing to that key. No traffic key the observer derives from what it
/// holds and the recording opens a recorded frame.
async fn a_recorded_session_does_not_open_under_the_server_static_key<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let established = established::<F>(PeerAuthentication::Anonymous).await;
	let Established { server_identity, run, client_session, .. } = established;

	let record = sealed_record(&client_session)?;
	let Recovered { observer, .. } = F::recover(&run, &server_identity).await;

	let attempts = observer.record_attempts(&record)?;
	let mut outcomes = attempts.iter();
	assert_eq!(attempts.len(), F::RECORD_ATTEMPTS);
	assert!(outcomes.all(|attempt| matches!(attempt, Err(TightBeamError::EnvelopeError(EnvelopeError::KeyUnwrap)))));
	Ok(())
}

/// A mutual handshake carries no byte of the client identity in clear: not
/// its certificate, its key identifier, its issuer and serial number, its key,
/// or the signature of its client Finished.
async fn a_mutual_handshake_carries_no_byte_of_the_client_identity<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let client_identity = create_issued_test_certificate([0x5a; 16]);
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
async fn two_identities_of_different_lengths_close_with_one_length<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let short = create_issued_test_certificate([0x5a]);
	let long = create_issued_test_certificate([0x5a; 20]);
	let short_run = mutual_run::<F>(&short, into_provider(short.signing_key.to_owned())).await;
	let long_run = mutual_run::<F>(&long, into_provider(long.signing_key.to_owned())).await;

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
async fn an_identified_closing_pads_to_the_floor<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let Parties { client, server, .. } = parties::<F>(mutual_with(ExpiryValidator));
	let run = run(client, server).await;
	assert_eq!(sealed_length(&run), 1024);
	Ok(())
}

/// A receipt countersignature adds about 620 bytes more, so a budget-bearing
/// identified closing pads past the floor to 1536 bytes.
async fn a_budget_bearing_identified_closing_pads_past_the_floor<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let Parties { mut client, mut server, .. } = parties::<F>(mutual_with(ExpiryValidator));
	client.transport_offer = Some(budget_offer());
	client.receipt_approver = Some(Arc::new(PayingApprover));
	server.transport = Some(budget_offer());
	server.transport_authorizer = Some(Arc::new(ChallengingAuthorizer));

	let run = run(client, server).await;
	assert_eq!(sealed_length(&run), 1536);
	Ok(())
}

/// A recorder that later obtains the server's static key holds no closing
/// key: the closing holds no byte of the certificate, and no closing key the
/// recorder derives opens it. The session is budget-bearing, so the client
/// Finished carries the countersignature inside that seal.
async fn the_client_identity_is_sealed_from_the_server_static_key<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let mutual = mutual_with(ExpiryValidator);
	let Parties { server_identity, client_identity, mut client, mut server } = parties::<F>(mutual);
	client.transport_offer = Some(budget_offer());
	client.receipt_approver = Some(Arc::new(PayingApprover));
	server.transport = Some(budget_offer());
	server.transport_authorizer = Some(Arc::new(ChallengingAuthorizer));

	let run = run(client, server).await;
	let Recovered { observer, .. } = F::recover(&run, &server_identity).await;
	let sealed = run.closing.der();
	let certificate_der = client_identity.certificate.to_der()?;

	let attempts = observer.closing_attempts(&run.transcript_hash, sealed).await?;
	let mut outcomes = attempts.iter();
	assert!(!contains_window(sealed, &certificate_der));
	assert_eq!(attempts.len(), F::CLOSING_ATTEMPTS);
	assert!(outcomes.all(|attempt| matches!(attempt, Err(HandshakeError::SealedClosing(_)))));
	Ok(())
}

/// Settlement is the last gate of the closing, so a refused settlement drops
/// the handshake secret with the step and leaves nothing to complete or to
/// replay with.
async fn a_refused_settlement_leaves_the_server_spent<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let Parties { mut client, mut server, .. } = parties::<F>(mutual_with(ExpiryValidator));
	client.transport_offer = Some(budget_offer());
	client.receipt_approver = Some(Arc::new(PayingApprover));
	server.transport = Some(budget_offer());
	server.transport_authorizer = Some(Arc::new(RefusingAuthorizer));

	let mut client = Handshake::client(client);
	let mut server = Handshake::server(server);

	let reply = server.reply(client.start()?).await?;
	let closing = client.respond(reply).await?;
	let refused = server.finish(closing.to_owned()).await;
	assert!(matches!(refused, Err(HandshakeError::SettlementRejected { .. })));
	assert_eq!(server.phase(), HandshakePhase::Spent);

	let replayed = server.finish(closing).await;
	assert!(matches!(replayed, Err(HandshakeError::InvalidState)));
	assert!(matches!(server.complete(), Err(HandshakeError::InvalidState)));
	Ok(())
}

/// A server that demands no client certificate verifies the proof of an
/// offered one and records no peer.
async fn an_anonymous_server_records_no_peer<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let Established { server_session, .. } = established::<F>(PeerAuthentication::Anonymous).await;
	assert!(server_session.peer().is_none());
	Ok(())
}

/// A mutual server records the certificate every validator accepted.
async fn a_mutual_server_records_the_accepted_peer<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let Parties { client_identity, client, mut server, .. } = parties::<F>(PeerAuthentication::Anonymous);
	let pinned = DirectTrustValidator::default().with_trust_chain([client_identity.certificate.to_owned()]);
	server.peer_authentication = mutual_with(pinned);

	let mut run = run(client, server).await;
	let session = run.server.complete()?;
	assert_eq!(session.peer(), Some(&client_identity.certificate));
	Ok(())
}

/// A mutual server refuses a closing whose certificate a validator refuses.
/// A direct-trust validator with no anchor refuses every certificate.
async fn a_mutual_server_refuses_a_refused_certificate<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let (mut client, mut server) = pair::<F>(mutual_with(DirectTrustValidator::default()));

	let reply = server.reply(client.start()?).await?;
	let closing = client.respond(reply).await?;
	let refusal = server.finish(closing).await;
	assert!(matches!(refusal, Err(HandshakeError::CertificateValidationError(_))));
	Ok(())
}

/// A pin reads no validity period, so a mutual server reads it itself and
/// refuses an expired certificate that its pin accepts.
async fn a_mutual_server_refuses_an_expired_certificate_its_pin_accepts<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let server_identity = create_test_server();
	let client_identity = create_expired_test_certificate();
	let pinned = [client_identity.certificate.to_owned()];
	let pin = RuntimeCertificatePinning::<Sha3_256>::from_certificates(pinned)?;
	let mut server_config = F::server(&server_identity);
	server_config.peer_authentication = mutual_with(pin);

	let mut client = Handshake::client(F::client(&server_identity, &client_identity));
	let mut server = Handshake::server(server_config);

	let reply = server.reply(client.start()?).await?;
	let closing = client.respond(reply).await?;
	let refusal = server.finish(closing).await;
	assert!(matches!(refusal, Err(HandshakeError::CertificateValidationError(Expired))));
	Ok(())
}

/// A mutual server reads the validity period before its validators, so an
/// expired certificate that its pin also refuses is refused as expired.
async fn a_mutual_server_reads_the_validity_period_before_its_validators<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let server_identity = create_test_server();
	let client_identity = create_expired_test_certificate();
	let pinned = [create_test_certificate().certificate];
	let pin = RuntimeCertificatePinning::<Sha3_256>::from_certificates(pinned)?;
	let mut server_config = F::server(&server_identity);
	server_config.peer_authentication = mutual_with(pin);

	let mut client = Handshake::client(F::client(&server_identity, &client_identity));
	let mut server = Handshake::server(server_config);

	let reply = server.reply(client.start()?).await?;
	let closing = client.respond(reply).await?;
	let refusal = server.finish(closing).await;
	assert!(matches!(refusal, Err(HandshakeError::CertificateValidationError(Expired))));
	Ok(())
}

/// A server takes the first profile it runs that the client also offered,
/// and both sides fix that profile.
async fn both_sides_fix_the_offered_profile_the_server_runs<F: TestFlow>() -> Result<(), Box<dyn Error>> {
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
async fn a_server_refuses_an_offer_that_names_no_profile_it_runs<F: TestFlow>() -> Result<(), Box<dyn Error>> {
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

/// Multiplexing negotiates when the client offers it and the server enables
/// it, and the cap each side advertises bounds the streams its peer initiates.
async fn multiplexing_negotiates_when_offered_and_enabled<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let Parties { mut client, mut server, .. } = parties::<F>(PeerAuthentication::Anonymous);
	client.transport_offer = Some(TransportOffer::mux(8));
	server.transport = Some(TransportOffer::mux(4));

	let run = run(client, server).await;

	let caps = |mux: MuxSettings| (mux.local_initiated_cap, mux.peer_initiated_cap);
	let server_caps = run.server.negotiated_mux().map(caps);
	assert_eq!(server_caps, Some((8, 4)));

	let client_caps = run.client.negotiated_mux().map(caps);
	assert_eq!(client_caps, Some((4, 8)));
	Ok(())
}

/// A session stays single-flight when the client offers multiplexing and the
/// server does not enable it.
async fn an_offer_alone_stays_single_flight<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let Parties { mut client, server, .. } = parties::<F>(PeerAuthentication::Anonymous);
	client.transport_offer = Some(TransportOffer::mux(8));

	let run = run(client, server).await;
	assert_eq!(run.server.negotiated_mux(), None);
	assert_eq!(run.client.negotiated_mux(), None);
	Ok(())
}

/// A session stays single-flight when the server enables multiplexing and
/// the client does not offer it.
async fn a_local_advertisement_alone_stays_single_flight<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let Parties { client, mut server, .. } = parties::<F>(PeerAuthentication::Anonymous);
	server.transport = Some(TransportOffer::mux(4));

	let run = run(client, server).await;
	assert_eq!(run.server.negotiated_mux(), None);
	assert_eq!(run.client.negotiated_mux(), None);
	Ok(())
}

/// Run each named test body once per protocol.
macro_rules! over_each_flow {
	($($test:ident),* $(,)?) => {
		#[cfg(feature = "transport-hpke")]
		mod hpke {
			use super::*;

			$(
				#[tokio::test]
				async fn $test() -> Result<(), Box<dyn Error>> {
					super::$test::<Hpke>().await
				}
			)*
		}

		#[cfg(feature = "transport-cms")]
		mod cms {
			use super::*;

			$(
				#[tokio::test]
				async fn $test() -> Result<(), Box<dyn Error>> {
					super::$test::<Cms>().await
				}
			)*
		}
	};
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
	an_anonymous_server_records_no_peer,
	a_mutual_server_records_the_accepted_peer,
	a_mutual_server_refuses_a_refused_certificate,
	a_mutual_server_refuses_an_expired_certificate_its_pin_accepts,
	a_mutual_server_reads_the_validity_period_before_its_validators,
	both_sides_fix_the_offered_profile_the_server_runs,
	a_server_refuses_an_offer_that_names_no_profile_it_runs,
	multiplexing_negotiates_when_offered_and_enabled,
	an_offer_alone_stays_single_flight,
	a_local_advertisement_alone_stays_single_flight,
}

/// The base secret of the CMS opening crosses the wire only sealed, so no
/// leg carries its bytes in the clear (CWE-311).
#[cfg(feature = "transport-cms")]
#[tokio::test]
async fn the_base_secret_crosses_the_wire_only_sealed() -> Result<(), Box<dyn Error>> {
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
