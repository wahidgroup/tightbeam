//! Tests of the step order, the phases, and the decisions, run over both
//! flows.
//!
//! Each test body is generic over [`TestFlow`], and [`over_each_flow`] runs
//! it once per protocol. A test of one protocol's wire sits beside that flow.

use std::error::Error;
use std::sync::Arc;

use crate::asn1::OctetString;
use crate::cms::enveloped_data::EnvelopedData;
use crate::cms::signed_data::SignerInfo;
use crate::crypto::aead::DecryptContent;
use crate::crypto::profiles::SecurityProfileDesc;
use crate::crypto::secret::ToInsecure;
use crate::crypto::x509::policy::{DirectTrustValidator, ExpiryValidator};
use crate::der::Decode;
use crate::oids::AES_128_GCM;
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::negotiation::{MuxSettings, NegotiationError, SecurityOffer, TransportOffer};
use crate::transport::handshake::receipt::StoredReceipt;
use crate::transport::handshake::tests::*;
use crate::transport::handshake::{Handshake, HandshakeMessage, HandshakePhase, PeerAuthentication};
use crate::TightBeamError;

#[cfg(feature = "transport-cms")]
use crate::transport::handshake::Cms;
#[cfg(feature = "transport-ecies")]
use crate::transport::handshake::Ecies;

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

	// Nothing but the opening runs on an idle client.
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

	// Nothing but the opening runs on an idle server.
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

/// A handshake that agreed admits no wire step again, and each refusal leaves
/// what it agreed in place.
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

/// A completed handshake is terminal: it admits no wire step, and each
/// refusal leaves it completed.
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
	let mut other = Handshake::client(F::client(&server_identity.certificate, &create_test_certificate()));
	let stray = server.reply(other.start()?).await?;

	client.start()?;

	let refused = client.respond(stray.to_owned()).await;
	let forged = matches!(refused, Err(HandshakeError::SignatureError(_)));
	let unverified = matches!(refused, Err(HandshakeError::SignatureVerificationFailed));
	assert!(forged || unverified);
	assert_eq!(client.phase(), HandshakePhase::Spent);

	let replayed = client.respond(stray).await;
	assert!(matches!(replayed, Err(HandshakeError::InvalidState)));
	assert!(matches!(client.start(), Err(HandshakeError::InvalidState)));
	assert!(matches!(client.complete(), Err(HandshakeError::InvalidState)));
	Ok(())
}

/// A closing from another handshake is refused, and the server admits no
/// step after the refusal. ECIES refuses the possession proof, which signs
/// another transcript. CMS refuses the certificate, which the opening did not
/// bind.
async fn a_refused_closing_leaves_the_server_spent<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let (mut client, mut server) = pair::<F>(PeerAuthentication::Anonymous);
	let other = established::<F>(PeerAuthentication::Anonymous).await;

	server.reply(client.start()?).await?;

	let refused = server.finish(other.run.closing.to_owned()).await;
	let forged = matches!(refused, Err(HandshakeError::SignatureError(_)));
	let unbound = matches!(refused, Err(HandshakeError::ClientCertificateMismatch));
	assert!(forged || unbound);
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

	let to_client = server_session.keys().send().encrypt_next(b"server to client", None)?;
	let opened = client_session.keys().recv().decrypt_content(&to_client)?.to_insecure();
	assert_eq!(opened.as_slice(), b"server to client");
	Ok(())
}

/// Both sides of a mutually authenticated handshake derive one key schedule:
/// a frame the client seals opens on the server.
async fn both_sides_derive_the_same_keys_under_mutual_authentication<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let Established { client_session, server_session, .. } = established::<F>(mutual_with(ExpiryValidator)).await;

	let frame = sealed_record(&client_session)?;
	let opened = server_session.keys().recv().decrypt_content(&frame)?.to_insecure();
	assert_eq!(opened.as_slice(), RECORD_PLAINTEXT);
	Ok(())
}

/// A passive observer who records the whole session and later obtains the
/// server's static key still recovers the base secret. No traffic key the
/// observer derives from that base and the recording opens a recorded frame.
async fn a_recorded_session_does_not_open_under_the_server_static_key<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let established = established::<F>(PeerAuthentication::Anonymous).await;
	let Established { server_identity, run, client_session, .. } = established;

	let frame = sealed_record(&client_session)?;

	// The static key still recovers the base secret, which `recover` requires.
	let Recovered { observer, .. } = F::recover(&run, &server_identity);

	let attempts = observer.record_attempts(&frame)?;
	let mut outcomes = attempts.iter();
	assert_eq!(attempts.len(), RECORD_ATTEMPTS);
	assert!(outcomes.all(|attempt| matches!(attempt, Err(TightBeamError::EncryptionError(_)))));
	Ok(())
}

/// The same observer, on a budget-bearing session, finds the receipt
/// acknowledgement sealed. It is neither a plaintext `SignerInfo` nor an
/// `EnvelopedData` to the static key, and no acknowledgement key the observer
/// derives opens it, so the bearer settlement answer stays confidential.
async fn the_settlement_answer_is_sealed_from_the_server_static_key<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let Parties { server_identity, mut client, mut server, .. } = parties::<F>(mutual_with(ExpiryValidator));
	client.transport_offer = Some(budget_offer());
	client.receipt_approver = Some(Arc::new(PayingApprover));
	server.transport = Some(budget_offer());
	server.transport_authorizer = Some(Arc::new(ChallengingAuthorizer));

	let run = run(client, server).await;

	// Positive control: the real server settled the real answer.
	let settled = run.server.session_receipt().and_then(StoredReceipt::ancillary_response);
	assert_eq!(settled.map(OctetString::as_bytes), Some(TEST_ANSWER));

	let Recovered { observer, sealed_ack, .. } = F::recover(&run, &server_identity);
	let sealed = sealed_ack.ok_or("a budget-bearing closing carries the acknowledgement")?;
	assert!(SignerInfo::from_der(&sealed).is_err());
	assert!(EnvelopedData::from_der(&sealed).is_err());

	let attempts = observer.ack_attempts(&run.transcript_hash, &sealed)?;
	let mut outcomes = attempts.iter();
	assert_eq!(attempts.len(), ACK_ATTEMPTS);
	assert!(outcomes.all(|attempt| matches!(attempt, Err(HandshakeError::ReceiptAckCipher(_)))));
	Ok(())
}

/// The base secret crosses the wire only sealed, so no leg carries its bytes
/// in the clear (CWE-311).
async fn the_base_secret_crosses_the_wire_only_sealed<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let Parties { server_identity, client, server, .. } = parties::<F>(PeerAuthentication::Anonymous);
	let run = run(client, server).await;

	let Recovered { base, .. } = F::recover(&run, &server_identity);
	assert!(!contains_window(run.wire_bytes(), &base));
	Ok(())
}

/// Two handshakes draw two base secrets, so no session shares its key
/// schedule input with another (CWE-321).
async fn two_handshakes_draw_different_base_secrets<F: TestFlow>() -> Result<(), Box<dyn Error>> {
	let first = established::<F>(PeerAuthentication::Anonymous).await;
	let second = established::<F>(PeerAuthentication::Anonymous).await;

	let first = F::recover(&first.run, &first.server_identity);
	let second = F::recover(&second.run, &second.server_identity);
	assert_ne!(first.base, second.base);
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
		#[cfg(feature = "transport-ecies")]
		mod ecies {
			use super::*;

			$(
				#[tokio::test]
				async fn $test() -> Result<(), Box<dyn Error>> {
					super::$test::<Ecies>().await
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
	the_settlement_answer_is_sealed_from_the_server_static_key,
	the_base_secret_crosses_the_wire_only_sealed,
	two_handshakes_draw_different_base_secrets,
	a_refused_settlement_leaves_the_server_spent,
	an_anonymous_server_records_no_peer,
	a_mutual_server_records_the_accepted_peer,
	a_mutual_server_refuses_a_refused_certificate,
	both_sides_fix_the_offered_profile_the_server_runs,
	a_server_refuses_an_offer_that_names_no_profile_it_runs,
	multiplexing_negotiates_when_offered_and_enabled,
	an_offer_alone_stays_single_flight,
	a_local_advertisement_alone_stays_single_flight,
}
