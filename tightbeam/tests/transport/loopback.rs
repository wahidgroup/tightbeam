//! Loopback end-to-end tests for handshake orchestrators.
//!
//! Drives the ECIES and CMS client/server orchestrators against each other
//! entirely through the `ClientHandshakeProtocol`/`ServerHandshakeProtocol`
//! trait surface (the same surface `io.rs` consumes) and verifies:
//!
//! - Both sides complete and agree on the negotiated profile
//! - The derived directional `SessionKeys` are complementary
//! - CMS session keys are random per handshake, never constant (CWE-321)

#![cfg(all(feature = "transport", feature = "x509", feature = "aead", feature = "tokio"))]

use std::sync::Arc;

use tightbeam::{
	crypto::{
		aead::{Decryptor, SessionKeys},
		profiles::{DefaultCryptoProvider, SecurityProfileDesc},
		secret::ToInsecure,
	},
	exactly, tb_assert_spec, tb_scenario,
	testing::SetupEnv,
	trace::TraceCollector,
	transport::handshake::{negotiation::SecurityOffer, ClientHandshakeProtocol, ServerHandshakeProtocol},
	TightBeamError,
};

#[cfg(feature = "transport-ecies")]
use tightbeam::{
	crypto::ecies::Secp256k1EciesMessage,
	transport::handshake::{client::EciesHandshakeClient, server::EciesHandshakeServer},
};

#[cfg(feature = "transport-cms")]
use tightbeam::{
	crypto::key::{Secp256k1KeyProvider, SigningKeyProvider},
	crypto::sign::ecdsa::Secp256k1SigningKey,
	random::OsRng,
	testing::utils::create_test_certificate,
	transport::handshake::{client::CmsHandshakeClient, server::CmsHandshakeServer},
};

use crate::common::security::{default_security_profile, expectation_failure, ServerMaterials};

#[cfg(feature = "transport-cms")]
use crate::common::security::pinning_trust_store;
#[cfg(feature = "transport-ecies")]
use crate::common::security::pinning_validator;

/// Number of CMS loopback passes (0 when the feature is disabled).
const CMS_RUNS: u32 = cfg!(feature = "transport-cms") as u32;

/// Number of ECIES loopback passes (0 when the feature is disabled).
const ECIES_RUNS: u32 = cfg!(feature = "transport-ecies") as u32;

const ZERO_KEY: [u8; 32] = [0u8; 32];

tb_assert_spec! {
	pub HandshakeLoopbackSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(loopback_ecies_complete, exactly!(ECIES_RUNS), equals!(true)),
			(loopback_ecies_roundtrip, exactly!(ECIES_RUNS), equals!(true)),
			(loopback_ecies_profile_agreed, exactly!(ECIES_RUNS), equals!(true)),
			(loopback_cms_complete, exactly!(CMS_RUNS), equals!(true)),
			(loopback_cms_roundtrip, exactly!(CMS_RUNS), equals!(true)),
			(loopback_cms_profile_agreed, exactly!(CMS_RUNS), equals!(true)),
			(loopback_cms_unique_keys, exactly!(CMS_RUNS), equals!(true))
		]
	}
}

tb_scenario! {
	name: handshake_loopback,
	spec: HandshakeLoopbackSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::generate();

			#[cfg(feature = "transport-ecies")]
			ecies_loopback(&trace, &materials).await?;

			#[cfg(feature = "transport-cms")]
			{
				cms_loopback(&trace, &materials).await?;
				cms_unique_session_keys(&trace, &materials).await?;
			}

			Ok(())
		}
	}
}

fn security_offer(profile: SecurityProfileDesc) -> SecurityOffer {
	SecurityOffer::new(vec![profile])
}

/// Probe both directions. Return whether plaintexts match the probes.
///
/// Each direction has its own key and counter nonce, so no `(key, nonce)`
/// pair can repeat across the two probes.
fn bidirectional_roundtrip_ok(client_keys: &SessionKeys, server_keys: &SessionKeys) -> Result<bool, TightBeamError> {
	let c2s_probe = b"client->server probe";
	let c2s_ciphertext = client_keys.send().encrypt_next(c2s_probe, None)?;
	let c2s_plaintext = server_keys.recv().decrypt_content(&c2s_ciphertext)?.to_insecure()?;
	let c2s_ok = &c2s_plaintext[..] == c2s_probe;

	let s2c_probe = b"server->client probe";
	let s2c_ciphertext = server_keys.send().encrypt_next(s2c_probe, None)?;
	let s2c_plaintext = client_keys.recv().decrypt_content(&s2c_ciphertext)?.to_insecure()?;
	let s2c_ok = &s2c_plaintext[..] == s2c_probe;

	Ok(c2s_ok && s2c_ok)
}

/// Complete both peers, prove AEAD key agreement, and record negotiated profile.
///
/// Emits the three named booleans for `HandshakeLoopbackSpec` to verify via
/// `equals!(true)`.
async fn emit_session_ready<C, S>(
	client: &mut C,
	server: &mut S,
	profile: SecurityProfileDesc,
	trace: &TraceCollector,
	events: (&'static str, &'static str, &'static str),
) -> Result<(), TightBeamError>
where
	C: ClientHandshakeProtocol,
	S: ServerHandshakeProtocol,
	TightBeamError: From<C::Error> + From<S::Error>,
{
	let (complete_event, roundtrip_event, profile_event) = events;

	let client_aead = ClientHandshakeProtocol::complete(client).await?;
	let server_aead = ServerHandshakeProtocol::complete(server).await?;
	let complete = ClientHandshakeProtocol::is_complete(client) && ServerHandshakeProtocol::is_complete(server);
	trace.event_with(complete_event, &[], complete)?;

	let roundtrip = bidirectional_roundtrip_ok(&client_aead, &server_aead)?;
	trace.event_with(roundtrip_event, &[], roundtrip)?;

	let client_profile = ClientHandshakeProtocol::selected_profile(client);
	let server_profile = ServerHandshakeProtocol::selected_profile(server);
	let profile_agreed = client_profile == Some(profile) && server_profile == Some(profile);
	trace.event_with(profile_event, &[], profile_agreed)?;

	Ok(())
}

/// Require a handshake reply and convert a missing reply into an expectation failure.
fn require_reply(reply: Option<Vec<u8>>, msg: &'static str) -> Result<Vec<u8>, TightBeamError> {
	let bytes = reply.ok_or_else(|| expectation_failure(msg))?;
	Ok(bytes)
}

/// Protocol step that must produce no further reply.
fn require_terminal(reply: Option<Vec<u8>>, msg: &'static str) -> Result<(), TightBeamError> {
	if reply.is_some() {
		return Err(expectation_failure(msg));
	}
	Ok(())
}

/// ECIES loopback through the orchestrator trait surface.
#[cfg(feature = "transport-ecies")]
async fn ecies_loopback(trace: &TraceCollector, materials: &ServerMaterials) -> Result<(), TightBeamError> {
	let profile = default_security_profile();
	let offer = security_offer(profile);
	let validator = pinning_validator(&materials.certificate);

	let mut client = EciesHandshakeClient::<DefaultCryptoProvider, Secp256k1EciesMessage>::new(None)
		.with_security_offer(offer)
		.with_certificate_validator(validator);

	let key_provider = Arc::clone(&materials.key_provider);
	let certificate = Arc::clone(&materials.certificate);
	let mut server = EciesHandshakeServer::<DefaultCryptoProvider>::new(key_provider, certificate, None, None)
		.with_supported_profiles(vec![profile]);

	// ClientHello -> ServerHandshake -> ClientKeyExchange -> (no reply)
	let client_hello = ClientHandshakeProtocol::start(&mut client).await?;
	let server_reply = server.handle_request(&client_hello).await?;
	let server_handshake = require_reply(server_reply, "ECIES server must answer ClientHello")?;

	let client_reply = client.handle_response(&server_handshake).await?;
	let client_kex = require_reply(client_reply, "ECIES client must answer ServerHandshake")?;

	let no_reply = server.handle_request(&client_kex).await?;
	require_terminal(no_reply, "ECIES server must not reply to ClientKeyExchange")?;

	let events = (
		"loopback_ecies_complete",
		"loopback_ecies_roundtrip",
		"loopback_ecies_profile_agreed",
	);
	emit_session_ready(&mut client, &mut server, profile, trace, events).await
}

/// Build a CMS client/server pair sharing the fixture server identity.
#[cfg(feature = "transport-cms")]
#[allow(clippy::type_complexity)]
fn build_cms_pair(
	materials: &ServerMaterials,
) -> Result<
	(
		CmsHandshakeClient<DefaultCryptoProvider>,
		CmsHandshakeServer<DefaultCryptoProvider>,
	),
	TightBeamError,
> {
	let profile = default_security_profile();
	let offer = security_offer(profile);
	let trust_store = pinning_trust_store(&materials.certificate)?;

	let client_key = k256::ecdsa::SigningKey::random(&mut OsRng);
	let client_cert = create_test_certificate(&client_key);
	let signing_key = Secp256k1SigningKey::from(client_key);
	let client_provider: Arc<dyn SigningKeyProvider> = Arc::new(Secp256k1KeyProvider::from(signing_key));

	let server_certificate = Arc::clone(&materials.certificate);
	let client = CmsHandshakeClient::<DefaultCryptoProvider>::new(
		DefaultCryptoProvider::default(),
		client_provider,
		server_certificate,
	)
	.with_security_offer(offer)
	.with_trust_store(trust_store);

	let key_provider = Arc::clone(&materials.key_provider);
	let profiles = vec![profile];
	let mut server =
		CmsHandshakeServer::<DefaultCryptoProvider>::new(key_provider, None).with_supported_profiles(profiles);
	server.set_client_certificate(client_cert)?;

	Ok((client, server))
}

/// Clone the session key held by a CMS client after `start`.
#[cfg(feature = "transport-cms")]
fn session_key_bytes(
	client: &CmsHandshakeClient<DefaultCryptoProvider>,
	missing_msg: &'static str,
) -> Result<Vec<u8>, TightBeamError> {
	let secret = client.session_key().ok_or_else(|| expectation_failure(missing_msg))?;
	let bytes = secret.with(|bytes| bytes.to_owned())?;
	Ok(bytes)
}

/// True when `needle` appears as a contiguous window inside `haystack`.
#[cfg(feature = "transport-cms")]
fn contains_window(haystack: &[u8], needle: &[u8]) -> bool {
	haystack.windows(needle.len()).any(|window| window == needle)
}

/// CMS loopback through the orchestrator trait surface.
///
/// Regression coverage for random session key lets both sides derive a working
/// AEAD and client learns the negotiated profile from the server-Finished
/// `SecurityAccept` attribute and can `complete()`.
#[cfg(feature = "transport-cms")]
async fn cms_loopback(trace: &TraceCollector, materials: &ServerMaterials) -> Result<(), TightBeamError> {
	let profile = default_security_profile();
	let (mut client, mut server) = build_cms_pair(materials)?;

	// KeyExchange -> ServerFinished -> ClientFinished -> (no reply)
	let key_exchange = ClientHandshakeProtocol::start(&mut client).await?;

	// Confidentiality (CWE-311): the CMS backend transports the session key
	// wrapped inside the KeyExchange EnvelopedData, so the raw key MUST NOT
	// appear anywhere in the cleartext wire bytes. This is the CMS analogue of
	// the ECIES `confidentiality` threat test, exercised on the real
	// random-key path (not the fixture's constant test key).
	let session_key = session_key_bytes(&client, "CMS client must hold a session key after start")?;
	if contains_window(&key_exchange, &session_key) {
		return Err(expectation_failure(
			"CMS session key must not appear in cleartext KeyExchange wire bytes",
		));
	}

	let server_reply = server.handle_request(&key_exchange).await?;
	let server_finished = require_reply(server_reply, "CMS server must answer KeyExchange with ServerFinished")?;

	let client_reply = client.handle_response(&server_finished).await?;
	let client_finished = require_reply(client_reply, "CMS client must answer ServerFinished with ClientFinished")?;

	let no_reply = server.handle_request(&client_finished).await?;
	require_terminal(no_reply, "CMS server must not reply to ClientFinished")?;

	let events = ("loopback_cms_complete", "loopback_cms_roundtrip", "loopback_cms_profile_agreed");
	emit_session_ready(&mut client, &mut server, profile, trace, events).await
}

/// CMS session keys must be random per handshake (CWE-321).
#[cfg(feature = "transport-cms")]
async fn cms_unique_session_keys(trace: &TraceCollector, materials: &ServerMaterials) -> Result<(), TightBeamError> {
	let (mut client_a, _server_a) = build_cms_pair(materials)?;
	let (mut client_b, _server_b) = build_cms_pair(materials)?;

	let _kex_a = ClientHandshakeProtocol::start(&mut client_a).await?;
	let _kex_b = ClientHandshakeProtocol::start(&mut client_b).await?;

	let key_a = session_key_bytes(&client_a, "CMS client A must hold a session key after start")?;
	let key_b = session_key_bytes(&client_b, "CMS client B must hold a session key after start")?;

	let unique_keys =
		key_a.as_slice() != ZERO_KEY.as_slice() && key_b.as_slice() != ZERO_KEY.as_slice() && key_a != key_b;
	trace.event_with(HandshakeLoopbackSpec::loopback_cms_unique_keys, &[], unique_keys)?;

	Ok(())
}
