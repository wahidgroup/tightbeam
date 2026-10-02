//! Loopback end-to-end tests for handshake orchestrators.
//!
//! The tests drive the ECIES and CMS client and server orchestrators against
//! each other entirely through the `ClientHandshakeProtocol` and
//! `ServerHandshakeProtocol` trait surface (the same surface `io.rs`
//! consumes) and verify:
//!
//! - Both sides complete and agree on the negotiated profile.
//! - The derived directional `SessionKeys` are complementary.
//! - CMS traffic keys are fresh per handshake, never shared (CWE-321).

#![cfg(all(feature = "transport", feature = "x509", feature = "aead", feature = "tokio"))]

#[cfg(feature = "transport-ecies")]
use std::sync::Arc;

use tightbeam::{
	crypto::{
		aead::{DecryptContent, SessionKeys},
		profiles::{DefaultCryptoProvider, SecurityProfileDesc},
		secret::ToInsecure,
	},
	exactly, tb_assert_spec, tb_scenario,
	testing::SetupEnv,
	trace::TraceCollector,
	transport::handshake::{ClientHandshakeProtocol, EstablishedSession, ServerHandshakeProtocol},
	TightBeamError,
};

#[cfg(feature = "transport-ecies")]
use tightbeam::{
	crypto::ecies::Secp256k1EciesMessage,
	transport::handshake::negotiation::SecurityOffer,
	transport::handshake::{client::EciesHandshakeClient, server::EciesHandshakeServer, PeerAuthentication},
};

#[cfg(feature = "transport-cms")]
use tightbeam::transport::handshake::HandshakeMessage;
use tightbeam::transport::handshake::{client::CmsHandshakeClient, server::CmsHandshakeServer};

use crate::common::security::{default_security_profile, expectation_failure, ServerMaterials};

#[cfg(feature = "transport-cms")]
use crate::common::security::cms_handshake_pair;
#[cfg(feature = "transport-ecies")]
use crate::common::security::pinning_validator;

use tightbeam::utils::urn::Urn;

pub(crate) const LOOPBACK_CMS_COMPLETE: Urn<'static> = tightbeam::urn!("test", "event:loopback/loopback-cms-complete");
pub(crate) const LOOPBACK_CMS_PROFILE_AGREED: Urn<'static> =
	tightbeam::urn!("test", "event:loopback/loopback-cms-profile-agreed");
pub(crate) const LOOPBACK_CMS_ROUNDTRIP: Urn<'static> =
	tightbeam::urn!("test", "event:loopback/loopback-cms-roundtrip");
pub(crate) const LOOPBACK_CMS_UNIQUE_KEYS: Urn<'static> =
	tightbeam::urn!("test", "event:loopback/loopback-cms-unique-keys");
pub(crate) const LOOPBACK_ECIES_COMPLETE: Urn<'static> =
	tightbeam::urn!("test", "event:loopback/loopback-ecies-complete");
pub(crate) const LOOPBACK_ECIES_PROFILE_AGREED: Urn<'static> =
	tightbeam::urn!("test", "event:loopback/loopback-ecies-profile-agreed");
pub(crate) const LOOPBACK_ECIES_ROUNDTRIP: Urn<'static> =
	tightbeam::urn!("test", "event:loopback/loopback-ecies-roundtrip");

/// Number of CMS loopback passes (0 when the feature is disabled).
const CMS_RUNS: u32 = cfg!(feature = "transport-cms") as u32;

/// Number of ECIES loopback passes (0 when the feature is disabled).
const ECIES_RUNS: u32 = cfg!(feature = "transport-ecies") as u32;

tb_assert_spec! {
	pub HandshakeLoopbackSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(LOOPBACK_ECIES_COMPLETE, exactly!(ECIES_RUNS), equals!(true)),
			(LOOPBACK_ECIES_ROUNDTRIP, exactly!(ECIES_RUNS), equals!(true)),
			(LOOPBACK_ECIES_PROFILE_AGREED, exactly!(ECIES_RUNS), equals!(true)),
			(LOOPBACK_CMS_COMPLETE, exactly!(CMS_RUNS), equals!(true)),
			(LOOPBACK_CMS_ROUNDTRIP, exactly!(CMS_RUNS), equals!(true)),
			(LOOPBACK_CMS_PROFILE_AGREED, exactly!(CMS_RUNS), equals!(true)),
			(LOOPBACK_CMS_UNIQUE_KEYS, exactly!(CMS_RUNS), equals!(true))
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
				cms_unique_traffic_keys(&trace, &materials).await?;
			}

			Ok(())
		}
	}
}

#[cfg(feature = "transport-ecies")]
fn security_offer(profile: SecurityProfileDesc) -> SecurityOffer {
	SecurityOffer::new(vec![profile])
}

/// Probe both directions and return whether the plaintexts match the
/// probes.
///
/// Each direction has its own key and counter nonce, so no `(key, nonce)`
/// pair can repeat across the two probes.
fn bidirectional_roundtrip_ok(client_keys: &SessionKeys, server_keys: &SessionKeys) -> Result<bool, TightBeamError> {
	let c2s_probe = b"client->server probe";
	let c2s_ciphertext = client_keys.send().encrypt_next(c2s_probe, None)?;
	let c2s_plaintext = server_keys.recv().decrypt_content(&c2s_ciphertext)?.to_insecure();
	let c2s_ok = &c2s_plaintext[..] == c2s_probe;

	let s2c_probe = b"server->client probe";
	let s2c_ciphertext = server_keys.send().encrypt_next(s2c_probe, None)?;
	let s2c_plaintext = client_keys.recv().decrypt_content(&s2c_ciphertext)?.to_insecure();
	let s2c_ok = &s2c_plaintext[..] == s2c_probe;

	Ok(c2s_ok && s2c_ok)
}

/// Complete both peers, prove AEAD key agreement, and record the negotiated
/// profile.
///
/// The function emits the three named booleans that `HandshakeLoopbackSpec`
/// verifies with `equals!(true)`.
async fn emit_session_ready<C, S>(
	client: Box<C>,
	server: Box<S>,
	profile: SecurityProfileDesc,
	trace: &TraceCollector,
	events: (Urn<'static>, Urn<'static>, Urn<'static>),
) -> Result<(), TightBeamError>
where
	C: ClientHandshakeProtocol,
	S: ServerHandshakeProtocol,
	TightBeamError: From<C::Error> + From<S::Error>,
{
	let (complete_event, roundtrip_event, profile_event) = events;

	// Completing consumes each orchestrator, so both machines are read while
	// they still exist. `complete()` makes the final transition itself, so the
	// pair is mid-flight here and the event records that transition happening.
	let pending_before_completion = !ClientHandshakeProtocol::is_complete(client.as_ref())
		&& !ServerHandshakeProtocol::is_complete(server.as_ref());

	let client_profile = ClientHandshakeProtocol::selected_profile(client.as_ref());
	let server_profile = ServerHandshakeProtocol::selected_profile(server.as_ref());

	let client_session = ClientHandshakeProtocol::complete(client).await?;
	let server_session = ServerHandshakeProtocol::complete(server).await?;
	trace.event_with(complete_event, &[], pending_before_completion)?;

	let roundtrip = bidirectional_roundtrip_ok(client_session.keys(), server_session.keys())?;
	trace.event_with(roundtrip_event, &[], roundtrip)?;

	let profile_agreed = client_profile == Some(profile) && server_profile == Some(profile);
	trace.event_with(profile_event, &[], profile_agreed)?;

	Ok(())
}

/// Require a handshake reply and convert a missing reply into an
/// expectation failure.
fn require_reply(reply: Option<HandshakeMessage>, msg: &'static str) -> Result<HandshakeMessage, TightBeamError> {
	let message = reply.ok_or_else(|| expectation_failure(msg))?;
	Ok(message)
}

/// Require that a protocol step produce no further reply.
fn require_terminal(reply: Option<HandshakeMessage>, msg: &'static str) -> Result<(), TightBeamError> {
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
	let mut server = EciesHandshakeServer::<DefaultCryptoProvider>::new(
		key_provider,
		certificate,
		None,
		PeerAuthentication::Anonymous,
	)
	.with_supported_profiles(vec![profile]);

	// The flow is ClientHello, then ServerHandshake, then ClientKeyExchange,
	// which draws no reply.
	let client_hello = ClientHandshakeProtocol::start(&mut client).await?;
	let server_reply = server.handle_request(client_hello).await?;
	let server_handshake = require_reply(server_reply, "ECIES server must answer ClientHello")?;

	let client_reply = client.handle_response(server_handshake).await?;
	let client_kex = require_reply(client_reply, "ECIES client must answer ServerHandshake")?;

	let no_reply = server.handle_request(client_kex).await?;
	require_terminal(no_reply, "ECIES server must not reply to ClientKeyExchange")?;

	let events = (LOOPBACK_ECIES_COMPLETE, LOOPBACK_ECIES_ROUNDTRIP, LOOPBACK_ECIES_PROFILE_AGREED);
	emit_session_ready(Box::new(client), Box::new(server), profile, trace, events).await
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
	let pair = cms_handshake_pair(materials, vec![profile], vec![profile], PeerAuthentication::Anonymous)?;
	Ok((pair.client, pair.server))
}

/// Drive a CMS pair through its three legs. The flow is KeyExchange, then
/// ServerFinished, then ClientFinished, which draws no reply.
#[cfg(feature = "transport-cms")]
async fn drive_cms_pair(
	client: &mut CmsHandshakeClient<DefaultCryptoProvider>,
	server: &mut CmsHandshakeServer<DefaultCryptoProvider>,
) -> Result<(), TightBeamError> {
	let key_exchange = ClientHandshakeProtocol::start(client).await?;
	let server_reply = server.handle_request(key_exchange).await?;
	let server_finished = require_reply(server_reply, "CMS server must answer KeyExchange with ServerFinished")?;

	let client_reply = client.handle_response(server_finished).await?;
	let client_finished = require_reply(client_reply, "CMS client must answer ServerFinished with ClientFinished")?;

	let no_reply = server.handle_request(client_finished).await?;
	require_terminal(no_reply, "CMS server must not reply to ClientFinished")
}

/// CMS loopback through the orchestrator trait surface.
///
/// Both sides derive a working AEAD from the handshake secret, and the client
/// learns the negotiated profile from the server-Finished `SecurityAccept`
/// attribute and can `complete()`.
#[cfg(feature = "transport-cms")]
async fn cms_loopback(trace: &TraceCollector, materials: &ServerMaterials) -> Result<(), TightBeamError> {
	let profile = default_security_profile();
	let (mut client, mut server) = build_cms_pair(materials)?;
	drive_cms_pair(&mut client, &mut server).await?;

	let events = (LOOPBACK_CMS_COMPLETE, LOOPBACK_CMS_ROUNDTRIP, LOOPBACK_CMS_PROFILE_AGREED);
	emit_session_ready(Box::new(client), Box::new(server), profile, trace, events).await
}

/// Complete one CMS handshake against the fixture server and hand back both
/// sessions.
#[cfg(feature = "transport-cms")]
async fn established_cms_pair(
	materials: &ServerMaterials,
) -> Result<(EstablishedSession, EstablishedSession), TightBeamError> {
	let (mut client, mut server) = build_cms_pair(materials)?;
	drive_cms_pair(&mut client, &mut server).await?;

	let client_session = ClientHandshakeProtocol::complete(Box::new(client)).await?;
	let server_session = ServerHandshakeProtocol::complete(Box::new(server)).await?;
	Ok((client_session, server_session))
}

/// CMS traffic keys must be fresh per handshake (CWE-321): two sessions
/// against one server seal the same probe differently, and a frame from one
/// session does not open on the other.
#[cfg(feature = "transport-cms")]
async fn cms_unique_traffic_keys(trace: &TraceCollector, materials: &ServerMaterials) -> Result<(), TightBeamError> {
	let (client_a, _server_a) = established_cms_pair(materials).await?;
	let (client_b, server_b) = established_cms_pair(materials).await?;

	let probe = b"same probe under two sessions";
	let frame_a = client_a.keys().send().encrypt_next(probe, None)?;
	let frame_b = client_b.keys().send().encrypt_next(probe, None)?;

	let distinct = frame_a.encrypted_content != frame_b.encrypted_content;
	let isolated = server_b.keys().recv().decrypt_content(&frame_a).is_err();
	trace.event_with(LOOPBACK_CMS_UNIQUE_KEYS, &[], distinct && isolated)?;

	Ok(())
}
