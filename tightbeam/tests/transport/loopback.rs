//! The loopback end-to-end tests of the handshake orchestrators.
//!
//! The tests drive the HPKE and CMS client and server orchestrators against
//! each other entirely through the `ClientHandshakeProtocol` and
//! `ServerHandshakeProtocol` trait surface (the same surface `io.rs`
//! consumes) and verify:
//!
//! - Both sides complete and agree on the negotiated profile.
//! - The derived directional `SessionKeys` are complementary.
//! - CMS traffic keys are fresh per handshake, never shared (CWE-321).

#![cfg(all(feature = "transport", feature = "x509", feature = "aead", feature = "tokio"))]

use tightbeam::{
	crypto::{
		aead::SessionKeys,
		profiles::{DefaultCryptoProvider, SecurityProfileDesc},
	},
	der::Encode,
	transport::handshake::{
		ClientHandshakeProtocol, EstablishedSession, Handshake, HandshakeMessage, ServerHandshakeProtocol,
	},
	TightBeamError,
};

#[cfg(feature = "transport-hpke")]
use tightbeam::transport::handshake::negotiation::SecurityOffer;
#[cfg(feature = "transport-cms")]
use tightbeam::transport::handshake::{Client, Cms, PeerAuthentication, Server};

use crate::common::security::{default_security_profile, expectation_failure, ServerMaterials};

#[cfg(feature = "transport-cms")]
use crate::common::security::cms_handshake_pair;
#[cfg(feature = "transport-hpke")]
use crate::common::security::{hpke_client_config, hpke_server_config, pinning_validator};

#[cfg(feature = "transport-hpke")]
fn security_offer(profile: SecurityProfileDesc) -> SecurityOffer {
	SecurityOffer::new(vec![profile])
}

/// Probes both directions and returns whether the plaintexts match the
/// probes.
///
/// Each direction has its own key and record sequence, and each record has
/// its own content key.
fn bidirectional_roundtrip_ok(client_keys: &SessionKeys, server_keys: &SessionKeys) -> Result<bool, TightBeamError> {
	let c2s_probe = b"client->server probe";
	let mut c2s_record = client_keys.send().encrypt_next(c2s_probe)?.to_der()?;
	let c2s_plaintext = server_keys.recv().open(&mut c2s_record)?;
	let c2s_ok = c2s_plaintext == c2s_probe;

	let s2c_probe = b"server->client probe";
	let mut s2c_record = server_keys.send().encrypt_next(s2c_probe)?.to_der()?;
	let s2c_plaintext = client_keys.recv().open(&mut s2c_record)?;
	let s2c_ok = s2c_plaintext == s2c_probe;

	Ok(c2s_ok && s2c_ok)
}

/// What a pair of handshake machines showed as it completed.
struct Completion {
	/// Whether both machines were mid-flight before `complete()`.
	pending_before_completion: bool,
	/// Whether the session keys of each peer open the records of the other.
	keys_interoperate: bool,
	/// The profile that the client and the server selected.
	profiles: (Option<SecurityProfileDesc>, Option<SecurityProfileDesc>),
}

/// Completes both peers, and returns the [`Completion`] that they showed.
async fn complete_pair<C, S>(client: Box<C>, server: Box<S>) -> Result<Completion, TightBeamError>
where
	C: ClientHandshakeProtocol,
	S: ServerHandshakeProtocol,
{
	// `complete()` consumes each orchestrator and makes its final transition,
	// so the test reads both machines first. The pair is mid-flight here, and
	// the caller checks the transition that `complete()` makes.
	let pending_before_completion = !ClientHandshakeProtocol::is_complete(client.as_ref())
		&& !ServerHandshakeProtocol::is_complete(server.as_ref());

	let client_profile = ClientHandshakeProtocol::selected_profile(client.as_ref());
	let server_profile = ServerHandshakeProtocol::selected_profile(server.as_ref());

	let client_session = ClientHandshakeProtocol::complete(client).await?;
	let server_session = ServerHandshakeProtocol::complete(server).await?;
	let keys_interoperate = bidirectional_roundtrip_ok(client_session.keys(), server_session.keys())?;

	Ok(Completion {
		pending_before_completion,
		keys_interoperate,
		profiles: (client_profile, server_profile),
	})
}

/// Returns the handshake reply, or an expectation failure with `msg` when the
/// step drew none.
fn require_reply(reply: Option<HandshakeMessage>, msg: &'static str) -> Result<HandshakeMessage, TightBeamError> {
	let message = reply.ok_or_else(|| expectation_failure(msg))?;
	Ok(message)
}

/// Passes when a protocol step draws no reply, and returns an expectation
/// failure with `msg` otherwise.
fn require_terminal(reply: Option<HandshakeMessage>, msg: &'static str) -> Result<(), TightBeamError> {
	if reply.is_some() {
		return Err(expectation_failure(msg));
	}

	Ok(())
}

/// Runs the HPKE loopback through the orchestrator trait surface.
#[cfg(feature = "transport-hpke")]
#[tokio::test]
async fn hpke_loopback() -> Result<(), TightBeamError> {
	let materials = ServerMaterials::generate();
	let profile = default_security_profile();
	let offer = security_offer(profile);
	let validator = pinning_validator(&materials.certificate);

	let mut config = hpke_client_config::<DefaultCryptoProvider>(validator);
	config.security_offer = Some(offer);

	let mut client = Handshake::client(config);
	let server_config = hpke_server_config::<DefaultCryptoProvider>(&materials, [profile]);
	let mut server = Handshake::server(server_config);

	// The flow is the hello, then the signed reply, then the closing, which
	// draws no reply.
	let client_hello = ClientHandshakeProtocol::start(&mut client).await?;
	let server_reply = server.handle_request(client_hello).await?;
	let server_handshake = require_reply(server_reply, "HPKE server must answer the hello")?;

	let client_reply = client.handle_response(server_handshake).await?;
	let closing = require_reply(client_reply, "HPKE client must answer the reply")?;

	let no_reply = server.handle_request(closing).await?;
	require_terminal(no_reply, "HPKE server must not reply to the closing")?;

	let completion = complete_pair(Box::new(client), Box::new(server)).await?;
	assert!(
		completion.pending_before_completion,
		"both HPKE machines must be mid-flight before complete()"
	);
	assert!(
		completion.keys_interoperate,
		"the HPKE session keys must open each other's records"
	);
	assert_eq!(
		completion.profiles,
		(Some(profile), Some(profile)),
		"both HPKE machines must select the offered profile"
	);
	Ok(())
}

/// Builds a CMS client and server pair that shares the fixture server identity.
#[cfg(feature = "transport-cms")]
#[allow(clippy::type_complexity)]
fn build_cms_pair(
	materials: &ServerMaterials,
) -> Result<
	(
		Handshake<Client, Cms, DefaultCryptoProvider>,
		Handshake<Server, Cms, DefaultCryptoProvider>,
	),
	TightBeamError,
> {
	let profile = default_security_profile();
	let pair = cms_handshake_pair(materials, vec![profile], vec![profile], PeerAuthentication::Anonymous)?;
	Ok((Handshake::client(pair.client), Handshake::server(pair.server)))
}

/// Drives a CMS pair through its three legs. The flow is the opening, then
/// ServerFinished, then the closing with the ClientFinished, which draws no
/// reply.
#[cfg(feature = "transport-cms")]
async fn drive_cms_pair(
	client: &mut Handshake<Client, Cms, DefaultCryptoProvider>,
	server: &mut Handshake<Server, Cms, DefaultCryptoProvider>,
) -> Result<(), TightBeamError> {
	let opening = ClientHandshakeProtocol::start(client).await?;
	let server_reply = server.handle_request(opening).await?;
	let server_finished = require_reply(server_reply, "CMS server must answer the opening with ServerFinished")?;

	let client_reply = client.handle_response(server_finished).await?;
	let client_finished = require_reply(client_reply, "CMS client must answer ServerFinished with ClientFinished")?;

	let no_reply = server.handle_request(client_finished).await?;
	require_terminal(no_reply, "CMS server must not reply to ClientFinished")
}

/// Runs the CMS loopback through the orchestrator trait surface.
///
/// Both sides derive a working AEAD from the handshake secret, and the client
/// learns the negotiated profile from the server-Finished `SecurityAccept`
/// attribute and can `complete()`.
#[cfg(feature = "transport-cms")]
#[tokio::test]
async fn cms_loopback() -> Result<(), TightBeamError> {
	let materials = ServerMaterials::generate();
	let profile = default_security_profile();
	let (mut client, mut server) = build_cms_pair(&materials)?;
	drive_cms_pair(&mut client, &mut server).await?;

	let completion = complete_pair(Box::new(client), Box::new(server)).await?;
	assert!(
		completion.pending_before_completion,
		"both CMS machines must be mid-flight before complete()"
	);
	assert!(
		completion.keys_interoperate,
		"the CMS session keys must open each other's records"
	);
	assert_eq!(
		completion.profiles,
		(Some(profile), Some(profile)),
		"both CMS machines must select the offered profile"
	);
	Ok(())
}

/// Completes one CMS handshake against the fixture server, and returns both
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

/// CMS traffic keys must be fresh per handshake (CWE-321): a record of one
/// session does not open on another session against the same server.
#[cfg(feature = "transport-cms")]
#[tokio::test]
async fn cms_unique_traffic_keys() -> Result<(), TightBeamError> {
	let materials = ServerMaterials::generate();
	let (client_a, _server_a) = established_cms_pair(&materials).await?;
	let (_client_b, server_b) = established_cms_pair(&materials).await?;

	let probe = b"same probe under two sessions";
	let record_a = client_a.keys().send().encrypt_next(probe)?;

	let mut arrived_a = record_a.to_der()?;
	let isolated = server_b.keys().recv().open(&mut arrived_a).is_err();
	assert!(isolated, "a CMS record of one session must not open under another (CWE-321)");

	Ok(())
}
