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

#![cfg(all(
	feature = "tokio",
	feature = "testing",
	any(feature = "transport-hpke", feature = "transport-cms")
))]

use tightbeam::{
	crypto::{
		aead::SessionKeys,
		profiles::{DefaultCryptoProvider, SecurityProfileDesc},
	},
	der::Encode,
	tb_cases,
	transport::handshake::{ClientHandshakeProtocol, EstablishedSession, Handshake, ServerHandshakeProtocol},
};

#[cfg(feature = "transport-cms")]
use tightbeam::crypto::cms::EnvelopeError;
#[cfg(feature = "transport-cms")]
use tightbeam::transport::handshake::PeerAuthentication;
#[cfg(feature = "transport-cms")]
use tightbeam::TightBeamError;

use crate::common::security::{default_security_profile, ServerMaterials};

/// The probe that the client seals to the server.
const CLIENT_PROBE: &[u8] = b"client->server probe";

/// The probe that the server seals to the client.
const SERVER_PROBE: &[u8] = b"server->client probe";

/// The handshake flow of a loopback pair, over the fixture server and the
/// default profile.
#[derive(Clone, Copy)]
enum Backend {
	/// The hello, then the signed reply, then the closing.
	#[cfg(feature = "transport-hpke")]
	Hpke,
	/// The opening, then ServerFinished, then the closing with the
	/// ClientFinished.
	#[cfg(feature = "transport-cms")]
	Cms,
}

impl Backend {
	/// What a pair of this flow shows as it completes.
	async fn completion(self) -> Completion {
		let materials = ServerMaterials::fixed();
		let profile = default_security_profile();
		match self {
			#[cfg(feature = "transport-hpke")]
			Backend::Hpke => {
				let (client, server) = materials.hpke_pair::<DefaultCryptoProvider>([profile], [profile]);
				Completion::of(client, server).await
			}
			#[cfg(feature = "transport-cms")]
			Backend::Cms => {
				let pair = materials.cms_pair([profile], [profile], PeerAuthentication::Anonymous);
				Completion::of(Handshake::client(pair.client), Handshake::server(pair.server)).await
			}
		}
	}
}

/// What a pair of handshake machines showed as it completed.
struct Completion {
	/// Whether the client and the server read as complete before
	/// `complete()`.
	complete_before: (bool, bool),
	/// The probe of the client as the server opened it, then the probe of the
	/// server as the client opened it.
	opened: (Vec<u8>, Vec<u8>),
	/// The profile that the client and the server selected.
	profiles: (Option<SecurityProfileDesc>, Option<SecurityProfileDesc>),
}

impl Completion {
	/// Drives `client` and `server` to their last message and completes both,
	/// and returns what they showed.
	async fn of<C, S>(mut client: C, mut server: S) -> Self
	where
		C: ClientHandshakeProtocol + 'static,
		S: ServerHandshakeProtocol + 'static,
	{
		drive_pair(&mut client, &mut server).await;

		// `complete()` consumes each orchestrator and makes its final
		// transition, so the pair reads both machines first.
		let complete_before = (client.is_complete(), server.is_complete());
		let profiles = (client.selected_profile(), server.selected_profile());

		let (client_session, server_session) = complete_both(client, server).await;
		let opened = exchange_probes(&mut client_session.into_keys(), &mut server_session.into_keys());
		Completion { complete_before, opened, profiles }
	}
}

/// Drives `client` and `server` through the three legs of their flow, and
/// checks that the closing draws no reply.
async fn drive_pair<C, S>(client: &mut C, server: &mut S)
where
	C: ClientHandshakeProtocol,
	S: ServerHandshakeProtocol,
{
	let opening = client.start().await.expect("the client opens its handshake");
	let reply = server.handle_request(opening).await.expect("the server reads the opening");
	let reply = reply.expect("the server answers the opening");

	let closing = client.handle_response(reply).await.expect("the client reads the reply");
	let closing = closing.expect("the client answers the reply");

	let last = server.handle_request(closing).await.expect("the server reads the closing");
	assert!(last.is_none());
}

/// Completes `client` and `server`, and returns the session of each.
async fn complete_both<C, S>(client: C, server: S) -> (EstablishedSession, EstablishedSession)
where
	C: ClientHandshakeProtocol + 'static,
	S: ServerHandshakeProtocol + 'static,
{
	let client_session = ClientHandshakeProtocol::complete(Box::new(client)).await;
	let server_session = ServerHandshakeProtocol::complete(Box::new(server)).await;
	let client_session = client_session.expect("a driven client completes");
	(client_session, server_session.expect("a driven server completes"))
}

/// Seals each probe on the send key of one peer and opens it on the receive
/// key of the other, and returns the two opened plaintexts.
///
/// Each direction has its own key and record sequence, and each record has
/// its own content key.
fn exchange_probes(client_keys: &mut SessionKeys, server_keys: &mut SessionKeys) -> (Vec<u8>, Vec<u8>) {
	let mut c2s_record = sealed(client_keys, CLIENT_PROBE);
	let c2s_opened = server_keys.recv_mut().open(&mut c2s_record);
	let c2s_opened = c2s_opened.expect("the server opens the record of the client");

	let mut s2c_record = sealed(server_keys, SERVER_PROBE);
	let s2c_opened = client_keys.recv_mut().open(&mut s2c_record);
	let s2c_opened = s2c_opened.expect("the client opens the record of the server");
	(c2s_opened.to_vec(), s2c_opened.to_vec())
}

/// The DER of the next record that `keys` seals around `probe`.
fn sealed(keys: &SessionKeys, probe: &[u8]) -> Vec<u8> {
	let record = keys.send().encrypt_next(probe).expect("a fresh send key seals");
	record.to_der().expect("a record encodes")
}

// A loopback pair of each flow is mid-flight before `complete()`, so neither
// machine reads as complete.
tb_cases! {
	async fn a_handshake_pair_is_pending_before_completion(backend: Backend) {
		let completion = backend.completion().await;
		assert_eq!(completion.complete_before, (false, false));
	}
	cases {
		#[cfg(feature = "transport-hpke")]
		hpke => Backend::Hpke,
		#[cfg(feature = "transport-cms")]
		cms => Backend::Cms,
	}
}

// The session keys that each flow derives are complementary, so each peer
// opens the record of the other.
tb_cases! {
	async fn the_session_keys_of_each_peer_open_the_records_of_the_other(backend: Backend) {
		let completion = backend.completion().await;
		assert_eq!(completion.opened, (CLIENT_PROBE.to_vec(), SERVER_PROBE.to_vec()));
	}
	cases {
		#[cfg(feature = "transport-hpke")]
		hpke => Backend::Hpke,
		#[cfg(feature = "transport-cms")]
		cms => Backend::Cms,
	}
}

// Both peers of each flow select the one profile the client offers and the
// server runs. The CMS client learns it from the `SecurityAccept` attribute
// of ServerFinished.
tb_cases! {
	async fn both_peers_select_the_offered_profile(backend: Backend) {
		let profile = default_security_profile();
		let completion = backend.completion().await;
		assert_eq!(completion.profiles, (Some(profile), Some(profile)));
	}
	cases {
		#[cfg(feature = "transport-hpke")]
		hpke => Backend::Hpke,
		#[cfg(feature = "transport-cms")]
		cms => Backend::Cms,
	}
}

/// The client and the server sessions of one CMS handshake against the
/// fixture server of `materials`.
#[cfg(feature = "transport-cms")]
async fn established_cms_pair(materials: &ServerMaterials) -> (EstablishedSession, EstablishedSession) {
	let profile = default_security_profile();
	let pair = materials.cms_pair([profile], [profile], PeerAuthentication::Anonymous);
	let (mut client, mut server) = (Handshake::client(pair.client), Handshake::server(pair.server));

	drive_pair(&mut client, &mut server).await;
	complete_both(client, server).await
}

/// CMS traffic keys are fresh per handshake (CWE-321), so a record of one
/// session fails to unwrap under the key of another session against the same
/// server.
#[cfg(feature = "transport-cms")]
#[tokio::test]
async fn a_cms_record_of_one_session_opens_under_no_other() {
	let materials = ServerMaterials::fixed();
	let (client_a, _server_a) = established_cms_pair(&materials).await;
	let (_client_b, server_b) = established_cms_pair(&materials).await;
	let mut record_a = sealed(client_a.keys(), CLIENT_PROBE);

	let opened = server_b.into_keys().recv_mut().open(&mut record_a);
	assert!(matches!(opened, Err(TightBeamError::EnvelopeError(EnvelopeError::KeyUnwrap))));
}
