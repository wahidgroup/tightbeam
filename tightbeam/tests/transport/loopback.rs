//! Loopback end-to-end tests for handshake orchestrators.
//!
//! Drives the ECIES and CMS client/server orchestrators against each other
//! entirely through the `ClientHandshakeProtocol`/`ServerHandshakeProtocol`
//! trait surface (the same surface `io.rs` consumes) and verifies:
//!
//! - Both sides complete and agree on the negotiated profile
//! - The derived `RuntimeAead` keys match (bidirectional encrypt/decrypt)
//! - CMS session keys are random per handshake, never constant (CWE-321)

#![cfg(all(feature = "transport", feature = "x509", feature = "aead", feature = "tokio"))]

use std::sync::Arc;

use tightbeam::crypto::aead::Decryptor;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::secret::ToInsecure;
use tightbeam::exactly;
use tightbeam::random::generate_nonce;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::config::ScenarioConf;
use tightbeam::transport::handshake::negotiation::SecurityOffer;
use tightbeam::transport::handshake::{ClientHandshakeProtocol, ServerHandshakeProtocol};
use tightbeam::TightBeamError;

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

tb_assert_spec! {
	pub HandshakeLoopbackSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("loopback_ecies_complete", exactly!(ECIES_RUNS)),
			("loopback_ecies_roundtrip", exactly!(ECIES_RUNS)),
			("loopback_ecies_profile_agreed", exactly!(ECIES_RUNS)),
			("loopback_cms_complete", exactly!(CMS_RUNS)),
			("loopback_cms_roundtrip", exactly!(CMS_RUNS)),
			("loopback_cms_profile_agreed", exactly!(CMS_RUNS)),
			("loopback_cms_unique_keys", exactly!(CMS_RUNS))
		]
	}
}

tb_scenario! {
	name: handshake_loopback,
	config: ScenarioConf::<()>::builder()
		.with_spec(HandshakeLoopbackSpec::latest())
		.build(),
	environment Bare {
		exec: |trace| async move {
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

/// Verify both peers derived the same session key by pushing traffic through
/// the type-erased ciphers in both directions.
///
/// Distinct nonces per direction: the peers share one AEAD key, so a repeated
/// `(key, nonce)` pair would be GCM nonce reuse even inside a test.
fn assert_bidirectional_roundtrip(
	client_aead: &tightbeam::crypto::aead::RuntimeAead,
	server_aead: &tightbeam::crypto::aead::RuntimeAead,
) -> Result<(), TightBeamError> {
	let nonce_c2s = generate_nonce::<12>(None)?;
	let nonce_s2c = generate_nonce::<12>(None)?;
	assert_eq!(
		client_aead.nonce_size(),
		nonce_c2s.len(),
		"loopback assumes AES-GCM 12-byte nonces"
	);

	let c2s = client_aead.encrypt_content(b"client->server probe", nonce_c2s, None)?;
	let c2s_plain = server_aead.decrypt_content(&c2s)?.to_insecure()?;
	assert_eq!(
		&c2s_plain[..],
		b"client->server probe",
		"server must decrypt client traffic with the derived session key"
	);

	let s2c = server_aead.encrypt_content(b"server->client probe", nonce_s2c, None)?;
	let s2c_plain = client_aead.decrypt_content(&s2c)?.to_insecure()?;
	assert_eq!(
		&s2c_plain[..],
		b"server->client probe",
		"client must decrypt server traffic with the derived session key"
	);

	Ok(())
}

/// ECIES loopback through the orchestrator trait surface.
#[cfg(feature = "transport-ecies")]
async fn ecies_loopback(
	trace: &tightbeam::trace::TraceCollector,
	materials: &ServerMaterials,
) -> Result<(), TightBeamError> {
	let profile = default_security_profile();

	let mut client = EciesHandshakeClient::<DefaultCryptoProvider, Secp256k1EciesMessage>::new(None)
		.with_security_offer(SecurityOffer::new(vec![profile]))
		.with_certificate_validator(pinning_validator(&materials.certificate));
	let mut server = EciesHandshakeServer::<DefaultCryptoProvider>::new(
		Arc::clone(&materials.key_provider),
		Arc::clone(&materials.certificate),
		None,
		None,
	)
	.with_supported_profiles(vec![profile]);

	// ClientHello -> ServerHandshake -> ClientKeyExchange -> (no reply)
	let client_hello = ClientHandshakeProtocol::start(&mut client).await?;
	let server_handshake = server
		.handle_request(&client_hello)
		.await?
		.ok_or_else(|| expectation_failure("ECIES server must answer ClientHello"))?;
	let client_kex = client
		.handle_response(&server_handshake)
		.await?
		.ok_or_else(|| expectation_failure("ECIES client must answer ServerHandshake"))?;

	let no_reply = server.handle_request(&client_kex).await?;
	assert!(no_reply.is_none(), "ECIES server must not reply to ClientKeyExchange");

	let client_aead = ClientHandshakeProtocol::complete(&mut client).await?;
	let server_aead = ServerHandshakeProtocol::complete(&mut server).await?;
	assert!(
		ClientHandshakeProtocol::is_complete(&client),
		"ECIES client must report completion"
	);
	assert!(
		ServerHandshakeProtocol::is_complete(&server),
		"ECIES server must report completion"
	);

	trace.event("loopback_ecies_complete")?;
	assert_bidirectional_roundtrip(&client_aead, &server_aead)?;
	trace.event("loopback_ecies_roundtrip")?;

	assert_eq!(
		ClientHandshakeProtocol::selected_profile(&client),
		Some(profile),
		"ECIES client must record the negotiated profile"
	);
	assert_eq!(
		ServerHandshakeProtocol::selected_profile(&server),
		Some(profile),
		"ECIES server must record the negotiated profile"
	);

	trace.event("loopback_ecies_profile_agreed")?;

	Ok(())
}

/// Build a CMS client/server pair sharing the harness server identity.
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

	let client_key = k256::ecdsa::SigningKey::random(&mut OsRng);
	let client_cert = create_test_certificate(&client_key);
	let signing_key = Secp256k1SigningKey::from(client_key);
	let client_provider: Arc<dyn SigningKeyProvider> = Arc::new(Secp256k1KeyProvider::from(signing_key));
	let offer = SecurityOffer::new(vec![profile]);
	let trust_store = pinning_trust_store(&materials.certificate)?;

	let client = CmsHandshakeClient::<DefaultCryptoProvider>::new(
		DefaultCryptoProvider::default(),
		client_provider,
		Arc::clone(&materials.certificate),
	)
	.with_security_offer(offer)
	.with_trust_store(trust_store);

	let key_provider = Arc::clone(&materials.key_provider);
	let mut server =
		CmsHandshakeServer::<DefaultCryptoProvider>::new(key_provider, None).with_supported_profiles(vec![profile]);
	server.set_client_certificate(client_cert)?;

	Ok((client, server))
}

/// CMS loopback through the orchestrator trait surface.
///
/// Regression coverage for random session key lets both sides derive a working
/// AEAD and client learns the negotiated profile from the server-Finished
/// `SecurityAccept` attribute and can `complete()`.
#[cfg(feature = "transport-cms")]
async fn cms_loopback(
	trace: &tightbeam::trace::TraceCollector,
	materials: &ServerMaterials,
) -> Result<(), TightBeamError> {
	let profile = default_security_profile();
	let (mut client, mut server) = build_cms_pair(materials)?;

	// KeyExchange -> ServerFinished -> ClientFinished -> (no reply)
	let key_exchange = ClientHandshakeProtocol::start(&mut client).await?;

	// Confidentiality (CWE-311): the CMS backend transports the session key
	// wrapped inside the KeyExchange EnvelopedData, so the raw key MUST NOT
	// appear anywhere in the cleartext wire bytes. This is the CMS analogue of
	// the ECIES `confidentiality` threat test, exercised on the real
	// random-key path (not the harness's constant test key).
	let session_key = client
		.session_key()
		.ok_or_else(|| expectation_failure("CMS client must hold a session key after start"))?
		.with(|bytes| bytes.clone())?;
	assert!(
		!key_exchange
			.windows(session_key.len())
			.any(|window| window == session_key.as_slice()),
		"CMS session key must not appear in cleartext KeyExchange wire bytes"
	);

	let server_finished = server
		.handle_request(&key_exchange)
		.await?
		.ok_or_else(|| expectation_failure("CMS server must answer KeyExchange with ServerFinished"))?;
	let client_finished = client
		.handle_response(&server_finished)
		.await?
		.ok_or_else(|| expectation_failure("CMS client must answer ServerFinished with ClientFinished"))?;

	let no_reply = server.handle_request(&client_finished).await?;
	assert!(no_reply.is_none(), "CMS server must not reply to ClientFinished");

	let client_aead = ClientHandshakeProtocol::complete(&mut client).await?;
	let server_aead = ServerHandshakeProtocol::complete(&mut server).await?;
	assert!(
		ClientHandshakeProtocol::is_complete(&client),
		"CMS client must report completion"
	);
	assert!(
		ServerHandshakeProtocol::is_complete(&server),
		"CMS server must report completion"
	);

	trace.event("loopback_cms_complete")?;
	assert_bidirectional_roundtrip(&client_aead, &server_aead)?;
	trace.event("loopback_cms_roundtrip")?;

	assert_eq!(
		ClientHandshakeProtocol::selected_profile(&client),
		Some(profile),
		"CMS client must learn the negotiated profile from SecurityAccept"
	);
	assert_eq!(
		ServerHandshakeProtocol::selected_profile(&server),
		Some(profile),
		"CMS server must record the negotiated profile"
	);

	trace.event("loopback_cms_profile_agreed")?;

	Ok(())
}

/// CMS session keys must be random per handshake (CWE-321).
#[cfg(feature = "transport-cms")]
async fn cms_unique_session_keys(
	trace: &tightbeam::trace::TraceCollector,
	materials: &ServerMaterials,
) -> Result<(), TightBeamError> {
	let (mut client_a, _server_a) = build_cms_pair(materials)?;
	let (mut client_b, _server_b) = build_cms_pair(materials)?;

	let _kex_a = ClientHandshakeProtocol::start(&mut client_a).await?;
	let _kex_b = ClientHandshakeProtocol::start(&mut client_b).await?;

	let key_a = client_a
		.session_key()
		.ok_or_else(|| expectation_failure("CMS client A must hold a session key after start"))?
		.with(|bytes| bytes.clone())?;
	let key_b = client_b
		.session_key()
		.ok_or_else(|| expectation_failure("CMS client B must hold a session key after start"))?
		.with(|bytes| bytes.clone())?;
	assert_ne!(key_a, vec![0u8; 32], "CMS session key must never be the constant zero key");
	assert_ne!(key_b, vec![0u8; 32], "CMS session key must never be the constant zero key");
	assert_ne!(key_a, key_b, "independent CMS handshakes must generate distinct session keys");

	trace.event("loopback_cms_unique_keys")?;

	Ok(())
}
