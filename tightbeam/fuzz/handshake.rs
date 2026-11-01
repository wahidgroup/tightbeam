//! The handshake against a hostile peer.
//!
//! A peer controls each message of a handshake before any signature or seal
//! holds. This target plays those messages at both endpoints of both flows,
//! and at the decoders of the handshake types. The first input octet picks the
//! stage, and the rest of the input is the message.
//!
//! # Properties
//!
//! - A hostile message ends in a typed answer, so a panic is a crash.
//! - A reply or a closing that AFL wrote is refused, because each carries a
//!   proof of its peer. An opening carries none, so a server may answer one.
//! - A refused reply or closing spends the handshake, so a peer gets one attempt.
//! - A handshake type re-encodes to the octets it decoded from.
//!
//! # Reach
//!
//! Any client can seal to the key of a server, so one stage seals the input
//! itself. That stage reaches the decoder of the opening content, which sits
//! behind the seal. The content of a closing sits behind a key of the session
//! and stays out of reach.
//!
//! # Run
//!
//!   cargo afl build --bin fuzz_handshake --features "full,testing-fuzz"
//!   cargo afl fuzz -i tightbeam/fuzz/handshake/seeds -o fuzz_out \
//!     target/debug/fuzz_handshake

#![allow(unexpected_cfgs)]
#![cfg(all(feature = "full", feature = "testing-fuzz"))]

use std::sync::{Arc, OnceLock};

use tightbeam::cms::content_info::ContentInfo;
use tightbeam::cms::signed_data::SignedData;
use tightbeam::constants::TIGHTBEAM_OPENING_UKM_LABEL;
use tightbeam::crypto::cms::{AuthEnvelopedData, Recipient};
use tightbeam::crypto::key::{Secp256k1KeyProvider, SigningKeyProvider};
use tightbeam::crypto::profiles::{DefaultCryptoProvider, SecurityProfileDesc, TightbeamProfile};
use tightbeam::crypto::sign::ecdsa::Secp256k1SigningKey;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::policy::{CertificateValidation, DirectTrustValidator};
use tightbeam::crypto::x509::KeyPurposes;
use tightbeam::oids::HANDSHAKE_OPENING_CONTENT;
use tightbeam::random::OsRng;
use tightbeam::tb_scenario;
use tightbeam::testing::fixtures::{TestCertificate, TestKey};
use tightbeam::testing::fuzz::assert_one_encoding;
use tightbeam::testing::TestCmsServer;
use tightbeam::transport::handshake::receipt::SessionReceipt;
use tightbeam::transport::handshake::{
	Client, ClientConfig, ClientFlow, ClientHello, Cms, CmsClientSettings, CmsServerSettings, Handshake,
	HandshakeMessage, HandshakePhase, Hpke, HpkeClientSettings, HpkeServerSettings, LearnedTrust, Server, ServerConfig,
	ServerFlow, ServerHandshake, SupportedProfiles,
};
use tightbeam::transport::wire_der::WireDer;

/// The provider of every endpoint of the target.
type Provider = DefaultCryptoProvider;

/// The message that one iteration plays.
#[derive(Clone, Copy)]
enum Stage {
	/// The opening that an HPKE server reads.
	HpkeOpening,
	/// The opening that a CMS server reads.
	CmsOpening,
	/// The reply that an HPKE client reads after its own opening.
	HpkeReply,
	/// The Finished that a CMS client reads after its own opening.
	CmsReply,
	/// The closing that an HPKE server reads after a genuine opening.
	HpkeClosing,
	/// The closing that a CMS server reads after a genuine opening.
	CmsClosing,
	/// The DER of a [`ClientHello`].
	Hello,
	/// The DER of a [`ServerHandshake`].
	ServerContent,
	/// The DER of a [`SessionReceipt`].
	Receipt,
	/// The content that a CMS client seals to the server in its opening.
	OpeningContent,
}

impl Stage {
	/// Every stage, in the order that the selector octet names.
	const ALL: [Self; 10] = [
		Self::HpkeOpening,
		Self::CmsOpening,
		Self::HpkeReply,
		Self::CmsReply,
		Self::HpkeClosing,
		Self::CmsClosing,
		Self::Hello,
		Self::ServerContent,
		Self::Receipt,
		Self::OpeningContent,
	];

	/// The stage that `selector` names.
	fn of(selector: u8) -> Self {
		let stage = Self::ALL.iter().cycle().nth(usize::from(selector));
		*stage.expect("a cycle of stages never ends")
	}

	/// Plays `message` at this stage.
	async fn play(self, message: &[u8], materials: &Materials) {
		match self {
			Self::HpkeOpening => {
				if let Ok(wire) = WireDer::<ContentInfo>::try_from(message) {
					let opening = HandshakeMessage::Data(Box::new(wire));
					let answer = Handshake::server(materials.hpke_server()).reply(opening).await;
					drop(answer);
				}
			}
			Self::CmsOpening => {
				if let Ok(wire) = WireDer::<AuthEnvelopedData>::try_from(message) {
					let opening = HandshakeMessage::AuthEnvelopedData(Box::new(wire));
					let answer = Handshake::server(materials.cms_server()).reply(opening).await;
					drop(answer);
				}
			}
			Self::HpkeReply => {
				if let Ok(wire) = WireDer::<SignedData>::try_from(message) {
					let reply = HandshakeMessage::SignedData(Box::new(wire));
					refuse_reply(Handshake::client(materials.hpke_client()), reply).await;
				}
			}
			Self::CmsReply => {
				if let Ok(wire) = WireDer::<SignedData>::try_from(message) {
					let reply = HandshakeMessage::SignedData(Box::new(wire));
					refuse_reply(Handshake::client(materials.cms_client()), reply).await;
				}
			}
			Self::HpkeClosing => {
				if let Ok(wire) = WireDer::<AuthEnvelopedData>::try_from(message) {
					let closing = HandshakeMessage::AuthEnvelopedData(Box::new(wire));
					let client = Handshake::client(materials.hpke_client());
					let server = Handshake::server(materials.hpke_server());
					refuse_closing(client, server, closing).await;
				}
			}
			Self::CmsClosing => {
				if let Ok(wire) = WireDer::<AuthEnvelopedData>::try_from(message) {
					let closing = HandshakeMessage::AuthEnvelopedData(Box::new(wire));
					let client = Handshake::client(materials.cms_client());
					let server = Handshake::server(materials.cms_server());
					refuse_closing(client, server, closing).await;
				}
			}
			Self::Hello => assert_one_encoding::<ClientHello>(message),
			Self::ServerContent => assert_one_encoding::<ServerHandshake>(message),
			Self::Receipt => assert_one_encoding::<SessionReceipt>(message),
			Self::OpeningContent => {
				let identity = materials.cms_server.key_agreement_identity();
				let recipient =
					Recipient::Kem { recipient: identity.recipient(), ukm_label: TIGHTBEAM_OPENING_UKM_LABEL };
				let sealed = AuthEnvelopedData::seal::<Provider>(
					recipient,
					HANDSHAKE_OPENING_CONTENT,
					message.to_vec(),
					[],
					Some(&mut OsRng),
				);
				let opening = HandshakeMessage::try_from(sealed.expect("a seal takes any content"));
				let opening = opening.expect("a sealed opening encodes");

				let answer = Handshake::server(materials.cms_server()).reply(opening).await;
				drop(answer);
			}
		}
	}
}

/// Starts `client`, and holds it to the refusal of `reply`.
async fn refuse_reply<F: ClientFlow<Provider>>(mut client: Handshake<Client, F, Provider>, reply: HandshakeMessage) {
	let opening = client.start();
	opening.expect("a client starts");

	let answer = client.respond(reply).await;
	let spent = client.phase() == HandshakePhase::Spent;
	assert!(answer.is_err(), "a client accepted a reply that AFL wrote");
	assert!(spent, "a refused reply left the handshake alive");
}

/// Runs the genuine opening of `client` through `server`, and holds `server`
/// to the refusal of `closing`.
async fn refuse_closing<F>(
	mut client: Handshake<Client, F, Provider>,
	mut server: Handshake<Server, F, Provider>,
	closing: HandshakeMessage,
) where
	F: ClientFlow<Provider> + ServerFlow<Provider>,
{
	let opening = client.start().expect("a client starts");
	let reply = server.reply(opening).await;
	reply.expect("a server answers a genuine opening");

	let answer = server.finish(closing).await;
	let spent = server.phase() == HandshakePhase::Spent;
	assert!(answer.is_err(), "a server accepted a closing that AFL wrote");
	assert!(spent, "a refused closing left the handshake alive");
}

/// The credentials of every endpoint, built once in each fuzz process.
struct Materials {
	/// The certificate and the key of the HPKE server.
	hpke_identity: SigningIdentity,
	/// The validator through which an HPKE client pins that certificate.
	hpke_validator: Arc<dyn CertificateValidation>,
	/// The two identities of the CMS server.
	cms_server: TestCmsServer,
	/// The identity that a CMS client presents.
	cms_identity: SigningIdentity,
}

impl Materials {
	/// The credentials of one fuzz process.
	fn generate() -> Self {
		let hpke_key = TestKey::insecure_fixed_signing();
		let hpke_certificate = TestCertificate::self_signed(&hpke_key);
		let trust_chain = vec![hpke_certificate.clone()];
		let validator = DirectTrustValidator::default().with_trust_chain(trust_chain);
		let validator = validator.expect("a test certificate encodes");

		Self {
			hpke_identity: identity_of(hpke_key, hpke_certificate),
			hpke_validator: Arc::new(validator),
			cms_server: TestCmsServer::generate("tightbeam fuzz server"),
			cms_identity: {
				let cms_key = Secp256k1SigningKey::random(&mut OsRng);
				let cms_certificate = TestCertificate::self_signed(&cms_key);
				identity_of(cms_key, cms_certificate)
			},
		}
	}

	/// The configuration of an HPKE server.
	fn hpke_server(&self) -> ServerConfig<Hpke, Provider> {
		let identity = self.hpke_identity.clone();
		let config = ServerConfig::new(HpkeServerSettings::new(), identity, profiles(), KeyPurposes::HOUSE);
		config.expect("a test server identity serves the server role")
	}

	/// The configuration of a CMS server.
	fn cms_server(&self) -> ServerConfig<Cms, Provider> {
		let pair = self.cms_server.pair();
		let config = ServerConfig::new(CmsServerSettings, pair, profiles(), KeyPurposes::HOUSE);
		config.expect("a test server pair serves the server role")
	}

	/// The configuration of an HPKE client that pins the HPKE server.
	fn hpke_client(&self) -> ClientConfig<Hpke, Provider> {
		let trust = LearnedTrust::from(Arc::clone(&self.hpke_validator));
		let config = ClientConfig::new(HpkeClientSettings::new(trust), KeyPurposes::HOUSE);
		config.expect("an anonymous client holds no identity to refuse")
	}

	/// The configuration of a CMS client that seals to the CMS server.
	fn cms_client(&self) -> ClientConfig<Cms, Provider> {
		let settings = CmsClientSettings { trust: self.cms_server.trust(), identity: self.cms_identity.clone() };
		let config = ClientConfig::new(settings, KeyPurposes::HOUSE);
		config.expect("a test client identity serves the client role")
	}
}

/// The identity of `key` under `certificate`.
fn identity_of(key: Secp256k1SigningKey, certificate: tightbeam::x509::Certificate) -> SigningIdentity {
	let provider: Arc<dyn SigningKeyProvider> = Arc::new(Secp256k1KeyProvider::from(key));
	let identity = SigningIdentity::new(Arc::new(certificate), provider);
	identity.expect("a test key matches its certificate")
}

/// The one profile that every server runs.
fn profiles() -> SupportedProfiles {
	SupportedProfiles::from(SecurityProfileDesc::from(&TightbeamProfile))
}

/// The credentials of this fuzz process.
static MATERIALS: OnceLock<Materials> = OnceLock::new();

tb_scenario! {
	fuzz: afl,
	raw: |data: &[u8]| {
		let Some((selector, message)) = data.split_first() else {
			return;
		};

		// The runtime holds no worker thread, and the iteration builds it, so
		// nothing runs across the AFL forkserver handoff.
		let built = tokio::runtime::Builder::new_current_thread().enable_all().build();
		let runtime = built.expect("the harness builds its Tokio runtime");
		let materials = MATERIALS.get_or_init(Materials::generate);

		runtime.block_on(Stage::of(*selector).play(message, materials));
	}
}
