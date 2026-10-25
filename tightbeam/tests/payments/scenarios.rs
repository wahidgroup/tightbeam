//! The test scenarios of the payment gateway.
//!
//! One scenario sends a signed, hashed, and encrypted payment authorization
//! through a cluster, a hive, and a servlet with bio-inspired ACO/ABC routing.
//! A second scenario seals a card token to the key manager servlet, which
//! opens it and refuses a tampered copy.

#![cfg(all(
	feature = "std",
	feature = "tokio",
	feature = "testing",
	feature = "x509",
	feature = "secp256k1",
	feature = "signature"
))]

use std::sync::Arc;

use sha3::Sha3_256;
use tightbeam::exactly;
use tightbeam::{
	builder::TypeBuilder,
	colony::{
		cluster::{Cluster, ClusterConfig, ClusterTlsConfig},
		hive::{Hive, HiveConfig, HiveTlsConfig},
		servlet::ServletConfig,
		urn::ColonyNamespace,
		SubmitWork,
	},
	compose,
	crypto::{
		hpke::{HpkePublicKeyOps, HpkeSecp256k1Sha256Aes256Gcm},
		key::{Aes256GcmKeyProvider, Secp256k1KeyProvider},
		policy::Secp256k1Policy,
		profiles::DefaultCryptoProvider,
		sign::{
			ecdsa::{
				k256::{PublicKey, SecretKey},
				Secp256k1Signature, Secp256k1SigningKey,
			},
			CertifiedKey,
		},
		x509::{
			store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder},
			Certificate, CertificateSpec,
		},
	},
	decode,
	instrumentation::events,
	policy::TransitStatus,
	random::OsRng,
	tb_assert_spec, tb_scenario,
	testing::{ClientEnv, ServletEnv, SetupEnv},
	transport::{
		handshake::negotiation::TransportOffer, tcp::r#async::TokioListener, ClientBuilder, ConnectionBuilder,
		TransportError,
	},
	urn::Urn,
	Frame, TightBeamError, Version,
};

use crate::common::hive::scenario_hive_config;
use crate::common::security::expectation_failure;
use crate::common::x509::create_test_cert_with_key;

use super::cluster::PaymentGatewayCluster;
use super::currency::MonetaryAmount;
use super::hives::PaymentProcessorHive;
use super::messages::{
	CreditTransferTransaction, DecryptRequest, DecryptResponse, GetPublicKeyRequest, GetPublicKeyResponse,
	PaymentIdentification, TransactionStatus,
};
use super::servlets::{
	AuthorizationServlet, KeyManagerRequest, KeyManagerServlet, AUTHORIZATION_APPROVED, INTEGRITY_VERIFIED,
	KEYMANAGER_DECRYPT_SUCCESS, KEYMANAGER_PUBKEY_SERVED, KEY_MANAGER_HPKE_INFO,
};

/// Client-observed work reply status (`TransitStatus` on the wire response).
pub(crate) const WORK_STATUS: Urn<'static> = tightbeam::urn!("test", "event:scenarios/work-status");

/// Client-observed approval decoded from inside the servlet's response frame.
pub(crate) const CLIENT_AUTH_APPROVED: Urn<'static> = tightbeam::urn!("test", "event:scenarios/client-auth-approved");

/// Client-observed plaintext of the key manager's reply to a sealed card token.
pub(crate) const OPENED_CARD_TOKEN: Urn<'static> = tightbeam::urn!("test", "event:scenarios/opened-card-token");

/// Client-observed status of the key manager's reply to a tampered card token.
pub(crate) const TAMPERED_TOKEN_STATUS: Urn<'static> = tightbeam::urn!("test", "event:scenarios/tampered-token-status");

/// The card token that the client seals to the key manager.
const CARD_TOKEN: &str = "tok_4111_1111_1111_1111";

/// The type URN that the payment scenario registers and targets.
fn authorization_urn() -> Urn<'static> {
	ColonyNamespace::default()
		.servlet("authorization")
		.expect("test names satisfy the mint grammar")
}

struct TestCerts {
	cluster_cert: Certificate,
	cluster_key: Secp256k1SigningKey,
	cluster_trust: Arc<dyn CertificateTrust>,
	hive_cert: Certificate,
	hive_key: Secp256k1SigningKey,
	hive_trust: Arc<dyn CertificateTrust>,
}

impl TestCerts {
	fn generate() -> Self {
		let (cluster_cert, cluster_key) =
			create_test_cert_with_key("CN=Payment Gateway", 365).expect("Failed to create cluster cert");
		let cluster_trust: Arc<dyn CertificateTrust> = Arc::new(
			CertificateTrustBuilder::from(Secp256k1Policy::default())
				.with_chain(vec![cluster_cert.to_owned()])
				.expect("Failed to build cluster trust")
				.build(),
		);

		let (hive_cert, hive_key) =
			create_test_cert_with_key("CN=Payment Hive", 365).expect("Failed to create hive cert");
		let hive_trust: Arc<dyn CertificateTrust> = Arc::new(
			CertificateTrustBuilder::from(Secp256k1Policy::default())
				.with_chain(vec![hive_cert.to_owned()])
				.expect("Failed to build hive trust")
				.build(),
		);

		Self { cluster_cert, cluster_key, cluster_trust, hive_cert, hive_key, hive_trust }
	}

	/// The certificate and the signing key that the hive and each servlet
	/// present.
	fn hive_identity(&self) -> (CertificateSpec, Arc<Secp256k1KeyProvider>) {
		let certificate = CertificateSpec::Built(Box::new(self.hive_cert.to_owned()));
		let key = Arc::new(Secp256k1KeyProvider::from(self.hive_key.to_owned()));
		(certificate, key)
	}
}

fn cluster_tls_config(certs: &TestCerts) -> ClusterTlsConfig {
	ClusterTlsConfig::new(
		CertificateSpec::Built(Box::new(certs.cluster_cert.to_owned())),
		Arc::new(Secp256k1KeyProvider::from(certs.cluster_key.to_owned())),
	)
	.expect("the test certificate must decode")
	.with_hive_trust(Some(Arc::clone(&certs.hive_trust)))
}

fn hive_tls_config(certs: &TestCerts) -> HiveConfig {
	let (certificate, key) = certs.hive_identity();
	let hive_tls = HiveTlsConfig::new(certificate, key, vec![]).expect("the hive TLS material must decode");
	HiveConfig {
		hive_tls: Some(Arc::new(hive_tls)),
		trust_store: Some(Arc::clone(&certs.cluster_trust)),
		..scenario_hive_config()
	}
}

fn servlet_tls_config(
	certs: &TestCerts,
) -> Result<ServletConfig<TokioListener, CreditTransferTransaction, DefaultCryptoProvider>, TightBeamError> {
	let (certificate, key) = certs.hive_identity();
	Ok(
		ServletConfig::<TokioListener, CreditTransferTransaction, DefaultCryptoProvider>::builder()
			.with_certificate(certificate, key, vec![])?
			// The servlet offers mux as the cluster and the hive do, so work
			// forwards negotiate mux.
			.with_mux_offer(Some(TransportOffer::mux(8)))
			.with_message_decryptor(shared_payment_cipher())
			.with_config(Arc::new(()))
			.build(),
	)
}

/// The shared key-encryption key of the client-to-servlet confidential body.
///
/// `CreditTransferTransaction` declares `confidential`, so the client
/// frame carries an encrypted message and the servlet decrypts it before
/// typed dispatch. A fixed key stands in for a real exchange in tests.
fn shared_payment_cipher() -> Aes256GcmKeyProvider {
	let cipher = Aes256GcmKeyProvider::new(vec![0x42u8; 32], b"tb/test/payments/kek/v1".to_vec());
	cipher.expect("32 octets is the key of AES-256 key wrap")
}

fn create_auth_transaction(end_to_end_id: impl AsRef<[u8]>, amount: MonetaryAmount) -> CreditTransferTransaction {
	let end_to_end_id = end_to_end_id.as_ref();
	let timestamp = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_millis() as u64)
		.unwrap_or(0);

	CreditTransferTransaction::new(
		PaymentIdentification::new(
			format!("INST{}", timestamp).as_bytes(),
			end_to_end_id,
			format!("TXN{}", timestamp).as_bytes(),
		),
		amount,
		b"CRED_ACCT_TOKEN",
		b"DEB_ACCT_TOKEN",
		Some(b"Payment for services".to_vec()),
		timestamp,
	)
}

tb_assert_spec! {
	pub PaymentGatewaySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_WORK_ROUTED, exactly!(1)),
			(events::CLUSTER_WORK_REFUSED, exactly!(0)),
			(events::CLUSTER_WORK_UNAVAILABLE, exactly!(0)),
			(events::CLUSTER_WORK_FAILED, exactly!(0)),
			(events::CLUSTER_REGISTER_REFUSED, exactly!(0)),
			(WORK_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(AUTHORIZATION_APPROVED, exactly!(1), equals!(true)),
			(INTEGRITY_VERIFIED, exactly!(1), equals!(true)),
			(CLIENT_AUTH_APPROVED, exactly!(1), equals!(true))
		]
	}
}

tb_scenario! {
	name: payment_gateway_cluster,
	spec: PaymentGatewaySpec,
	environment Bare {
		context: TestCerts::generate(),
		exec: |SetupEnv { trace, context: certs }| async move {
			// The cluster, the hive, and the servlet share one collector, so
			// cluster instrument events and servlet outcomes land on the
			// scenario spec, as in the colony registration tests.
			let mut cluster_conf = ClusterConfig::new(cluster_tls_config(&certs));
			cluster_conf.pool_config.mux_offer = Some(Arc::new(TransportOffer::mux(8)));

			let cluster = PaymentGatewayCluster::start(Arc::new(trace.share()), cluster_conf).await?;
			let cluster_addr = cluster.addr();

			let servlet_conf = servlet_tls_config(&certs)?;
			let servlet = AuthorizationServlet::start(Arc::new(trace.share()), servlet_conf).await?;

			let mut hive_conf = hive_tls_config(&certs);
			hive_conf.pool.mux_offer = Some(Arc::new(TransportOffer::mux(8)));

			let mut hive = PaymentProcessorHive::new(Some(hive_conf))?;
			let spawner = |t| AuthorizationServlet::start(t, ServletConfig::cleartext());
			hive.register(authorization_urn(), servlet, spawner)?;
			hive.establish(Arc::new(trace.share())).await?;

			let _reg_response = hive.register_with_cluster(cluster_addr).await?;

			let transaction = create_auth_transaction(b"E2E-001", MonetaryAmount::new(10000, *b"USD"));
			let inner = Version::V1.compose()
				.with_id(b"payment-auth-txn")
				.with_order(0)
				.with_message(transaction)
				.with_message_hasher::<Sha3_256>([])
				.with_witness_hasher::<Sha3_256>()
				.with_encryptor(shared_payment_cipher())
				.with_signer::<Secp256k1Signature, _>(CertifiedKey::new(&certs.cluster_cert, certs.cluster_key.to_owned())?)
				.build()?;

			let builder = ClientBuilder::<TokioListener>::builder()
				.with_trust_store(Arc::clone(&certs.cluster_trust))
				.build();

			// `submit_work_to` returns the servlet's frame under an `Ok`
			// gateway status alone (`ClusterWorkResponse::served`), so the
			// event after it records the wire status that the spec asserts.
			let mut client = builder.connect(cluster_addr.to_owned()).await?;
			let servlet_frame = client.submit_work_to(authorization_urn(), &inner).await?;
			trace.event_with(WORK_STATUS, &[], TransitStatus::Ok)?;

			// The gateway returns the servlet's complete response frame. The
			// typed approval decodes from inside it, which proves that the
			// response envelope survived the route back to the client.
			let status: TransactionStatus = decode(servlet_frame.message())?;
			trace.event_with(CLIENT_AUTH_APPROVED, &[], status.status.is_success())?;

			hive.stop();
			cluster.stop();

			Ok(())
		}
	}
}

/// The frame that carries `request` to the key manager under `id`.
fn key_manager_frame(id: impl AsRef<[u8]>, request: KeyManagerRequest) -> Frame {
	let frame = compose! {
		V0: id: id.as_ref(),
			message: request
	};

	frame.expect("a key manager request composes into a V0 frame")
}

/// `ciphertext` with the last octet of its AEAD tag flipped.
fn with_flipped_tag(ciphertext: impl AsRef<[u8]>) -> Vec<u8> {
	let mut tampered = ciphertext.as_ref().to_vec();
	let last = tampered.last_mut().expect("an HPKE ciphertext ends with its AEAD tag");
	*last ^= 0x01;

	tampered
}

/// Resolves the reply to a request that the key manager must refuse into the
/// transit status of the refusal.
///
/// A served reply and a failure with no transit status are errors, so a local
/// transport fault cannot pass for the refusal.
fn refusal_status(reply: Result<Option<Frame>, TransportError>) -> Result<TransitStatus, TightBeamError> {
	match reply {
		Err(error) => error.transit_status().ok_or_else(|| error.into()),
		Ok(_) => Err(expectation_failure("the key manager served a tampered card token")),
	}
}

tb_assert_spec! {
	pub KeyManagerSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(KEYMANAGER_PUBKEY_SERVED, exactly!(1), equals!(true)),
			(KEYMANAGER_DECRYPT_SUCCESS, exactly!(1), equals!(true)),
			(OPENED_CARD_TOKEN, exactly!(1), equals!(CARD_TOKEN)),
			(TAMPERED_TOKEN_STATUS, exactly!(1), equals!(TransitStatus::Internal))
		]
	}
}

// The client seals a card token to the public key that the key manager
// serves, and the key manager opens it. A copy with one tag octet flipped
// fails to open, so the handler fails and the client reads `Internal`.
tb_scenario! {
	name: key_manager_opens_a_sealed_card_token,
	spec: KeyManagerSpec,
	environment Servlet {
		context: TestCerts::generate(),
		start: |SetupEnv { trace, context: certs }| async move {
			let hpke_key = Arc::new(SecretKey::random(&mut OsRng));
			let (certificate, key) = certs.hive_identity();
			let servlet_conf = ServletConfig::<TokioListener, KeyManagerRequest>::builder()
				.with_certificate(certificate, key, vec![])?
				.with_config(Arc::new(hpke_key))
				.build();

			KeyManagerServlet::start(Arc::new(trace), servlet_conf).await
		},
		setup: |ClientEnv { addr, context: certs, .. }| async move {
			let builder = ClientBuilder::<TokioListener>::builder()
				.with_trust_store(Arc::clone(&certs.hive_trust))
				.build();
			let client = builder.connect(addr).await?;
			Ok(client)
		},
		client: |ServletEnv { trace, mut client, .. }| async move {
			let key_request = KeyManagerRequest::GetPublicKey(GetPublicKeyRequest { _placeholder: None });
			let key_reply = client.emit(key_manager_frame(b"key-manager-public-key", key_request), None).await?;
			let key_frame = key_reply.ok_or(TightBeamError::MissingResponse)?;
			let served: GetPublicKeyResponse = decode(key_frame.message())?;
			let public_key = PublicKey::from_sec1_bytes(&served.public_key)?;
			let sealed = public_key.seal::<HpkeSecp256k1Sha256Aes256Gcm>(KEY_MANAGER_HPKE_INFO, b"", CARD_TOKEN, None)?;
			let ciphertext = sealed.to_bytes();
			let tampered = with_flipped_tag(&ciphertext);

			let open_request = KeyManagerRequest::Decrypt(DecryptRequest { ciphertext });
			let open_reply = client.emit(key_manager_frame(b"key-manager-open", open_request), None).await?;
			let open_frame = open_reply.ok_or(TightBeamError::MissingResponse)?;
			let opened: DecryptResponse = decode(open_frame.message())?;
			trace.event_with(OPENED_CARD_TOKEN, &[], String::from_utf8_lossy(&opened.plaintext).into_owned())?;

			let tampered_request = KeyManagerRequest::Decrypt(DecryptRequest { ciphertext: tampered });
			let tampered_reply = client.emit(key_manager_frame(b"key-manager-tampered", tampered_request), None).await;
			trace.event_with(TAMPERED_TOKEN_STATUS, &[], refusal_status(tampered_reply)?)?;

			Ok(())
		}
	}
}
