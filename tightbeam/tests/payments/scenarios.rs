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
		servlet::{ServletConfig, ServletFuture},
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
	der::asn1::OctetString,
	encode,
	instrumentation::events,
	policy::TransitStatus,
	random::OsRng,
	tb_assert_spec, tb_scenario,
	testing::{ClientEnv, ServletEnv, SetupEnv},
	trace::TraceCollector,
	transport::{
		handshake::negotiation::TransportOffer,
		tcp::{r#async::TokioListener, TightBeamSocketAddr},
		ClientBuilder, ConnectionBuilder, GenericClient, TransportError,
	},
	urn::Urn,
	utils::digest,
	Frame, Message, TightBeamError, Version,
};

use crate::common::hive::scenario_hive_config;
use crate::common::security::expectation_failure;
use crate::common::x509::create_test_cert_with_key;

use super::cluster::PaymentGatewayCluster;
use super::currency::MonetaryAmount;
use super::harness::{PaymentHarness, CHAIN_BROKEN, CHAIN_VALID, DEDUP_CACHE_HIT};
use super::hives::PaymentProcessorHive;
use super::messages::{
	CaptureTransaction, CreditTransferTransaction, DecryptRequest, DecryptResponse, GetPublicKeyRequest,
	GetPublicKeyResponse, PaymentIdentification, TransactionStatus,
};
use super::servlets::{
	AuthorizationServlet, CaptureServlet, KeyManagerRequest, KeyManagerServlet, AUTHORIZATION_APPROVED,
	CAPTURE_COMPLETED, INTEGRITY_VERIFIED, KEYMANAGER_DECRYPT_SUCCESS, KEYMANAGER_PUBKEY_SERVED, KEY_MANAGER_HPKE_INFO,
};

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

fn servlet_tls_config<M: Message>(
	certs: &TestCerts,
	harness: &Arc<PaymentHarness>,
) -> Result<ServletConfig<TokioListener, M, DefaultCryptoProvider, PaymentHarness>, TightBeamError> {
	let (certificate, key) = certs.hive_identity();
	Ok(ServletConfig::<TokioListener, M, DefaultCryptoProvider>::builder()
		.with_certificate(certificate, key, vec![])?
		// The servlet offers mux as the cluster and the hive do, so work
		// forwards negotiate mux.
		.with_mux_offer(Some(TransportOffer::mux(8)))
		.with_message_decryptor(shared_payment_cipher())
		.with_config(Arc::clone(harness))
		.build())
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

	let payment_id = PaymentIdentification::new(
		format!("INST{}", timestamp).as_bytes(),
		end_to_end_id,
		format!("TXN{}", timestamp).as_bytes(),
	);

	let payment_id = payment_id.expect("short identifiers fit an OCTET STRING");
	let transaction = CreditTransferTransaction::new(
		payment_id,
		amount,
		b"CRED_ACCT_TOKEN",
		b"DEB_ACCT_TOKEN",
		Some(b"Payment for services".to_vec()),
		timestamp,
	);
	transaction.expect("short references fit an OCTET STRING")
}

/// The frame that carries `transaction` to an authorization servlet: hashed,
/// witnessed, sealed under the shared payment cipher, and signed by the
/// cluster key.
fn authorization_frame(certs: &TestCerts, transaction: CreditTransferTransaction) -> Frame {
	let signer = CertifiedKey::new(&certs.cluster_cert, certs.cluster_key.to_owned());
	let frame = Version::V1
		.compose()
		.with_id(b"payment-auth-txn")
		.with_order(0)
		.with_message(transaction)
		.with_message_hasher::<Sha3_256>([])
		.with_witness_hasher::<Sha3_256>()
		.with_encryptor(shared_payment_cipher())
		.with_signer::<Secp256k1Signature, _>(signer.expect("the cluster key certifies"))
		.build();

	frame.expect("an authorization frame builds")
}

/// The start of an authorization instance, which the hive calls for each
/// instance it spawns.
///
/// Each instance presents the hive certificate, offers mux, opens the
/// confidential body with the shared payment cipher, and records into the
/// payment flow of `harness`.
fn authorization_spawner(
	certs: Arc<TestCerts>,
	harness: Arc<PaymentHarness>,
) -> impl Fn(Arc<TraceCollector>) -> ServletFuture<AuthorizationServlet> + Send + Sync + 'static {
	move |trace| {
		let config = servlet_tls_config(&certs, &harness);
		Box::pin(async move { AuthorizationServlet::start(trace, config?).await })
	}
}

/// A client that trusts the hive certificate, connected to the servlet at
/// `addr`.
async fn hive_client(certs: &TestCerts, addr: TightBeamSocketAddr) -> GenericClient<TokioListener> {
	let builder = ClientBuilder::<TokioListener>::builder()
		.with_trust_store(Arc::clone(&certs.hive_trust))
		.build();

	builder.connect(addr).await.expect("a client of the hive certificate connects")
}

/// The capture of `capture`, linked to the authorization of `authorized`
/// through the digest of its body.
fn capture_frame(certs: &TestCerts, capture: CaptureTransaction, authorized: &CreditTransferTransaction) -> Frame {
	let body = encode(authorized).expect("a credit transfer encodes");
	let previous = digest::<Sha3_256>(&body).expect("SHA3-256 digests the body");
	let signer = CertifiedKey::new(&certs.cluster_cert, certs.cluster_key.to_owned());
	let frame = Version::V2
		.compose()
		.with_id(b"payment-capture-txn")
		.with_order(1)
		.with_message(capture)
		.with_message_hasher::<Sha3_256>([])
		.with_witness_hasher::<Sha3_256>()
		.with_encryptor(shared_payment_cipher())
		.with_signer::<Secp256k1Signature, _>(signer.expect("the cluster key certifies"))
		.with_previous_hash(previous)
		.build();

	frame.expect("a capture frame builds")
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
			(AUTHORIZATION_APPROVED, exactly!(1)),
			(INTEGRITY_VERIFIED, exactly!(1), equals!(true))
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

			let spawner = authorization_spawner(Arc::clone(&certs), Arc::default());
			let servlet = spawner(Arc::new(trace.share())).await?;

			let mut hive_conf = hive_tls_config(&certs);
			hive_conf.pool.mux_offer = Some(Arc::new(TransportOffer::mux(8)));

			let mut hive = PaymentProcessorHive::new(Some(hive_conf))?;
			hive.register(authorization_urn(), servlet, spawner)?;
			hive.establish(Arc::new(trace.share())).await?;

			let _reg_response = hive.register_with_cluster(cluster_addr).await?;

			let transaction = create_auth_transaction(b"E2E-001", MonetaryAmount::new(10000, *b"USD"));
			let inner = authorization_frame(&certs, transaction);

			let builder = ClientBuilder::<TokioListener>::builder()
				.with_trust_store(Arc::clone(&certs.cluster_trust))
				.build();

			// The spec asserts the routing decision that the gateway records
			// as `CLUSTER_WORK_ROUTED`. The gateway returns the servlet's frame
			// under an `Ok` status alone (`ClusterWorkResponse::served`).
			let mut client = builder.connect(cluster_addr.to_owned()).await?;
			let servlet_frame = client.submit_work_to(authorization_urn(), &inner).await?;

			// The gateway returns the servlet's complete response frame. The
			// typed approval decodes from inside it, which proves that the
			// response envelope survived the route back to the client.
			let status: TransactionStatus = decode(servlet_frame.message())?;
			assert!(status.status.is_success(), "the client decoded no approval from the servlet frame");

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
			(KEYMANAGER_PUBKEY_SERVED, exactly!(1)),
			(KEYMANAGER_DECRYPT_SUCCESS, exactly!(1)),
			(events::HANDLER_FAILED, exactly!(1), equals!(TransitStatus::Internal))
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
		client: |ServletEnv { mut client, .. }| async move {
			let key_request = KeyManagerRequest::GetPublicKey(GetPublicKeyRequest { _placeholder: None });
			let key_reply = client.emit(key_manager_frame(b"key-manager-public-key", key_request), None).await?;
			let key_frame = key_reply.ok_or(TightBeamError::MissingResponse)?;
			let served: GetPublicKeyResponse = decode(key_frame.message())?;
			let public_key = PublicKey::from_sec1_bytes(served.public_key.as_bytes())?;
			let sealed = public_key.seal::<HpkeSecp256k1Sha256Aes256Gcm>(KEY_MANAGER_HPKE_INFO, b"", CARD_TOKEN, None)?;
			let ciphertext = sealed.to_bytes();
			let tampered = with_flipped_tag(&ciphertext);

			let open_request = KeyManagerRequest::Decrypt(DecryptRequest { ciphertext: OctetString::new(ciphertext)? });
			let open_reply = client.emit(key_manager_frame(b"key-manager-open", open_request), None).await?;
			let open_frame = open_reply.ok_or(TightBeamError::MissingResponse)?;
			let opened: DecryptResponse = decode(open_frame.message())?;
			assert_eq!(opened.plaintext.as_bytes(), CARD_TOKEN.as_bytes(), "the key manager returned another plaintext");

			let tampered_request = KeyManagerRequest::Decrypt(DecryptRequest { ciphertext: OctetString::new(tampered)? });
			let tampered_reply = client.emit(key_manager_frame(b"key-manager-tampered", tampered_request), None).await;
			let tampered_status = refusal_status(tampered_reply)?;
			assert_eq!(tampered_status, TransitStatus::Internal, "the key manager refused a tampered token with another status");

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub SpawnedAuthorizationSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(INTEGRITY_VERIFIED, exactly!(1), equals!(true)),
			(AUTHORIZATION_APPROVED, exactly!(1))
		]
	}
}

// An instance that the hive's spawner starts presents the hive certificate
// and holds the payment decryptor, so it approves a confidential transfer as
// the first instance does.
tb_scenario! {
	name: a_spawned_authorization_instance_opens_a_confidential_transfer,
	spec: SpawnedAuthorizationSpec,
	environment Servlet {
		context: TestCerts::generate(),
		start: |SetupEnv { trace, context: certs }| async move {
			let spawn = authorization_spawner(certs, Arc::default());
			spawn(Arc::new(trace)).await
		},
		setup: |ClientEnv { addr, context: certs, .. }| async move {
			Ok(hive_client(&certs, addr).await)
		},
		client: |ServletEnv { mut client, context: certs, .. }| async move {
			let transaction = create_auth_transaction(b"E2E-SPAWNED", MonetaryAmount::new(10000, *b"USD"));
			let reply = client.emit(authorization_frame(&certs, transaction), None).await?;
			let reply = reply.ok_or(TightBeamError::MissingResponse)?;
			let status: TransactionStatus = decode(reply.message())?;
			assert!(status.status.is_success(), "the client decoded no approval from the servlet frame");

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ReplaySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(AUTHORIZATION_APPROVED, exactly!(1)),
			(DEDUP_CACHE_HIT, exactly!(1))
		]
	}
}

// The servlet answers a replayed authorization frame from its dedup cache, so
// it approves the transfer once.
tb_scenario! {
	name: a_replayed_authorization_is_answered_from_the_dedup_cache,
	spec: ReplaySpec,
	environment Servlet {
		context: TestCerts::generate(),
		start: |SetupEnv { trace, context: certs }| async move {
			AuthorizationServlet::start(Arc::new(trace), servlet_tls_config(&certs, &Arc::default())?).await
		},
		setup: |ClientEnv { addr, context: certs, .. }| async move {
			Ok(hive_client(&certs, addr).await)
		},
		client: |ServletEnv { mut client, context: certs, .. }| async move {
			let transaction = create_auth_transaction(b"E2E-REPLAY", MonetaryAmount::new(10000, *b"USD"));
			let transfer = authorization_frame(&certs, transaction);
			client.emit(transfer.to_owned(), None).await?;
			client.emit(transfer, None).await?;

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub CaptureSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(AUTHORIZATION_APPROVED, exactly!(1)),
			(CHAIN_VALID, exactly!(2)),
			(CHAIN_BROKEN, exactly!(0)),
			(CAPTURE_COMPLETED, exactly!(1))
		]
	}
}

// The client authorizes a transfer and then captures it, with the capture's
// `previous_frame` set to the digest of the authorization, so the payment
// chain links the two frames.
tb_scenario! {
	name: a_capture_links_to_its_authorization,
	spec: CaptureSpec,
	environment Bare {
		context: TestCerts::generate(),
		exec: |SetupEnv { trace, context: certs }| async move {
			let harness = Arc::default();
			let authorizer = AuthorizationServlet::start(Arc::new(trace.share()), servlet_tls_config(&certs, &harness)?).await?;
			let capturer = CaptureServlet::start(Arc::new(trace.share()), servlet_tls_config(&certs, &harness)?).await?;
			let amount = MonetaryAmount::new(10000, *b"USD");
			let authorized = create_auth_transaction(b"E2E-CAPTURE", amount.to_owned());
			let capture = CaptureTransaction::new(b"E2E-CAPTURE", amount, authorized.creation_datetime)?;
			let capture = capture_frame(&certs, capture, &authorized);
			let mut authorization_client = hive_client(&certs, *authorizer.addr()).await;
			let mut capture_client = hive_client(&certs, *capturer.addr()).await;

			authorization_client.emit(authorization_frame(&certs, authorized), None).await?;
			capture_client.emit(capture, None).await?;

			Ok(())
		}
	}
}
