//! Shared fixtures for security threat integration tests.

#![allow(dead_code)]

use std::sync::Arc;

use tightbeam::{
	crypto::profiles::DefaultCryptoProvider,
	crypto::{
		hash::Sha3_256,
		key::{Secp256k1KeyProvider, SigningKeyProvider},
		policy::Secp256k1Policy,
		profiles::{SecurityProfileDesc, TightbeamProfile},
		sign::ecdsa::Secp256k1SigningKey,
		x509::policy::{CertificateValidation, DirectTrustValidator},
		x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder},
	},
	oids::{AES_128_GCM, AES_256_GCM, CURVE_SECP256K1, HASH_SHA3_256, SIGNER_ECDSA_WITH_SHA3_256},
	random::OsRng,
	testing::{
		error::{FdrConfigError, TestingError},
		utils::{create_test_certificate, create_test_signing_key},
	},
	transport::handshake::HandshakeKeyManager,
	x509::Certificate,
	TightBeamError,
};

/// Build the standard testing error used by threat scenarios to signal that an
/// insecure outcome was observed (turns into a spec `ModeMismatch`).
pub fn expectation_failure(reason: &'static str) -> TightBeamError {
	TightBeamError::TestingError(TestingError::InvalidFdrConfig(FdrConfigError {
		field: "security_threat",
		reason,
	}))
}

/// Generated server-side credentials for handshake orchestration.
#[derive(Clone)]
pub struct ServerMaterials {
	pub certificate: Arc<Certificate>,
	pub key_provider: Arc<dyn SigningKeyProvider>,
	/// Secret key for test verification (ECIES decryption). Held in an `Arc`
	/// so the bundle is `Clone` without copying secret material.
	secret_key: Arc<k256::SecretKey>,
}

impl ServerMaterials {
	pub fn generate() -> Self {
		let signing_key = create_test_signing_key();
		let certificate = Arc::new(create_test_certificate(&signing_key));

		let secret_key_bytes = signing_key.to_bytes();
		let secret_key = k256::SecretKey::from_bytes(&secret_key_bytes).expect("valid secret key");

		let server_key = Secp256k1SigningKey::from(signing_key);
		let provider: Arc<dyn SigningKeyProvider> = Arc::new(Secp256k1KeyProvider::from(server_key));
		Self { certificate, key_provider: provider, secret_key: Arc::new(secret_key) }
	}

	/// Secret key for ECIES decryption (test verification only).
	pub fn secret_key(&self) -> &k256::SecretKey {
		&self.secret_key
	}
}

/// Generated client-side credentials for mutual-authentication handshakes.
#[derive(Clone)]
pub struct ClientMaterials {
	pub certificate: Arc<Certificate>,
	pub key_manager: Arc<HandshakeKeyManager<DefaultCryptoProvider>>,
}

impl ClientMaterials {
	/// Fresh random identity, distinct from any server materials.
	pub fn generate() -> Self {
		let signing_key = random_signing_key();
		let certificate = Arc::new(test_certificate(&signing_key));
		let key_manager = Arc::new(HandshakeKeyManager::from(signing_key));
		Self { certificate, key_manager }
	}
}

/// Direct-trust validator pinning the given server certificate.
///
/// Handshake clients fail closed without a validator (CWE-295), so every
/// session pins the identity of the server it orchestrates against.
pub fn pinning_validator(certificate: &Certificate) -> Arc<dyn CertificateValidation> {
	let trust_chain = vec![certificate.clone()];
	let data = DirectTrustValidator::default().with_trust_chain(trust_chain);

	Arc::new(data)
}

/// Trust store pinning the given server certificate (for CMS clients).
pub fn pinning_trust_store(certificate: &Certificate) -> Result<Arc<dyn CertificateTrust>, TightBeamError> {
	let store = CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
		.with_certificate(certificate.clone())?
		.build();
	Ok(Arc::new(store))
}

/// Deterministic signing key (fixed seed) for stable single-identity fixtures.
pub fn deterministic_signing_key() -> Secp256k1SigningKey {
	create_test_signing_key()
}

/// Fresh random signing key for distinct, unrelated identities.
pub fn random_signing_key() -> Secp256k1SigningKey {
	Secp256k1SigningKey::random(&mut OsRng)
}

/// Self-signed test certificate for the given signing key.
pub fn test_certificate(signing_key: &Secp256k1SigningKey) -> Certificate {
	create_test_certificate(signing_key)
}

/// Default profile descriptor shared across threats.
pub fn default_security_profile() -> SecurityProfileDesc {
	SecurityProfileDesc::from(&TightbeamProfile)
}

/// Strong profile (AES-256-GCM) for downgrade testing.
pub fn strong_security_profile() -> SecurityProfileDesc {
	SecurityProfileDesc {
		digest: Some(HASH_SHA3_256),
		aead: Some(AES_256_GCM),
		aead_key_size: Some(32),
		signature: Some(SIGNER_ECDSA_WITH_SHA3_256),
		kdf: Some(HASH_SHA3_256),
		curve: Some(CURVE_SECP256K1),
		key_wrap: None,
		kem: None,
	}
}

/// Weak profile (AES-128-GCM) for downgrade testing.
pub fn weak_security_profile() -> SecurityProfileDesc {
	SecurityProfileDesc {
		digest: Some(HASH_SHA3_256),
		aead: Some(AES_128_GCM),
		aead_key_size: Some(16),
		signature: Some(SIGNER_ECDSA_WITH_SHA3_256),
		kdf: Some(HASH_SHA3_256),
		curve: Some(CURVE_SECP256K1),
		key_wrap: None,
		kem: None,
	}
}

/// Shared hooks and doubles for receipt/settlement threat scenarios.
#[cfg(all(
	any(feature = "transport-cms", feature = "transport-ecies"),
	feature = "transport-multiplex"
))]
mod receipt_fixtures {
	use std::sync::atomic::{AtomicUsize, Ordering};
	use std::sync::{Arc, Mutex};

	use tightbeam::asn1::OctetString;
	use tightbeam::transport::handshake::negotiation::{
		AuthorizationGrant, AuthorizationRefusal, TransportAuthorizer, TransportOffer,
	};
	use tightbeam::transport::handshake::receipt::{
		ApprovalRefusal, ReceiptApprover, SessionObserver, SessionOutcome, SessionReceipt,
	};
	use tightbeam::utils::marker::MaybeSendFuture;
	use tightbeam::TightBeamError;

	/// True when `needle` appears as a contiguous window inside `haystack`.
	pub fn contains_window(haystack: &[u8], needle: &[u8]) -> bool {
		haystack.windows(needle.len()).any(|window| window == needle)
	}

	/// Grants the requested budgets, optionally issuing a settlement
	/// challenge, and settles anything.
	pub struct GrantingAuthorizer {
		challenge: Option<OctetString>,
	}

	impl GrantingAuthorizer {
		/// Grant without demanding a settlement answer.
		pub fn challenge_free() -> Self {
			Self { challenge: None }
		}

		/// Grant with the given settlement challenge attached.
		pub fn challenging(challenge: &[u8]) -> Result<Self, TightBeamError> {
			Ok(Self { challenge: Some(OctetString::new(challenge)?) })
		}
	}

	impl TransportAuthorizer for GrantingAuthorizer {
		fn authorize<'a>(
			&'a self,
			offer: &'a TransportOffer,
		) -> MaybeSendFuture<'a, Result<AuthorizationGrant, AuthorizationRefusal>> {
			Box::pin(async move {
				Ok(AuthorizationGrant { budgets: offer.requested_budgets, challenge: self.challenge.clone() })
			})
		}
	}

	/// Grants budgets with a settlement challenge and counts every call
	/// to `settle`, so a scenario can prove whether the hook fired.
	pub struct SettleSpyAuthorizer {
		challenge: OctetString,
		settle_calls: Arc<AtomicUsize>,
	}

	impl SettleSpyAuthorizer {
		/// Spy granting budgets with the given settlement challenge.
		pub fn challenging(challenge: &[u8]) -> Result<Self, TightBeamError> {
			Ok(Self {
				challenge: OctetString::new(challenge)?,
				settle_calls: Arc::new(AtomicUsize::new(0)),
			})
		}

		/// Calls the `settle` hook has received so far.
		pub fn settle_calls(&self) -> usize {
			self.settle_calls.load(Ordering::SeqCst)
		}
	}

	impl TransportAuthorizer for SettleSpyAuthorizer {
		fn authorize<'a>(
			&'a self,
			offer: &'a TransportOffer,
		) -> MaybeSendFuture<'a, Result<AuthorizationGrant, AuthorizationRefusal>> {
			Box::pin(async move {
				Ok(AuthorizationGrant { budgets: offer.requested_budgets, challenge: Some(self.challenge.clone()) })
			})
		}

		fn settle<'a>(
			&'a self,
			_receipt: &'a SessionReceipt,
			_response: Option<&'a [u8]>,
		) -> MaybeSendFuture<'a, Result<(), AuthorizationRefusal>> {
			self.settle_calls.fetch_add(1, Ordering::SeqCst);
			Box::pin(async move { Ok(()) })
		}
	}

	/// Approves every receipt, answering its challenge with a fixed
	/// settlement answer.
	pub struct PayingApprover {
		response: OctetString,
	}

	impl PayingApprover {
		/// Approver answering every challenge with `response`.
		pub fn answering(response: &[u8]) -> Result<Self, TightBeamError> {
			Ok(Self { response: OctetString::new(response)? })
		}
	}

	impl ReceiptApprover for PayingApprover {
		fn approve<'a>(
			&'a self,
			_receipt: &'a SessionReceipt,
		) -> MaybeSendFuture<'a, Result<Option<OctetString>, ApprovalRefusal>> {
			Box::pin(async move { Ok(Some(self.response.clone())) })
		}
	}

	/// Records every [`SessionOutcome`] the server hands to the observer.
	#[derive(Default)]
	pub struct RecordingObserver {
		outcomes: Mutex<Vec<SessionOutcome>>,
	}

	impl RecordingObserver {
		/// Snapshot of the outcomes recorded so far.
		pub fn recorded(&self) -> Vec<SessionOutcome> {
			self.outcomes.lock().map(|outcomes| outcomes.clone()).unwrap_or_default()
		}
	}

	impl SessionObserver for RecordingObserver {
		fn on_outcome<'a>(&'a self, outcome: SessionOutcome) -> MaybeSendFuture<'a, ()> {
			Box::pin(async move {
				if let Ok(mut outcomes) = self.outcomes.lock() {
					outcomes.push(outcome);
				}
			})
		}
	}
}

#[cfg(all(
	any(feature = "transport-cms", feature = "transport-ecies"),
	feature = "transport-multiplex"
))]
pub use receipt_fixtures::*;

/// Manual-drive CMS client/server pair fixture for receipt scenarios.
#[cfg(all(feature = "transport-cms", feature = "transport-multiplex"))]
mod cms_fixtures {
	use std::sync::Arc;

	use tightbeam::crypto::key::{Secp256k1KeyProvider, SigningKeyProvider};
	use tightbeam::crypto::profiles::DefaultCryptoProvider;
	use tightbeam::crypto::sign::ecdsa::Secp256k1SigningKey;
	use tightbeam::crypto::x509::policy::{CertificateValidation, ExpiryValidator};
	use tightbeam::testing::utils::{create_test_certificate, create_test_signing_key};
	use tightbeam::transport::handshake::negotiation::{
		MuxBudgets, SecurityOffer, TransportAuthorizer, TransportOffer,
	};
	use tightbeam::transport::handshake::receipt::{ReceiptApprover, SessionObserver};
	use tightbeam::transport::handshake::{client::CmsHandshakeClient, server::CmsHandshakeServer};
	use tightbeam::TightBeamError;

	use super::{default_security_profile, pinning_trust_store, ServerMaterials};

	/// Hooks installed on a [`cms_mutual_budget_pair`] fixture.
	#[derive(Default)]
	pub struct CmsSessionHooks {
		pub authorizer: Option<Arc<dyn TransportAuthorizer>>,
		pub approver: Option<Arc<dyn ReceiptApprover>>,
		pub observer: Option<Arc<dyn SessionObserver>>,
	}

	/// Mutually authenticated CMS client/server pair with a
	/// budget-bearing transport offer, ready to drive manually.
	pub struct CmsSessionPair {
		pub client: CmsHandshakeClient<DefaultCryptoProvider>,
		pub server: CmsHandshakeServer<DefaultCryptoProvider>,
	}

	/// Build the pair with a fresh client identity pinned to the server
	/// materials, requesting `request` budgets.
	pub fn cms_mutual_budget_pair(
		materials: &ServerMaterials,
		request: MuxBudgets,
		hooks: CmsSessionHooks,
	) -> Result<CmsSessionPair, TightBeamError> {
		let profile = default_security_profile();

		let client_signing = create_test_signing_key();
		let client_cert = Arc::new(create_test_certificate(&client_signing));
		let signing_key = Secp256k1SigningKey::from(client_signing);
		let client_provider: Arc<dyn SigningKeyProvider> = Arc::new(Secp256k1KeyProvider::from(signing_key));
		let trust_store = pinning_trust_store(&materials.certificate)?;

		let mut client = CmsHandshakeClient::<DefaultCryptoProvider>::new(
			DefaultCryptoProvider::default(),
			client_provider,
			Arc::clone(&materials.certificate),
		)
		.with_security_offer(SecurityOffer::new(vec![profile]))
		.with_trust_store(trust_store)
		.with_client_certificate(Arc::clone(&client_cert))
		.with_transport_offer(TransportOffer::mux(4).with_budgets(request));
		if let Some(approver) = hooks.approver {
			client = client.with_receipt_approver(approver);
		}

		let validators: Arc<Vec<Arc<dyn CertificateValidation>>> = Arc::new(vec![Arc::new(ExpiryValidator)]);
		let mut server =
			CmsHandshakeServer::<DefaultCryptoProvider>::new(Arc::clone(&materials.key_provider), Some(validators))
				.with_supported_profiles(vec![profile])
				.with_transport_config(TransportOffer::mux(4));
		if let Some(authorizer) = hooks.authorizer {
			server = server.with_transport_authorizer(authorizer);
		}
		if let Some(observer) = hooks.observer {
			server = server.with_session_observer(observer);
		}
		server.set_client_certificate((*client_cert).clone())?;

		Ok(CmsSessionPair { client, server })
	}
}

#[cfg(all(feature = "transport-cms", feature = "transport-multiplex"))]
pub use cms_fixtures::*;
