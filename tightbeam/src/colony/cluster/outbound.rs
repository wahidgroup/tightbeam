//! Outbound connection-pool construction for cluster gateways
//!
//! Hive and peer hops use separate pools so each trust plane stays
//! attached to the dials it authorizes. Client identity is materialized
//! once and shared by `Arc` across both pools.

use std::sync::Arc;

use crate::crypto::profiles::DefaultCryptoProvider;
use crate::crypto::x509::store::CertificateTrust;
use crate::crypto::x509::Certificate;
use crate::transport::client::pool::{ConnectionBuilder, ConnectionPool, PoolConfig};
use crate::transport::handshake::HandshakeKeyManager;
use crate::transport::Protocol;
use crate::TightBeamError;

#[cfg(feature = "x509")]
mod x509 {
	pub(crate) use crate::colony::cluster::ClusterTlsConfig;
	pub(crate) use crate::crypto::policy::VerificationPolicy;
	pub(crate) use crate::crypto::x509::error::CertificateValidationError;
	pub(crate) use crate::crypto::x509::policy::CertificateValidation;
	pub(crate) use crate::SignerInfo;
}

#[cfg(feature = "x509")]
use x509::*;

type ClusterPool<P> = ConnectionPool<P, DefaultCryptoProvider>;
type ClusterKey = HandshakeKeyManager<DefaultCryptoProvider>;

/// Hive pool plus the optional peer-plane pool
///
/// Named fields because both pools share one type: a tuple would let a
/// hive/peer transposition compile, crossing the two trust planes.
pub struct ClusterPools<P: Protocol> {
	/// Outbound dials to this gateway's own hives (`hive_trust` plane)
	pub hive: Arc<ClusterPool<P>>,
	/// Outbound dials to federated peer gateways (`peer_trust` plane);
	/// `None` when federation is disabled
	pub peer: Option<Arc<ClusterPool<P>>>,
}

/// Build hive and optional peer outbound pools from one client identity
///
/// Takes the whole TLS config: `hive_trust` and `peer_trust` share a
/// type, so passing them positionally would let a swap compile and
/// cross the trust planes.
#[cfg(feature = "x509")]
#[doc(hidden)]
pub fn build_cluster_pools<P>(
	pool_config: PoolConfig,
	tls: &ClusterTlsConfig,
) -> Result<ClusterPools<P>, TightBeamError>
where
	P: Protocol + Send + Sync + 'static,
	P::Address: core::hash::Hash + Eq + Clone + Send + Sync,
	P::Transport: Send + Sync,
{
	let certificate = Arc::new(Certificate::try_from(tls.certificate.clone())?);
	let key = Arc::new(ClusterKey::new(Arc::clone(&tls.key)));

	let hive_pool = build_one::<P>(
		pool_config.clone(),
		Arc::clone(&certificate),
		Arc::clone(&key),
		tls.hive_trust
			.as_ref()
			.map(|trust| validated_trust(Arc::clone(trust), &tls.validators)),
	);
	let peer_pool = tls.peer_trust.as_ref().map(|trust| {
		build_one::<P>(
			pool_config,
			Arc::clone(&certificate),
			Arc::clone(&key),
			Some(validated_trust(Arc::clone(trust), &tls.validators)),
		)
	});

	Ok(ClusterPools { hive: hive_pool, peer: peer_pool })
}

/// Outbound trust store composed with the operator validator chain.
///
/// The handshake client validates the server certificate through one
/// validation object cast from the pool trust store. This composite
/// keeps every trust-store operation delegated and appends
/// `ClusterTlsConfig::validators` to `evaluate`, so each outbound dial
/// enforces the operator's extra checks (pinning, expiry, policy).
///
/// # Evaluation order
///
/// 1. The underlying trust store evaluates the certificate.
/// 2. Each configured operator validator evaluates in registration order.
///
/// [`CertificateTrust::is_trusted`] still delegates to the store alone.
/// Outbound handshakes use [`CertificateValidation::evaluate`], so the
/// validator chain is the production path.
#[cfg(feature = "x509")]
struct ValidatedTrust {
	store: Arc<dyn CertificateTrust>,
	validators: Vec<Arc<dyn CertificateValidation>>,
}

#[cfg(feature = "x509")]
impl core::fmt::Debug for ValidatedTrust {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("ValidatedTrust")
			.field("store", &self.store)
			.field("validators", &format!("[{} validators]", self.validators.len()))
			.finish()
	}
}

#[cfg(feature = "x509")]
impl CertificateValidation for ValidatedTrust {
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		self.store.evaluate(cert)?;
		for validator in self.validators.iter() {
			validator.evaluate(cert)?;
		}

		Ok(())
	}
}

#[cfg(feature = "x509")]
impl CertificateTrust for ValidatedTrust {
	fn is_trusted(&self, cert: &Certificate) -> bool {
		self.store.is_trusted(cert)
	}

	fn verify_chain(&self, chain: &[Certificate]) -> Result<(), CertificateValidationError> {
		self.store.verify_chain(chain)
	}

	fn find_by_signer_info(&self, signer_info: &SignerInfo) -> Option<&Certificate> {
		self.store.find_by_signer_info(signer_info)
	}

	fn to_policy_ref(&self) -> &dyn VerificationPolicy {
		self.store.to_policy_ref()
	}
}

/// Wrap `store` with the validator chain when one is configured.
///
/// An empty chain returns the store unchanged, so the common
/// no-validator path adds no indirection.
#[cfg(feature = "x509")]
fn validated_trust(
	store: Arc<dyn CertificateTrust>,
	validators: &[Arc<dyn CertificateValidation>],
) -> Arc<dyn CertificateTrust> {
	if validators.is_empty() {
		return store;
	}

	Arc::new(ValidatedTrust { store, validators: validators.iter().map(Arc::clone).collect() })
}

#[cfg(feature = "x509")]
fn build_one<P>(
	pool_config: PoolConfig,
	certificate: Arc<Certificate>,
	key: Arc<ClusterKey>,
	trust: Option<Arc<dyn CertificateTrust>>,
) -> Arc<ClusterPool<P>>
where
	P: Protocol + Send + Sync + 'static,
	P::Address: core::hash::Hash + Eq + Clone + Send + Sync,
	P::Transport: Send + Sync,
{
	let mut builder = ClusterPool::<P>::builder()
		.with_config(pool_config)
		.with_shared_client_identity(certificate, key);

	if let Some(store) = trust {
		builder = builder.with_trust_store(store);
	}

	Arc::new(builder.build())
}

#[cfg(all(test, feature = "x509"))]
mod tests {
	use super::*;
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::policy::Secp256k1Policy;
	use crate::crypto::x509::store::{CertificateTrustBuilder, TrustBuilder};
	use crate::testing::{create_test_certificate, create_test_signing_key};

	struct RejectAll;

	impl CertificateValidation for RejectAll {
		fn evaluate(&self, _cert: &Certificate) -> Result<(), CertificateValidationError> {
			Err(CertificateValidationError::CertificateDenied)
		}
	}

	fn trust_of(cert: &Certificate) -> Arc<dyn CertificateTrust> {
		let store = CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
			.with_certificate(cert.clone())
			.expect("test certificates satisfy the trust builder")
			.build();
		Arc::new(store)
	}

	#[test]
	fn empty_validator_chain_returns_store_unchanged() {
		let store = trust_of(&create_test_certificate(&create_test_signing_key()));
		let composed = validated_trust(Arc::clone(&store), &[]);

		assert!(Arc::ptr_eq(&store, &composed));
	}

	#[test]
	fn operator_validator_rejects_store_trusted_certificate() {
		let cert = create_test_certificate(&create_test_signing_key());
		let composed = validated_trust(trust_of(&cert), &[Arc::new(RejectAll)]);

		assert!(composed.is_trusted(&cert));
		assert!(composed.evaluate(&cert).is_err());
	}
}
