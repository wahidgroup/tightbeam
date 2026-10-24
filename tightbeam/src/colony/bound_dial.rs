//! A dial bound to the identity its answer must prove.
//!
//! A gateway dials its hives, their servlets, and its peer gateways, and a
//! hive dials its sibling servlets. Each dial of a target that a route or a
//! registration names is a [`BoundDial`], and [`ExpectedSigner::admits`] is
//! its one decision, so a frame leaves only toward the party named
//! (CWE-346).

use std::sync::Arc;

use crate::cms::signed_data::SignerIdentifier;
use crate::colony::cluster::{ClusterConfig, ClusterError, ColonyDialProtocol, DialTarget};
use crate::crypto::x509::utils::CertificateExt;
use crate::crypto::x509::Certificate;
use crate::transport::client::ConnectionPool;
use crate::transport::PooledClient;

/// The identity a dial's answer must prove before any frame leaves.
///
/// [`Self::admits`] is the one decision of a bound dial, so a plane admits
/// the party that answers by its certificate alone (CWE-346).
pub(crate) enum ExpectedSigner<'a> {
	/// A peer gateway, named by its slate key.
	Gateway {
		/// The slate key of the gateway that must answer.
		gateway_id: &'a [u8],
		/// The configuration whose peer trust names the gateway that answers.
		config: &'a ClusterConfig,
	},
	/// A hive, or a servlet of a hive, named by the [`SignerIdentifier`] its
	/// registration carries.
	Hive(Arc<SignerIdentifier>),
}

impl ExpectedSigner<'_> {
	/// Whether `answer`, the certificate the dialed party presented in its
	/// handshake, is the identity this dial expects.
	///
	/// - [`ClusterConfig::peer_identity`] names a gateway's answer the way an
	///   advertisement names its signer, so a gateway that rotated its
	///   certificate under one key keeps its name.
	/// - A hive's or a servlet's answer is the certificate its registration's
	///   signer identifier names (RFC 5652 §5.3).
	/// - It refuses an answer whose name fails to decode.
	pub(crate) fn admits(&self, answer: &Certificate) -> bool {
		match self {
			Self::Gateway { gateway_id, config } => {
				let answered = config.peer_identity(answer);
				answered.as_deref() == Some(*gateway_id)
			}
			Self::Hive(registered) => matches!(answer.is_named_by(registered.as_ref()), Ok(true)),
		}
	}
}

/// A dial target beside the identity its answer must prove.
///
/// [`Self::connect`] is the one dial of a target that a route or a
/// registration names, so a frame leaves only toward the party named.
pub(crate) struct BoundDial<'a> {
	target: DialTarget,
	expected: ExpectedSigner<'a>,
}

impl<'a> BoundDial<'a> {
	/// Binds `target` to the identity `expected` names, so [`Self::connect`]
	/// admits only that answer.
	pub(crate) fn new(target: DialTarget, expected: ExpectedSigner<'a>) -> Self {
		Self { target, expected }
	}

	/// The endpoint this dial reaches.
	pub(crate) fn target(&self) -> &DialTarget {
		&self.target
	}

	/// Connects to the target on `pool` and returns the client once the party
	/// that answered proved to be the one this dial expects.
	///
	/// 1. Connect, and complete the handshake. A cold connection defers its
	///    handshake to the first emit, so it completes here, before the caller
	///    can send anything.
	/// 2. Ask [`ExpectedSigner::admits`] about the certificate the answer presented.
	/// 3. Refuse an answer with no certificate, or one the expected signer does not name.
	///
	/// # Errors
	///
	/// - [`ClusterError::InvalidAddress`] -- the target does not parse as an address of this protocol.
	/// - [`ClusterError::ConnectFailed`] -- the dial or the handshake failed.
	/// - [`ClusterError::PeerMismatch`] -- the answer presented another party's certificate, or none.
	pub(crate) async fn connect<P: ColonyDialProtocol>(
		self,
		pool: &Arc<ConnectionPool<P>>,
	) -> Result<PooledClient<P>, ClusterError> {
		let address: P::Address = self.target.protocol_address()?;
		let connected = pool.connect(address).await;
		let mut client = connected.map_err(|_| ClusterError::ConnectFailed)?;
		let handshake = client.complete_handshake().await;
		handshake.map_err(|_| ClusterError::ConnectFailed)?;

		let admitted = client.peer_certificate().is_some_and(|answer| self.expected.admits(answer));
		if !admitted {
			return Err(ClusterError::PeerMismatch);
		}

		Ok(client)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::crypto::x509::error::CertificateValidationError;
	use crate::testing::{TestCertificate, TestKey};

	/// A hive identity's certificate on a key of its own.
	fn other_certificate() -> Certificate {
		let key = Secp256k1SigningKey::from_bytes(&[2u8; 32].into()).expect("the fixture scalar is a valid key");
		TestCertificate::self_signed(&key)
	}

	/// The certificate on the fixed test key, whose signer a hive registered.
	fn registered_certificate() -> Certificate {
		let key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
		TestCertificate::self_signed(&key)
	}

	// The control plane answers under the identity that signed the hive's
	// registration, so the dial admits that certificate.
	#[test]
	fn a_hive_dial_admits_the_registered_signer() -> Result<(), CertificateValidationError> {
		let registered = registered_certificate();
		let expected = ExpectedSigner::Hive(Arc::new(registered.signer_identifier()?));

		let admitted = expected.admits(&registered);

		assert!(admitted);
		Ok(())
	}

	// The dial refuses another identity at the hive's address before any
	// frame leaves toward it (CWE-346).
	#[test]
	fn a_hive_dial_refuses_another_identity() -> Result<(), CertificateValidationError> {
		let registered = registered_certificate();
		let expected = ExpectedSigner::Hive(Arc::new(registered.signer_identifier()?));

		let admitted = expected.admits(&other_certificate());

		assert!(!admitted);
		Ok(())
	}
}
