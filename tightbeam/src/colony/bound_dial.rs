//! A dial bound to the identity its answer must prove.
//!
//! A gateway dials its hives, their servlets, and its peer gateways, and a
//! hive dials its sibling servlets. Each dial of a target that a route or a
//! registration names is a [`BoundDial`], and [`ExpectedSigner::admits`] is
//! its one decision, so a frame leaves only toward the party named
//! (CWE-346).

use std::sync::Arc;

use crate::cms::signed_data::SignerIdentifier;
use crate::colony::cluster::{ClusterError, ColonyConfig, ColonyDialProtocol, DialTarget};
use crate::crypto::x509::utils::CertificateExt;
use crate::crypto::x509::Certificate;
use crate::instrumentation::events::CLUSTER_DIAL_REFUSED;
use crate::trace::TraceCollector;
use crate::transport::client::ConnectionPool;
use crate::transport::{PooledClient, Protocol};

/// The identity a dial's answer must prove before any frame leaves, on a
/// dial of protocol `P`.
///
/// [`Self::admits`] is the one decision of a bound dial, so a plane admits
/// the party that answers by its certificate alone (CWE-346).
pub(crate) enum ExpectedSigner<'a, P> {
	/// A peer gateway, named by its slate key.
	Gateway {
		/// The slate key of the gateway that must answer.
		gateway_id: &'a [u8],
		/// The configuration whose [`ColonyConfig::peer_identity`] names the
		/// gateway that answers.
		config: &'a ColonyConfig<P>,
	},
	/// A hive, or a servlet of a hive, named by the [`SignerIdentifier`] its
	/// registration carries.
	Hive(Arc<SignerIdentifier>),
}

impl<P: Protocol> ExpectedSigner<'_, P> {
	/// Whether `answer`, the certificate the dialed party presented in its
	/// handshake, is the identity this dial expects.
	///
	/// - [`ColonyConfig::peer_identity`] names a gateway's answer under the
	///   colony digest, the way an advertisement names its signer, so a
	///   gateway that rotated its certificate under one key keeps its name.
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

/// A dial target of protocol `P` beside the identity its answer must prove.
///
/// [`Self::connect`] is the one dial of a target that a route or a
/// registration names, so a frame leaves only toward the party named.
pub(crate) struct BoundDial<'a, P> {
	target: DialTarget,
	expected: ExpectedSigner<'a, P>,
}

impl<'a, P> BoundDial<'a, P> {
	/// Binds `target` to the identity `expected` names, so [`Self::connect`]
	/// admits only that answer.
	pub(crate) fn new(target: DialTarget, expected: ExpectedSigner<'a, P>) -> Self {
		Self { target, expected }
	}

	/// Connects to the target on `pool` and returns the client once the party
	/// that answered proved to be the one this dial expects.
	///
	/// 1. Connect, and complete the handshake. A cold connection defers its
	///    handshake to the first emit, so it completes here, before the caller
	///    can send anything.
	/// 2. Ask [`ExpectedSigner::admits`] about the certificate the answer presented.
	/// 3. Refuse an answer with no certificate, or one the expected signer does not name.
	/// 4. Take a refused answer's connection out of the pool, so a later dial
	///    of the address meets the party that answers it then.
	/// 5. Record the refusal on `trace` as [`CLUSTER_DIAL_REFUSED`], with the dialed address as its payload.
	///
	/// # Errors
	///
	/// - [`ClusterError::InvalidAddress`] -- the target does not parse as an address of this protocol.
	/// - [`ClusterError::ConnectFailed`] -- the dial or the handshake failed.
	/// - [`ClusterError::PeerMismatch`] -- the answer presented another party's certificate, or none.
	/// - [`ClusterError::Transport`] -- the runtime fault model injects a fault
	///   at the eviction of the refused connection.
	/// - [`ClusterError::Frame`] -- the runtime fault model injects a fault at the refusal event.
	pub(crate) async fn connect(
		self,
		pool: &Arc<ConnectionPool<P>>,
		trace: &TraceCollector,
	) -> Result<PooledClient<P>, ClusterError>
	where
		P: ColonyDialProtocol,
	{
		let address: P::Address = self.target.protocol_address()?;
		let connected = pool.connect(address).await;
		let mut client = connected.map_err(|_| ClusterError::ConnectFailed)?;
		let handshake = client.complete_handshake().await;
		handshake.map_err(|_| ClusterError::ConnectFailed)?;

		let answer = client.peer_certificate();
		let admitted = answer.is_some_and(|answer| self.expected.admits(answer));
		if !admitted {
			client.discard()?;
			let refused = self.target.as_bytes();
			trace.emit_event_with_value_and_evidence(CLUSTER_DIAL_REFUSED, "PeerMismatch", (), Some(refused))?;
			return Err(ClusterError::PeerMismatch);
		}

		Ok(client)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::colony::protocol::ServletInfo;
	use crate::tb_cases;
	use crate::testing::{TestCertificate, TestKey};
	use crate::transport::TokioListener;

	// The control plane answers under the identity that signed the hive's
	// registration, so the dial admits that certificate, and it refuses
	// another identity at the hive's address before any frame leaves toward
	// it (CWE-346).
	tb_cases! {
		fn a_hive_dial_admits_only_the_registered_signer((presented, admitted): (Certificate, bool)) {
			let registered = ServletInfo::fixture_signer();
			let expected = ExpectedSigner::<TokioListener>::Hive(Arc::new(registered));

			let verdict = expected.admits(&presented);
			assert_eq!(verdict, admitted);
		}
		cases {
			the_registered_signer => (TestCertificate::insecure_fixed(), true),
			another_identity => (TestCertificate::self_signed(&TestKey::fixed(0x02)), false),
		}
	}
}
