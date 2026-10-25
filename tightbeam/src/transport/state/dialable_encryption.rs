//! This module holds the provisioning a transport is built from, once it
//! passes the dialer rule and the key-purpose check, and the negotiation input
//! a session holds beside it. Each flow builds its configurations from the
//! two, and each mux role builds its renewal from them.
//!
//! The field of [`DialableEncryption`] is private to this module, so it keeps
//! what the checks read. The fields of [`Negotiation`] are private too, so its
//! methods alone write them.

use super::EncryptionConfig;
use crate::crypto::profiles::CryptoProvider;
use crate::transport::handshake::HandshakeProtocolKind;
use crate::transport::TransportResult;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use super::Arc;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::error::TransportError;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::negotiation::RunnableProfile;
#[cfg(feature = "transport-cms")]
use crate::transport::handshake::negotiation::SecurityOffer;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::negotiation::TransportAuthorizer;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::negotiation::TransportOffer;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::receipt::{ReceiptApprover, SessionObserver};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::{BoxedClientHandshake, BoxedServerHandshake, HandshakeError};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::{ClientConfig, ClientFlow, HandshakeProvider};
#[cfg(feature = "transport-cms")]
use crate::transport::handshake::{Cms, CmsClientSettings, CmsServerSettings};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::{FlowProvisioning, Provisioning, ServerConfig, ServerFlow, SupportedProfiles};
#[cfg(feature = "transport-hpke")]
use crate::transport::handshake::{Hpke, HpkeClientSettings, HpkeServerSettings, LearnedTrust};
#[cfg(mux_rekey)]
use crate::transport::rekey::Renewal;

/// Provisioning that holds both facts [`Self::new`] checks: it answers the
/// dialer rule of [`EncryptionConfig::check_dial_permitted`], and each identity
/// it presents names the key purpose of its role (RFC 5280 §4.2.1.12).
///
/// The constructors of [`SessionState`] take this form alone, so every
/// installed provisioning holds both facts as the checks read them.
///
/// [`SessionState`]: super::SessionState
#[derive(Clone)]
pub struct DialableEncryption<P: CryptoProvider>(EncryptionConfig<P>);

impl<P: CryptoProvider> DialableEncryption<P> {
	/// Check `encryption` against the dialer rule, and each identity it
	/// presents against the key purpose of its role.
	///
	/// # Errors
	///
	/// - [`TransportError::PeerAuthenticationUnconfigured`] -- the endpoint
	///   authenticates no peer and does not name cleartext, or it sets a server
	///   policy and holds no trust in a server, whether or not it names
	///   cleartext.
	/// - [`TransportError::HandshakeError`] -- an identity names a key purpose
	///   other than its role's, or its extended key usage fails to decode.
	pub fn new(encryption: EncryptionConfig<P>) -> TransportResult<Self> {
		encryption.check_dial_permitted()?;
		#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
		encryption.admit_own_identities().map_err(HandshakeError::from)?;
		Ok(Self(encryption))
	}

	/// Name cleartext as a choice, with no peer authority and no encryption.
	///
	/// Frames travel with no confidentiality, integrity, or peer
	/// authentication, which suits a loopback fixture or a link a lower layer
	/// already secures.
	pub fn cleartext() -> Self {
		let encryption = EncryptionConfig { allow_cleartext: true, ..EncryptionConfig::unconfigured() };
		Self(encryption)
	}

	/// `encryption` as it stands, for the test forge that places a session
	/// directly in the phase a test names.
	#[cfg(test)]
	pub(super) fn unchecked(encryption: EncryptionConfig<P>) -> Self {
		Self(encryption)
	}

	/// The provisioning this value holds.
	pub fn encryption(&self) -> &EncryptionConfig<P> {
		&self.0
	}
}

/// The negotiation input of an endpoint: what its handshakes offer and run,
/// and the hooks that its handshakes and their rekeys consult.
///
/// It sits beside the provisioning that [`DialableEncryption::new`] checks. A
/// builder fills it, a session takes it whole when the session starts, and
/// the setters of [`SessionState`] write it afterwards.
///
/// [`SessionState`]: super::SessionState
#[derive(Clone, Default)]
pub(crate) struct Negotiation {
	/// The local multiplexing capability the handshake advertises.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	mux_offer: Option<Arc<TransportOffer>>,
	/// The budget-grant policy between the client's offer and the server's
	/// accept. `None` grants the local configuration ceiling.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	transport_authorizer: Option<Arc<dyn TransportAuthorizer>>,
	/// The approver a client consults for a challenge-bearing session receipt.
	/// `None` fails closed when a challenge is present.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	receipt_approver: Option<Arc<dyn ReceiptApprover>>,
	/// The observer that records budget-bearing handshake outcomes.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	session_observer: Option<Arc<dyn SessionObserver>>,
	/// The handshake protocol a provisioned endpoint runs.
	handshake_protocol: HandshakeProtocolKind,
}

impl Negotiation {
	/// The handshake protocol a provisioned endpoint runs.
	pub(super) fn handshake_protocol(&self) -> HandshakeProtocolKind {
		self.handshake_protocol
	}

	/// Replace the multiplexing capability this endpoint offers.
	#[cfg(mux_rekey)]
	pub(super) fn offer_mux(&mut self, offer: Option<Arc<TransportOffer>>) {
		self.mux_offer = offer;
	}

	/// Replace the budget-grant policy a server consults.
	#[cfg(all(
		any(feature = "tcp", feature = "async-transport"),
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	pub(super) fn authorize_transport(&mut self, authorizer: Arc<dyn TransportAuthorizer>) {
		self.transport_authorizer = Some(authorizer);
	}

	/// Replace the observer of budget-bearing handshake outcomes.
	#[cfg(all(
		any(feature = "tcp", feature = "async-transport"),
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	pub(super) fn observe_sessions(&mut self, observer: Arc<dyn SessionObserver>) {
		self.session_observer = Some(observer);
	}

	/// Replace the approver a client consults before it countersigns a
	/// challenge-bearing receipt.
	#[cfg(all(feature = "std", any(feature = "transport-cms", feature = "transport-hpke")))]
	pub(crate) fn approve_receipts(&mut self, approver: Arc<dyn ReceiptApprover>) {
		self.receipt_approver = Some(approver);
	}

	/// Replace the handshake protocol a provisioned endpoint runs.
	pub(crate) fn select_handshake(&mut self, kind: HandshakeProtocolKind) {
		self.handshake_protocol = kind;
	}
}

/// The endpoint a session runs as: the proof of its provisioning and its
/// negotiation input, lent together.
///
/// Each flow builds both of its configurations from this view, and each mux
/// role takes what it renews under from it.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub(crate) struct Endpoint<'a, P: CryptoProvider> {
	/// The provisioning, as [`DialableEncryption::new`] checked it.
	proof: &'a DialableEncryption<P>,
	/// The negotiation input the session holds beside it.
	negotiation: &'a Negotiation,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<'a, P: CryptoProvider> Endpoint<'a, P> {
	/// The endpoint of `proof` beside `negotiation`.
	pub(super) fn new(proof: &'a DialableEncryption<P>, negotiation: &'a Negotiation) -> Self {
		Self { proof, negotiation }
	}

	/// The client handshake this endpoint dials with, of the flow that its
	/// handshake protocol names.
	///
	/// # Errors
	///
	/// - [`TransportError`] -- the errors of [`HandshakeProtocolKind::client_handshake`].
	pub(crate) fn client_handshake(&self) -> TransportResult<BoxedClientHandshake>
	where
		P: HandshakeProvider,
	{
		self.negotiation.handshake_protocol.client_handshake::<P, Self>(self)
	}

	/// The server handshake this endpoint answers with, of the flow that
	/// its handshake protocol names.
	///
	/// # Errors
	///
	/// - [`TransportError`] -- the errors of [`HandshakeProtocolKind::server_handshake`].
	pub(crate) fn server_handshake(&self) -> TransportResult<BoxedServerHandshake>
	where
		P: HandshakeProvider,
	{
		self.negotiation.handshake_protocol.server_handshake::<P, Self>(self)
	}

	/// The configuration of a client handshake of flow `F` over `flow`.
	///
	/// Each implementation of [`FlowProvisioning`] builds `flow` from this
	/// provisioning, whose client identity passed the key-purpose check that
	/// [`ClientConfig::admitted`] requires. The key purposes, transport offer,
	/// receipt approver, and server policy enter that constructor as required
	/// parts, so each flow passes them alike.
	fn client_config_with<F>(&self, flow: F::Settings) -> ClientConfig<F, P>
	where
		F: ClientFlow<P>,
		P: HandshakeProvider,
	{
		let encryption = &self.proof.0;
		let transport_offer = self.negotiation.mux_offer.as_deref().cloned();
		let receipt_approver = self.negotiation.receipt_approver.as_ref().map(Arc::clone);
		let server_policy = encryption.server_policy.clone();

		ClientConfig::admitted(flow, encryption.key_purposes, transport_offer, receipt_approver, server_policy)
	}

	/// The configuration of a server handshake of flow `F` around `flow` and
	/// `identity`, with the parts every flow carries from this endpoint.
	///
	/// The server runs the one profile its provider names. Each implementation
	/// of [`FlowProvisioning`] passes the identity this provisioning presents,
	/// which passed the purpose check that [`ServerConfig::admitted`] requires.
	fn server_config_with<F>(&self, flow: F::Settings, identity: F::Identity) -> ServerConfig<F, P>
	where
		F: ServerFlow<P>,
		P: HandshakeProvider,
	{
		let encryption = &self.proof.0;
		let profiles = SupportedProfiles::from(RunnableProfile::<P>::native().descriptor());

		let mut config = ServerConfig::admitted(flow, identity, profiles, encryption.key_purposes);
		config.peer_authentication = encryption.peer_authentication.clone();
		config.transport = self.negotiation.mux_offer.as_deref().cloned();
		config.transport_authorizer = self.negotiation.transport_authorizer.as_ref().map(Arc::clone);
		config.session_observer = self.negotiation.session_observer.as_ref().map(Arc::clone);
		config
	}

	/// What the client role renews under: the client identity this endpoint
	/// presented, the server purpose the handshake admitted its peer under,
	/// and the receipt approver, or `None` without a client identity.
	#[cfg(mux_rekey)]
	pub(crate) fn client_renewal(&self) -> Option<Renewal<P>> {
		let encryption = &self.proof.0;
		let identity = encryption.client_identity.clone()?;
		let approver = self.negotiation.receipt_approver.as_ref().map(Arc::clone);

		Some(Renewal::client(identity, encryption.key_purposes.server, approver))
	}

	/// What the server role renews under: the signing identity this endpoint
	/// presented, the client purpose the handshake admitted its peer under,
	/// the transport authorizer, and the session observer, or `None` without
	/// a server identity.
	#[cfg(mux_rekey)]
	pub(crate) fn server_renewal(&self) -> Option<Renewal<P>> {
		let encryption = &self.proof.0;
		let identity = encryption.server_identity.as_ref()?.signing().clone();
		let authorizer = self.negotiation.transport_authorizer.as_ref().map(Arc::clone);
		let observer = self.negotiation.session_observer.as_ref().map(Arc::clone);

		Some(Renewal::server(identity, encryption.key_purposes.client, authorizer, observer))
	}
}

/// The HPKE flow learns its server from the reply, so its client takes the
/// trust store to validate the path the reply presents, beside the client
/// identity when one is set. Its server signs with the signing identity it
/// presents, and its secret derives from the two ephemerals alone.
#[cfg(feature = "transport-hpke")]
impl<P: HandshakeProvider> FlowProvisioning<Hpke, P> for Endpoint<'_, P> {
	/// The client proves its identity when one is set and dials anonymously
	/// otherwise. A client with no trust store fails closed before it sends
	/// anything (CWE-295).
	///
	/// # Errors
	///
	/// - [`TransportError::HandshakeError`] with
	///   [`HandshakeError::MissingTrustStore`] -- no trust store is configured.
	fn client_config(&self) -> TransportResult<ClientConfig<Hpke, P>> {
		let encryption = &self.proof.0;
		let store = encryption.trust_store.as_ref().ok_or(HandshakeError::MissingTrustStore)?;
		let trust = LearnedTrust::anchored(Arc::clone(store));
		let identity = encryption.client_identity.clone();

		let settings = HpkeClientSettings { trust, identity };
		Ok(self.client_config_with::<Hpke>(settings))
	}

	/// The server signs its reply with the signing identity it presents.
	///
	/// # Errors
	///
	/// - [`TransportError::MissingEncryption`] -- no server identity is configured.
	fn server_config(&self) -> TransportResult<ServerConfig<Hpke, P>> {
		let identity = self.proof.0.server_identity.as_ref();
		let identity = identity.ok_or(TransportError::MissingEncryption)?;
		Ok(self.server_config_with::<Hpke>(HpkeServerSettings, identity.signing().clone()))
	}
}

/// The CMS flow seals the base secret to the key-agreement certificate of its
/// server up front, so its client takes the trust in that server, and the
/// identity its Finished signs under. Its server presents the pair of
/// identities it opens and signs with.
#[cfg(feature = "transport-cms")]
impl<P: HandshakeProvider> FlowProvisioning<Cms, P> for Endpoint<'_, P> {
	/// The server verifies the client Finished under the client's certificate,
	/// so a client without an identity fails closed before it sends anything.
	/// The client offers the one profile its provider runs.
	///
	/// # Errors
	///
	/// - [`TransportError::MissingServerCertificateChain`] -- no server trust is provisioned.
	/// - [`TransportError::HandshakeError`] with
	///   [`HandshakeError::MutualAuthRequired`] -- no client identity is set.
	fn client_config(&self) -> TransportResult<ClientConfig<Cms, P>> {
		let encryption = &self.proof.0;
		let trust = encryption.cms_server.clone();
		let trust = trust.ok_or(TransportError::MissingServerCertificateChain)?;
		let identity = encryption.client_identity.as_ref().ok_or(HandshakeError::MutualAuthRequired)?;
		let settings = CmsClientSettings { trust, identity: identity.clone() };

		let mut config = self.client_config_with::<Cms>(settings);
		config.security_offer = Some(SecurityOffer::new(vec![RunnableProfile::<P>::native().descriptor()]));
		Ok(config)
	}

	/// The server opens the opening under its key-agreement identity and signs
	/// its Finished under its signing identity.
	///
	/// # Errors
	///
	/// - [`TransportError::MissingEncryption`] -- no server identity is configured.
	/// - [`TransportError::MissingKeyAgreementIdentity`] -- the server holds a signing identity alone.
	fn server_config(&self) -> TransportResult<ServerConfig<Cms, P>> {
		let identity = self.proof.0.server_identity.as_ref();
		let identity = identity.ok_or(TransportError::MissingEncryption)?;
		let pair = identity.cms_pair()?.clone();
		Ok(self.server_config_with::<Cms>(CmsServerSettings, pair))
	}
}

/// Each flow of this build reads both of its configurations from the endpoint.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<P: HandshakeProvider> Provisioning<P> for Endpoint<'_, P> {}
