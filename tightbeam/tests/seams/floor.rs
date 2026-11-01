//! These tests hold the strength floor of a provider at the TCP transport,
//! under the outside profile, whose AEAD key is 128 bits.
//!
//! - [`OutsideProvider`] names [`NoStrengthFloor`] as its floor, so its endpoints run the profile.
//! - [`FlooredOutsideProvider`] runs the same profile under the default floor, so its endpoints refuse it.
//! - The house provider runs a profile of its own, so it refuses an outside peer.
//!
//! [`NoStrengthFloor`]: tightbeam::crypto::profiles::NoStrengthFloor

use std::net::SocketAddr;
use std::sync::Arc;

use tightbeam::crypto::exchange::Ecdhe;
use tightbeam::crypto::hash::Sha3_512;
use tightbeam::crypto::k256::Secp256k1;
use tightbeam::crypto::profiles::{
	AeadProvider, Aes128Wrap, CryptoProvider, DefaultCryptoProvider, DigestProvider, KdfProvider, KeyExchangeProvider,
	KeyWrapProvider, SigningProvider,
};
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::policy::TransitStatus;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::transport::handshake::negotiation::NegotiationError;
use tightbeam::transport::handshake::{HandshakeError, HandshakeProvider};
use tightbeam::transport::tcp::r#async::{TcpTransport, TokioListener, TokioStream};
use tightbeam::transport::{
	ClientBuilder, EncryptedMessageIO, EncryptedProtocol, MessageCollector, TransportEncryptionConfig, TransportError,
	TransportResult,
};
use tightbeam::Frame;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

use super::{
	outside_identity, OutsideGcm, OutsideKdf, OutsideKem, OutsideProfile, OutsideProvider, OutsideSignature,
	OutsideVerifyingKey, SERVER_SEED,
};
use crate::common::result::TestResult;
use crate::common::security::trust_under;

/// The outside profile under a provider that keeps the default floor of
/// [`CryptoProvider::strength_floor`].
#[derive(Debug, Default, Clone, Copy)]
struct FlooredOutsideProvider {
	profile: OutsideProfile,
}

impl DigestProvider for FlooredOutsideProvider {
	type Digest = Sha3_512;
}

impl AeadProvider for FlooredOutsideProvider {
	type AeadCipher = OutsideGcm;
}

impl KeyWrapProvider for FlooredOutsideProvider {
	type KeyWrap = Aes128Wrap;
}

impl SigningProvider for FlooredOutsideProvider {
	type Signature = OutsideSignature;
	type VerifyingKey = OutsideVerifyingKey;
}

impl KdfProvider for FlooredOutsideProvider {
	type Kdf = OutsideKdf;
}

impl KeyExchangeProvider for FlooredOutsideProvider {
	type KeyExchange = Ecdhe<Secp256k1>;
}

impl CryptoProvider for FlooredOutsideProvider {
	type Profile = OutsideProfile;
	type Kem = OutsideKem;

	fn profile(&self) -> &Self::Profile {
		&self.profile
	}
}

/// A listener under `P` on a loopback port, whose transports present
/// `identity`, and the address it binds.
async fn listener_under<P: HandshakeProvider>(identity: SigningIdentity) -> (TokioListener<P>, SocketAddr) {
	let config = TransportEncryptionConfig::<P>::new(identity);
	let bind = "127.0.0.1:0".parse::<TightBeamSocketAddr>().expect("a loopback address parses");
	let bound = TokioListener::<P>::bind_with(bind, config).await;
	let (listener, addr) = bound.expect("a loopback listener binds");
	(listener, *addr)
}

/// A listener under `P` on a loopback port, whose transports present the
/// outside identity of [`SERVER_SEED`], beside that identity and the address
/// the listener binds.
pub(super) async fn outside_listener<P: HandshakeProvider>() -> (SigningIdentity, TokioListener<P>, SocketAddr) {
	let server = outside_identity(SERVER_SEED);
	let (listener, addr) = listener_under::<P>(server.clone()).await;
	(server, listener, addr)
}

/// A client transport under `P`, connected to `addr`, that trusts the
/// certificate of `server` alone, under the policy of the outside provider
/// that signs it.
pub(super) async fn client_under<P: HandshakeProvider>(
	addr: SocketAddr,
	server: &SigningIdentity,
) -> TcpTransport<TokioStream, P> {
	let store = trust_under::<OutsideProvider>([server.certificate()]);

	let stream = TcpStream::connect(addr).await.expect("the client reaches the listener");
	let client = ClientBuilder::<TokioListener<P>>::builder().with_trust_store(store);
	let client = client.adopt(TokioStream::from(stream)).expect("the client names a trust store");
	client.into_transport()
}

/// A server under `P` that serves the handshake of one connection and
/// collects its first message.
fn serve_one<P: HandshakeProvider>(
	listener: TokioListener<P>,
) -> JoinHandle<TransportResult<(Arc<Frame>, TransitStatus)>> {
	tokio::spawn(async move {
		let (mut transport, _) = listener.accept().await?;
		transport.collect_message().await
	})
}

/// The handshake of a client under `C` with an outside server that serves
/// one connection under [`OutsideProvider`].
async fn client_handshake_under<C: HandshakeProvider>() -> TransportResult<()> {
	let (server, listener, addr) = outside_listener::<OutsideProvider>().await;
	let _serving = serve_one(listener);

	let mut client = client_under::<C>(addr, &server).await;
	client.perform_client_handshake().await
}

/// A client whose provider keeps the default floor refuses the outside
/// profile that an outside server selects, at its admission of the selection.
#[tokio::test]
async fn a_client_of_the_default_floor_refuses_a_profile_below_it() {
	let refused = client_handshake_under::<FlooredOutsideProvider>().await;
	assert!(matches!(
		refused,
		Err(TransportError::HandshakeError(HandshakeError::NegotiationError(
			NegotiationError::BelowStrengthFloor
		)))
	));
}

/// A server whose provider keeps the default floor refuses to choose the
/// outside profile for an outside client.
#[tokio::test]
async fn a_server_of_the_default_floor_refuses_a_profile_below_it() -> TestResult {
	let (server, listener, addr) = outside_listener::<FlooredOutsideProvider>().await;
	let mut client = client_under::<OutsideProvider>(addr, &server).await;
	let _dialing = tokio::spawn(async move { client.perform_client_handshake().await });

	let (mut transport, _) = listener.accept().await?;
	let refused = transport.collect_message().await;
	assert!(matches!(
		refused,
		Err(TransportError::HandshakeError(HandshakeError::NegotiationError(
			NegotiationError::BelowStrengthFloor
		)))
	));
	Ok(())
}

/// A house client refuses an outside server. The server signs its reply under
/// the outside signature and digest, so the house check of the signature fails.
#[tokio::test]
async fn a_house_client_refuses_an_outside_server() {
	let refused = client_handshake_under::<DefaultCryptoProvider>().await;
	assert!(matches!(
		refused,
		Err(TransportError::HandshakeError(HandshakeError::SignatureVerificationFailed))
	));
}
