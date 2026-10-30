//! A hybrid pairing an outside crate names: the outside ML-KEM-768 with the
//! outside ECDH over P-256, under [`OutsidePair`] and an identifier of the
//! outside arc. The house [`Hybrid`] runs it as it runs the house pairing,
//! since each outside share states its fixed width.
//!
//! These suites run under it:
//!
//! - both handshake flows and an in-band renewal of a multiplexed session, and
//! - the refusal, end to end, of a server share whose classical part is the server's key-agreement key.
//!
//! The house [`PreviewPqcProvider`] renews its epoch in band under the same
//! harness.

use core::marker::PhantomData;
use std::error::Error;

use p256::NistP256;
use tightbeam::crypto::exchange::{Hybrid, HybridPair};
use tightbeam::der::asn1::ObjectIdentifier;
use tightbeam::der::oid::AssociatedOid;
use tightbeam::transport::handshake::HandshakeError;

#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
use tightbeam::crypto::k256::ecdsa::SigningKey;
#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
use tightbeam::crypto::profiles::PreviewPqcProvider;
#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
use tightbeam::crypto::sign::SigningIdentity;
#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
use tightbeam::random::OsRng;
#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
use tightbeam::testing::fixtures::TestIdentity;

use super::ml_kem::MlKem768;
use super::{
	cms_opens, cms_pair, hpke_opens, p384_cms_server, p384_identity, AgreementBackend, DhCurve, Draw, Fresh,
	KnownReply, OnP384, OutsideDh, CONTENT,
};

/// The outside ML-KEM-768 paired with ECDH over P-256, whose scalars `D`
/// draws, under an identifier of the outside arc.
struct OutsidePair<D>(PhantomData<fn() -> D>);

impl<D: Draw> AssociatedOid for OutsidePair<D> {
	const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.17");
}

impl<D: Draw> HybridPair for OutsidePair<D> {
	type PostQuantum = MlKem768;
	type Classical = OutsideDh<NistP256, D>;
}

/// The provider of the outside pairing with fresh scalars.
type HybridProvider = OnP384<Hybrid<OutsidePair<Fresh>>>;

/// The HPKE flow runs under the outside pairing.
#[tokio::test]
async fn an_outside_hybrid_runs_the_hpke_flow() -> Result<(), Box<dyn Error>> {
	assert_eq!(hpke_opens::<HybridProvider>().await?, CONTENT);
	Ok(())
}

/// The CMS flow runs under the outside pairing.
#[tokio::test]
async fn an_outside_hybrid_runs_the_cms_flow() -> Result<(), Box<dyn Error>> {
	assert_eq!(cms_opens::<HybridProvider>().await?, CONTENT);
	Ok(())
}

/// A session under the outside pairing renews its epoch in band.
#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
#[tokio::test]
async fn an_outside_hybrid_renews_its_epoch() -> Result<(), Box<dyn Error>> {
	let renewed = super::super::renewal::renews_its_epoch::<HybridProvider>(p384_identity).await?;
	assert!(renewed);
	Ok(())
}

/// A server whose classical part answers with the scalar of its key-agreement
/// key sends that key inside its hybrid share, so the client refuses the
/// share.
#[tokio::test]
async fn a_hybrid_share_that_carries_the_key_agreement_key_is_refused() -> Result<(), Box<dyn Error>> {
	type Collapsing = OnP384<Hybrid<OutsidePair<KnownReply>>>;
	let backend = AgreementBackend::of(NistP256::known());
	let server = p384_cms_server::<Collapsing, _>("collapsing hybrid server", backend);
	let (mut client, mut server) = cms_pair::<Collapsing>(server, p384_identity());

	let reply = server.reply(client.start()?).await?;
	let refused = client.respond(reply).await;
	assert!(matches!(refused, Err(HandshakeError::ServerEphemeralIsStatic)));
	Ok(())
}

/// A house identity of a fresh secp256k1 key.
#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
fn house_identity() -> SigningIdentity {
	TestIdentity::of(&SigningKey::random(&mut OsRng))
}

/// A session under the house hybrid renews its epoch in band.
#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
#[tokio::test]
async fn the_house_preview_provider_renews_its_epoch() -> Result<(), Box<dyn Error>> {
	let renewed = super::super::renewal::renews_its_epoch::<PreviewPqcProvider>(house_identity).await?;
	assert!(renewed);
	Ok(())
}
