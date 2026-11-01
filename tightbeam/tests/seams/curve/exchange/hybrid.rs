//! A hybrid pairing an outside crate names: the outside ML-KEM-768 with the
//! outside ECDH over P-256, under [`OutsidePair`] and an identifier of the
//! outside arc. The house [`Hybrid`] runs it as it runs the house pairing,
//! since each outside share states its fixed width.
//!
//! These suites run under it:
//!
//! - both handshake flows and an in-band renewal of a multiplexed session,
//! - the refusal, end to end, of a server share whose classical part is the server's key-agreement key, and
//! - the ACVP vectors of an offer and of a reply, which the house [`Hybrid`] draws part by part.
//!
//! The house [`PreviewPqcProvider`] renews its epoch in band under the same
//! harness.

use core::marker::PhantomData;

use p256::NistP256;
use tightbeam::crypto::exchange::{Hybrid, HybridPair, KeyExchange, KeyShare};
use tightbeam::der::asn1::ObjectIdentifier;
use tightbeam::der::oid::AssociatedOid;
use tightbeam::testing::vectors::ml_kem::ML_KEM_768;
use tightbeam::testing::{unhex, PublishedDraw, TestKey};
use tightbeam::transport::handshake::HandshakeError;

#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
use tightbeam::crypto::profiles::PreviewPqcProvider;
#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
use tightbeam::crypto::sign::SigningIdentity;
#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
use tightbeam::testing::fixtures::TestIdentity;

use super::ml_kem::MlKem768;
use super::{
	answer_to_a_collapsing_server, cms_opens, hpke_opens, Draw, Fresh, KnownOffer, KnownReply, OnP384, OutsideDh,
	CONTENT,
};
use crate::common::result::TestResult;

#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
use super::p384_identity;
#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
use crate::common::security::fixed_signing_key;

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
async fn an_outside_hybrid_runs_the_hpke_flow() -> TestResult {
	let opened = hpke_opens::<HybridProvider>().await?;
	assert_eq!(opened, CONTENT);
	Ok(())
}

/// The CMS flow runs under the outside pairing.
#[tokio::test]
async fn an_outside_hybrid_runs_the_cms_flow() -> TestResult {
	let opened = cms_opens::<HybridProvider>().await?;
	assert_eq!(opened, CONTENT);
	Ok(())
}

/// A session under the outside pairing renews its epoch in band.
#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
#[tokio::test]
async fn an_outside_hybrid_renews_its_epoch() -> TestResult {
	let renewed = super::super::renewal::renews_its_epoch::<HybridProvider>(p384_identity).await?;
	assert!(renewed);
	Ok(())
}

/// The pairing whose initiator draws the known scalar of P-256.
type KnownOfferHybrid = Hybrid<OutsidePair<KnownOffer>>;

/// The pairing whose responder draws the known scalar of P-256.
type KnownReplyHybrid = Hybrid<OutsidePair<KnownReply>>;

/// The share of the known scalar of P-256, the public key of RFC 6979 §A.2.5
/// in the compressed form.
fn known_share() -> Vec<u8> {
	TestKey::RFC6979_P256_COMPRESSED.to_vec()
}

/// The house [`Hybrid`] draws the seeds of the ACVP key generation vector for
/// its first part, and offers the key of that vector before the share of its
/// second part.
#[test]
fn an_outside_hybrid_offers_the_key_of_its_key_generation_vector() {
	let seeds = [unhex(ML_KEM_768.keygen_d), unhex(ML_KEM_768.keygen_z)].concat();
	let (_pending, offer) = KnownOfferHybrid::offer(&mut PublishedDraw(seeds));
	assert_eq!(offer.to_octets(), [unhex(ML_KEM_768.keygen_ek), known_share()].concat());
}

/// The house [`Hybrid`] answers an offer of the ACVP key under the message of
/// the encapsulation vector with the ciphertext of that vector, before the
/// share of its second part.
#[test]
fn an_outside_hybrid_responds_as_its_encapsulation_vector() -> TestResult {
	let octets = [unhex(ML_KEM_768.encap_ek), known_share()].concat();
	let offer = <<KnownReplyHybrid as KeyExchange>::Offer as KeyShare<KnownReplyHybrid>>::from_octets(&octets)?;

	let (reply, _secret) = KnownReplyHybrid::respond(&offer, &mut PublishedDraw(unhex(ML_KEM_768.encap_m)))?;
	assert_eq!(reply.to_octets(), [unhex(ML_KEM_768.encap_c), known_share()].concat());
	Ok(())
}

/// A server whose classical part answers with the scalar of its key-agreement
/// key sends that key inside its hybrid share, so the client refuses the
/// share.
#[tokio::test]
async fn a_hybrid_share_that_carries_the_key_agreement_key_is_refused() {
	type Collapsing = OnP384<Hybrid<OutsidePair<KnownReply>>>;

	let refused = answer_to_a_collapsing_server::<Collapsing>().await;
	assert!(matches!(refused, Err(HandshakeError::ServerEphemeralIsStatic)));
}

/// A house identity of the secp256k1 key whose scalar is thirty-two `seed`
/// octets.
#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
fn house_identity(seed: u8) -> SigningIdentity {
	TestIdentity::of(&fixed_signing_key(seed))
}

/// A session under the house hybrid renews its epoch in band.
#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
#[tokio::test]
async fn the_house_preview_provider_renews_its_epoch() -> TestResult {
	let renewed = super::super::renewal::renews_its_epoch::<PreviewPqcProvider>(house_identity).await?;
	assert!(renewed);
	Ok(())
}
