//! The handshake and the rekey run here under key exchanges an outside crate
//! brings, each a [`KeyExchange`] with shares of its own:
//!
//! - [`OutsideDh`], ECDH over P-256 or P-384 under the outside arc, whose draw a test can fix,
//! - [`X25519`](x25519::X25519), the exchange of RFC 7748, through `x25519-dalek`, and
//! - [`MlKem768`](ml_kem::MlKem768), the KEM of FIPS 203, through `ml-kem`.
//!
//! [`OnP384`] runs each of them. It signs under ECDSA over P-384, and a CMS
//! server under it agrees through a key on P-256, so no signing key is a key
//! of a P-256 exchange.
//!
//! These suites run under it:
//!
//! - both handshake flows and an in-band renewal of a multiplexed session, under each exchange,
//! - the refusal, end to end, of a server share equal to the server's
//!   key-agreement key, and of a client share equal to the client's signing
//!   key, and
//! - the published vectors of X25519 and of ML-KEM-768, through the operations of each exchange.

use core::marker::PhantomData;
use std::error::Error;

use p256::elliptic_curve::ecdh::diffie_hellman;
use p256::elliptic_curve::point::AffineCoordinates;
use p256::elliptic_curve::sec1::{CompressedPointSize, ToEncodedPoint};
use p256::elliptic_curve::{NonZeroScalar, PublicKey, SecretKey};
use p256::NistP256;
use p384::ecdsa::SigningKey;
use p384::NistP384;
use tightbeam::crypto::common::typenum::Unsigned;
use tightbeam::crypto::exchange::{Ecdhe, HandshakeCurve, KeyExchange, KeyExchangeError, KeyShare, ReplyKind};
use tightbeam::crypto::profiles::SecurityStrength;
use tightbeam::crypto::secret::SecretSlice;
use tightbeam::der::asn1::ObjectIdentifier;
use tightbeam::der::oid::AssociatedOid;
use tightbeam::random::CryptoRngCore;
use tightbeam::spki::SubjectPublicKeyInfoRef;
use tightbeam::testing::unhex;
use tightbeam::transport::handshake::{HandshakeError, HandshakeProvider};
use tightbeam::zeroize::Zeroizing;

use super::p384::{p384_cms_server, p384_identity, p384_identity_of, OnP384};
use super::{
	cms_pair, first_record_opened, hello_carrying, hpke_pair, AgreementBackend, P256Kem, PublishedDraw, CONTENT,
};

mod ml_kem;
mod x25519;

/// A curve of [`OutsideDh`], with the facts the exchange reads from it.
trait DhCurve: HandshakeCurve {
	/// The identifier of ECDH over the curve, under the outside arc.
	const DH: ObjectIdentifier;
	/// The strength NIST SP 800-57 Part 1 Rev. 5 Table 2 gives the size of
	/// the order.
	const STRENGTH: SecurityStrength;
	/// The scalar a test draws in place of a fresh one, in big-endian hex: the
	/// private key of RFC 6979 Appendix A.2 on the curve.
	const KNOWN: &'static str;

	/// The scalar of [`Self::KNOWN`].
	fn known() -> NonZeroScalar<Self> {
		let scalar = NonZeroScalar::<Self>::try_from(unhex(Self::KNOWN).as_slice());
		scalar.expect("the private key of RFC 6979 is a scalar of its curve")
	}
}

/// RFC 6979 A.2.5 names the known scalar.
impl DhCurve for NistP256 {
	const DH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.15");
	const STRENGTH: SecurityStrength = SecurityStrength::BITS_128;
	const KNOWN: &'static str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
}

/// RFC 6979 A.2.6 names the known scalar.
impl DhCurve for NistP384 {
	const DH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.16");
	const STRENGTH: SecurityStrength = SecurityStrength::BITS_192;
	const KNOWN: &'static str =
		"6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5";
}

/// How [`OutsideDh`] draws the scalar of each share. Each scalar is fresh
/// unless the draw names the known scalar of the curve in its place, so a
/// test can make a share collapse into a static key.
trait Draw: Default + Copy + Send + Sync + 'static {
	/// The scalar of the initiator's share.
	fn offer<C: DhCurve>(mut rng: &mut dyn CryptoRngCore) -> NonZeroScalar<C> {
		NonZeroScalar::random(&mut rng)
	}

	/// The scalar of the responder's share.
	fn respond<C: DhCurve>(mut rng: &mut dyn CryptoRngCore) -> NonZeroScalar<C> {
		NonZeroScalar::random(&mut rng)
	}
}

/// Every scalar is fresh.
#[derive(Debug, Default, Clone, Copy)]
struct Fresh;

impl Draw for Fresh {}

/// The responder draws the known scalar, so a server whose key-agreement key
/// holds that scalar sends its key as its share.
#[derive(Debug, Default, Clone, Copy)]
struct KnownReply;

impl Draw for KnownReply {
	fn respond<C: DhCurve>(_rng: &mut dyn CryptoRngCore) -> NonZeroScalar<C> {
		C::known()
	}
}

/// The initiator draws the known scalar, so a client whose signing key holds
/// that scalar sends its key as its share.
#[derive(Debug, Default, Clone, Copy)]
struct KnownOffer;

impl Draw for KnownOffer {
	fn offer<C: DhCurve>(_rng: &mut dyn CryptoRngCore) -> NonZeroScalar<C> {
		C::known()
	}
}

/// ECDH over the curve `C` as an outside crate writes it, whose scalars `D`
/// draws. The secret is the x-coordinate of the agreement (SEC 1 v2.0
/// §3.3.1).
///
/// Its shares take the provided opening form under [`DhCurve::DH`], and it
/// names [`ReplyKind::Dh`], so its reply travels as the `OriginatorPublicKey`
/// of its share.
#[derive(Debug, Default, Clone, Copy)]
struct OutsideDh<C, D>(PhantomData<fn() -> (C, D)>);

impl<C: DhCurve, D: Draw> AssociatedOid for OutsideDh<C, D> {
	const OID: ObjectIdentifier = C::DH;
}

/// One share of [`OutsideDh`]: a point of `C`, which the OCTET STRING
/// carriers hold in its compressed form.
struct DhShare<C: DhCurve>(PublicKey<C>);

impl<C: DhCurve> DhShare<C> {
	/// The x-coordinate of the agreement of `scalar` with this share, as wide
	/// as the field of `C` (SEC 1 v2.0 §3.3.1). The agreement wipes where it
	/// drops.
	fn agreed_with(&self, scalar: &NonZeroScalar<C>) -> SecretSlice<u8> {
		let shared = diffie_hellman(scalar, self.0.as_affine());
		SecretSlice::from(shared.raw_secret_bytes().to_vec())
	}
}

impl<C: DhCurve, D: Draw> KeyShare<OutsideDh<C, D>> for DhShare<C> {
	fn from_octets(octets: &[u8]) -> Result<Self, KeyExchangeError> {
		let expected = CompressedPointSize::<C>::USIZE;
		if octets.len() != expected {
			return Err(KeyExchangeError::Width { expected, actual: octets.len() });
		}

		let compressed = matches!(octets.first(), Some(0x02 | 0x03));
		if !compressed {
			return Err(KeyExchangeError::Malformed);
		}

		let point = PublicKey::<C>::from_sec1_bytes(octets).map_err(|_| KeyExchangeError::Malformed)?;
		Ok(Self(point))
	}

	fn to_octets(&self) -> Vec<u8> {
		let compressed = self.0.to_encoded_point(true);
		compressed.as_bytes().to_vec()
	}

	/// ECDH keeps the x-coordinate alone, so a point and its negation agree
	/// alike (SEC 1 v2.0 §3.3.1).
	fn collapses_into(&self, key: &PublicKey<C>) -> bool {
		self.0.as_affine().x() == key.as_affine().x()
	}
}

impl<C: DhCurve, D: Draw> KeyExchange for OutsideDh<C, D> {
	type Offer = DhShare<C>;
	type Reply = DhShare<C>;
	type Pending = SecretKey<C>;
	type StaticKey = PublicKey<C>;

	const REPLY: ReplyKind = ReplyKind::Dh;

	fn strength() -> SecurityStrength {
		C::STRENGTH
	}

	fn offer(rng: &mut dyn CryptoRngCore) -> (SecretKey<C>, DhShare<C>) {
		let pending = SecretKey::from(D::offer::<C>(rng));
		let offer = DhShare(pending.public_key());
		(pending, offer)
	}

	fn respond(
		offer: &DhShare<C>,
		rng: &mut dyn CryptoRngCore,
	) -> Result<(DhShare<C>, SecretSlice<u8>), KeyExchangeError> {
		let scalar = Zeroizing::new(D::respond::<C>(rng));
		let reply = DhShare(PublicKey::from_secret_scalar(&scalar));
		Ok((reply, offer.agreed_with(&scalar)))
	}

	fn complete(pending: &SecretKey<C>, reply: &DhShare<C>) -> Result<SecretSlice<u8>, KeyExchangeError> {
		let scalar = Zeroizing::new(pending.to_nonzero_scalar());
		Ok(reply.agreed_with(&scalar))
	}

	fn static_key(spki: SubjectPublicKeyInfoRef<'_>) -> Option<PublicKey<C>> {
		Ecdhe::<C>::static_key(spki)
	}
}

/// The provider of ECDH over P-256 with fresh scalars.
type DhProvider = OnP384<OutsideDh<NistP256, Fresh>>;

/// The first record an anonymous HPKE client under `P` seals once the three
/// legs run, as the server opens it.
async fn hpke_opens<P: HandshakeProvider>() -> Result<Vec<u8>, Box<dyn Error>> {
	let opened = first_record_opened(hpke_pair::<P>(p384_identity())).await?;
	Ok(opened)
}

/// The first record a CMS client under `P` seals once the three legs run, as
/// a server that agrees through a fresh P-256 key opens it.
async fn cms_opens<P>() -> Result<Vec<u8>, Box<dyn Error>>
where
	P: HandshakeProvider<VerifyingKey: PartialEq, Kem = P256Kem>,
{
	let server = p384_cms_server::<P, NistP256>("outside exchange server", AgreementBackend::random());
	let opened = first_record_opened(cms_pair::<P>(server, p384_identity())).await?;
	Ok(opened)
}

/// The HPKE flow runs under the outside ECDH over P-256.
#[tokio::test]
async fn an_outside_dh_exchange_runs_the_hpke_flow() -> Result<(), Box<dyn Error>> {
	assert_eq!(hpke_opens::<DhProvider>().await?, CONTENT);
	Ok(())
}

/// The CMS flow runs under the outside ECDH over P-256.
#[tokio::test]
async fn an_outside_dh_exchange_runs_the_cms_flow() -> Result<(), Box<dyn Error>> {
	assert_eq!(cms_opens::<DhProvider>().await?, CONTENT);
	Ok(())
}

/// A session under the outside ECDH over P-256 renews its epoch in band.
#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
#[tokio::test]
async fn an_outside_dh_exchange_renews_its_epoch() -> Result<(), Box<dyn Error>> {
	let renewed = super::renewal::renews_its_epoch::<DhProvider>(p384_identity).await?;
	assert!(renewed);
	Ok(())
}

/// A server whose exchange answers with the scalar of its key-agreement key
/// sends that key as its share. Its signing key is on P-384, so the client
/// compares the share with the key-agreement key alone, and refuses it.
#[tokio::test]
async fn a_server_share_equal_to_its_key_agreement_key_is_refused() -> Result<(), Box<dyn Error>> {
	type Collapsing = OnP384<OutsideDh<NistP256, KnownReply>>;
	let backend = AgreementBackend::of(NistP256::known());
	let server = p384_cms_server::<Collapsing, _>("collapsing server", backend);
	let (mut client, mut server) = cms_pair::<Collapsing>(server, p384_identity());

	let reply = server.reply(client.start()?).await?;
	let refused = client.respond(reply).await;
	assert!(matches!(refused, Err(HandshakeError::ServerEphemeralIsStatic)));
	Ok(())
}

/// A client whose exchange offers the scalar of its signing key sends that
/// key as its share, so the server refuses the closing that names it.
#[tokio::test]
async fn a_client_share_equal_to_its_signing_key_is_refused() -> Result<(), Box<dyn Error>> {
	type Collapsing = OnP384<OutsideDh<NistP384, KnownOffer>>;
	let identity = p384_identity_of(SigningKey::from(NistP384::known()));
	let server = p384_cms_server::<Collapsing, NistP256>("server", AgreementBackend::random());
	let (mut client, mut server) = cms_pair::<Collapsing>(server, identity);

	let reply = server.reply(client.start()?).await?;
	let closing = client.respond(reply).await?;
	let refused = server.finish(closing).await;
	assert!(matches!(refused, Err(HandshakeError::ClientEphemeralIsStatic)));
	Ok(())
}
