//! # Cipher downgrade threat
//!
//! ## Weakness
//! A negotiated handshake may complete with a weaker cipher than the client
//! prefers if the signed transcript does not detect message substitution
//! across cipher strengths.
//!
//! The strength floor of the victim is the second line: it refuses AES-128-GCM
//! with `BelowStrengthFloor` whatever the transcript says, so each test reads
//! the first line by its variant, `SignatureVerificationFailed`.
//!
//! ## Attack
//! 1. The victim offers AES-256-GCM, the strong cipher, ahead of AES-128-GCM: the
//!    `SecurityOffer` of its opening carries the AEAD OID (`...3.4.1.46`).
//! 2. A MITM changes the opening so that it offers AES-128-GCM alone, the weak cipher (OID `...3.4.1.6`).
//! 3. A server that runs the weak cipher answers it with a reply that selects AES-128-GCM.
//! 4. The MITM hands that reply to the victim.
//!
//! An HPKE hello travels in the clear, so the MITM forges the offer and keeps
//! the client random and `R`. A CMS opening carries its offer as an
//! authenticated attribute of its seal, so the MITM forges the attribute in
//! place, or sends an opening that it seals itself.
//!
//! ## Expected control
//! The transcript MUST bind the opening with its offer. The server signed a
//! transcript of the weak opening, and the victim checks the reply against a
//! transcript of its strong opening, so the reply's signature MUST fail
//! (`SignatureVerificationFailed`) before the victim reads the selection.
//!
//! A CMS server MUST refuse an offer forged in place, because the seal of the
//! opening authenticates it.
//!
//! ## References
//! - CWE-757: Selection of Less-Secure Algorithm During Negotiation ('Algorithm
//!   Downgrade') <https://cwe.mitre.org/data/definitions/757.html>
//! - CAPEC-220: Client-Server Protocol Manipulation <https://capec.mitre.org/data/definitions/220.html>
//! - CAPEC-620: Drop Encryption Level <https://capec.mitre.org/data/definitions/620.html>
//! - RFC 9846 (TLS 1.3) §4.1.3: downgrade protection

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::der::Decode;
use tightbeam::transport::handshake::negotiation::SecurityOffer;
use tightbeam::transport::handshake::{ClientHello, HandshakeError, HandshakeMessage, Hpke};
use tightbeam::TightBeamError;

#[cfg(feature = "transport-cms")]
use tightbeam::crypto::cms::EnvelopeError;
#[cfg(feature = "transport-cms")]
use tightbeam::transport::handshake::Cms;

use crate::common::result::TestResult;
use crate::common::security::{carried_hello, hello_opening, weak_security_profile, ServerMaterials};
use crate::security::common::{Aes128CryptoProvider, DowngradeAttack, SessionFlow};

#[cfg(feature = "transport-cms")]
use crate::security::common::forge_sealed_offer;

/// `opening` with a forged offer of the weak profile alone. The hello keeps its
/// `client_random` and its client ephemeral.
fn weakened_hello(opening: HandshakeMessage) -> Result<HandshakeMessage, TightBeamError> {
	let mut hello = ClientHello::from_der(&carried_hello(opening))?;
	hello.security_offer = Some(SecurityOffer::new(vec![weak_security_profile()]));
	Ok(hello_opening(&hello))
}

/// The victim of flow `F` accepts the reply of its server to its opening, so a
/// refusal of a downgrade comes from what the MITM changed.
async fn the_victim_accepts_its_own_exchange<F>() -> TestResult
where
	F: SessionFlow<DefaultCryptoProvider> + SessionFlow<Aes128CryptoProvider>,
{
	let mut attack = DowngradeAttack::<F>::new(&ServerMaterials::fixed());
	let opening = attack.victim_opening()?;
	let reply = attack.strong_reply(opening).await?;

	attack.victim_reads(reply).await?;
	Ok(())
}

/// An HPKE victim accepts the reply to its own opening.
#[tokio::test]
async fn an_hpke_victim_accepts_the_reply_to_its_own_opening() -> TestResult {
	the_victim_accepts_its_own_exchange::<Hpke>().await
}

/// A CMS victim accepts the reply to its own opening.
#[cfg(feature = "transport-cms")]
#[tokio::test]
async fn a_cms_victim_accepts_the_reply_to_its_own_opening() -> TestResult {
	the_victim_accepts_its_own_exchange::<Cms>().await
}

/// A MITM forges the offer of an HPKE hello to name the weak profile, and the
/// weak server signs the forged hello, so the signature fails against the hello
/// that the victim sent.
#[tokio::test]
async fn a_forged_hpke_offer_fails_the_reply_signature() -> TestResult {
	let mut attack = DowngradeAttack::<Hpke>::new(&ServerMaterials::fixed());
	let opening = attack.victim_opening()?;
	let reply = attack.weak_reply(weakened_hello(opening)?).await?;

	let verdict = attack.victim_reads(reply).await;
	assert!(matches!(verdict, Err(HandshakeError::SignatureVerificationFailed)));
	Ok(())
}

/// A MITM replaces a CMS opening with a weak opening that it seals itself, and
/// the weak server signs that opening, so the signature fails against the
/// opening that the victim sent.
#[cfg(feature = "transport-cms")]
#[tokio::test]
async fn a_cms_opening_of_the_mitm_fails_the_reply_signature() -> TestResult {
	let mut attack = DowngradeAttack::<Cms>::new(&ServerMaterials::fixed());
	attack.victim_opening()?;

	let substitute = attack.mitm_opening()?;
	let reply = attack.weak_reply(substitute).await?;

	let verdict = attack.victim_reads(reply).await;
	assert!(matches!(verdict, Err(HandshakeError::SignatureVerificationFailed)));
	Ok(())
}

/// A MITM forges the sealed offer of a CMS opening in place, and the seal
/// authenticates the offer, so the server refuses the opening.
#[cfg(feature = "transport-cms")]
#[tokio::test]
async fn a_cms_offer_forged_in_place_fails_the_seal_of_its_opening() -> TestResult {
	let mut attack = DowngradeAttack::<Cms>::new(&ServerMaterials::fixed());
	let opening = attack.victim_opening()?;
	let forged = forge_sealed_offer(&opening)?;

	let refused = attack.strong_reply(forged).await;
	assert!(matches!(refused, Err(HandshakeError::Envelope(EnvelopeError::Authentication))));
	Ok(())
}
