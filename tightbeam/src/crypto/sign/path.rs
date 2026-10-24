//! The certification path a signer presents in the `certificates` of a
//! `SignedData` (RFC 5652 §5.1).
//!
//! A handshake reply, and the client Finished of a mutual client, carry the
//! signing certificate and the issuers above it, so a peer whose store holds
//! the trust anchor alone can build the path. [`PresentedCertificates`] is
//! what a signing identity presents.
//!
//! # The walk
//!
//! The set is unordered, so [`PresentedPath`] builds the path once by name,
//! from the certificate the signer's `sid` names:
//!
//! 1. The set holds at most [`MAX_PRESENTED_PATH`] certificates.
//! 2. Each step takes the one certificate whose subject is the issuer of the
//!    one below it (RFC 5280 §6.1.3(a)(4)).
//! 3. A self-issued certificate, or an issuer that the set does not hold, ends the path.
//!
//! The walk refuses two certificates of one subject, and a path that returns
//! to a certificate it holds. The store then validates the path to one of its
//! trust anchors (RFC 5280 §6.1). A signing identity holds only a chain that
//! the walk takes whole.

use core::iter;

#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, string::ToString, sync::Arc, vec::Vec};
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::asn1::admission::DerAdmission;
use crate::cms::cert::CertificateChoices;
use crate::cms::signed_data::CertificateSet;
use crate::constants::MAX_PRESENTED_PATH;
use crate::crypto::sign::SignerError;
use crate::crypto::x509::error::CertificateValidationError;
use crate::der::asn1::{ContextSpecificRef, SetOfVec};
use crate::der::{Encode, TagMode, TagNumber};
use crate::frame::CERTIFICATES_TAG;
use crate::x509::Certificate;

/// The certification path of a signing certificate as a `SignedData`
/// presents it: the certificate the signer's `sid` names, and each issuer
/// above it that the set holds.
///
/// The HPKE trust names it as what a reply presents, so it is `pub` in a
/// private module. Its fields and its constructors stay in the crate.
pub struct PresentedPath {
	/// The certificate the signer's `sid` names.
	leaf: Certificate,
	/// The issuers above the leaf that the set holds.
	issuers: PresentedIssuers,
}

/// The issuers above a signing certificate that its `SignedData` holds, the
/// top first, so each issues the one after it and the last issues the leaf.
///
/// A trust that holds a store validates them with the leaf, through the
/// `verify_presented` of a [`CertificateTrust`] or the `evaluate_presented`
/// of a [`CertificateValidation`].
///
/// [`CertificateTrust`]: crate::crypto::x509::store::CertificateTrust
/// [`CertificateValidation`]: crate::crypto::x509::policy::CertificateValidation
pub(crate) struct PresentedIssuers(Vec<Certificate>);

impl PresentedPath {
	/// Refuse a set of `presented` certificates past [`MAX_PRESENTED_PATH`].
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::PathLenExceeded`] -- the set holds more
	///   than [`MAX_PRESENTED_PATH`] certificates.
	pub(crate) fn bound(presented: usize) -> Result<(), CertificateValidationError> {
		if presented > MAX_PRESENTED_PATH {
			return Err(CertificateValidationError::PathLenExceeded);
		}

		Ok(())
	}

	/// The path of `leaf` among `held`, the other certificates of its set.
	///
	/// A certificate of `held` off the path stays out of it, so a validator
	/// reads the path alone.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::PathLenExceeded`] -- the set holds more
	///   than [`MAX_PRESENTED_PATH`] certificates.
	/// - The errors of [`Self::issuer_order`].
	pub(crate) fn walk(leaf: Certificate, held: Vec<Certificate>) -> Result<Self, CertificateValidationError> {
		Self::bound(held.len().saturating_add(1))?;
		let order = Self::issuer_order(&leaf, &held)?;

		// Each issuer moves out of the set by its position, top first.
		let mut held: Vec<Option<Certificate>> = held.into_iter().map(Some).collect();
		let take = |position: &usize| held.get_mut(*position).and_then(Option::take);
		let taken = order.iter().rev().filter_map(take);
		let issuers = PresentedIssuers(taken.collect());
		Ok(Self { leaf, issuers })
	}

	/// The positions in `held` of the issuers above `leaf`, the nearest
	/// first.
	///
	/// Each step takes the certificate of `held` whose subject is the issuer
	/// of the one below it. The walk ends at a self-issued certificate, or at
	/// an issuer that `held` does not hold. Each step takes a certificate the
	/// walk has not taken, so the walk ends within `held.len()` steps.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::AmbiguousIssuer`] -- two certificates of
	///   `held` carry as subject the name of one issuer.
	/// - [`CertificateValidationError::PathCycle`] -- the walk returns to a certificate of the path.
	fn issuer_order(leaf: &Certificate, held: &[Certificate]) -> Result<Vec<usize>, CertificateValidationError> {
		let mut order: Vec<usize> = Vec::new();
		let mut current = leaf;
		while current.tbs_certificate.issuer != current.tbs_certificate.subject {
			let issuer = &current.tbs_certificate.issuer;
			let names_issuer = |(_, held): &(usize, &Certificate)| held.tbs_certificate.subject == *issuer;
			let mut named = held.iter().enumerate().filter(names_issuer);
			let Some((position, next)) = named.next() else {
				break;
			};

			if named.next().is_some() {
				return Err(CertificateValidationError::AmbiguousIssuer { issuer: issuer.to_string() });
			}
			if order.contains(&position) || leaf.tbs_certificate.subject == *issuer {
				return Err(CertificateValidationError::PathCycle { issuer: issuer.to_string() });
			}

			order.push(position);
			current = next;
		}

		Ok(order)
	}

	/// The leaf, and the issuers the set holds above it.
	pub(crate) fn into_parts(self) -> (Certificate, PresentedIssuers) {
		(self.leaf, self.issuers)
	}
}

impl PresentedIssuers {
	/// The issuers, top first, the order that
	/// [`CertificateTrust::verify_presented`] reads.
	///
	/// [`CertificateTrust::verify_presented`]: crate::crypto::x509::store::CertificateTrust::verify_presented
	pub(crate) fn as_slice(&self) -> &[Certificate] {
		&self.0
	}
}

/// The `certificates` field a signing identity presents in a `SignedData`:
/// its signing certificate and each issuer it presents, encoded once.
///
/// [`Self::chain`] is its one constructor, and it holds a chain that the walk
/// of [`PresentedPath`] takes whole, so every reader rebuilds the path the
/// identity presents.
#[derive(Clone, Debug)]
pub(crate) struct PresentedCertificates {
	/// The set the signer writes into `certificates`.
	set: Arc<CertificateSet>,
	/// The DER of the `[0] IMPLICIT` field that holds the set, which a
	/// handshake transcript binds as it is sent.
	field: Arc<[u8]>,
}

impl PresentedCertificates {
	/// The field of `leaf` and `issuers`, in which each certificate names the
	/// next one as its issuer.
	///
	/// A self-issued certificate ends the walk of a reader, so it ends the
	/// chain too, and the walk then takes the whole chain.
	///
	/// # Errors
	///
	/// - [`SignerError::Certificate`] -- a certificate does not name the next
	///   one as its issuer, a self-issued certificate sits below another, the
	///   chain repeats a subject or returns to a certificate it holds, or it
	///   holds more than [`MAX_PRESENTED_PATH`] certificates.
	/// - [`SignerError::Encoding`] -- the set or the field fails to encode.
	pub(crate) fn chain(leaf: &Certificate, issuers: &[Arc<Certificate>]) -> Result<Self, SignerError> {
		// 1. Each certificate names the next one as its issuer, and a
		//    self-issued one, which is its own issuer, is the last.
		let lower = iter::once(leaf).chain(issuers.iter().map(AsRef::as_ref));
		for (lower, upper) in lower.zip(issuers.iter()) {
			let issuer = &lower.tbs_certificate.issuer;
			if *issuer != upper.tbs_certificate.subject {
				let subject = upper.tbs_certificate.subject.to_string();
				return Err(CertificateValidationError::InvalidChain { issuer: issuer.to_string(), subject }.into());
			}
			if *issuer == lower.tbs_certificate.subject {
				return Err(CertificateValidationError::AmbiguousIssuer { issuer: issuer.to_string() }.into());
			}
		}

		// 2. A reader walks the set back to this chain, within the cap, and
		//    the walk hands each certificate back to the set.
		let held = issuers.iter().map(|issuer| Certificate::clone(issuer)).collect();
		let (leaf, issuers) = PresentedPath::walk(leaf.to_owned(), held)?.into_parts();

		// 3. Encode the set, and the field that holds it, once, with its
		//    choices in DER order (X.690 § 11.6), as a `Signed` encode of a
		//    `SignedData` of the set sends them.
		let presented = iter::once(leaf).chain(issuers.0);
		let choices: Vec<CertificateChoices> = presented.map(CertificateChoices::Certificate).collect();
		let set = SetOfVec::try_from(choices)?;
		let field = ContextSpecificRef { tag_number: TagNumber::N0, tag_mode: TagMode::Implicit, value: &set };
		let mut field = field.to_der()?;
		DerAdmission::arrange_fields(&mut field, &[CERTIFICATES_TAG])?;
		Ok(Self { set: Arc::new(CertificateSet(set)), field: Arc::from(field) })
	}

	/// The set the signer writes into `certificates`, as a copy a
	/// `SignedData` owns.
	pub(crate) fn set(&self) -> CertificateSet {
		CertificateSet::clone(&self.set)
	}

	/// The DER of the `certificates` field, which a handshake transcript
	/// binds as it is sent.
	pub(crate) fn field(&self) -> &[u8] {
		&self.field
	}
}
