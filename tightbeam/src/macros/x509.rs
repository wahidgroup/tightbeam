/// Construct an X.509 certificate for a given profile.
///
/// The validity of a certificate starts at its construction and lasts for
/// `duration:`. Explicit validity bounds take a
/// [`Validity`](crate::crypto::x509::time::Validity) built by hand and
/// [`CertificateBuilder`](crate::crypto::x509::builder::CertificateBuilder).
///
/// # Key identifiers
///
/// - Each certificate carries a subjectKeyIdentifier by RFC 7093 §2 method 1 (RFC 5280 §4.2.1.2).
/// - The method takes the leftmost 160 bits of the SHA-256 of the `subjectPublicKey` BIT STRING.
/// - An issued certificate also carries the issuer's `authorityKeyIdentifier` by the same method.
///
/// # Signature type
///
/// The optional `signature:` key names the type the signer signs under, such
/// as `p256::ecdsa::DerSignature` for a P-256 signer. Without the key, the
/// certificate carries an ECDSA signature over secp256k1 in DER form.
///
/// # Examples
///
/// ```ignore
/// use core::time::Duration;
///
/// use tightbeam::cert;
///
/// // Self-signed root (unbounded path length), valid for one year from now.
/// let cert = cert!(
///     profile: Root,
///     subject: "CN=My Root CA",
///     serial: 1u32,
///     duration: Duration::from_secs(365 * 24 * 60 * 60),
///     signer: &signing_key,
///     subject_public_key: spki
/// )?;
///
/// // Bounded root: pathLenConstraint per RFC 5280 §4.2.1.9 (Root=2, Org=1, Schema=0).
/// let bounded = cert!(
///     profile: Root,
///     subject: "CN=My Root CA",
///     serial: 1u32,
///     duration: Duration::from_secs(365 * 24 * 60 * 60),
///     signer: &signing_key,
///     subject_public_key: spki,
///     path_len: 2u8
/// )?;
/// ```
#[macro_export]
macro_rules! cert {
	// Parse a string into a distinguished `Name` (RFC 5280 §4.1.2.4/§4.1.2.6).
	(@name $value:expr) => {
		<$crate::crypto::x509::name::Name as core::str::FromStr>::from_str($value)?
	};

	// The `authorityKeyIdentifier` of the key that `$signer` holds, by RFC 7093
	// §2 method 1 (RFC 5280 §4.2.1.1).
	(@authority $signer:expr) => {{
		use $crate::crypto::sign::Keypair;

		let issuer_public_key = $crate::spki::SubjectPublicKeyInfoOwned::from_key($signer.verifying_key())?;
		let issuer_key_identifier = $crate::crypto::x509::utils::Skid::of_public_key(&issuer_public_key);
		$crate::crypto::x509::ext::pkix::AuthorityKeyIdentifier {
			key_identifier: Some($crate::der::asn1::OctetString::new(issuer_key_identifier.as_bytes().as_slice())?),
			authority_cert_issuer: None,
			authority_cert_serial_number: None,
		}
	}};

	// The `keyUsage` of a CA: certificate and CRL signing (RFC 5280 §4.2.1.3).
	(@ca_usage) => {
		$crate::crypto::x509::ext::pkix::KeyUsage(
			$crate::crypto::x509::ext::pkix::KeyUsages::KeyCertSign
				| $crate::crypto::x509::ext::pkix::KeyUsages::CRLSign,
		)
	};

	// Drive `CertificateBuilder` once for every profile, under the manual
	// profile, so the macro writes every extension: the subject key identifier
	// of RFC 7093 §2 method 1, then the extensions of the arm.
	(@build
		issuer: $issuer:expr,
		subject: $subject:expr,
		serial: $serial:expr,
		duration: $duration:expr,
		subject_public_key: $spki:expr,
		signer: $signer:expr,
		signature: $sig:ty,
		extensions: [$($ext:expr),* $(,)?]
	) => {{
		use $crate::crypto::x509::builder::Builder;

		let subject_public_key_info: $crate::spki::SubjectPublicKeyInfoOwned = $spki;
		let key_identifier = $crate::crypto::x509::utils::Skid::of_public_key(&subject_public_key_info);
		let key_identifier = $crate::crypto::x509::ext::pkix::SubjectKeyIdentifier::try_from(key_identifier)?;

		let mut builder = $crate::crypto::x509::builder::CertificateBuilder::new(
			$crate::crypto::x509::builder::Profile::Manual { issuer: $issuer },
			$crate::crypto::x509::serial_number::SerialNumber::from($serial),
			$crate::crypto::x509::time::Validity::from_now($duration)?,
			$subject,
			subject_public_key_info,
			$signer,
		)?;

		builder.add_extension(&key_identifier)?;
		$( builder.add_extension(&$ext)?; )*

		builder.build::<$sig>()
	}};

	// A root CA certificate that sets pathLenConstraint (RFC 5280 §4.2.1.9).
	(
		profile: Root,
		subject: $subject:expr,
		serial: $serial:expr,
		duration: $duration:expr,
		signer: $signer:expr,
		subject_public_key: $spki:expr,
		path_len: $path_len:expr
		$(, signature: $sig:ty)?
	) => {{
		$crate::cert!(@build
			issuer: None,
			subject: $crate::cert!(@name $subject),
			serial: $serial,
			duration: $duration,
			subject_public_key: $spki,
			signer: $signer,
			signature: $crate::cert!(@signature $($sig)?),
			extensions: [
				$crate::crypto::x509::ext::pkix::BasicConstraints { ca: true, path_len_constraint: Some($path_len) },
				$crate::cert!(@ca_usage),
			]
		)
	}};

	// A root CA certificate with an unbounded path length.
	(
		profile: Root,
		subject: $subject:expr,
		serial: $serial:expr,
		duration: $duration:expr,
		signer: $signer:expr,
		subject_public_key: $spki:expr
		$(, signature: $sig:ty)?
	) => {{
		$crate::cert!(@build
			issuer: None,
			subject: $crate::cert!(@name $subject),
			serial: $serial,
			duration: $duration,
			subject_public_key: $spki,
			signer: $signer,
			signature: $crate::cert!(@signature $($sig)?),
			extensions: [
				$crate::crypto::x509::ext::pkix::BasicConstraints { ca: true, path_len_constraint: None },
				$crate::cert!(@ca_usage),
			]
		)
	}};

	// A root CA certificate with no `subject_public_key:` is a compile error.
	(
		profile: Root,
		subject: $subject:expr,
		serial: $serial:expr,
		duration: $duration:expr,
		signer: $signer:expr
	) => {{
		compile_error!(
			"cert!(profile: Root, ...) requires `subject_public_key: <SPKI>`.\n\
			 Pass the subject's SPKI explicitly to avoid argument shifting.\n\
			 If you want it derived from the signer, please specify how to obtain SPKI from your signer type."
		);
	}};

	// A leaf certificate. `key_usage:` replaces the default `keyUsage`, as
	// `digitalSignature | keyAgreement` does for a certificate a KEM
	// encapsulates to.
	(
		profile: Leaf,
		subject: $subject:expr,
		issuer: $issuer:expr,
		serial: $serial:expr,
		duration: $duration:expr,
		subject_public_key: $spki:expr,
		signer: $signer:expr
		$(, key_usage: $key_usage:expr)?
		$(, extensions: [$($ext:expr),* $(,)?])?
		$(, signature: $sig:ty)?
	) => {{
		$crate::cert!(@build
			issuer: Some($crate::cert!(@name $issuer)),
			subject: $crate::cert!(@name $subject),
			serial: $serial,
			duration: $duration,
			subject_public_key: $spki,
			signer: $signer,
			signature: $crate::cert!(@signature $($sig)?),
			extensions: [
				$crate::cert!(@authority $signer),
				$crate::crypto::x509::ext::pkix::BasicConstraints { ca: false, path_len_constraint: None },
				$crate::crypto::x509::ext::pkix::KeyUsage($crate::cert!(@leaf_usage $( $key_usage )?)),
				$($($ext),*)?
			]
		)
	}};

	// A subordinate CA certificate, with an optional pathLenConstraint.
	(
		profile: SubCA,
		subject: $subject:expr,
		issuer: $issuer:expr,
		serial: $serial:expr,
		duration: $duration:expr,
		subject_public_key: $spki:expr,
		signer: $signer:expr
		$(, path_len: $path_len:expr)?
		$(, signature: $sig:ty)?
	) => {{
		$crate::cert!(@build
			issuer: Some($crate::cert!(@name $issuer)),
			subject: $crate::cert!(@name $subject),
			serial: $serial,
			duration: $duration,
			subject_public_key: $spki,
			signer: $signer,
			signature: $crate::cert!(@signature $($sig)?),
			extensions: [
				$crate::cert!(@authority $signer),
				$crate::crypto::x509::ext::pkix::BasicConstraints {
					ca: true,
					path_len_constraint: $crate::cert!(@path_len $( $path_len )?),
				},
				$crate::cert!(@ca_usage),
			]
		)
	}};

	// Resolve the signature type: the `signature:` key, or ECDSA over
	// secp256k1 in DER when the key is absent.
	(@signature) => {
		$crate::crypto::sign::ecdsa::der::Signature<$crate::crypto::sign::ecdsa::Secp256k1>
	};
	(@signature $sig:ty) => {
		$sig
	};

	// Resolve an optional pathLenConstraint: absent yields an unbounded path.
	(@path_len) => {
		None
	};
	(@path_len $path_len:expr) => {
		Some($path_len)
	};

	// Resolve an optional leaf `keyUsage`: absent yields `digitalSignature |
	// nonRepudiation` (RFC 5280 §4.2.1.3).
	(@leaf_usage) => {
		$crate::crypto::x509::ext::pkix::KeyUsages::DigitalSignature
			| $crate::crypto::x509::ext::pkix::KeyUsages::NonRepudiation
	};
	(@leaf_usage $key_usage:expr) => {
		($key_usage).into()
	};
}

/// Builds a PKCS #10 certificate signing request (RFC 2986) for `subject`,
/// signed by `signer`.
///
/// The optional `signature:` key names the signature type, as it does for
/// [`cert!`](crate::cert). The default is an ECDSA signature over secp256k1 in
/// DER form. Each entry of `extensions:` goes into the extensionRequest
/// attribute of the request (RFC 2985 §5.4.2).
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::sign::ecdsa::Secp256k1SigningKey;
/// use tightbeam::crypto::sign::Sha3Signer;
/// use tightbeam::csr;
///
/// let signing_key = Secp256k1SigningKey::from_bytes(&[7; 32].into())?;
/// let signer = Sha3Signer::from(&signing_key);
///
/// let request = csr!(subject: "CN=example.com", signer: &signer)?;
/// assert_eq!(request.info.subject.to_string(), "CN=example.com");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[cfg(feature = "x509")]
#[macro_export]
macro_rules! csr {
	(
		subject: $subject:expr,
		signer: $signer:expr
		$(, extensions: [$($ext:expr),* $(,)?])?
		$(, signature: $sig:ty)?
	) => {{
		use core::str::FromStr;

		use $crate::crypto::x509::builder::{Builder, RequestBuilder};
		use $crate::crypto::x509::name::Name;

		let subject = Name::from_str($subject)?;
		let mut builder = RequestBuilder::new(subject, $signer)?;

		$(
			$(
				builder.add_extension(&$ext)?;
			)*
		)?

		builder.build::<$crate::cert!(@signature $($sig)?)>()
	}};
}

#[cfg(test)]
mod tests {
	use crate::crypto::policy::{Secp256k1Policy, VerificationPolicy};
	use crate::crypto::sign::ecdsa::{Secp256k1SigningKey, Secp256k1VerifyingKey};
	use crate::crypto::sign::Sha3Signer;
	use crate::crypto::x509::ext::pkix::{
		AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier,
	};
	use crate::crypto::x509::store::CertificateTrust;
	use crate::crypto::x509::utils::CertificateExt;
	use crate::der::asn1::OctetString;
	use crate::der::Encode;
	use crate::spki::SubjectPublicKeyInfoOwned;
	use crate::testing::fixtures::TestStore;
	use crate::testing::{TestKey, TestResult};
	use crate::x509::Certificate;

	const SUBJECT: &str = "CN=Test Root CA,O=Test Org,C=US";

	/// Returns the key of `seed` beside its SubjectPublicKeyInfo.
	///
	/// `Sha3Signer` borrows its key, so callers own the key and build the
	/// signer locally to keep the borrow alive across the `cert!` invocation.
	fn signing_material(seed: u8) -> (Secp256k1SigningKey, SubjectPublicKeyInfoOwned) {
		let signing_key = TestKey::fixed(seed);
		let verifying_key = Secp256k1VerifyingKey::from(&signing_key);
		let spki = SubjectPublicKeyInfoOwned::from_key(verifying_key);
		(signing_key, spki.expect("a secp256k1 key encodes as a SubjectPublicKeyInfo"))
	}

	fn one_year() -> core::time::Duration {
		core::time::Duration::from_secs(365 * 24 * 60 * 60)
	}

	/// Returns the certificate that `issue` issues. The expansion of `cert!`
	/// returns each error it meets with `?`, so `issue` returns a `Result`.
	fn issued(issue: impl FnOnce() -> Result<Certificate, Box<dyn core::error::Error>>) -> Certificate {
		issue().expect("a cert! invocation issues its certificate")
	}

	/// A `cert!` root names its own subject as its issuer.
	#[test]
	fn a_cert_macro_root_is_self_issued() {
		let (_, certificate) = root(1);
		assert_eq!(certificate.tbs_certificate.subject, certificate.tbs_certificate.issuer);
	}

	/// A `cert!` root with `path_len:` states that path length in its
	/// `basicConstraints` (RFC 5280 §4.2.1.9).
	#[test]
	fn a_cert_macro_root_carries_the_path_length_it_names() -> TestResult {
		let (signing_key, spki) = signing_material(1);
		let signer = Sha3Signer::from(&signing_key);

		let cert = cert!(
			profile: Root,
			subject: SUBJECT,
			serial: 1u32,
			duration: one_year(),
			signer: &signer,
			subject_public_key: spki,
			path_len: 2u8
		)?;

		let basic_constraints = &cert.extension::<BasicConstraints>()?;
		assert_eq!(cert.tbs_certificate.subject, cert.tbs_certificate.issuer);
		assert!(matches!(
			basic_constraints,
			Some(BasicConstraints { ca: true, path_len_constraint: Some(2) })
		));

		Ok(())
	}

	/// A self-signed `cert!` root under the key of `seed`.
	fn root(seed: u8) -> (Secp256k1SigningKey, Certificate) {
		let (signing_key, spki) = signing_material(seed);
		let signer = Sha3Signer::from(&signing_key);
		let certificate = issued(|| {
			Ok(cert!(
				profile: Root,
				subject: SUBJECT,
				serial: 1u32,
				duration: one_year(),
				signer: &signer,
				subject_public_key: spki
			)?)
		});
		(signing_key, certificate)
	}

	/// A `cert!` leaf of the key of the seed 2 that the root of `root_key`
	/// issues.
	fn leaf_of(root_key: &Secp256k1SigningKey) -> Certificate {
		let (_, spki) = signing_material(2);
		let signer = Sha3Signer::from(root_key);
		issued(|| {
			Ok(cert!(
				profile: Leaf,
				subject: "CN=Test Leaf,O=Test Org,C=US",
				issuer: SUBJECT,
				serial: 2u32,
				duration: one_year(),
				subject_public_key: spki,
				signer: &signer
			)?)
		})
	}

	/// The signature of a `cert!` root is a DER `ECDSA-Sig-Value`, so it
	/// verifies under the crate's own policy (RFC 3279 §2.2.3).
	#[test]
	fn a_cert_macro_root_verifies_under_the_secp256k1_policy() -> TestResult {
		let (_, certificate) = root(1);
		let public_key_der = certificate.tbs_certificate.subject_public_key_info.to_der()?;
		let message = certificate.tbs_certificate.to_der()?;
		let algorithm = certificate.signature_algorithm.oid;

		let policy = Secp256k1Policy::default();
		policy.verify_signature(&algorithm, &public_key_der, &message, certificate.signature.raw_bytes())?;

		Ok(())
	}

	/// A `cert!` root carries the `subjectKeyIdentifier` of RFC 7093 §2
	/// method 1, which RFC 5280 §4.2.1.2 requires of a CA certificate. The
	/// root's key is the `0x01` key, whose identifier comes from Python's
	/// `hashlib` over the independently computed point, not from the crate.
	#[test]
	fn a_cert_macro_root_carries_its_rfc_7093_key_identifier() -> TestResult {
		let (_, certificate) = root(1);
		let expected = SubjectKeyIdentifier::from(OctetString::new(TestKey::INSECURE_FIXED_KEY_IDENTIFIER)?);

		let carried = certificate.extension::<SubjectKeyIdentifier>()?;
		assert_eq!(carried, Some(expected));
		Ok(())
	}

	/// A `cert!` leaf names its issuer's key by the issuer's own key
	/// identifier (RFC 5280 §4.2.1.1).
	#[test]
	fn a_cert_macro_leaf_names_its_issuer_by_its_key_identifier() -> TestResult {
		let (root_key, root_certificate) = root(1);
		let leaf = leaf_of(&root_key);

		let issuer = root_certificate.extension::<SubjectKeyIdentifier>()?;
		let authority = leaf.extension::<AuthorityKeyIdentifier>()?;
		let named = authority.and_then(|authority| authority.key_identifier);
		let identifier = issuer.map(|issuer| issuer.0);
		assert_eq!(named, identifier);
		Ok(())
	}

	/// A `cert!` leaf validates under a store that anchors its `cert!` root,
	/// signature and key identifiers included.
	#[test]
	fn a_cert_macro_chain_validates_under_the_secp256k1_policy() -> TestResult {
		let (root_key, root_certificate) = root(1);
		let leaf = leaf_of(&root_key);
		let store = TestStore::holding([root_certificate.clone()]);

		store.verify_chain(&[root_certificate, leaf])?;

		Ok(())
	}

	/// A `cert!` leaf with no `key_usage:` asserts `digitalSignature |
	/// nonRepudiation` (RFC 5280 §4.2.1.3).
	#[test]
	fn a_cert_macro_leaf_signs_by_default() -> TestResult {
		let (root_key, _) = root(1);
		let leaf = leaf_of(&root_key);

		let key_usage = leaf.extension::<KeyUsage>()?;
		let expected = KeyUsages::DigitalSignature | KeyUsages::NonRepudiation;
		assert_eq!(key_usage.map(|key_usage| key_usage.0), Some(expected));
		Ok(())
	}

	/// A `cert!` leaf with `key_usage:` asserts the usage it names in place
	/// of the default, so a CMS server certificate permits key agreement.
	#[test]
	fn a_cert_macro_leaf_carries_the_key_usage_it_names() -> TestResult {
		let (root_key, _) = root(1);
		let (_, spki) = signing_material(3);
		let signer = Sha3Signer::from(&root_key);
		let usage = KeyUsages::DigitalSignature | KeyUsages::KeyAgreement;
		let leaf = cert!(
			profile: Leaf,
			subject: "CN=Test Server,O=Test Org,C=US",
			issuer: SUBJECT,
			serial: 2u32,
			duration: one_year(),
			subject_public_key: spki,
			signer: &signer,
			key_usage: usage
		)?;

		let key_usage = leaf.extension::<KeyUsage>()?;
		assert_eq!(key_usage.map(|key_usage| key_usage.0), Some(usage));
		Ok(())
	}
}
