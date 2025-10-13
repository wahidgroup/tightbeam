///
/// This macro provides a convenient way to construct X.509 certificates with
/// various profiles and configurations.
///
/// # Examples
///
/// ```ignore
/// use tightbeam::cert;
///
/// // Self-signed certificate
/// let cert = cert!(
///     profile: Root,
///     subject: "CN=My Root CA",
///     serial: 1u32,
///     validity: (not_before, not_after),
///     signer: &signing_key
/// )?;
/// ```
#[macro_export]
macro_rules! cert {
	// Root CA certificate (requires subject_public_key)
	(
		profile: Root,
		subject: $subject:expr,
		serial: $serial:expr,
		validity: ($not_before:expr, $not_after:expr),
		signer: $signer:expr,
		subject_public_key: $spki:expr
	) => {{
		use core::str::FromStr;

		use $crate::crypto::x509::builder::{Builder, Profile};
		use $crate::crypto::x509::name::Name;

		let subject = Name::from_str($subject)?;
		let serial = $crate::crypto::x509::serial_number::SerialNumber::from($serial);

		let builder = $crate::crypto::x509::builder::CertificateBuilder::new(
			Profile::Root,
			serial,
			$crate::crypto::x509::time::Validity::from_now($not_after - $not_before)?,
			subject.clone(),
			$spki,
			$signer,
		)?;

		builder.build::<$crate::crypto::sign::ecdsa::der::Signature<$crate::crypto::sign::ecdsa::Secp256k1>>()
	}};

	// Root CA certificate (no SPKI provided -> clearer error)
	(
		profile: Root,
		subject: $subject:expr,
		serial: $serial:expr,
		validity: ($not_before:expr, $not_after:expr),
		signer: $signer:expr
	) => {{
		compile_error!(
			"cert!(profile: Root, ...) requires [subject_public_key: <SPKI>](http://_vscodecontentref_/0).\n\
			 Pass the subject's SPKI explicitly to avoid argument shifting.\n\
			 If you want it derived from the signer, please specify how to obtain SPKI from your signer type."
		);
	}};

	// Leaf certificate
	(
		profile: Leaf,
		subject: $subject:expr,
		issuer: $issuer:expr,
		serial: $serial:expr,
		validity: ($not_before:expr, $not_after:expr),
		subject_public_key: $spki:expr,
		signer: $signer:expr
		$(, extensions: [$($ext:expr),* $(,)?])?
	) => {{
		use $crate::crypto::x509::builder::{Builder, Profile};
		use $crate::crypto::x509::name::Name;
		use $crate::der::Encode;

		let subject = Name::from_str($subject)?;
		let issuer = Name::from_str($issuer)?;
		let serial = $crate::crypto::x509::serial_number::SerialNumber::from($serial);

		let mut builder = $crate::crypto::x509::builder::CertificateBuilder::new(
			Profile::Leaf { issuer: issuer.clone(), enable_key_agreement: false },
			serial,
			$crate::crypto::x509::time::Validity::from_now($not_after - $not_before)?,
			subject,
			$spki,
			$signer,
		)?;

		$(
			$(
				builder.add_extension(&$ext)?;
			)*
		)?

		builder.build::<$crate::crypto::sign::Signer>()
	}};

	// SubCA certificate
	(
		profile: SubCA,
		subject: $subject:expr,
		issuer: $issuer:expr,
		serial: $serial:expr,
		validity: ($not_before:expr, $not_after:expr),
		subject_public_key: $spki:expr,
		signer: $signer:expr
		$(, path_len: $path_len:expr)?
	) => {{
		use $crate::crypto::x509::builder::{Builder, Profile};
		use $crate::crypto::x509::name::Name;
		use $crate::der::Encode;

		let subject = Name::from_str($subject)?;
		let issuer = Name::from_str($issuer)?;
		let serial = $crate::crypto::x509::serial_number::SerialNumber::from($serial);

		let profile = Profile::SubCA {
			issuer: issuer.clone(),
			path_len_constraint: $( Some($path_len) )?,
		};

		let builder = $crate::crypto::x509::builder::CertificateBuilder::new(
			profile,
			serial,
			$crate::crypto::x509::time::Validity::from_now($not_after - $not_before)?,
			subject,
			$spki,
			$signer,
		)?;

		builder.build::<$crate::crypto::sign::Signer>()
	}};
}

/// Create an X.509 Certificate Signing Request using the builder pattern
///
/// # Examples
///
/// ```ignore
/// use tightbeam::csr;
///
/// let csr = csr!(
///	 subject: "CN=example.com",
///	 signer: &signing_key
/// )?;
/// ```
#[cfg(feature = "x509")]
#[macro_export]
macro_rules! csr {
	(
		subject: $subject:expr,
		signer: $signer:expr
		$(, extensions: [$($ext:expr),* $(,)?])?
	) => {{
		use core::str::FromStr;

		use $crate::crypto::x509::builder::RequestBuilder;
		use $crate::crypto::x509::name::Name;
		use $crate::der::Encode;

		let subject = Name::from_str($subject)?;
		let mut builder = RequestBuilder::new(subject, $signer)?;

		$(
			$(
				builder.add_extension(&$ext)?;
			)*
		)?

		builder.build::<$crate::crypto::sign::Signer>()
	}};
}

#[cfg(test)]
mod tests {
	use crate::crypto::sign::ecdsa::{Secp256k1SigningKey, Secp256k1VerifyingKey};
	use crate::crypto::sign::Sha3Signer;
	use crate::spki::SubjectPublicKeyInfoOwned;

	#[test]
	fn test_cert_macro_root() -> Result<(), Box<dyn core::error::Error>> {
		// Generate a key pair for signing
		let signing_key = Secp256k1SigningKey::random(&mut rand_core::OsRng);
		let verifying_key = Secp256k1VerifyingKey::from(&signing_key);
		let sha3_signer = Sha3Signer::from(&signing_key);
		let spki = SubjectPublicKeyInfoOwned::from_key(verifying_key)?;

		let not_before = std::time::Instant::now();
		let not_after = not_before + std::time::Duration::from_secs(365 * 24 * 60 * 60);

		// Create a self-signed root certificate
		let cert = cert!(
			profile: Root,
			subject: "CN=Test Root CA,O=Test Org,C=US",
			serial: 1u32,
			validity: (not_before, not_after),
			signer: &sha3_signer,
			subject_public_key: spki
		)?;

		// Verify the certificate was created
		assert_eq!(cert.tbs_certificate.subject, cert.tbs_certificate.issuer);

		Ok(())
	}
}
