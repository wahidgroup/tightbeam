///
/// This macro provides a convenient way to construct X.509 certificates with
/// various profiles and configurations.
///
/// # Examples
///
/// ```ignore
/// use tightbeam::cert;
///
/// // Self-signed root (unbounded path length).
/// let cert = cert!(
///     profile: Root,
///     subject: "CN=My Root CA",
///     serial: 1u32,
///     validity: (not_before, not_after),
///     signer: &signing_key,
///     subject_public_key: spki
/// )?;
///
/// // Bounded root: pathLenConstraint per RFC 5280 §4.2.1.9 (Root=2, Org=1, Schema=0).
/// let bounded = cert!(
///     profile: Root,
///     subject: "CN=My Root CA",
///     serial: 1u32,
///     validity: (not_before, not_after),
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

	// Resolve an optional pathLenConstraint: absent yields an unbounded path.
	(@path_len) => {
		None
	};
	(@path_len $path_len:expr) => {
		Some($path_len)
	};

	// Drive `CertificateBuilder` once for every profile: same argument order,
	// optional extensions, caller-selected signature algorithm.
	(@build
		profile: $profile:expr,
		subject: $subject:expr,
		serial: $serial:expr,
		validity: ($not_before:expr, $not_after:expr),
		subject_public_key: $spki:expr,
		signer: $signer:expr,
		signature: $signature:ty
		$(, extensions: [$($ext:expr),* $(,)?])?
	) => {{
		use $crate::crypto::x509::builder::Builder;

		#[allow(unused_mut)]
		let mut builder = $crate::crypto::x509::builder::CertificateBuilder::new(
			$profile,
			$crate::crypto::x509::serial_number::SerialNumber::from($serial),
			$crate::crypto::x509::time::Validity::from_now($not_after - $not_before)?,
			$subject,
			$spki,
			$signer,
		)?;

		$( $( builder.add_extension(&$ext)?; )* )?

		builder.build::<$signature>()
	}};

	// Root CA certificate with an explicit pathLenConstraint (RFC 5280 §4.2.1.9).
	// `x509_cert`'s `Profile::Root` emits no pathLenConstraint, so a bounded root is
	// modelled as a self-issued sub-CA (issuer == subject) carrying the constraint.
	(
		profile: Root,
		subject: $subject:expr,
		serial: $serial:expr,
		validity: ($not_before:expr, $not_after:expr),
		signer: $signer:expr,
		subject_public_key: $spki:expr,
		path_len: $path_len:expr
	) => {{
		let subject = $crate::cert!(@name $subject);

		$crate::cert!(@build
			profile: $crate::crypto::x509::builder::Profile::SubCA {
				issuer: subject.clone(),
				path_len_constraint: Some($path_len),
			},
			subject: subject,
			serial: $serial,
			validity: ($not_before, $not_after),
			subject_public_key: $spki,
			signer: $signer,
			signature: $crate::crypto::sign::ecdsa::der::Signature<$crate::crypto::sign::ecdsa::Secp256k1>
		)
	}};

	// Root CA certificate (requires subject_public_key)
	(
		profile: Root,
		subject: $subject:expr,
		serial: $serial:expr,
		validity: ($not_before:expr, $not_after:expr),
		signer: $signer:expr,
		subject_public_key: $spki:expr
	) => {{
		$crate::cert!(@build
			profile: $crate::crypto::x509::builder::Profile::Root,
			subject: $crate::cert!(@name $subject),
			serial: $serial,
			validity: ($not_before, $not_after),
			subject_public_key: $spki,
			signer: $signer,
			signature: $crate::crypto::sign::ecdsa::der::Signature<$crate::crypto::sign::ecdsa::Secp256k1>
		)
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
			"cert!(profile: Root, ...) requires `subject_public_key: <SPKI>`.\n\
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
		$crate::cert!(@build
			profile: $crate::crypto::x509::builder::Profile::Leaf {
				issuer: $crate::cert!(@name $issuer),
				enable_key_agreement: false,
			},
			subject: $crate::cert!(@name $subject),
			serial: $serial,
			validity: ($not_before, $not_after),
			subject_public_key: $spki,
			signer: $signer,
			signature: $crate::crypto::sign::Signer
			$(, extensions: [$($ext),*])?
		)
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
		$crate::cert!(@build
			profile: $crate::crypto::x509::builder::Profile::SubCA {
				issuer: $crate::cert!(@name $issuer),
				path_len_constraint: $crate::cert!(@path_len $( $path_len )?),
			},
			subject: $crate::cert!(@name $subject),
			serial: $serial,
			validity: ($not_before, $not_after),
			subject_public_key: $spki,
			signer: $signer,
			signature: $crate::crypto::sign::Signer
		)
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
///     subject: "CN=example.com",
///     signer: &signing_key
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
	use crate::crypto::x509::ext::pkix::BasicConstraints;
	use crate::crypto::x509::utils::certificate_extension;
	use crate::spki::SubjectPublicKeyInfoOwned;

	const SUBJECT: &str = "CN=Test Root CA,O=Test Org,C=US";

	type TestResult = Result<(), Box<dyn core::error::Error>>;

	// `Sha3Signer` borrows its key, so callers own the key and build the signer
	// locally to keep the borrow alive across the `cert!` invocation.
	fn signing_material() -> Result<(Secp256k1SigningKey, SubjectPublicKeyInfoOwned), Box<dyn core::error::Error>> {
		let signing_key = Secp256k1SigningKey::random(&mut rand_core::OsRng);
		let verifying_key = Secp256k1VerifyingKey::from(&signing_key);
		let spki = SubjectPublicKeyInfoOwned::from_key(verifying_key)?;

		Ok((signing_key, spki))
	}

	fn one_year() -> (std::time::Instant, std::time::Instant) {
		let not_before = std::time::Instant::now();

		(not_before, not_before + std::time::Duration::from_secs(365 * 24 * 60 * 60))
	}

	#[test]
	fn test_cert_macro_root() -> TestResult {
		let (signing_key, spki) = signing_material()?;
		let signer = Sha3Signer::from(&signing_key);
		let (not_before, not_after) = one_year();

		let cert = cert!(
			profile: Root,
			subject: SUBJECT,
			serial: 1u32,
			validity: (not_before, not_after),
			signer: &signer,
			subject_public_key: spki
		)?;

		assert_eq!(cert.tbs_certificate.subject, cert.tbs_certificate.issuer);

		Ok(())
	}

	#[test]
	fn test_cert_macro_root_path_len() -> TestResult {
		let (signing_key, spki) = signing_material()?;
		let signer = Sha3Signer::from(&signing_key);
		let (not_before, not_after) = one_year();

		let cert = cert!(
			profile: Root,
			subject: SUBJECT,
			serial: 1u32,
			validity: (not_before, not_after),
			signer: &signer,
			subject_public_key: spki,
			path_len: 2u8
		)?;

		let basic_constraints = certificate_extension::<BasicConstraints>(&cert)?;

		assert_eq!(cert.tbs_certificate.subject, cert.tbs_certificate.issuer);
		assert!(matches!(
			basic_constraints,
			Some(BasicConstraints { ca: true, path_len_constraint: Some(2) })
		));

		Ok(())
	}
}
