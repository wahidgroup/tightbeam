// Re-exports
pub use rand_core::{CryptoRngCore, OsRng, RngCore};

use crate::error::Result;

/// Generate a cryptographically random nonce.
///
/// # Security
/// - Each nonce MUST be unique for a given key
/// - Uses OS-level CSPRNG via `getrandom` (cryptographically secure)
/// - For AES-GCM: N=12 (96 bits, birthday bound at ~2^32 messages)
///
/// # Example
/// ```rust
/// use aes_gcm::Aes256Gcm;
///
/// let nonce = tightbeam::random::generate_nonce::<12>(None).expect("nonce"); // For AES-GCM
/// assert_eq!(nonce.len(), 12);
/// ```
#[inline]
pub fn generate_nonce<const N: usize>(rng: Option<&mut dyn CryptoRngCore>) -> Result<[u8; N]> {
	let mut nonce = [0u8; N];
	let rng = if let Some(rng) = rng {
		rng
	} else {
		&mut rand_core::OsRng
	};

	rng.fill_bytes(&mut nonce);
	Ok(nonce)
}

/// Generate a random number of specified byte size
pub fn generate_random_number<const N: usize>(rng: Option<&mut dyn RngCore>) -> Result<usize> {
	const USIZE_BYTES: usize = core::mem::size_of::<usize>();
	if N > USIZE_BYTES {
		return Err(crate::TightBeamError::InvalidOverflowValue);
	}

	let mut bytes = [0u8; USIZE_BYTES];
	generate_random_bytes(&mut bytes[..N], rng)?;
	Ok(usize::from_le_bytes(bytes))
}

/// Fill the provided byte slice with random bytes.
/// If `rng` is `None`, uses OS-level CSPRNG (`OsRng`). If an RNG is provided,
/// its security properties depend on the RNG you pass.
#[inline]
pub fn generate_random_bytes(bytes: &mut [u8], rng: Option<&mut dyn RngCore>) -> Result<()> {
	let rng = if let Some(rng) = rng {
		rng
	} else {
		&mut rand_core::OsRng
	};

	rng.fill_bytes(bytes);
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_random() -> Result<()> {
		// (size, generator) table with inline generators
		#[allow(clippy::type_complexity)]
		let cases: &[(usize, fn(&mut rand_core::OsRng) -> Result<(Vec<u8>, Vec<u8>)>)] = &[
			(8, |rng| {
				let n1 = generate_random_number::<8>(Some(rng))?;
				let n2 = generate_random_number::<8>(None)?;
				Ok((n1.to_be_bytes().to_vec(), n2.to_be_bytes().to_vec()))
			}),
			(16, |rng| {
				let n1 = generate_nonce::<16>(Some(rng))?;
				let n2 = generate_nonce::<16>(None)?;
				Ok((n1.to_vec(), n2.to_vec()))
			}),
			(24, |rng| {
				let mut n1 = [0u8; 24];
				generate_random_bytes(&mut n1, Some(rng))?;
				let mut n2 = [0u8; 24];
				generate_random_bytes(&mut n2, None)?;
				Ok((n1.to_vec(), n2.to_vec()))
			}),
		];

		for &(size, gen) in cases {
			let mut rng = rand_core::OsRng;
			let (nonce1, nonce2) = gen(&mut rng)?;

			// Correct length
			assert_eq!(nonce1.len(), size);
			assert_eq!(nonce2.len(), size);

			// Unique (extremely unlikely to be equal)
			assert_ne!(nonce1, nonce2);

			// Not all zeros
			assert_ne!(nonce1, vec![0u8; size]);
			assert_ne!(nonce2, vec![0u8; size]);
		}

		Ok(())
	}
}
