pub use rand_core::{CryptoRngCore, OsRng, RngCore};

#[cfg(all(feature = "std", feature = "transport"))]
use std::hash::{DefaultHasher, Hash, Hasher};
#[cfg(all(feature = "std", feature = "transport"))]
use std::sync::OnceLock;

#[cfg(all(host_clock, feature = "transport"))]
use crate::clock::{Clock, SystemClock};
use crate::error::Result;
#[cfg(any(feature = "transport-cms", feature = "hpke"))]
use rand_core::CryptoRng;

/// The static whose address [`placement_entropy`] hashes.
#[cfg(all(feature = "std", feature = "transport"))]
static PLACEMENT_ANCHOR: u8 = 0;

/// The value of [`placement_entropy`], which its first call takes.
#[cfg(all(feature = "std", feature = "transport"))]
static PLACEMENT: OnceLock<u64> = OnceLock::new();

/// The entropy of the placement of this process, one value per process.
///
/// The first call hashes two readings, and the process keeps the hash:
///
/// - The address of a static of this crate, which address-space layout
///   randomization places apart in each process.
/// - The monotonic clock in nanoseconds, where the host has one, so no address alone gives the value.
///
/// A draw that the random source refused seeds from it, so peers that lose the
/// source together seed apart. The value seeds a spread and is no secret.
#[cfg(all(feature = "std", feature = "transport"))]
pub(crate) fn placement_entropy() -> u64 {
	let take = || {
		let mut hasher = DefaultHasher::new();
		core::ptr::addr_of!(PLACEMENT_ANCHOR).addr().hash(&mut hasher);
		#[cfg(host_clock)]
		SystemClock.monotonic().hash(&mut hasher);

		hasher.finish()
	};

	*PLACEMENT.get_or_init(take)
}

/// Adapts a `&mut dyn CryptoRngCore` to the `Sized` `CryptoRng + RngCore`
/// bounds required by generic constructors such as `SecretKey::random`.
///
/// A `dyn` RNG is unsized, so `impl CryptoRngCore` bounds take this sized
/// wrapper. It forwards every method to the underlying trait object, so
/// callers can inject their own CSPRNG.
#[cfg(any(feature = "transport-cms", feature = "hpke"))]
pub(crate) struct RngWrapper<'a>(pub(crate) &'a mut dyn CryptoRngCore);

#[cfg(any(feature = "transport-cms", feature = "hpke"))]
impl RngCore for RngWrapper<'_> {
	fn next_u32(&mut self) -> u32 {
		self.0.next_u32()
	}

	fn next_u64(&mut self) -> u64 {
		self.0.next_u64()
	}

	fn fill_bytes(&mut self, dest: &mut [u8]) {
		self.0.fill_bytes(dest)
	}

	fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
		self.0.try_fill_bytes(dest)
	}
}

#[cfg(any(feature = "transport-cms", feature = "hpke"))]
impl CryptoRng for RngWrapper<'_> {}

/// Generates a cryptographically random nonce.
///
/// `None` draws from the OS CSPRNG through `getrandom`, and `Some` draws from
/// the supplied RNG.
///
/// # Security
///
/// - Each nonce MUST be unique for a given key.
/// - For AES-GCM, `N` is 12 (96 bits), and the birthday bound sits near 2^32 messages.
///
/// # Example
///
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

	rng.try_fill_bytes(&mut nonce)?;
	Ok(nonce)
}

/// Generates a random number that is `N` bytes wide.
///
/// `None` draws from the OS CSPRNG, as [`generate_nonce`] does.
pub fn generate_random_number<const N: usize>(rng: Option<&mut dyn CryptoRngCore>) -> Result<usize> {
	const USIZE_BYTES: usize = core::mem::size_of::<usize>();
	let mut bytes = [0u8; USIZE_BYTES];
	let Some(drawn) = bytes.get_mut(..N) else {
		return Err(crate::TightBeamError::InvalidOverflowValue);
	};

	generate_random_bytes(drawn, rng)?;
	Ok(usize::from_le_bytes(bytes))
}

/// Fills the provided byte slice with random bytes.
///
/// `None` draws from the OS CSPRNG, and a supplied RNG must be
/// cryptographically secure, so no caller can weaken the source.
#[inline]
pub fn generate_random_bytes(bytes: &mut [u8], rng: Option<&mut dyn CryptoRngCore>) -> Result<()> {
	let rng = if let Some(rng) = rng {
		rng
	} else {
		&mut rand_core::OsRng
	};

	rng.try_fill_bytes(bytes)?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use crate::testing::{SeededStream, TestResult};

	use super::*;

	/// A generator that draws from the source it is handed and yields the draw
	/// as octets.
	type Draw = fn(Option<&mut dyn CryptoRngCore>) -> Result<Vec<u8>>;

	/// The eight octets of [`generate_random_number`], least significant
	/// first.
	fn number(rng: Option<&mut dyn CryptoRngCore>) -> Result<Vec<u8>> {
		Ok(generate_random_number::<8>(rng)?.to_le_bytes().to_vec())
	}

	/// The sixteen octets of [`generate_nonce`].
	fn nonce(rng: Option<&mut dyn CryptoRngCore>) -> Result<Vec<u8>> {
		Ok(generate_nonce::<16>(rng)?.to_vec())
	}

	/// Twenty-four octets of [`generate_random_bytes`].
	fn bytes(rng: Option<&mut dyn CryptoRngCore>) -> Result<Vec<u8>> {
		let mut drawn = vec![0u8; 24];
		generate_random_bytes(&mut drawn, rng)?;
		Ok(drawn)
	}

	// Each generator fills its draw from the source it is handed. The seeded
	// source fills its first draw with `0x01`, so a generator that drew from
	// the OS in its place fails.
	crate::tb_cases! {
		fn a_supplied_source_fills_the_draw((draw, expected): (Draw, Vec<u8>)) -> TestResult {
			let mut source = SeededStream(0);
			let drawn = draw(Some(&mut source))?;
			assert_eq!(drawn, expected);
			Ok(())
		}
		cases {
			number => (number, vec![0x01; 8]),
			nonce => (nonce, vec![0x01; 16]),
			bytes => (bytes, vec![0x01; 24]),
		}
	}

	// Each generator with no source fills its whole draw from the OS source,
	// which draws afresh each time. Two draws are equal, or all zeros, with
	// negligible probability.
	crate::tb_cases! {
		fn the_os_source_fills_a_fresh_draw((draw, size): (Draw, usize)) -> TestResult {
			let first = draw(None)?;
			let second = draw(None)?;
			assert_eq!((first.len(), second.len()), (size, size));
			assert_ne!(first, second);
			assert_ne!(first, vec![0u8; size]);
			assert_ne!(second, vec![0u8; size]);
			Ok(())
		}
		cases {
			number => (number, 8),
			nonce => (nonce, 16),
			bytes => (bytes, 24),
		}
	}

	/// The balancers of a gateway seed by XOR with the placement, which keeps
	/// their seeds distinct only while it holds one value in a process.
	#[cfg(all(feature = "std", feature = "transport"))]
	#[test]
	fn the_placement_entropy_holds_one_value_per_process() {
		assert_eq!(placement_entropy(), placement_entropy());
	}

	/// The hash of the address of the anchor alone, which an observer who
	/// enumerates the address space can compute.
	#[cfg(all(feature = "std", feature = "transport"))]
	fn address_hash() -> u64 {
		let placed = core::ptr::addr_of!(PLACEMENT_ANCHOR).addr();
		let mut hasher = DefaultHasher::new();
		placed.hash(&mut hasher);

		hasher.finish()
	}

	/// A retry delay reveals the placement, so the placement holds more than
	/// the hash of an address that the layout of the process names.
	#[cfg(all(feature = "std", feature = "transport"))]
	#[test]
	fn the_placement_entropy_is_more_than_the_hash_of_an_address() {
		assert_ne!(placement_entropy(), address_hash());
	}

	/// The name that [`two_processes_take_two_placements`] runs in a child
	/// process.
	#[cfg(all(feature = "std", feature = "transport"))]
	const PLACEMENT_PRINTER: &str = "random::tests::print_the_placement_of_this_process";

	/// The child half of [`two_processes_take_two_placements`], which prints
	/// the placement of the process it runs in.
	#[cfg(all(feature = "std", feature = "transport"))]
	#[test]
	#[ignore = "the child half of two_processes_take_two_placements, which runs it in a process of its own"]
	fn print_the_placement_of_this_process() {
		println!("placement={}", placement_entropy());
	}

	/// The placement that the child half prints in a process of its own.
	#[cfg(all(feature = "std", feature = "transport"))]
	fn placement_of_a_child_process() -> u64 {
		let exe = std::env::current_exe().expect("the test binary has a path");
		let args = ["--ignored", "--exact", PLACEMENT_PRINTER, "--nocapture", "--test-threads=1"];
		let output = std::process::Command::new(exe).args(args).output();
		let output = output.expect("the test binary runs as a child process");
		let stdout = String::from_utf8(output.stdout).expect("the child prints UTF-8");
		let printed = stdout
			.lines()
			.find_map(|line| line.split_once("placement=").map(|(_, placement)| placement));

		let printed = printed.expect("the child prints its placement");
		printed.trim().parse().expect("the child prints its placement as a number")
	}

	/// Peers that lose the random source together seed apart only while each
	/// process takes a placement of its own.
	#[cfg(all(feature = "std", feature = "transport"))]
	#[test]
	fn two_processes_take_two_placements() {
		let child = placement_of_a_child_process();
		assert_ne!(child, placement_entropy());
	}
}
