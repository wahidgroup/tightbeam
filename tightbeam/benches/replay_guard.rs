//! The admission of one signed command by the replay guard, against the
//! records the guard holds.
//!
//! Each row reports the time of one round against the live records of the
//! admitting signer and the number of other signers.
//!
//! - A round admits a fresh signature with `ReplayGuard::check_and_insert`
//!   and returns its slot with `ReplayGuard::forget`, so every round meets
//!   the same records.
//! - The admission drops the expired records of its own signer, which scans that signer's partition.
//! - Each other signer holds [`OTHER_RECORDS`] live records.
//!
//! `make bench` runs it.

mod measure;

use core::time::Duration;
use std::hint::black_box;

use tightbeam::colony::hive::gates::{ReplayGuard, REPLAY_GUARD_CAPACITY};
use tightbeam::crypto::sign::ecdsa::k256::Scalar;
use tightbeam::crypto::sign::ecdsa::{Secp256k1, Secp256k1Signature, Signature};
use tightbeam::crypto::sign::{Error, PrehashVerifier, VerifiedSignature};
use tightbeam::utils::time::UnixMillis;

use measure::median_ns;

/// The live records of the admitting signer, one count per row.
const HELD: [usize; 3] = [0, 64, REPLAY_GUARD_CAPACITY.saturating_sub(1)];

/// The number of other signers, one count per row.
const OTHER_SIGNERS: [usize; 2] = [0, 1000];

/// The live records each other signer holds.
const OTHER_RECORDS: usize = 16;

/// The rounds of one measurement.
const ROUNDS: u32 = 20_000;

/// The freshness window of the guard.
const WINDOW: Duration = Duration::from_secs(30);

/// The instant every record states and every admission reads.
const NOW: UnixMillis = UnixMillis::new(1_000_000);

/// The signer that admits the measured signature.
const SIGNER: &[u8] = b"admitting signer";

/// A verifier that accepts every signature, so the bench reaches a
/// [`VerifiedSignature`] of any canonical value through the one producer.
struct AcceptAll;

impl PrehashVerifier<Secp256k1Signature> for AcceptAll {
	fn verify_prehash(&self, _prehash: &[u8], _signature: &Secp256k1Signature) -> Result<(), Error> {
		Ok(())
	}
}

/// A guard and the signatures it holds, with the next index that names a
/// signature it has not seen.
struct Filled {
	guard: ReplayGuard,
	next: u64,
}

impl Filled {
	/// A guard whose admitting signer holds `held` live records, beside
	/// `others` other signers that each hold [`OTHER_RECORDS`].
	fn new(held: usize, others: usize) -> Self {
		let mut filled = Self { guard: ReplayGuard::new(WINDOW), next: 0 };
		filled.record(SIGNER, held);
		for other in 0..others {
			let signer = format!("other signer {other}");
			filled.record(signer.as_bytes(), OTHER_RECORDS);
		}

		filled
	}

	/// Returns a low-s signature value that no earlier call returned.
	fn fresh(&mut self) -> VerifiedSignature {
		self.next = self.next.saturating_add(1);
		let r = Scalar::from(self.next).to_bytes();
		let s = Scalar::ONE.to_bytes();

		let scalars = Signature::<Secp256k1>::from_scalars(r, s).expect("small scalars are in range");
		let encoded = scalars.to_der();
		let verified = VerifiedSignature::verify::<Secp256k1Signature, _>(&AcceptAll, [0u8; 32], encoded.as_bytes());
		verified.expect("the accepting verifier admits every canonical value")
	}

	/// Records `count` fresh signatures of `signer`.
	fn record(&mut self, signer: &[u8], count: usize) {
		for _ in 0..count {
			let signature = self.fresh();
			let admitted = self.guard.check_and_insert(signer, &signature, NOW, NOW);
			assert!(admitted, "the guard admits a fresh signature below its capacity");
		}
	}

	/// Prints the row of `held` records of the admitting signer beside
	/// `others` other signers.
	fn row(held: usize, others: usize) {
		let mut filled = Self::new(held, others);
		let probe = filled.fresh();
		let guard = &filled.guard;

		let ns = median_ns(ROUNDS, || {
			let admitted = guard.check_and_insert(SIGNER, &probe, NOW, NOW);
			guard.forget(&probe);
			black_box(admitted);
		});
		println!("replay held={held:>4} other_signers={others:>4} admit+forget={ns:>9.1} ns");
	}
}

fn main() {
	for others in OTHER_SIGNERS {
		for held in HELD {
			Filled::row(held, others);
		}
	}
}
