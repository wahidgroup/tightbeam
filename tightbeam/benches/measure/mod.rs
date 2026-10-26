//! The timing every bench reports: the median of nine batch means of one
//! round, after a warm-up of a tenth of the rounds.
//!
//! The median of the batch means holds against a batch that a scheduler
//! stall or a frequency step slows, which a mean of every round would carry.

use std::time::Instant;

/// The number of batches of one measurement.
const BATCHES: u32 = 9;

/// The index of the median batch mean, once the means are sorted.
const MEDIAN: usize = 4;

/// Returns the median over [`BATCHES`] batches of the mean nanoseconds of
/// `round`, after a warm-up of a tenth of `rounds`.
pub fn median_ns(rounds: u32, mut round: impl FnMut()) -> f64 {
	for _ in 0..rounds / 10 {
		round();
	}

	let per_batch = rounds / BATCHES;
	let mut means: Vec<f64> = (0..BATCHES)
		.map(|_| {
			let start = Instant::now();
			for _ in 0..per_batch {
				round();
			}

			start.elapsed().as_secs_f64() * 1e9 / f64::from(per_batch)
		})
		.collect();

	means.sort_by(f64::total_cmp);
	means.get(MEDIAN).copied().expect("nine batches hold a median")
}
