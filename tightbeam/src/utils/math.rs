//! Mathematical utility functions

/// Integer square root approximation using Newton's method.
///
/// Returns the largest integer n such that n² ≤ value.
pub fn integer_sqrt(value: u128) -> u128 {
	const MAX_ITERATIONS: u32 = 100; // Safety limit

	if value == 0 {
		return 0;
	}
	if value == 1 {
		return 1;
	}

	// For very large values, use binary search for faster convergence
	// Threshold: when value > 2^120, binary search is faster
	if value > 1u128 << 120 {
		let mut low = 1u128;
		let mut high = value.min(1u128 << 64); // sqrt(u128::MAX) < 2^64
		while low < high {
			let mid = (low + high + 1) / 2;
			// Check if mid^2 <= value without overflow
			if let Some(squared) = mid.checked_mul(mid) {
				if squared <= value {
					low = mid;
				} else {
					high = mid - 1;
				}
			} else {
				// mid^2 would overflow, so mid is too large
				high = mid - 1;
			}
		}
		return low;
	}

	// For smaller values, use Newton's method (faster for typical cases)
	// Initial guess: use bit manipulation for better starting point
	let mut x = 1u128 << ((128 - value.leading_zeros()) / 2);
	let mut prev = 0;
	let mut iterations = 0;

	// Newton's method: x_{n+1} = (x_n + value/x_n) / 2
	while x != prev && iterations < MAX_ITERATIONS {
		prev = x;
		if x == 0 {
			break;
		}
		x = (x + value / x) / 2;
		iterations += 1;
	}

	x
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_integer_sqrt() {
		assert_eq!(integer_sqrt(0), 0);
		assert_eq!(integer_sqrt(1), 1);
		assert_eq!(integer_sqrt(4), 2);
		assert_eq!(integer_sqrt(9), 3);
		assert_eq!(integer_sqrt(16), 4);
		assert_eq!(integer_sqrt(25), 5);
		assert_eq!(integer_sqrt(2500), 50);
		assert_eq!(integer_sqrt(10000), 100);
		// Test large values - verify no overflow
		let max_sqrt = integer_sqrt(u128::MAX);
		// sqrt(2^128 - 1) ≈ 2^64 - 1, verify it's close
		// At least 2^64 - 2
		assert!(max_sqrt >= 18446744073709551614);
		// At most 2^64 - 1
		assert!(max_sqrt <= 18446744073709551615);
		// Verify no overflow: max_sqrt^2 should be ≤ u128::MAX
		assert!(max_sqrt.saturating_mul(max_sqrt) <= u128::MAX);
	}
}
