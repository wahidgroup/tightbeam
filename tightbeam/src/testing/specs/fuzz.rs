//! Fuzz specification types and macro
//!
//! Provides declarative fuzz configuration specs using `tb_fuzz_spec!` macro.

#![cfg(all(feature = "std", feature = "testing-csp"))]

/// Fuzz specification trait
pub trait FuzzSpec {
	/// Number of random test cases to generate
	fn test_cases() -> usize;

	/// Generate a random input for the given iteration
	fn generate_input(iteration: usize) -> Vec<u8>;

	/// Optional: Get the random seed for reproducibility
	fn seed() -> Option<u32> {
		None
	}

	/// Minimum success rate required (0.0 to 100.0)
	/// Default: 10.0%
	fn min_success_rate() -> f64 {
		10.0
	}

	/// Whether to print statistics after fuzzing
	/// Default: false (silent)
	fn print_stats() -> bool {
		false
	}
}

/// Define a fuzz specification type
///
/// # Examples
///
/// ```ignore
/// // Simple spec with fixed parameters
/// tb_fuzz_spec! {
///     pub MyFuzz,
///     test_cases: 100,
///     input_length: 10, 100
/// }
///
/// // With reproducible seed
/// tb_fuzz_spec! {
///     pub ReproducibleFuzz,
///     test_cases: 500,
///     input_length: 32, 256,
///     seed: 0x12345678
/// }
///
/// // With custom input generator
/// tb_fuzz_spec! {
///     pub CustomFuzz,
///     test_cases: 200,
///     input_gen: |iteration| {
///         // Custom logic per iteration
///         vec![iteration as u8; 16]
///     }
/// }
/// ```
#[macro_export]
macro_rules! tb_fuzz_spec {
	// With input_length range
	(
		$vis:vis $name:ident,
		test_cases: $test_cases:expr,
		input_length: $min:expr, $max:expr
		$(, seed: $seed:expr)?
		$(, min_success_rate: $min_rate:expr)?
		$(, print_stats: $print:expr)?
		$(,)?
	) => {
		$vis struct $name;

		impl $crate::testing::specs::FuzzSpec for $name {
			fn test_cases() -> usize {
				$test_cases
			}

			fn generate_input(iteration: usize) -> Vec<u8> {
				// Calculate seed for this iteration
				let base_seed = 0u32 $(.wrapping_add($seed))?;
				let mut seed = base_seed
					.wrapping_add(0x9E3779B9)
					.wrapping_add(iteration as u32);

				// Xorshift PRNG
				let mut rand = || -> u8 {
					seed ^= seed << 13;
					seed ^= seed >> 17;
					seed ^= seed << 5;
					(seed & 0xFF) as u8
				};

				// Generate random length in range
				let range = ($max) - ($min);
				let len = if range > 0 {
					($min) + ((rand() as usize) % range)
				} else {
					$min
				};

				// Generate random bytes
				let mut input = Vec::with_capacity(len);
				for _ in 0..len {
					input.push(rand());
				}

				input
			}

			$(
				fn seed() -> Option<u32> {
					Some($seed)
				}
			)?

			$(
				fn min_success_rate() -> f64 {
					$min_rate
				}
			)?

			$(
				fn print_stats() -> bool {
					$print
				}
			)?
		}
	};

	// With custom input generator
	(
		$vis:vis $name:ident,
		test_cases: $test_cases:expr,
		input_gen: $input_gen:expr
		$(, min_success_rate: $min_rate:expr)?
		$(, print_stats: $print:expr)?
		$(,)?
	) => {
		$vis struct $name;

		impl $crate::testing::specs::FuzzSpec for $name {
			fn test_cases() -> usize {
				$test_cases
			}

		fn generate_input(iteration: usize) -> Vec<u8> {
			let gen: fn(usize) -> Vec<u8> = $input_gen;
			gen(iteration)
		}

		$(
			fn min_success_rate() -> f64 {
				$min_rate
			}
		)?

		$(
			fn print_stats() -> bool {
				$print
			}
		)?
	}
};
}
#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn fuzz_spec_with_input_range() {
		crate::tb_fuzz_spec! {
			pub TestFuzz,
			test_cases: 50,
			input_length: 4, 12
		}

		assert_eq!(TestFuzz::test_cases(), 50);

		// Generate a few inputs
		let input1 = TestFuzz::generate_input(0);
		let input2 = TestFuzz::generate_input(1);

		assert!(input1.len() >= 4 && input1.len() < 12);
		assert!(input2.len() >= 4 && input2.len() < 12);
		assert_ne!(input1, input2); // Should be different
	}

	#[test]
	fn fuzz_spec_with_seed() {
		crate::tb_fuzz_spec! {
			pub SeededFuzz,
			test_cases: 10,
			input_length: 8, 16,
			seed: 0xDEADBEEF
		}

		assert_eq!(SeededFuzz::seed(), Some(0xDEADBEEF));

		// Generate inputs - they should be consistent for same iteration
		let input0_a = SeededFuzz::generate_input(0);
		let input0_b = SeededFuzz::generate_input(0);
		let input1_a = SeededFuzz::generate_input(1);
		let input1_b = SeededFuzz::generate_input(1);

		// Same iteration should produce same output
		assert_eq!(input0_a, input0_b);
		assert_eq!(input1_a, input1_b);
		// Different iterations should produce different output
		assert_ne!(input0_a, input1_a);
	}

	#[test]
	fn fuzz_spec_with_custom_gen() {
		crate::tb_fuzz_spec! {
			pub CustomFuzz,
			test_cases: 5,
			input_gen: |iteration| {
				vec![iteration as u8; 10]
			}
		}

		assert_eq!(CustomFuzz::test_cases(), 5);

		let input0 = CustomFuzz::generate_input(0);
		let input1 = CustomFuzz::generate_input(1);

		assert_eq!(input0, vec![0; 10]);
		assert_eq!(input1, vec![1; 10]);
	}
}
