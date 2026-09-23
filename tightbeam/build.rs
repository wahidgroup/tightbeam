// `cfg_aliases!` parses its predicate token-by-token through recursive
// macro rules: the five-clause alias overflows the default limit of 128.
#![recursion_limit = "256"]

use cfg_aliases::cfg_aliases;

fn main() {
	// Declare the `fuzzing` cfg so rustc check-cfg accepts IJON and fuzz
	// gates in the library. AFL harnesses set it through RUSTFLAGS.
	println!("cargo::rustc-check-cfg=cfg(fuzzing)");

	// Names the compound predicates that gate whole subsystems, so the
	// build graph has one definition instead of hand-copied clause lists
	// that can drift independently.
	cfg_aliases! {
		// Pooled multiplexing: the mux engine, the serve module's
		// connector, an encryption handshake, and a tokio executor for
		// the driver tasks.
		pooled_mux: {
			all(
				feature = "x509",
				feature = "tokio",
				feature = "transport-policy",
				feature = "transport-multiplex",
				any(feature = "transport-cms", feature = "transport-ecies")
			)
		},
		// The standard library's clocks work: `std` is linked and the
		// target is not `wasm32-unknown-unknown`, where reading
		// `SystemTime` or `Instant` panics.
		host_clock: {
			all(
				feature = "std",
				not(all(target_arch = "wasm32", target_os = "unknown"))
			)
		},
	}
}
