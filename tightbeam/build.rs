// `cfg_aliases!` parses its predicate token-by-token through recursive
// macro rules, so the five-clause alias overflows the default limit of 128.
#![recursion_limit = "256"]

use cfg_aliases::cfg_aliases;

fn main() {
	// Declare the `fuzzing` cfg so rustc check-cfg accepts IJON and fuzz
	// gates in the library. AFL harnesses set it through RUSTFLAGS.
	println!("cargo::rustc-check-cfg=cfg(fuzzing)");

	// Declare the `tightbeam_loom` cfg, under which `make loom` builds the
	// library tests with the atomics of `loom`. The name is the crate's own,
	// because tokio reads `loom` and drops its networking under it.
	println!("cargo::rustc-check-cfg=cfg(tightbeam_loom)");

	// The aliases name the compound predicates that gate whole subsystems, so
	// the build graph holds one definition of each predicate instead of copied
	// clause lists that can drift apart.
	cfg_aliases! {
		// Pooled multiplexing needs the mux engine, the service module's
		// connector, an encryption handshake, and a tokio executor for the
		// driver tasks.
		pooled_mux: {
			all(
				feature = "x509",
				feature = "tokio",
				feature = "transport-policy",
				feature = "transport-multiplex",
				any(feature = "transport-cms", feature = "transport-hpke")
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
		// The in-band rekey of a multiplexed session needs the mux engine and
		// an encryption handshake. It runs in the mux driver, which an async
		// runtime runs, and `tokio` turns on `async-transport`.
		mux_rekey: {
			all(
				feature = "transport-multiplex",
				feature = "async-transport",
				any(feature = "transport-cms", feature = "transport-hpke")
			)
		},
	}
}
