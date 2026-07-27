// `cfg_aliases!` parses its predicate token-by-token through recursive
// macro rules: the five-clause alias overflows the default limit of 128.
#![recursion_limit = "256"]

use cfg_aliases::cfg_aliases;

fn main() {
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
	}
}
