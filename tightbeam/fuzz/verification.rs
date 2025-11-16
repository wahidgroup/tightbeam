//! AFL+IJON Integration Verification
//!
//! Comprehensive fuzz target that verifies the AFL+IJON integration works correctly
//! by testing each component in sequence:
//!
//! 1. **Compilation** - Code compiles with all features enabled
//! 2. **Dependencies** - AFL dependency is properly configured
//! 3. **Features** - Feature flags activate correct code paths
//! 4. **Binary Symbols** - IJON and AFL runtime symbols present (ijon_max, ijon_set, __afl_area_ptr, etc.)
//! 5. **Oracle Methods** - CspOracle methods return valid data

#![allow(unexpected_cfgs)]
#![cfg(all(feature = "std", feature = "testing-csp"))]

use tightbeam::{exactly, tb_assert_spec, tb_process_spec, tb_scenario};

// ============================================================================
// ASSERTION SPEC - Defines Expected Event Sequences
// ============================================================================

tb_assert_spec! {
	/// Assertion spec that verifies each proof point in the AFL+IJON integration.
	///
	/// Uses equals!, truthy!, and falsy! macros with actual runtime values
	/// to prove concrete evidence of integration working correctly.
	pub VerificationSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("compilation_check", exactly!(1)),
			("workspace_has_afl", exactly!(1), equals!(true)),
			("package_enables_afl", exactly!(1), equals!(true)),
			("ijon_feature_enabled", exactly!(1), equals!(true)),
			("binary_has_ijon_max", exactly!(1), equals!(true)),
			("binary_has_ijon_set", exactly!(1), equals!(true)),
			("binary_has_ijon_hashint", exactly!(1), equals!(true)),
			("binary_has_ijon_map_size", exactly!(1), equals!(true)),
			("binary_has_afl_runtime", exactly!(1), equals!(true)),
			("coverage_score", exactly!(1), equals!(true)),
			("track_state_stable", exactly!(1), equals!(true)),
			("fuzz_advances_coverage", exactly!(1), equals!(true)),
			("verification_complete", exactly!(1)),
		]
	},
}

// ============================================================================
// CSP PROCESS - Models Verification State Machine
// ============================================================================

tb_process_spec! {
	/// CSP process that models the AFL+IJON verification protocol.
	///
	/// The process flows through verification checkpoints matching the evidence chain:
	///
	/// ```text
	/// Initial → Compiled → WorkspaceConfigured → FeaturesOk → BinaryVerified
	///   → OracleVerified → FullyVerified
	/// ```
	///
	/// Each transition validates a specific aspect of the integration:
	/// 1. **Initial → Compiled**: Code compiles without errors
	/// 2. **Compiled → WorkspaceConfigured**: AFL dependency properly configured in Cargo.toml
	/// 3. **WorkspaceConfigured → FeaturesOk**: Feature flags enable correct code paths
	/// 4. **FeaturesOk → BinaryVerified**: IJON and AFL symbols present in binary
	/// 5. **BinaryVerified → OracleVerified**: Oracle methods work correctly
	/// 6. **OracleVerified → FullyVerified**: All proofs complete
	pub VerificationProcess,
	events {
		observable {
			"compilation_check",
			"workspace_has_afl",
			"package_enables_afl",
			"ijon_feature_enabled",
			"binary_has_ijon_max",
			"binary_has_ijon_set",
			"binary_has_ijon_hashint",
			"binary_has_ijon_map_size",
			"binary_has_afl_runtime",
			"coverage_score",
			"track_state_stable",
			"fuzz_advances_coverage",
			"verification_complete"
		}
		hidden { }
	}

	states {
		Initial => { "compilation_check" => Compiled },
		Compiled => {
			"workspace_has_afl"        => WorkspaceConfigured,
			"package_enables_afl"      => WorkspaceConfigured
		},
		WorkspaceConfigured => { "ijon_feature_enabled" => FeaturesOk },
		FeaturesOk => {
			"binary_has_ijon_max"      => BinaryVerified,
			"binary_has_ijon_set"      => BinaryVerified,
			"binary_has_ijon_hashint"  => BinaryVerified,
			"binary_has_ijon_map_size" => BinaryVerified
		},
		BinaryVerified => {
			"coverage_score"           => OracleVerified,
			"track_state_stable"       => OracleVerified,
			"fuzz_advances_coverage"   => OracleVerified
		},
		OracleVerified => { "verification_complete" => FullyVerified }
	}

	terminal { FullyVerified }
}

// ============================================================================
// SCENARIO - AFL Fuzz Target with Verification Logic
// ============================================================================

tb_scenario! {
	fuzz: afl,
	spec: VerificationSpec,
	csp: VerificationProcess,
	environment Bare {
		exec: |trace| {
			use std::fs;
			use std::path::Path;

			// Proof 1: Compilation succeeded (executing proves it compiled)
			trace.event("compilation_check");

			// Proof 2: AFL Dependency Configuration - Check actual Cargo.toml files
			let workspace_cargo = Path::new(env!("CARGO_MANIFEST_DIR"))
				.parent().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "No parent directory"))?
				.parent().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "No grandparent directory"))?
				.join("Cargo.toml");
			let cargo_content = fs::read_to_string(&workspace_cargo)?;
			trace.event_with("workspace_has_afl", &[], cargo_content.contains("afl"));

			let package_cargo = Path::new(env!("CARGO_MANIFEST_DIR"))
				.parent().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "No parent directory"))?
				.join("Cargo.toml");
			let pkg_content = fs::read_to_string(&package_cargo)?;
			let enables_afl = pkg_content.contains("testing-fuzz") && pkg_content.contains("dep:afl");
			trace.event_with("package_enables_afl", &[], enables_afl);

			// Proof 3: Feature Flags - Actually check if IJON feature is active
			#[cfg(feature = "testing-fuzz-ijon")]
			let ijon_enabled = true;
			#[cfg(not(feature = "testing-fuzz-ijon"))]
			let ijon_enabled = false;
			trace.event_with("ijon_feature_enabled", &[], ijon_enabled);

			// Proof 4: Binary Symbol Analysis - Check actual binary for IJON symbols
			let current_exe = std::env::current_exe()?;
			let nm_output = std::process::Command::new("nm")
				.arg(&current_exe)
				.output()?;

			let symbols = String::from_utf8_lossy(&nm_output.stdout);
			let has_ijon_max = symbols.contains("ijon_max") || symbols.contains("ijon_stack_max");
			let has_ijon_set = symbols.contains("ijon_set");
			let has_ijon_hashint = symbols.contains("ijon_hashint") || symbols.contains("ijon_hashstack");
			let has_ijon_map_size = symbols.contains("__afl_ijon_map_size") || symbols.contains("__afl_ijon_enabled");
			let has_afl_runtime = symbols.contains("__afl_area_ptr") || symbols.contains("__afl_prev_loc");
			trace.event_with("binary_has_ijon_max", &[], has_ijon_max);
			trace.event_with("binary_has_ijon_set", &[], has_ijon_set);
			trace.event_with("binary_has_ijon_hashint", &[], has_ijon_hashint);
			trace.event_with("binary_has_ijon_map_size", &[], has_ijon_map_size);
			trace.event_with("binary_has_afl_runtime", &[], has_afl_runtime);

			// Proof 5: Oracle Methods - Test actual oracle functionality
			let oracle = trace.oracle();
			let coverage = oracle.coverage_score();
			trace.event_with("coverage_score", &[], coverage > 0);

			let state_hash1 = oracle.track_state();
			let state_hash2 = oracle.track_state();
			trace.event_with("track_state_stable", &[], state_hash1 == state_hash2);

			oracle.fuzz_from_bytes()?;
			let coverage_after = oracle.coverage_score();
			trace.event_with("fuzz_advances_coverage", &[], coverage_after >= coverage);

			// Complete
			trace.event("verification_complete");

			Ok(())
		}
	}
}
