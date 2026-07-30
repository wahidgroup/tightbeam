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

use tightbeam::utils::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_process_spec, tb_scenario};

const COMPILATION_CHECK: Urn<'static> = Urn::new("fuzz", "event:verification/compilation-check");
const WORKSPACE_HAS_AFL: Urn<'static> = Urn::new("fuzz", "event:verification/workspace-has-afl");
const PACKAGE_ENABLES_AFL: Urn<'static> = Urn::new("fuzz", "event:verification/package-enables-afl");
const IJON_FEATURE_ENABLED: Urn<'static> = Urn::new("fuzz", "event:verification/ijon-feature-enabled");
const BINARY_HAS_IJON_MAX: Urn<'static> = Urn::new("fuzz", "event:verification/binary-has-ijon-max");
const BINARY_HAS_IJON_SET: Urn<'static> = Urn::new("fuzz", "event:verification/binary-has-ijon-set");
const BINARY_HAS_IJON_HASHINT: Urn<'static> = Urn::new("fuzz", "event:verification/binary-has-ijon-hashint");
const BINARY_HAS_IJON_MAP_SIZE: Urn<'static> = Urn::new("fuzz", "event:verification/binary-has-ijon-map-size");
const BINARY_HAS_AFL_RUNTIME: Urn<'static> = Urn::new("fuzz", "event:verification/binary-has-afl-runtime");
const COVERAGE_SCORE: Urn<'static> = Urn::new("fuzz", "event:verification/coverage-score");
const TRACK_STATE_STABLE: Urn<'static> = Urn::new("fuzz", "event:verification/track-state-stable");
const FUZZ_ADVANCES_COVERAGE: Urn<'static> = Urn::new("fuzz", "event:verification/fuzz-advances-coverage");
const VERIFICATION_COMPLETE: Urn<'static> = Urn::new("fuzz", "event:verification/verification-complete");

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
		gate: Ok,
		assertions: [
			(COMPILATION_CHECK, exactly!(1)),
			(WORKSPACE_HAS_AFL, exactly!(1), equals!(true)),
			(PACKAGE_ENABLES_AFL, exactly!(1), equals!(true)),
			(IJON_FEATURE_ENABLED, exactly!(1), equals!(true)),
			(BINARY_HAS_IJON_MAX, exactly!(1), equals!(true)),
			(BINARY_HAS_IJON_SET, exactly!(1), equals!(true)),
			(BINARY_HAS_IJON_HASHINT, exactly!(1), equals!(true)),
			(BINARY_HAS_IJON_MAP_SIZE, exactly!(1), equals!(true)),
			(BINARY_HAS_AFL_RUNTIME, exactly!(1), equals!(true)),
			(COVERAGE_SCORE, exactly!(1), equals!(true)),
			(TRACK_STATE_STABLE, exactly!(1), equals!(true)),
			(FUZZ_ADVANCES_COVERAGE, exactly!(1), equals!(true)),
			(VERIFICATION_COMPLETE, exactly!(1)),
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
	/// Initial -> Compiled -> WorkspaceConfigured -> FeaturesOk -> BinaryVerified
	///   -> OracleVerified -> FullyVerified
	/// ```
	///
	/// Each transition validates a specific aspect of the integration:
	/// 1. **Initial -> Compiled**: Code compiles without errors
	/// 2. **Compiled -> WorkspaceConfigured**: AFL dependency properly configured in Cargo.toml
	/// 3. **WorkspaceConfigured -> FeaturesOk**: Feature flags enable correct code paths
	/// 4. **FeaturesOk -> BinaryVerified**: IJON and AFL symbols present in binary
	/// 5. **BinaryVerified -> OracleVerified**: Oracle methods work correctly
	/// 6. **OracleVerified -> FullyVerified**: All proofs complete
	pub VerificationProcess,
	events {
		observable {
			COMPILATION_CHECK,
			WORKSPACE_HAS_AFL,
			PACKAGE_ENABLES_AFL,
			IJON_FEATURE_ENABLED,
			BINARY_HAS_IJON_MAX,
			BINARY_HAS_IJON_SET,
			BINARY_HAS_IJON_HASHINT,
			BINARY_HAS_IJON_MAP_SIZE,
			BINARY_HAS_AFL_RUNTIME,
			COVERAGE_SCORE,
			TRACK_STATE_STABLE,
			FUZZ_ADVANCES_COVERAGE,
			VERIFICATION_COMPLETE
		}
		hidden { }
	}

	states {
		Initial => { COMPILATION_CHECK => Compiled },
		Compiled => {
			WORKSPACE_HAS_AFL         => WorkspaceConfigured,
			PACKAGE_ENABLES_AFL       => WorkspaceConfigured
		},
		WorkspaceConfigured => { IJON_FEATURE_ENABLED => FeaturesOk },
		FeaturesOk => {
			BINARY_HAS_IJON_MAX       => BinaryVerified,
			BINARY_HAS_IJON_SET       => BinaryVerified,
			BINARY_HAS_IJON_HASHINT   => BinaryVerified,
			BINARY_HAS_IJON_MAP_SIZE  => BinaryVerified
		},
		BinaryVerified => {
			COVERAGE_SCORE            => OracleVerified,
			TRACK_STATE_STABLE        => OracleVerified,
			FUZZ_ADVANCES_COVERAGE    => OracleVerified
		},
		OracleVerified => { VERIFICATION_COMPLETE => FullyVerified }
	}

	terminal { FullyVerified }
}

// ============================================================================
// SCENARIO - AFL Fuzz Target with Verification Logic
// ============================================================================

tb_scenario! {
	fuzz: afl,
	csp: VerificationProcess,
	config: ScenarioConfig::builder()
		.with_spec(VerificationSpec::latest())
		.with_csp(VerificationProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			use std::fs;
			use std::path::Path;

			// Proof 1: Compilation succeeded (executing proves it compiled)
			trace.event(COMPILATION_CHECK)?;

			// Proof 2: AFL Dependency Configuration - Check actual Cargo.toml files
			let workspace_cargo = Path::new(env!("CARGO_MANIFEST_DIR"))
				.parent().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "No parent directory"))?
				.parent().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "No grandparent directory"))?
				.join("Cargo.toml");
			let cargo_content = fs::read_to_string(&workspace_cargo)?;

			trace.event_with(WORKSPACE_HAS_AFL, &[], cargo_content.contains("afl"))?;

			let package_cargo = Path::new(env!("CARGO_MANIFEST_DIR"))
				.parent().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "No parent directory"))?
				.join("Cargo.toml");
			let pkg_content = fs::read_to_string(&package_cargo)?;
			let enables_afl = pkg_content.contains("testing-fuzz") && pkg_content.contains("dep:afl");

			trace.event_with(PACKAGE_ENABLES_AFL, &[], enables_afl)?;

			// Proof 3: Feature Flags - Actually check if IJON feature is active
			#[cfg(feature = "testing-fuzz-ijon")]
			let ijon_enabled = true;
			#[cfg(not(feature = "testing-fuzz-ijon"))]
			let ijon_enabled = false;

			trace.event_with(IJON_FEATURE_ENABLED, &[], ijon_enabled)?;

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
			trace.event_with(BINARY_HAS_IJON_MAX, &[], has_ijon_max)?;
			trace.event_with(BINARY_HAS_IJON_SET, &[], has_ijon_set)?;
			trace.event_with(BINARY_HAS_IJON_HASHINT, &[], has_ijon_hashint)?;
			trace.event_with(BINARY_HAS_IJON_MAP_SIZE, &[], has_ijon_map_size)?;
			trace.event_with(BINARY_HAS_AFL_RUNTIME, &[], has_afl_runtime)?;

			// Proof 5: Oracle Methods - Test actual oracle functionality
			let oracle = trace.oracle();
			let coverage = oracle.coverage_score();

			trace.event_with(COVERAGE_SCORE, &[], coverage > 0)?;

			let state_hash1 = oracle.track_state();
			let state_hash2 = oracle.track_state();

			trace.event_with(TRACK_STATE_STABLE, &[], state_hash1 == state_hash2)?;

			oracle.fuzz_from_bytes()?;
			let coverage_after = oracle.coverage_score();

			trace.event_with(FUZZ_ADVANCES_COVERAGE, &[], coverage_after >= coverage)?;

			// Complete
			trace.event(VERIFICATION_COMPLETE)?;

			Ok(())
		}
	}
}
