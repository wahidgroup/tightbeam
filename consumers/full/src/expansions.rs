//! Expansions of public macro arms, compiled from outside the crate.
//!
//! The crate that invokes a `macro_rules!` macro reads each
//! `#[cfg(feature = "...")]` in its body. The arms below expand here, where
//! tightbeam's feature names do not exist, so a leaked gate is an
//! `unexpected_cfgs` denial and a broken arm is a compile error.

use der::Sequence;
use tightbeam::{compose, flagset, Beamable, Flaggable};

#[derive(Beamable, Clone, Debug, Default, PartialEq, Eq, Sequence)]
#[beam(profile = 1)]
pub struct Note {
	pub order: u64,
}

#[derive(Flaggable, Default, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
	#[default]
	Default = 0,
	Maintenance = 2,
}

#[derive(Flaggable, Default, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DebugLevel {
	#[default]
	Default = 0,
	Basic = 1,
}

flagset!(pub ConsumerFlags: Mode, DebugLevel);

/// `compose!` builds a frame through the whole `FrameBuilder` call sequence.
pub fn compose_arm() -> tightbeam::error::Result<tightbeam::Frame> {
	compose! {
		V0:
			id: "consumer",
			order: 1_u64,
			message: Note { order: 1 },
	}
}

/// Both sync `client!` forms, with each top-level option they take.
///
/// Nothing calls it, because the body only has to expand and type-check.
#[allow(dead_code)]
async fn client_arms(
	addr: tightbeam::transport::tcp::TightBeamSocketAddr,
	cert: tightbeam::crypto::x509::CertificateSpec,
	key: std::sync::Arc<dyn tightbeam::crypto::key::SigningKeyProvider>,
	trust: std::sync::Arc<dyn tightbeam::crypto::x509::store::CertificateTrust>,
	stream: tightbeam::transport::tcp::r#async::TokioStream,
) -> tightbeam::error::Result<()> {
	type P = tightbeam::transport::tcp::r#async::TokioListener;

	let _identity = tightbeam::client!(
		connect P: addr,
		trust_store: std::sync::Arc::clone(&trust),
		identity: (cert.clone(), std::sync::Arc::clone(&key))
	);
	let _identity_with_policies = tightbeam::client!(
		connect P: addr,
		trust_store: trust,
		identity: (cert, key),
		policies: { timeout: core::time::Duration::from_secs(5) }
	);
	let _cleartext = tightbeam::client!(connect P: addr, cleartext);
	let _adopted = tightbeam::client!(P: stream, cleartext)?;

	Ok(())
}

#[cfg(test)]
mod tests {
	use tightbeam::testing::env::SetupEnv;
	use tightbeam::testing::ScenarioConfig;

	/// A CSP process that refuses every trace.
	///
	/// The scenario runner must turn the refusal into a panic. A runner that
	/// drops the verdict, or skips a process whose alphabet the trace never
	/// reaches, ends with no panic and fails the test.
	struct AlwaysInvalidSpec;

	impl tightbeam::testing::specs::csp::ProcessSpec for AlwaysInvalidSpec {
		fn validate_trace(
			&self,
			_process: &tightbeam::testing::specs::csp::Process,
			_trace: &tightbeam::trace::ConsumedTrace,
		) -> tightbeam::testing::specs::csp::CspValidationResult {
			use tightbeam::testing::specs::csp::{CspViolation, Event, State};

			tightbeam::testing::specs::csp::CspValidationResult {
				valid: false,
				violations: vec![CspViolation::Deadlock { event: Event("consumer/probe"), state: State("s0") }],
			}
		}

		fn to_process_cow(
			&self,
		) -> Result<
			std::borrow::Cow<'_, tightbeam::testing::specs::csp::Process>,
			tightbeam::testing::specs::composition::CompositionError,
		> {
			use tightbeam::testing::specs::csp::{Process, State};

			let process = Process::builder("always-invalid")
				.initial_state(State("s0"))
				.add_state(State("s0"))
				.build()?;
			Ok(std::borrow::Cow::Owned(process))
		}
	}

	#[test]
	#[should_panic(expected = "CSP process violation")]
	fn a_refused_csp_process_fails_the_scenario() {
		let config = tightbeam::__tb_accept_config!(ScenarioConfig::builder().with_csp(AlwaysInvalidSpec).build());
		let trace = config.trace();

		tightbeam::tb_scenario!(@run_bare_sync
			config: config,
			trace: trace,
			context: [],
			exec: |SetupEnv { trace, .. }| {
				trace.event(tightbeam::testing::specs::csp::Event("consumer/probe"))?;
				Ok(())
			}
		)
	}
}
