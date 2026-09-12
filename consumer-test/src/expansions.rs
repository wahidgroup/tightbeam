//! One expansion per public macro arm, compiled from outside the crate.
//!
//! A `#[cfg(feature = "...")]` written inside a `macro_rules!` body is read in
//! the crate that invokes the macro. Every arm below therefore expands here,
//! where tightbeam's feature names do not exist, so a leaked gate is a
//! `unexpected_cfgs` denial and a broken arm is a compile error.

use der::Sequence;
use tightbeam::{compose, flagset, Beamable, Flaggable};

#[derive(Beamable, Clone, Debug, Default, PartialEq, Eq, Sequence)]
#[beam(profile = 1)]
pub struct Note {
	pub order: u64,
}

#[derive(Flaggable, Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
	#[default]
	Default = 0,
	Maintenance = 2,
}

#[derive(Flaggable, Default, Debug, Clone, Copy, PartialEq, Eq)]
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

/// Both `client!` `identity:` arms, and the `connect` arm without one.
///
/// Never called: the point is that each arm expands and type-checks outside
/// this crate, which is where a leaked `#[cfg(feature = ...)]` would bite.
#[allow(dead_code)]
async fn client_arms(
	addr: tightbeam::transport::tcp::TightBeamSocketAddr,
	cert: tightbeam::crypto::x509::CertificateSpec,
	key: std::sync::Arc<dyn tightbeam::crypto::key::SigningKeyProvider>,
) -> tightbeam::error::Result<()> {
	type P = tightbeam::transport::tcp::r#async::TokioListener;

	let _identity = tightbeam::client!(connect P: addr, identity: (cert.clone(), std::sync::Arc::clone(&key)));
	let _identity_with_policies = tightbeam::client!(
		connect P: addr,
		identity: (cert, key),
		policies: { timeout: core::time::Duration::from_secs(5) }
	);
	let _plain = tightbeam::client!(connect P: addr);

	Ok(())
}

#[cfg(test)]
mod tests {
	use tightbeam::testing::env::SetupEnv;
	use tightbeam::testing::ScenarioConfig;

	/// A CSP process that refuses every trace.
	///
	/// The scenario runner must turn that refusal into a failure. A runner that
	/// dropped the verdict, or a process whose alphabet is never reached, would
	/// leave this test green with nothing checked, so the assertion is that it
	/// panics.
	struct AlwaysInvalidSpec;

	impl tightbeam::testing::specs::csp::ProcessSpec for AlwaysInvalidSpec {
		fn validate_trace(
			&self,
			_trace: &tightbeam::trace::ConsumedTrace,
		) -> tightbeam::testing::specs::csp::CspValidationResult {
			use tightbeam::testing::specs::csp::{CspViolation, Event, State};

			tightbeam::testing::specs::csp::CspValidationResult {
				valid: false,
				violations: vec![CspViolation::Deadlock { event: Event("consumer/probe"), state: State("s0") }],
			}
		}

		fn to_process_cow(&self) -> std::borrow::Cow<'_, tightbeam::testing::specs::csp::Process> {
			use tightbeam::testing::specs::csp::{Process, State};

			std::borrow::Cow::Owned(
				Process::builder("always-invalid")
					.initial_state(State("s0"))
					.add_state(State("s0"))
					.build()
					.expect("the initial state is set above"),
			)
		}
	}

	#[test]
	#[should_panic(expected = "CSP verification failed")]
	fn a_refused_csp_process_fails_the_scenario() {
		let config = ScenarioConfig::builder().with_csp(AlwaysInvalidSpec).build();
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
