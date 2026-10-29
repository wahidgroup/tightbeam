//! An outside crate writes its own [`ExpectedMatcher`], and a scenario grades
//! a frame against it through [`ExpectedMatcher::record_match`]. The spec of
//! the scenario asserts the recorded value with `equals!(true)`.

use tightbeam::testing::{Expect, ExpectedMatcher, Layer, ScenarioConfig, SetupEnv, TestFrame};
use tightbeam::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_scenario, Frame};

/// The event whose value states whether a frame carries the expected value.
const CARRIES_EXPECTED: Urn<'static> = tightbeam::urn!("outside", "event:matcher/carries-expected");

/// An outside matcher that expects a frame whose id starts with its prefix.
struct IdPrefix(&'static [u8]);

impl ExpectedMatcher for IdPrefix {
	fn matches(&self, frame: &Frame) -> bool {
		frame.metadata().id().starts_with(self.0)
	}
}

tb_assert_spec! {
	pub CarriesExpectedSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(CARRIES_EXPECTED, exactly!(1), equals!(true))
		]
	}
}

tb_scenario! {
	name: a_frame_that_an_outside_matcher_expects_passes_the_scenario,
	config: ScenarioConfig::builder().with_spec(CarriesExpectedSpec::latest()).build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			let reply = TestFrame::v0(None, Some("reply-7"));
			IdPrefix(b"reply-").record_match(&trace, CARRIES_EXPECTED, &reply)
		}
	}
}

tb_scenario! {
	name: a_frame_that_an_outside_matcher_does_not_expect_fails_the_assertion_layer,
	config: ScenarioConfig::builder()
		.with_spec(CarriesExpectedSpec::latest())
		.with_expect(Expect::Violation(Layer::Assertion))
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			let stray = TestFrame::v0(None, Some("stray"));
			IdPrefix(b"reply-").record_match(&trace, CARRIES_EXPECTED, &stray)
		}
	}
}
