//! The tests of the acceptance and refusal queries of [`RequestPathState`].

#![cfg(feature = "testing-fdr")]

use core::error::Error;

use tightbeam::testing::fdr::{AcceptanceSet, RequestPathState};
use tightbeam::testing::specs::csp::Event;

#[test]
fn the_acceptance_query_names_the_events_of_the_handler_state() -> Result<(), Box<dyn Error>> {
	let accepted = RequestPathState::Handler.acceptance();
	// The handler state accepts the exit of the handler and the response.
	assert_eq!(accepted, AcceptanceSet::from([Event("handler_exit"), Event("response")]));
	Ok(())
}

#[test]
fn the_refusal_query_answers_for_the_handler_state() -> Result<(), Box<dyn Error>> {
	// The handler state refuses a new request, and it accepts the response.
	let refuses_request = RequestPathState::Handler.refuses("request");
	let refuses_response = RequestPathState::Handler.refuses("response");
	assert_eq!([refuses_request, refuses_response], [true, false]);
	Ok(())
}
