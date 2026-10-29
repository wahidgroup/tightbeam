//! An outside crate implements [`RouterPolicy`] by hand. Its
//! `dispatch_cleartext` decodes each frame through [`CleartextFrame::decode`],
//! which holds the frame, as it arrived, to the requirements of the
//! dispatched type.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tightbeam::core::RequirementError;
use tightbeam::der::Sequence;
use tightbeam::router::{CleartextFrame, Result as RouteResult, RouterError, RouterPolicy};
use tightbeam::{compose, Beamable, Message, Version};

/// A reading of any version.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
struct Reading {
	value: u64,
}

/// A reading whose type requires V2 or later. Its DER is the DER of
/// [`Reading`].
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
#[beam(min_version = "V2")]
struct RecentReading {
	value: u64,
}

/// An outside policy that counts each frame whose body it decodes.
#[derive(Default)]
struct CountingRouter {
	delivered: AtomicUsize,
}

impl RouterPolicy for CountingRouter {
	fn dispatch_cleartext<T: Message + Send + 'static>(&self, frame: CleartextFrame) -> RouteResult<()> {
		// The policy proves the decode alone, so the message drops here.
		let _message: T = frame.decode()?;
		self.delivered.fetch_add(1, Ordering::Relaxed);
		Ok(())
	}
}

/// A frame at the minimum version of its type passes the decode of an
/// outside policy.
#[test]
fn an_outside_policy_decodes_a_frame_at_the_minimum_of_its_type() -> Result<(), Box<dyn std::error::Error>> {
	let router = CountingRouter::default();
	let frame = compose! { V2: id: "reading", order: 1u64, message: RecentReading { value: 7 } }?;

	router.dispatch::<RecentReading>(Arc::new(frame))?;
	assert_eq!(router.delivered.load(Ordering::Relaxed), 1);
	Ok(())
}

/// The decode of an outside policy refuses a frame below the minimum version
/// of its type.
#[test]
fn an_outside_policy_refuses_a_frame_below_the_minimum_of_its_type() -> Result<(), Box<dyn std::error::Error>> {
	let router = CountingRouter::default();
	let frame = compose! { V1: id: "reading", order: 1u64, message: Reading { value: 7 } }?;

	let refused = router.dispatch::<RecentReading>(Arc::new(frame));
	let below = RequirementError::Version((Version::V1, Version::V2).into());
	assert!(matches!(refused, Err(RouterError::Requirement(error)) if error == below));
	Ok(())
}
