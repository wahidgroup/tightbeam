/// Declares one or more policy types, each with the body that evaluates it.
///
/// A declaration names the policy trait, an optional visibility, the type
/// name, and the evaluation body. The generated type is a unit struct that
/// derives [`Default`], so a caller names it wherever a policy value is
/// expected.
///
/// | Declaration form | Traits the expansion implements |
/// | --- | --- |
/// | `GatePolicy: $vis $Name` followed by `\|frame, session\|`, `\|frame\|`, or no closure | [`GatePolicy`] |
/// | `ReceptorPolicy<$msg>: $vis $Name` followed by `\|message\|` or no closure | [`ReceptorPolicy`] over `$msg` |
/// | `RestartPolicy: $vis $Name` followed by `\|frame, failure, attempt\|` | [`RestartPolicy`] |
///
/// # Visibility
///
/// The optional visibility sits between the trait name and the type name, and
/// the generated `struct` carries it, so the caller decides where the policy
/// type is reachable from. An omitted visibility keeps the type private to the
/// declaring module.
///
/// ```
/// use tightbeam::policy::{GatePolicy, SessionContext, TransitStatus};
///
/// tightbeam::policy! {
///     GatePolicy: pub OpenGate {
///         TransitStatus::Ok
///     }
/// }
///
/// let verdict = OpenGate.evaluate(None, &SessionContext::default());
/// assert_eq!(verdict, TransitStatus::Ok);
/// ```
///
/// [`GatePolicy`]: crate::policy::GatePolicy
/// [`ReceptorPolicy`]: crate::policy::ReceptorPolicy
/// [`RestartPolicy`]: crate::transport::policy::RestartPolicy
#[macro_export]
macro_rules! policy {
	() => {};
	(GatePolicy: $vis:vis $name:ident | $frame:ident, $session:ident | { $($body:tt)* } $($rest:tt)*) => {
		#[derive(Default)]
		$vis struct $name;

		impl $crate::policy::GatePolicy for $name {
			#[allow(unused_variables)]
			fn evaluate(
				&self,
				$frame: ::core::option::Option<&$crate::Frame>,
				$session: &$crate::policy::SessionContext,
			) -> $crate::policy::TransitStatus {
				$($body)*
			}
		}

		$crate::policy! { $($rest)* }
	};
	(GatePolicy: $vis:vis $name:ident | $arg:ident | { $($body:tt)* } $($rest:tt)*) => {
		#[derive(Default)]
		$vis struct $name;

		impl $crate::policy::GatePolicy for $name {
			#[allow(unused_variables)]
			fn evaluate(
				&self,
				$arg: ::core::option::Option<&$crate::Frame>,
				_session: &$crate::policy::SessionContext,
			) -> $crate::policy::TransitStatus {
				$($body)*
			}
		}

		$crate::policy! { $($rest)* }
	};
	(GatePolicy: $vis:vis $name:ident { $($body:tt)* } $($rest:tt)*) => {
		#[derive(Default)]
		$vis struct $name;

		impl $crate::policy::GatePolicy for $name {
			#[allow(unused_variables)]
			fn evaluate(
				&self,
				frame: ::core::option::Option<&$crate::Frame>,
				_session: &$crate::policy::SessionContext,
			) -> $crate::policy::TransitStatus {
				$($body)*
			}
		}

		$crate::policy! { $($rest)* }
	};
	(ReceptorPolicy<$msg:ty>: $vis:vis $name:ident | $arg:ident | { $($body:tt)* } $($rest:tt)*) => {
		#[derive(Default)]
		$vis struct $name;

		impl $crate::policy::ReceptorPolicy<$msg> for $name {
			#[allow(unused_variables)]
			fn evaluate(&self, $arg: &$msg) -> $crate::policy::TransitStatus {
				$($body)*
			}
		}

		$crate::policy! { $($rest)* }
	};
	(ReceptorPolicy<$msg:ty>: $vis:vis $name:ident { $($body:tt)* } $($rest:tt)*) => {
		#[derive(Default)]
		$vis struct $name;

		impl $crate::policy::ReceptorPolicy<$msg> for $name {
			#[allow(unused_variables)]
			fn evaluate(&self, message: &$msg) -> $crate::policy::TransitStatus {
				$($body)*
			}
		}

		$crate::policy! { $($rest)* }
	};
	(RestartPolicy: $vis:vis $name:ident | $frame_arg:ident, $failure_arg:ident, $attempt_arg:ident | { $($body:tt)* } $($rest:tt)*) => {
		#[derive(Default)]
		$vis struct $name;

		impl $crate::transport::policy::RestartPolicy for $name {
			#[allow(unused_variables)]
			fn evaluate(
				&self,
				$frame_arg: Box<$crate::Frame>,
				$failure_arg: &$crate::transport::error::TransportFailure,
				$attempt_arg: usize,
			) -> $crate::transport::policy::RetryAction {
				$($body)*
			}
		}

		$crate::policy! { $($rest)* }
	};
}

#[cfg(test)]
mod tests {
	#![allow(unused_variables)]

	use crate::der::Sequence;
	use crate::policy::{GatePolicy, ReceptorPolicy, SessionContext, TransitStatus};
	use crate::transport::error::TransportFailure;
	use crate::transport::policy::{RestartPolicy, RetryAction};
	use crate::Beamable;

	#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
	struct DummyMessage {
		value: u64,
	}

	// Every public arm expands here, so a broken arm fails `cargo test`.
	policy! {
		GatePolicy: TestGateBusy |_frame| {
			TransitStatus::ResourceExhausted
		}
		GatePolicy: TestGateAccept |_frame| {
			TransitStatus::Ok
		}
		// The session-aware arm serves identity gates, which key on the
		// connection's authenticated peer context.
		GatePolicy: TestGateSessionAware |_frame, session| {
			if session.peer_certificate().is_some() {
				TransitStatus::Ok
			} else {
				TransitStatus::Unauthenticated
			}
		}
		// Macro hygiene hides the binding of an implicit-argument arm from the
		// caller's body, so these arms serve input-independent policies only.
		GatePolicy: TestGateImplicitArg {
			TransitStatus::Ok
		}
		GatePolicy: pub(crate) TestGateCrateVisible {
			TransitStatus::Ok
		}
		GatePolicy: pub TestGatePublic {
			TransitStatus::Ok
		}
		ReceptorPolicy<DummyMessage>: TestReceptorReject |message| {
			if message.value == 0 {
				TransitStatus::PermissionDenied
			} else {
				TransitStatus::Ok
			}
		}
		ReceptorPolicy<DummyMessage>: TestReceptorImplicitArg {
			TransitStatus::Ok
		}
		RestartPolicy: pub(crate) TestRestart |frame, _failure, attempt| {
			match attempt {
				0 => RetryAction::Retry { frame, delay: core::time::Duration::ZERO },
				_ => RetryAction::NoRetry,
			}
		}
	}

	#[test]
	fn test_gate_policy() -> Result<(), crate::TightBeamError> {
		let frame = compose! {
			V0: id: b"test", message: DummyMessage { value: 42 }
		}?;
		assert_eq!(
			TestGateBusy.evaluate(Some(&frame), &SessionContext::default()),
			TransitStatus::ResourceExhausted
		);
		assert_eq!(
			TestGateAccept.evaluate(Some(&frame), &SessionContext::default()),
			TransitStatus::Ok
		);

		Ok(())
	}

	#[test]
	fn test_session_aware_gate_arm() -> Result<(), crate::TightBeamError> {
		let frame = compose! {
			V0: id: b"test", message: DummyMessage { value: 42 }
		}?;
		assert_eq!(
			TestGateSessionAware.evaluate(Some(&frame), &SessionContext::default()),
			TransitStatus::Unauthenticated
		);

		Ok(())
	}

	#[test]
	fn test_receptor_policy() {
		let receptor = TestReceptorReject;
		assert_eq!(receptor.evaluate(&DummyMessage { value: 1 }), TransitStatus::Ok);
		assert_eq!(receptor.evaluate(&DummyMessage { value: 0 }), TransitStatus::PermissionDenied);
	}

	#[test]
	fn test_implicit_argument_arms() -> Result<(), crate::TightBeamError> {
		let frame = compose! {
			V0: id: b"test", message: DummyMessage { value: 42 }
		}?;
		assert_eq!(
			TestGateImplicitArg.evaluate(Some(&frame), &SessionContext::default()),
			TransitStatus::Ok
		);
		assert_eq!(TestReceptorImplicitArg.evaluate(&DummyMessage { value: 42 }), TransitStatus::Ok);

		let session = SessionContext::default();
		assert_eq!(TestGateCrateVisible.evaluate(None, &session), TransitStatus::Ok);
		assert_eq!(TestGatePublic.evaluate(None, &session), TransitStatus::Ok);

		Ok(())
	}

	/// The restart arm evaluates its body with the attempt the transport
	/// passes, so the second attempt stops where the first retries.
	#[test]
	fn test_restart_policy_evaluates_its_body() -> Result<(), crate::TightBeamError> {
		let frame = compose! {
			V0: id: b"test", message: DummyMessage { value: 42 }
		}?;
		let failure = TransportFailure::Unavailable;

		let first = TestRestart.evaluate(Box::new(frame.clone()), &failure, 0);
		let second = TestRestart.evaluate(Box::new(frame.clone()), &failure, 1);
		let retried = RetryAction::Retry { frame: Box::new(frame), delay: core::time::Duration::ZERO };
		assert_eq!((first, second), (retried, RetryAction::NoRetry));
		Ok(())
	}
}
