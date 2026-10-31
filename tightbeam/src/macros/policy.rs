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
	use crate::policy::{GatePolicy, ReceptorPolicy, SessionContext, TransitStatus};
	use crate::testing::{TestFrame, TestMessage};
	use crate::transport::error::TransportFailure;
	use crate::transport::policy::{RestartPolicy, RetryAction};
	use crate::Frame;

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
		ReceptorPolicy<TestMessage>: TestReceptorReject |message| {
			if message.content.is_empty() {
				TransitStatus::PermissionDenied
			} else {
				TransitStatus::Ok
			}
		}
		ReceptorPolicy<TestMessage>: TestReceptorImplicitArg {
			TransitStatus::Ok
		}
		RestartPolicy: pub(crate) TestRestart |frame, _failure, attempt| {
			match attempt {
				0 => RetryAction::Retry { frame, delay: core::time::Duration::ZERO },
				_ => RetryAction::NoRetry,
			}
		}
	}

	// A declared gate answers with the status its body names, with a frame or
	// with none.
	crate::tb_cases! {
		fn a_declared_gate_answers_its_body((gate, frame, expected): (&dyn GatePolicy, Option<Frame>, TransitStatus)) {
			assert_eq!(gate.evaluate(frame.as_ref(), &SessionContext::default()), expected);
		}
		cases {
			busy => (&TestGateBusy, Some(TestFrame::v0(None, Some("test"))), TransitStatus::ResourceExhausted),
			accepting => (&TestGateAccept, Some(TestFrame::v0(None, Some("test"))), TransitStatus::Ok),
			/// A session with no authenticated peer is refused.
			session_aware_without_a_peer => (
				&TestGateSessionAware,
				Some(TestFrame::v0(None, Some("test"))),
				TransitStatus::Unauthenticated,
			),
			implicit_argument => (&TestGateImplicitArg, Some(TestFrame::v0(None, Some("test"))), TransitStatus::Ok),
			crate_visible => (&TestGateCrateVisible, None, TransitStatus::Ok),
			public => (&TestGatePublic, None, TransitStatus::Ok),
		}
	}

	// A declared receptor answers with the status its body names for the
	// message it reads.
	crate::tb_cases! {
		fn a_declared_receptor_answers_its_body(
			(receptor, content, expected): (&dyn ReceptorPolicy<TestMessage>, &str, TransitStatus)
		) {
			let message = TestMessage { content: content.to_string() };
			assert_eq!(receptor.evaluate(&message), expected);
		}
		cases {
			a_message_with_content => (&TestReceptorReject, "content", TransitStatus::Ok),
			an_empty_message => (&TestReceptorReject, "", TransitStatus::PermissionDenied),
			implicit_argument => (&TestReceptorImplicitArg, "content", TransitStatus::Ok),
		}
	}

	/// The restart arm evaluates its body with the attempt the transport
	/// passes, so the second attempt stops where the first retries.
	#[test]
	fn a_restart_arm_retries_the_first_attempt_alone() {
		let frame = TestFrame::v0(None, Some("test"));
		let failure = TransportFailure::Unavailable;

		let first = TestRestart.evaluate(Box::new(frame.clone()), &failure, 0);
		let second = TestRestart.evaluate(Box::new(frame.clone()), &failure, 1);
		let retried = RetryAction::Retry { frame: Box::new(frame), delay: core::time::Duration::ZERO };
		assert_eq!((first, second), (retried, RetryAction::NoRetry));
	}
}
