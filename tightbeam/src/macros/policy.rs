#[macro_export]
macro_rules! policy {
	() => {};
	(GatePolicy: $name:ident | $frame:ident, $session:ident | { $($body:tt)* } $($rest:tt)*) => {
		#[derive(Default)]
		pub struct $name;

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
	(GatePolicy: $name:ident | $arg:ident | { $($body:tt)* } $($rest:tt)*) => {
		#[derive(Default)]
		pub struct $name;

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
	(GatePolicy: $name:ident { $($body:tt)* } $($rest:tt)*) => {
		#[derive(Default)]
		pub struct $name;

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
	(ReceptorPolicy<$msg:ty>: $name:ident | $arg:ident | { $($body:tt)* } $($rest:tt)*) => {
		#[derive(Default)]
		pub struct $name;

		impl $crate::policy::ReceptorPolicy<$msg> for $name {
			#[allow(unused_variables)]
			fn evaluate(&self, $arg: &$msg) -> $crate::policy::TransitStatus {
				$($body)*
			}
		}

		$crate::policy! { $($rest)* }
	};
	(ReceptorPolicy<$msg:ty>: $name:ident { $($body:tt)* } $($rest:tt)*) => {
		#[derive(Default)]
		pub struct $name;

		impl $crate::policy::ReceptorPolicy<$msg> for $name {
			#[allow(unused_variables)]
			fn evaluate(&self, message: &$msg) -> $crate::policy::TransitStatus {
				$($body)*
			}
		}

		$crate::policy! { $($rest)* }
	};
	// RestartPolicy with config: (max_attempts, delay_ms)
	(RestartPolicy: $name:ident ($max:expr, $delay:expr) | $frame_arg:ident, $failure_arg:ident, $attempt_arg:ident | { $($body:tt)* } $($rest:tt)*) => {
		#[derive(Default)]
		pub struct $name;

		impl $crate::transport::policy::CoreRetryPolicy for $name {
			fn max_attempts(&self) -> usize { $max }
			fn delay_ms(&self, attempt: usize) -> u64 { ($delay as u64).saturating_mul(attempt as u64 + 1) }
		}

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
	// RestartPolicy with max_attempts only: (max_attempts)
	(RestartPolicy: $name:ident ($max:expr) | $frame_arg:ident, $failure_arg:ident, $attempt_arg:ident | { $($body:tt)* } $($rest:tt)*) => {
		$crate::policy! { RestartPolicy: $name ($max, 0) | $frame_arg, $failure_arg, $attempt_arg | { $($body)* } $($rest)* }
	};
	// RestartPolicy default: max_attempts = 1, delay = 0
	(RestartPolicy: $name:ident | $frame_arg:ident, $failure_arg:ident, $attempt_arg:ident | { $($body:tt)* } $($rest:tt)*) => {
		#[derive(Default)]
		pub struct $name;

		impl $crate::transport::policy::CoreRetryPolicy for $name {
			fn max_attempts(&self) -> usize { 1 }
			fn delay_ms(&self, _attempt: usize) -> u64 { 0 }
		}

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
	use crate::transport::policy::RetryAction;
	use crate::Beamable;

	#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
	struct DummyMessage {
		value: u64,
	}

	// Every public arm is invoked here so broken expansions fail `cargo test`
	// instead of surviving until a consumer expands them.
	policy! {
		GatePolicy: TestGateBusy |_frame| {
			TransitStatus::ResourceExhausted
		}
		GatePolicy: TestGateAccept |_frame| {
			TransitStatus::Ok
		}
		// Session-aware arm: identity gates key on the connection's
		// authenticated peer context.
		GatePolicy: TestGateSessionAware |_frame, session| {
			if session.peer_certificate().is_some() {
				TransitStatus::Ok
			} else {
				TransitStatus::Unauthenticated
			}
		}
		// Implicit-argument arms: macro hygiene hides the generated binding
		// from the caller's body, so these arms serve input-independent
		// policies only.
		GatePolicy: TestGateImplicitArg {
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
		RestartPolicy: TestRestart |frame, _failure, _attempt| {
			RetryAction::Retry(frame)
		}
		RestartPolicy: TestRestartMaxOnly (2) |frame, _failure, _attempt| {
			RetryAction::Retry(frame)
		}
		RestartPolicy: TestRestartConfigured (3, 250) |frame, _failure, _attempt| {
			RetryAction::Retry(frame)
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

		Ok(())
	}

	#[test]
	fn test_restart_policy_retry_configuration() {
		use crate::transport::policy::CoreRetryPolicy;

		assert_eq!(TestRestart.max_attempts(), 1);
		assert_eq!(TestRestart.delay_ms(0), 0);
		assert_eq!(TestRestartMaxOnly.max_attempts(), 2);
		assert_eq!(TestRestartMaxOnly.delay_ms(1), 0);
		assert_eq!(TestRestartConfigured.max_attempts(), 3);
		assert_eq!(TestRestartConfigured.delay_ms(1), 500);
	}
}
