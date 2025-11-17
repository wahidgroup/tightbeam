#[macro_export]
macro_rules! policy {
	() => {};
	(GatePolicy: $name:ident | $arg:ident | { $($body:tt)* } $($rest:tt)*) => {
		#[derive(Default)]
		pub struct $name;

		impl $crate::policy::GatePolicy for $name {
			#[allow(unused_variables)]
			fn evaluate(&self, $arg: &$crate::Frame) -> $crate::policy::TransitStatus {
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
			fn evaluate(&self, frame: &$crate::Frame) -> $crate::policy::TransitStatus {
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
	(RestartPolicy: $name:ident | $msg_arg:ident, $res_arg:ident, $attempt_arg:ident | { $($body:tt)* } $($rest:tt)*) => {
		#[derive(Default)]
		pub struct $name;

		impl $crate::transport::policy::RestartPolicy for $name {
			#[allow(unused_variables)]
			fn evaluate(
				&self,
				$msg_arg: &$crate::Frame,
				$res_arg: &$crate::transport::TransportResult<&$crate::Frame>,
				$attempt_arg: usize,
			) -> $crate::transport::policy::RetryAction {
				$($body)*
			}
		}

		$crate::policy! { $($rest)* }
	};
	(RestartPolicy: $name:ident { $($body:tt)* } $($rest:tt)*) => {
		#[derive(Default)]
		pub struct $name;

		impl $crate::transport::policy::RestartPolicy for $name {
			#[allow(unused_variables)]
			fn evaluate(
				&self,
				message: &$crate::Frame,
				result: &$crate::transport::TransportResult<&$crate::Frame>,
				attempt: usize,
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
	use crate::policy::{GatePolicy, ReceptorPolicy, TransitStatus};
	use crate::Beamable;

	#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
	struct DummyMessage {
		value: u64,
	}

	policy! {
		GatePolicy: TestGateBusy |_frame| {
			TransitStatus::Busy
		}
		GatePolicy: TestGateAccept |_frame| {
			TransitStatus::Accepted
		}
		ReceptorPolicy<DummyMessage>: TestReceptorReject |message| {
			if message.value == 0 {
				TransitStatus::Forbidden
			} else {
				TransitStatus::Accepted
			}
		}
		RestartPolicy: TestRestart |message, result, attempt| {
			crate::transport::policy::RetryAction::RetryWithSame
		}
	}

	#[allow(dead_code)]
	impl TestGateAccept {}

	#[allow(dead_code)]
	impl TestRestart {}

	#[test]
	fn test_gate_policy() -> Result<(), crate::TightBeamError> {
		let gate = TestGateBusy;
		let frame = crate::compose! {
			V0: id: b"test", message: DummyMessage { value: 42 }
		}?;
		assert_eq!(gate.evaluate(&frame), TransitStatus::Busy);

		Ok(())
	}

	#[test]
	fn test_receptor_policy() {
		let receptor = TestReceptorReject;
		assert_eq!(receptor.evaluate(&DummyMessage { value: 1 }), TransitStatus::Accepted);
		assert_eq!(receptor.evaluate(&DummyMessage { value: 0 }), TransitStatus::Forbidden);
	}
}
