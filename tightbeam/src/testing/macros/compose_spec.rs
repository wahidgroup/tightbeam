//! tb_compose_spec! macro for defining CSP process compositions

/// Define a CSP Process Composition with declarative syntax.
///
/// ## Example
/// ```rust,ignore
/// tb_compose_spec! {
///     pub DtnConcurrentSystem,
///     processes: {
///         DtnCommandFlow,
///         DtnTelemetryFlow
///     },
///     composition: interface_parallel(
///         Event("relay_recv")
///     ),
///     properties: {
///         deadlock_free: true,
///         livelock_free: true
///     },
///     annotations {
///         description: "DTN concurrent flows"
///     }
/// }
/// ```
#[macro_export]
macro_rules! tb_compose_spec {
	// Main pattern: composition with properties and annotations
	(
		$(#[$meta:meta])*
		$vis:vis $name:ident,
		processes: {
			$left_process:ident,
			$right_process:ident
		},
		composition: interface_parallel(
			$($sync_event:expr),* $(,)?
		)
		$(, properties: {
			$(deadlock_free: $deadlock_free:expr)?
			$(, livelock_free: $livelock_free:expr)?
			$(, deterministic: $deterministic:expr)?
			$(,)?
		})?
		$(, annotations {
			description: $desc:expr
			$(,)?
		})?
		$(,)?
	) => {
		$(#[$meta])*
		$vis struct $name;

		impl $crate::testing::specs::composition::CompositionSpec for $name {
			fn process() -> $crate::testing::specs::csp::Process {
				use $crate::testing::specs::csp::{Event, Process};
				use std::collections::HashSet;

				let left = $left_process::process();
				let right = $right_process::process();

				let mut sync_alphabet = HashSet::new();
				$(
					sync_alphabet.insert(Event($sync_event));
				)*

				Process::interface_parallel(&left, &right, sync_alphabet)
					.expect("Valid composition")
			}

			fn metadata() -> $crate::testing::specs::composition::CompositionMetadata {
				use std::collections::HashSet;
				use $crate::testing::specs::csp::Event;
				use $crate::testing::specs::composition::{CompositionMetadata, CompositionProperties};

				let mut sync_alphabet = HashSet::new();
				$(
					sync_alphabet.insert(Event($sync_event));
				)*

				CompositionMetadata {
					name: stringify!($name),
					description: $crate::tb_compose_spec!(@desc $($desc)?),
					component_processes: vec![stringify!($left_process), stringify!($right_process)],
					sync_alphabet,
					properties: CompositionProperties {
						deadlock_free: $crate::tb_compose_spec!(@prop $($($deadlock_free)?)?),
						livelock_free: $crate::tb_compose_spec!(@prop $($($livelock_free)?)?),
						deterministic: $crate::tb_compose_spec!(@prop $($($deterministic)?)?),
					},
				}
			}

			fn verify_properties() -> Result<(), $crate::testing::specs::composition::CompositionError> {
				use $crate::testing::specs::composition::{DeadlockChecker, LivelockChecker, DeterminismChecker};

				let process = Self::process();
				let metadata = Self::metadata();

				// Check deadlock-freedom if requested
				if let Some(true) = metadata.properties.deadlock_free {
					DeadlockChecker::check(&process)?;
				}

				// Check livelock-freedom if requested
				if let Some(true) = metadata.properties.livelock_free {
					LivelockChecker::check(&process)?;
				}

				// Check determinism if requested
				if let Some(true) = metadata.properties.deterministic {
					DeterminismChecker::check(&process)?;
				}

				Ok(())
			}
		}
	};

	// Helper: extract description
	(@desc $desc:expr) => { Some($desc) };
	(@desc) => { None };

	// Helper: extract optional bool property
	(@prop $val:expr) => { Some($val) };
	(@prop) => { None };
}

pub use tb_compose_spec;
