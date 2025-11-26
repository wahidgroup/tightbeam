//! tb_compose_spec! macro for defining CSP process compositions

/// Define a CSP Process Composition with declarative syntax.
#[macro_export]
macro_rules! tb_compose_spec {
	// ========================================================================
	// PUBLIC PATTERNS - User-facing syntax for each composition operator
	// ========================================================================

	// Pattern 1: Synchronized parallel (P || Q)
	(
		$(#[$meta:meta])*
		$vis:vis $name:ident,
		processes: {
			$left_process:ident,
			$right_process:ident
		},
		composition: Synchronized
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
		$crate::tb_compose_spec! {
			@impl
			$(#[$meta])* $vis $name,
			$left_process, $right_process,
			@process_call { synchronized_parallel },
			@sync_alphabet_build { },
			$(deadlock_free: $($deadlock_free)?,)?
			$(livelock_free: $($livelock_free)?,)?
			$(deterministic: $($deterministic)?,)?
			$(description: $desc,)?
		}
	};

	// Pattern 2: Interleaved parallel (P ||| Q)
	(
		$(#[$meta:meta])*
		$vis:vis $name:ident,
		processes: {
			$left_process:ident,
			$right_process:ident
		},
		composition: Interleaved
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
		$crate::tb_compose_spec! {
			@impl
			$(#[$meta])* $vis $name,
			$left_process, $right_process,
			@process_call { interleaved_parallel },
			@sync_alphabet_build { },
			$(deadlock_free: $($deadlock_free)?,)?
			$(livelock_free: $($livelock_free)?,)?
			$(deterministic: $($deterministic)?,)?
			$(description: $desc,)?
		}
	};

	// Pattern 3: Interface parallel (P [| A |] Q)
	(
		$(#[$meta:meta])*
		$vis:vis $name:ident,
		processes: {
			$left_process:ident,
			$right_process:ident
		},
		composition: Interface {
			events: [$($sync_event:expr),* $(,)?]
		}
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
		$crate::tb_compose_spec! {
			@impl
			$(#[$meta])* $vis $name,
			$left_process, $right_process,
			@process_call { interface_parallel },
			@sync_alphabet_build { $($sync_event),* },
			$(deadlock_free: $($deadlock_free)?,)?
			$(livelock_free: $($livelock_free)?,)?
			$(deterministic: $($deterministic)?,)?
			$(description: $desc,)?
		}
	};

	// Pattern 4: Alphabetized parallel (P [| αP | αQ |] Q)
	(
		$(#[$meta:meta])*
		$vis:vis $name:ident,
		processes: {
			$left_process:ident,
			$right_process:ident
		},
		composition: Alphabetized {
			left: [$($left_event:expr),* $(,)?],
			right: [$($right_event:expr),* $(,)?]
		}
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
		$crate::tb_compose_spec! {
			@impl
			$(#[$meta])* $vis $name,
			$left_process, $right_process,
			@process_call { alphabetized_parallel },
			@sync_alphabet_build {
				@alphabetized
				left: [$($left_event),*],
				right: [$($right_event),*]
			},
			$(deadlock_free: $($deadlock_free)?,)?
			$(livelock_free: $($livelock_free)?,)?
			$(deterministic: $($deterministic)?,)?
			$(description: $desc,)?
		}
	};

	// ========================================================================
	// INTERNAL HELPER - Generates common boilerplate (DRY)
	// ========================================================================
	(@impl
		$(#[$meta:meta])* $vis:vis $name:ident,
		$left_process:ident, $right_process:ident,
		@process_call { $operator:ident },
		@sync_alphabet_build { $($alphabet_spec:tt)* },
		$(deadlock_free: $deadlock_free:expr,)?
		$(livelock_free: $livelock_free:expr,)?
		$(deterministic: $deterministic:expr,)?
		$(description: $desc:expr,)?
	) => {
		$(#[$meta])*
		$vis struct $name;

		impl Default for $name {
			fn default() -> Self {
				Self
			}
		}

		impl $crate::testing::specs::composition::CompositionSpec for $name {
			fn process() -> $crate::testing::specs::csp::Process {
				use $crate::testing::specs::csp::{Event, Process};
				use std::collections::HashSet;

				let left = $left_process::process();
				let right = $right_process::process();

				$crate::tb_compose_spec!(@build_process $operator, left, right, $($alphabet_spec)*)
					.expect("Valid composition")
			}

			fn metadata() -> $crate::testing::specs::composition::CompositionMetadata {
				use std::collections::HashSet;
				use $crate::testing::specs::csp::Event;
				use $crate::testing::specs::composition::{CompositionMetadata, CompositionProperties};

				let sync_alphabet = $crate::tb_compose_spec!(@build_sync_alphabet $($alphabet_spec)*);

				CompositionMetadata {
					name: stringify!($name),
					description: $crate::tb_compose_spec!(@opt_value $($desc)?),
					component_processes: vec![stringify!($left_process), stringify!($right_process)],
					sync_alphabet,
					properties: CompositionProperties {
						deadlock_free: $crate::tb_compose_spec!(@opt_value $($deadlock_free)?),
						livelock_free: $crate::tb_compose_spec!(@opt_value $($livelock_free)?),
						deterministic: $crate::tb_compose_spec!(@opt_value $($deterministic)?),
					},
				}
			}

			fn verify_properties() -> Result<(), $crate::testing::specs::composition::CompositionError> {
				use $crate::testing::specs::composition::{DeadlockChecker, LivelockChecker, DeterminismChecker};

				let process = Self::process();
				let metadata = Self::metadata();

				if let Some(true) = metadata.properties.deadlock_free {
					DeadlockChecker::check(&process)?;
				}

				if let Some(true) = metadata.properties.livelock_free {
					LivelockChecker::check(&process)?;
				}

				if let Some(true) = metadata.properties.deterministic {
					DeterminismChecker::check(&process)?;
				}

				Ok(())
			}
		}
	};

	// ========================================================================
	// INTERNAL HELPERS - Process building
	// ========================================================================

	// Synchronized parallel (no alphabet needed)
	(@build_process synchronized_parallel, $left:ident, $right:ident, ) => {
		Process::synchronized_parallel(&$left, &$right)
	};

	// Interleaved parallel (no alphabet needed)
	(@build_process interleaved_parallel, $left:ident, $right:ident, ) => {
		Process::interleaved_parallel(&$left, &$right)
	};

	// Interface parallel (with sync alphabet)
	(@build_process interface_parallel, $left:ident, $right:ident, $($sync_event:expr),*) => {
		{
			let mut sync_alphabet = HashSet::new();
			$(
				sync_alphabet.insert(Event($sync_event));
			)*
			Process::interface_parallel(&$left, &$right, sync_alphabet)
		}
	};

	// Alphabetized parallel (with left and right alphabets)
	(@build_process alphabetized_parallel, $left:ident, $right:ident,
		@alphabetized
		left: [$($left_event:expr),*],
		right: [$($right_event:expr),*]
	) => {
		{
			let mut left_alphabet = HashSet::new();
			$(
				left_alphabet.insert(Event($left_event));
			)*
			let mut right_alphabet = HashSet::new();
			$(
				right_alphabet.insert(Event($right_event));
			)*
			Process::alphabetized_parallel(&$left, left_alphabet, &$right, right_alphabet)
		}
	};

	// ========================================================================
	// INTERNAL HELPERS - Sync alphabet building for metadata
	// ========================================================================

	// Empty alphabet (synchronized/interleaved)
	(@build_sync_alphabet ) => {
		{
			use std::collections::HashSet;
			HashSet::new()
		}
	};

	// Interface alphabet (list of events)
	(@build_sync_alphabet $($sync_event:expr),*) => {
		{
			use std::collections::HashSet;
			use $crate::testing::specs::csp::Event;

			let mut sync_alphabet = HashSet::new();
			$(
				sync_alphabet.insert(Event($sync_event));
			)*
			sync_alphabet
		}
	};

	// Alphabetized alphabet (intersection of left and right)
	(@build_sync_alphabet
		@alphabetized
		left: [$($left_event:expr),*],
		right: [$($right_event:expr),*]
	) => {
		{
			use std::collections::HashSet;
			use $crate::testing::specs::csp::Event;

			let mut left_set = HashSet::new();
			$(
				left_set.insert(Event($left_event));
			)*
			let mut right_set = HashSet::new();
			$(
				right_set.insert(Event($right_event));
			)*
			left_set.intersection(&right_set).copied().collect()
		}
	};

	// ========================================================================
	// INTERNAL HELPERS - Optional value extraction
	// ========================================================================

	(@opt_value $val:expr) => { Some($val) };
	(@opt_value) => { None };
}

pub use tb_compose_spec;
