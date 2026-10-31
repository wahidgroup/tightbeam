//! The `tb_compose_spec!` macro, which composes two CSP process specs.

/// Defines a CSP composition of two process specs with a declarative syntax.
///
/// It emits a unit struct that implements [`CompositionSpec`], and so
/// [`ProcessSpec`]. Its process composes the two `processes:` operands under
/// the `composition:` operator:
///
/// - `Synchronized` is `P || Q`, which synchronizes on every shared event.
/// - `Interleaved` is `P ||| Q`, whose events all interleave.
/// - `Interface { events: [..] }` is `P [| A |] Q`, which synchronizes on the events of `A`.
/// - `Alphabetized { left: [..], right: [..] }` is `P [| αP | αQ |] Q`, each operand on its alphabet.
///
/// # Operands and claims
///
/// - An operand is a `tb_process_spec!` type or a composition spec, which needs [`CompositionSpec`] in scope.
/// - The optional `properties:` block claims any of `deadlock_free`, `livelock_free`, and `deterministic`.
/// - Each claim is `true` or `false`, and a scenario checks it once through [`ProcessSpec::verify_claims`].
/// - A scenario checks each claim of an operand composition too.
///
/// # Errors
///
/// - The generated `process()` returns a [`CompositionError`] for an operand that does not build.
/// - It returns one too for a declared alphabet with an event outside its operands.
///
/// # Examples
///
/// ```
/// use tightbeam::testing::specs::composition::{CompositionError, CompositionSpec};
/// use tightbeam::urn::Urn;
/// use tightbeam::{tb_compose_spec, tb_process_spec};
///
/// const PING: Urn<'static> = tightbeam::urn!("doc", "event:compose/ping");
/// const PONG: Urn<'static> = tightbeam::urn!("doc", "event:compose/pong");
///
/// tb_process_spec! {
///     pub Pings,
///     events { observable { PING } hidden { } }
///     states { P0 => { PING => P1 } }
///     terminal { P1 }
/// }
///
/// tb_process_spec! {
///     pub Pongs,
///     events { observable { PONG } hidden { } }
///     states { Q0 => { PONG => Q1 } }
///     terminal { Q1 }
/// }
///
/// tb_compose_spec! {
///     pub PingsBesidePongs,
///     processes: { Pings, Pongs },
///     composition: Interleaved,
///     properties: { deadlock_free: true }
/// }
///
/// // The interface names an event that neither operand performs.
/// tb_compose_spec! {
///     pub Misspelled,
///     processes: { Pings, Pongs },
///     composition: Interface { events: ["pnig"] }
/// }
///
/// assert_eq!(PingsBesidePongs::process()?.name(), "(Pings ||| Pongs)");
/// assert!(matches!(Misspelled::process(), Err(CompositionError::AlphabetMismatch { .. })));
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
///
/// [`CompositionSpec`]: crate::testing::specs::composition::CompositionSpec
/// [`CompositionError`]: crate::testing::specs::composition::CompositionError
/// [`ProcessSpec`]: crate::testing::specs::csp::ProcessSpec
/// [`ProcessSpec::verify_claims`]: crate::testing::specs::csp::ProcessSpec::verify_claims
#[cfg(feature = "testing-csp")]
#[macro_export]
macro_rules! tb_compose_spec {
	// The public arms, one for each composition operator.

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
			$( $property:ident: $claim:expr ),* $(,)?
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
			@operator { $crate::testing::specs::composition::CompositionOperator::Synchronized },
			@properties { $($( $property: $claim, )*)? },
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
			$( $property:ident: $claim:expr ),* $(,)?
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
			@operator { $crate::testing::specs::composition::CompositionOperator::Interleaved },
			@properties { $($( $property: $claim, )*)? },
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
			$( $property:ident: $claim:expr ),* $(,)?
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
			@operator {
				$crate::testing::specs::composition::CompositionOperator::Interface {
					events: ::std::collections::HashSet::from([$($crate::testing::specs::csp::Event($sync_event)),*]),
				}
			},
			@properties { $($( $property: $claim, )*)? },
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
			$( $property:ident: $claim:expr ),* $(,)?
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
			@operator {
				$crate::testing::specs::composition::CompositionOperator::Alphabetized {
					left: ::std::collections::HashSet::from([$($crate::testing::specs::csp::Event($left_event)),*]),
					right: ::std::collections::HashSet::from([$($crate::testing::specs::csp::Event($right_event)),*]),
				}
			},
			@properties { $($( $property: $claim, )*)? },
			$(description: $desc,)?
		}
	};

	// The internal arm that each public arm expands into.
	(@impl
		$(#[$meta:meta])* $vis:vis $name:ident,
		$left_process:ident, $right_process:ident,
		@operator { $operator:expr },
		@properties { $( $property:ident: $claim:expr, )* },
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
			fn process() -> ::core::result::Result<
				$crate::testing::specs::csp::Process,
				$crate::testing::specs::composition::CompositionError,
			> {
				let left = $left_process::process()?;
				let right = $right_process::process()?;
				let operator = $operator;

				operator.compose(&left, &right)
			}

			// A spec that claims every property names every field, and the
			// update then fills none.
			#[allow(clippy::needless_update)]
			fn metadata() -> ::core::result::Result<
				$crate::testing::specs::composition::CompositionMetadata,
				$crate::testing::specs::composition::CompositionError,
			> {
				use $crate::testing::specs::composition::{CompositionMetadata, CompositionProperties};

				let left = $left_process::process()?;
				let right = $right_process::process()?;
				let operator = $operator;

				::core::result::Result::Ok(CompositionMetadata {
					name: stringify!($name),
					description: $crate::tb_compose_spec!(@opt_value $($desc)?),
					component_processes: vec![stringify!($left_process), stringify!($right_process)],
					sync_alphabet: operator.sync_alphabet(&left, &right),
					properties: CompositionProperties {
						$( $property: Some($claim), )*
						..CompositionProperties::default()
					},
				})
			}

			// It checks this composition's claims, then each operand's, so a
			// composition used as an operand keeps its claims checked.
			fn verify_properties() -> ::core::result::Result<(), $crate::testing::specs::composition::CompositionError> {
				use $crate::testing::specs::csp::ProcessSpec as _;

				let process = Self::process()?;
				Self::metadata()?.properties.verify(&process)?;
				<$left_process as ::core::default::Default>::default().verify_claims()?;
				<$right_process as ::core::default::Default>::default().verify_claims()
			}
		}
	};

	// The internal arms that turn an optional description into an `Option`.

	(@opt_value $val:expr) => { Some($val) };
	(@opt_value) => { None };
}

#[cfg(feature = "testing-csp")]
pub use tb_compose_spec;

#[cfg(all(test, feature = "testing-csp"))]
mod tests {
	use std::collections::HashSet;

	use crate::testing::specs::composition::{CompositionError, CompositionProperty, CompositionSpec};
	use crate::testing::specs::csp::Event;
	use crate::testing::{ScenarioConfig, ScenarioConfigError, TestResult};
	use crate::urn::Urn;

	const PING: Urn<'static> = crate::urn!("test", "event:compose/ping");
	const PONG: Urn<'static> = crate::urn!("test", "event:compose/pong");

	crate::tb_process_spec! {
		pub PingFlow,
		events { observable { PING } hidden { } }
		states { PingIdle => { PING => PingDone }, PingDone => { } }
		terminal { PingDone }
	}

	crate::tb_process_spec! {
		pub PongFlow,
		events { observable { PONG } hidden { } }
		states { PongIdle => { PONG => PongDone }, PongDone => { } }
		terminal { PongDone }
	}

	crate::tb_process_spec! {
		pub PingThenPong,
		events { observable { PING, PONG } hidden { } }
		states { PingFirst => { PING => PongNext }, PongNext => { PONG => BothDone }, BothDone => { } }
		terminal { BothDone }
	}

	crate::tb_process_spec! {
		pub PongThenPing,
		events { observable { PING, PONG } hidden { } }
		states { PongFirst => { PONG => PingNext }, PingNext => { PING => BothSent }, BothSent => { } }
		terminal { BothSent }
	}

	// The interleaving of two one-step flows reaches its terminal state on
	// every path, so it is deadlock-free.
	crate::tb_compose_spec! {
		pub ClaimsInterleavingDeadlocks,
		processes: { PingFlow, PongFlow },
		composition: Interleaved,
		properties: { deadlock_free: false }
	}

	// Each operand waits for the event that the other one offers second, so
	// the synchronized composition deadlocks in its initial state.
	crate::tb_compose_spec! {
		pub ClaimsCrossedOrderDeadlocks,
		processes: { PingThenPong, PongThenPing },
		composition: Synchronized,
		properties: { deadlock_free: false }
	}

	crate::tb_compose_spec! {
		pub ClaimsCrossedOrderIsDeadlockFree,
		processes: { PingThenPong, PongThenPing },
		composition: Synchronized,
		properties: { deadlock_free: true }
	}

	// The outer composition claims nothing, and its operand claims a deadlock
	// that the operand lacks.
	crate::tb_compose_spec! {
		pub NestsAFalseClaim,
		processes: { ClaimsInterleavingDeadlocks, PingThenPong },
		composition: Interleaved
	}

	/// A synchronized spec states the events its operands share as its sync
	/// alphabet.
	#[test]
	fn a_synchronized_spec_states_the_shared_events_as_its_sync_alphabet() -> TestResult {
		let sync_alphabet = ClaimsCrossedOrderDeadlocks::metadata()?.sync_alphabet;
		assert_eq!(sync_alphabet, HashSet::from([Event::from(PING), Event::from(PONG)]));
		Ok(())
	}

	/// A false claim of deadlock is refused when the process is free of
	/// deadlock.
	#[test]
	fn a_false_claim_is_refused_when_the_process_holds_the_property() {
		let verified = ClaimsInterleavingDeadlocks::verify_properties();
		let holds = CompositionError::PropertyHolds { property: CompositionProperty::DeadlockFree };
		assert_eq!(verified, Err(holds));
	}

	/// A claim of deadlock holds when the checker finds a deadlock.
	#[test]
	fn a_false_claim_holds_when_the_checker_finds_a_witness() {
		let verified = ClaimsCrossedOrderDeadlocks::verify_properties();
		assert_eq!(verified, Ok(()));
	}

	/// A claim of deadlock freedom is refused with the deadlock that the
	/// checker finds at the initial state.
	#[test]
	fn a_true_claim_is_refused_when_the_checker_finds_a_witness() -> TestResult {
		let initial = ClaimsCrossedOrderIsDeadlockFree::process()?.initial;
		let verified = ClaimsCrossedOrderIsDeadlockFree::verify_properties();
		assert_eq!(verified, Err(CompositionError::DeadlockDetected { state: initial }));
		Ok(())
	}

	// The interface names an event that neither operand performs.
	crate::tb_compose_spec! {
		pub MisspellsItsInterface,
		processes: { PingFlow, PongFlow },
		composition: Interface { events: ["pnig"] }
	}

	/// An interface that names an event outside its operands refuses the
	/// composition.
	#[test]
	fn an_interface_outside_its_operands_refuses_the_composition() {
		let refused = MisspellsItsInterface::process();
		assert!(matches!(refused, Err(CompositionError::AlphabetMismatch { .. })));
	}

	/// A false claim of an operand composition refuses the scenario that
	/// names the outer composition.
	#[test]
	fn a_false_claim_of_an_operand_composition_fails_a_scenario() {
		let refused = ScenarioConfig::builder().with_csp(NestsAFalseClaim).build();
		let holds = CompositionError::PropertyHolds { property: CompositionProperty::DeadlockFree };
		assert_eq!(refused.err(), Some(ScenarioConfigError::CspRefused(holds)));
	}
}
