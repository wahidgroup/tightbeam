//! The integration tests of a deadline in FDR exploration.
//!
//! Exploration charges the WCET of each event to its branch, and it prunes the
//! branch whose time from the start of a deadline to its end passes the
//! deadline.

use core::time::Duration;

use tightbeam::testing::fdr::{DefaultFdrExplorer, FdrConfig};
use tightbeam::testing::specs::csp::{Process, ProcessBuildError};
use tightbeam::urn::Urn;
use tightbeam::{deadline, tb_cases, tb_process_spec, wcet};

use crate::common::result::TestResult;

pub(crate) const ARM: Urn<'static> = tightbeam::urn!("test", "event:deadline/arm");
pub(crate) const FIRE: Urn<'static> = tightbeam::urn!("test", "event:deadline/fire");

/// The seeds of each exploration, each of which walks the one branch of its
/// process.
const SEEDS: u32 = 4;

tb_process_spec! {
	/// A process whose `FIRE` lands 10 ms after `ARM`, past its deadline of
	/// 5 ms.
	pub PastItsDeadline,
	events {
		observable { ARM, FIRE }
		hidden { }
	}
	states {
		S0 => { ARM => S1 },
		S1 => { FIRE => S2 }
	}
	terminal { S2 }
	timing {
		wcet: {
			ARM => wcet!(Duration::from_millis(10)),
			FIRE => wcet!(Duration::from_millis(10))
		},
		deadline: {
			ARM => FIRE, deadline!(duration: Duration::from_millis(5))
		}
	}
}

tb_process_spec! {
	/// A process whose `FIRE` lands 10 ms after `ARM`, within its deadline of
	/// 15 ms.
	pub WithinItsDeadline,
	events {
		observable { ARM, FIRE }
		hidden { }
	}
	states {
		S0 => { ARM => S1 },
		S1 => { FIRE => S2 }
	}
	terminal { S2 }
	timing {
		wcet: {
			ARM => wcet!(Duration::from_millis(10)),
			FIRE => wcet!(Duration::from_millis(10))
		},
		deadline: {
			ARM => FIRE, deadline!(duration: Duration::from_millis(15))
		}
	}
}

// Each seed walks one branch, so a process whose `FIRE` passes the deadline
// prunes one branch per seed, and a process that meets it prunes none.
tb_cases! {
	fn the_prunes_of_a_walk_follow_its_deadline(
		(process, pruned): (fn() -> Result<Process, ProcessBuildError>, usize)
	) -> TestResult {
		let subject = process()?;
		let config = FdrConfig { seeds: SEEDS, ..FdrConfig::default() };
		let mut explorer = DefaultFdrExplorer::with_defaults(&subject, config);

		let verdict = explorer.explore()?;
		assert_eq!(verdict.timing_pruned, pruned);
		Ok(())
	}
	cases {
		/// `FIRE` passes the deadline, so each seed prunes its branch.
		past_the_deadline => (PastItsDeadline::process, 4),
		/// `FIRE` meets the deadline, so no seed prunes a branch.
		within_the_deadline => (WithinItsDeadline::process, 0),
	}
}
