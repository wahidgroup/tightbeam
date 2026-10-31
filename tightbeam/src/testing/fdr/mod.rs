//! Layer 3: Failures-Divergences Refinement checking
//!
//! This module provides bounded refinement checking following CSP theory.
//! [`FdrVerdict`] reports the outcome, and the explorer that fills it is
//! behind `testing-fdr`.

mod verdict;

pub use verdict::*;

#[cfg(feature = "testing-fdr")]
mod config;
#[cfg(feature = "testing-fdr")]
mod explorer;
#[cfg(feature = "testing-fdr")]
mod subsys;

#[cfg(feature = "testing-fdr")]
pub use config::*;
#[cfg(feature = "testing-fdr")]
pub use explorer::*;
#[cfg(feature = "testing-fdr")]
pub use subsys::*;

#[cfg(all(test, feature = "testing-fdr"))]
use crate::testing::specs::csp::{Event, Process};

#[cfg(all(test, feature = "testing-fdr"))]
impl Process {
	/// The verdict of an exploration of this process under `config`.
	pub(crate) fn verdict_under(&self, config: FdrConfig) -> FdrVerdict {
		let mut explorer = DefaultFdrExplorer::with_defaults(self, config);
		explorer.explore().expect("a test exploration completes")
	}

	/// The hidden run that an exploration of this process under `config`
	/// reports as its divergence witness.
	pub(crate) fn divergence_run_under(&self, config: FdrConfig) -> Option<Vec<Event>> {
		let witness = self.verdict_under(config).divergence_witness;
		witness.map(|(_seed, run)| run)
	}
}
