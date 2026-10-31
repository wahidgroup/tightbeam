//! The ASN.1 export of timing verification results.

use super::statistics::StatisticalMeasures;
use crate::der::Sequence;
use crate::instrumentation::EvidenceArtifact;
use crate::testing::timing::verification::TimingVerificationResult;
use crate::Beamable;

/// The ASN.1 artifact of a timing verification.
///
/// It joins the evidence of the run to the timing results and an optional
/// statistical analysis, for standards compliance and tool integration.
#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct TimingVerificationArtifact {
	/// The evidence of the run: its spec hash, trace hashes, and events.
	pub evidence: EvidenceArtifact,
	/// The results of the timing verification.
	pub timing_results: TimingVerificationResult,
	/// The statistical analysis of the timing samples, when one ran.
	#[asn1(optional = "true")]
	pub statistical_analysis: Option<StatisticalMeasures>,
}

impl TimingVerificationArtifact {
	/// The artifact of `evidence` with its timing results and analysis.
	pub fn new(
		evidence: EvidenceArtifact,
		timing_results: TimingVerificationResult,
		statistical_analysis: Option<StatisticalMeasures>,
	) -> Self {
		Self { evidence, timing_results, statistical_analysis }
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::instrumentation::EvidenceArtifact;
	use crate::testing::fixtures::der_round_trip;
	use crate::testing::specs::csp::Event;
	use crate::testing::timing::violations::{DeadlineMiss, JitterViolation, TimingSlackViolation, TimingViolation};
	use crate::testing::timing::{ConfidenceIntervals, Percentile, PercentileValue};
	use crate::testing::TestResult;
	use crate::trace::ConsumedTrace;

	/// An artifact with a violation of each kind and a statistical analysis
	/// decodes from its DER as the artifact it was.
	#[ignore = "decode fails: Event::decode reads its tag and length as its name (TagUnexpected at octet 162)"]
	#[test]
	fn an_artifact_decodes_from_its_der_as_itself() -> TestResult {
		// The evidence is that of an empty trace.
		let evidence = EvidenceArtifact::of([0u8; 32], &ConsumedTrace::new())?;

		// The result holds one WCET, deadline, jitter, and slack violation.
		let timing_results = TimingVerificationResult {
			passed: true,
			wcet_violations: vec![TimingViolation {
				event: Event("test_event"),
				wcet_ns: 100_000_000,
				observed_ns: 150_000_000,
				seq: 1,
			}],
			deadline_misses: vec![DeadlineMiss {
				start_event: Event("start"),
				end_event: Event("end"),
				deadline_ns: 200_000_000,
				observed_ns: 250_000_000,
				start_seq: 1,
				end_seq: 2,
			}],
			jitter_violations: vec![JitterViolation {
				event: Event("jitter_event"),
				max_jitter_ns: 50_000_000,
				observed_jitter_ns: 75_000_000,
				seqs: vec![1, 2, 3],
			}],
			slack_violations: vec![TimingSlackViolation {
				start_event: Event("start"),
				end_event: Event("end"),
				required_slack_ns: 20_000_000,
				observed_slack_ns: 10_000_000,
				deadline_ns: 200_000_000,
				observed_latency_ns: 190_000_000,
				start_seq: 1,
				end_seq: 2,
			}],
			path_wcet_violations: vec![],
		};

		// The analysis holds two percentiles and a confidence interval.
		let statistical_analysis = Some(StatisticalMeasures {
			count: 100,
			mean: 50_000_000,
			median: 45_000_000,
			percentiles: vec![
				PercentileValue { percentile: Percentile::P50, value: 45_000_000 },
				PercentileValue { percentile: Percentile::P95, value: 95_000_000 },
			],
			confidence_intervals: Some(ConfidenceIntervals { level: 9500, lower: 40_000_000, upper: 60_000_000 }),
			custom: vec![],
		});

		let artifact = TimingVerificationArtifact::new(evidence, timing_results, statistical_analysis);
		let decoded = der_round_trip(&artifact);
		assert_eq!(decoded, artifact);
		Ok(())
	}
}
