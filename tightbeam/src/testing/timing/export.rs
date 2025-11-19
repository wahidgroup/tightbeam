//! ASN.1 export for timing verification results

use crate::der::Sequence;
use crate::instrumentation::EvidenceArtifact;
use crate::testing::timing::verification::TimingVerificationResult;
use crate::utils::statistics::StatisticalMeasures;
use crate::Beamable;

/// Timing verification artifact in ASN.1 format
///
/// Combines evidence artifact (trace, spec hash, etc.) with timing
/// verification results and optional statistical analysis for standards
/// compliance and tool integration.
#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct TimingVerificationArtifact {
	/// Base evidence artifact (trace, spec hash, etc.)
	pub evidence: EvidenceArtifact,
	/// Timing verification results
	pub timing_results: TimingVerificationResult,
	/// Statistical analysis results (if performed)
	#[asn1(optional = "true")]
	pub statistical_analysis: Option<StatisticalMeasures>,
}

impl TimingVerificationArtifact {
	/// Create a new timing verification artifact
	pub fn new(
		evidence: EvidenceArtifact,
		timing_results: TimingVerificationResult,
		statistical_analysis: Option<StatisticalMeasures>,
	) -> Self {
		Self { evidence, timing_results, statistical_analysis }
	}

	/// Export to Markdown (human-readable report) - stub for future implementation
	pub fn to_markdown(&self) -> String {
		// TODO: Generate Markdown report for documentation
		todo!("Markdown export not yet implemented")
	}

	/// Export to UPPAAL format (stub for future implementation)
	pub fn to_uppaal(&self) -> String {
		// TODO: Generate UPPAAL XML format
		todo!("UPPAAL export not yet implemented")
	}

	/// Export to TCTL (Timed Computation Tree Logic) format (stub for future implementation)
	pub fn to_tctl(&self) -> String {
		// TODO: Generate TCTL specification
		todo!("TCTL export not yet implemented")
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::der::asn1::OctetString;
	use crate::instrumentation::EvidenceArtifact;
	use crate::testing::specs::csp::Event;
	use crate::testing::timing::violations::{DeadlineMiss, JitterViolation, TimingSlackViolation, TimingViolation};
	use crate::utils::statistics::{ConfidenceIntervals, Percentile, PercentileValue};
	use crate::utils::{decode, encode};
	use crate::TightBeamError;

	#[ignore]
	#[test]
	fn test_timing_verification_artifact_asn1_round_trip() -> Result<(), TightBeamError> {
		// Create test evidence artifact
		let spec_hash = [0u8; 32];
		let evidence = EvidenceArtifact {
			spec_hash: OctetString::new(spec_hash)?,
			trace_hash: OctetString::new(spec_hash)?,
			evidence_hash: OctetString::new(spec_hash)?,
			events: vec![],
			overflow: false,
		};

		// Create test timing verification result
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

		// Create test statistical measures
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

		// Encode to DER
		let encoded = encode(&artifact)?;
		// Decode from DER
		let decoded: TimingVerificationArtifact = decode(&encoded)?;

		// Verify round-trip
		assert_eq!(artifact.evidence.spec_hash.as_bytes(), decoded.evidence.spec_hash.as_bytes());
		assert_eq!(artifact.timing_results.passed, decoded.timing_results.passed);
		assert_eq!(
			artifact.timing_results.wcet_violations.len(),
			decoded.timing_results.wcet_violations.len()
		);
		assert_eq!(
			artifact.timing_results.deadline_misses.len(),
			decoded.timing_results.deadline_misses.len()
		);
		assert_eq!(
			artifact.timing_results.jitter_violations.len(),
			decoded.timing_results.jitter_violations.len()
		);
		assert_eq!(
			artifact.timing_results.slack_violations.len(),
			decoded.timing_results.slack_violations.len()
		);
		assert!(decoded.statistical_analysis.is_some());
		let decoded_stats = decoded.statistical_analysis.unwrap();
		assert_eq!(decoded_stats.count, 100);
		assert_eq!(decoded_stats.mean, 50_000_000);
		assert_eq!(decoded_stats.percentiles.len(), 2);

		Ok(())
	}
}
