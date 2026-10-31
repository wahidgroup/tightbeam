//! ASN.1 export for FMEA reports

use crate::der::Sequence;
use crate::instrumentation::EvidenceArtifact;
use crate::testing::fmea::{FailureMode, FmeaReport};
use crate::Beamable;

/// FMEA artifact in ASN.1 format
#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct FmeaArtifact {
	pub evidence: EvidenceArtifact,
	pub fmea_report: FmeaReportAsn1,
}

/// FMEA report in ASN.1 format
#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct FmeaReportAsn1 {
	pub severity_scale: u8,
	pub total_rpn: u32,
	pub failure_modes: Vec<FailureModeAsn1>,
}

/// Individual failure mode in ASN.1 format
#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct FailureModeAsn1 {
	pub component: Vec<u8>,
	pub failure: Vec<u8>,
	pub effects: Vec<u8>,
	pub severity: u8,
	pub occurrence: u16,
	pub detection: u8,
	pub rpn: u32,
}

impl FmeaArtifact {
	/// Create FMEA artifact from evidence and report
	pub fn new(evidence: EvidenceArtifact, report: FmeaReport) -> Self {
		let severity_scale = report.severity_scale.wire_code();
		let failure_modes = report.failure_modes.iter().map(FailureMode::to_asn1).collect();
		let fmea_report = FmeaReportAsn1 { severity_scale, total_rpn: report.total_rpn, failure_modes };

		Self { evidence, fmea_report }
	}
}

impl FailureMode {
	/// Wire form of this failure mode, effects joined into one field.
	fn to_asn1(&self) -> FailureModeAsn1 {
		let effects = self.effects.join("; ");

		FailureModeAsn1 {
			component: self.component.as_bytes().to_vec(),
			failure: self.failure.as_bytes().to_vec(),
			effects: effects.as_bytes().to_vec(),
			severity: self.severity,
			occurrence: self.occurrence,
			detection: self.detection,
			rpn: self.rpn,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::fixtures::der_round_trip;
	use crate::testing::fmea::SeverityScale;
	use crate::testing::TestResult;
	use crate::trace::ConsumedTrace;
	use crate::urn::Urn;

	const STEP: Urn<'static> = crate::urn!("test", "event:fmea-export/step");

	/// An artifact decodes from its DER to the artifact that encoded it, with
	/// the evidence of a recorded trace and a report of two failure modes.
	#[test]
	fn an_fmea_artifact_decodes_to_the_artifact_it_encodes() -> TestResult {
		let evidence = EvidenceArtifact::of([7u8; 32], &ConsumedTrace::recording([STEP]))?;
		let effects = ["Can reach terminal state(s): Done".to_string()];
		let modes = [
			FailureMode::new("Link.Ready", "send", effects, 8, 50, 6),
			FailureMode::new("Link.Sent", "ack", Vec::new(), 4, 2, 3),
		];

		let artifact = FmeaArtifact::new(evidence, FmeaReport::new(modes, SeverityScale::Iso26262, 100));
		let decoded = der_round_trip(&artifact);
		assert_eq!(decoded, artifact);
		Ok(())
	}
}
