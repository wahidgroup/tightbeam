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

		Self {
			evidence,
			fmea_report: FmeaReportAsn1 { severity_scale, total_rpn: report.total_rpn, failure_modes },
		}
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
	#[test]
	#[ignore]
	fn test_fmea_artifact_asn1_round_trip() {
		// Stub: Future ASN.1 encode/decode test
	}
}
