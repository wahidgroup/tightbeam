//! ASN.1 export for FMEA reports

use crate::der::Sequence;
use crate::instrumentation::EvidenceArtifact;
use crate::testing::fmea::{FailureMode, FmeaReport, SeverityScale};
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
		let severity_scale = encode_severity_scale(report.severity_scale);
		let failure_modes = report.failure_modes.iter().map(encode_failure_mode).collect();

		Self {
			evidence,
			fmea_report: FmeaReportAsn1 { severity_scale, total_rpn: report.total_rpn, failure_modes },
		}
	}
}

fn encode_severity_scale(scale: SeverityScale) -> u8 {
	match scale {
		SeverityScale::MilStd1629 => 0,
		SeverityScale::Iso26262 => 1,
	}
}

fn encode_failure_mode(fm: &FailureMode) -> FailureModeAsn1 {
	let effects_str = fm.effects.join("; ");
	FailureModeAsn1 {
		component: fm.component.as_bytes().to_vec(),
		failure: fm.failure.as_bytes().to_vec(),
		effects: effects_str.as_bytes().to_vec(),
		severity: fm.severity,
		occurrence: fm.occurrence,
		detection: fm.detection,
		rpn: fm.rpn,
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
