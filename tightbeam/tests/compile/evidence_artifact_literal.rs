use tightbeam::instrumentation::EvidenceArtifact;
use tightbeam::trace::ConsumedTrace;

fn main() -> Result<(), tightbeam::TightBeamError> {
	// `EvidenceArtifact::of` is the one constructor, so the hashes of an
	// artifact cover its events and its overflow reads its trace. A struct
	// literal would set a field past it, so it may not compile.
	let artifact = EvidenceArtifact::of([0u8; 32], &ConsumedTrace::new())?;
	let _updated = EvidenceArtifact { overflow: false, ..artifact };
	Ok(())
}
