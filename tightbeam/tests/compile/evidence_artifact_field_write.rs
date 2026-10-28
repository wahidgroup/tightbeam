use tightbeam::instrumentation::EvidenceArtifact;
use tightbeam::trace::ConsumedTrace;

fn main() -> Result<(), tightbeam::TightBeamError> {
	// `EvidenceArtifact::of` is the one constructor, so the hashes of an
	// artifact cover its events and its overflow reads its trace. A field
	// write would change a field past it, so it may not compile.
	let mut artifact = EvidenceArtifact::of([0u8; 32], &ConsumedTrace::new())?;
	artifact.overflow = false;
	Ok(())
}
