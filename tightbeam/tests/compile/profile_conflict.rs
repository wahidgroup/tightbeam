use tightbeam::crypto::profiles::TightbeamProfile;
use tightbeam::der::Sequence;
use tightbeam::Beamable;

// Numeric and type-based profiles are mutually exclusive
// This should fail to compile with the derive's conflict diagnostic
#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
#[beam(profile = 1, profile(TightbeamProfile))]
struct ConflictedMessage {
	content: String,
}

fn main() {}
