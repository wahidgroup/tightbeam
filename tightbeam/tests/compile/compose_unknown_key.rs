use tightbeam::compose;
use tightbeam::der::Sequence;
use tightbeam::Beamable;

#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
#[beam(min_version = "V0")]
struct BasicMessage {
	content: String,
}

fn main() {
	let message = BasicMessage { content: "test".to_string() };

	// `bogus` is not a builder method known to compose!
	// This should fail to compile with an "unknown builder key" error
	let _ = compose! {
		V0:
			id: "test-id",
			order: 1696521600u64,
			message: message,
			bogus: 42
	};
}
