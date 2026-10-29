use tightbeam::der::Sequence;
use tightbeam::Message;

// `Message::Profile` has no default, so a hand-written impl names it. This
// impl omits it, so it fails to compile.
#[derive(Clone, Debug, PartialEq, Sequence)]
struct HandWrittenMessage {
	content: String,
}

impl Message for HandWrittenMessage {}

fn main() {}
