use tightbeam::Errorizable;

// Every variant of an Errorizable enum must carry its own message. Without
// one, Display would print the variant name and drop the payload.
#[derive(Errorizable, Debug)]
pub enum SilentError {
	#[error("a described failure: {0}")]
	Described(u8),
	Undescribed(u8),
}

fn main() {}
