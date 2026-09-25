use tightbeam::Errorizable;

// A variant that carries data must render it. A message with no placeholder
// drops the values the caller needed.
#[derive(Errorizable, Debug)]
pub enum LossyError {
	#[error("the lengths disagree")]
	LengthMismatch { expected: usize, received: usize },
}

fn main() {}
