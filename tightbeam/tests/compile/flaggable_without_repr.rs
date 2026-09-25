use tightbeam::Flaggable;

// `as u8` truncates a discriminant above 255 in silence. `repr(u8)` makes the
// compiler reject one where it is written, so the derive requires it.
#[derive(Flaggable, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Unbounded {
	#[default]
	First,
	Second,
}

fn main() {}
