//! The failures of the walk and of the graph.

use core::fmt;
use std::io;
use std::path::PathBuf;

use super::path::ItemPath;

/// A failure to read the sources, or to find the module that the graph covers.
pub(super) enum GraphError {
	/// A source file that a `mod` declaration loads is unreadable.
	Read { path: PathBuf, error: io::Error },
	/// A source file holds a token sequence that the walk has no rule for.
	Syntax { file: String, line: usize, what: &'static str },
	/// The sources hold no module at the path that the graph covers.
	MissingScope(ItemPath),
}

// The harness prints an `Err` through `Debug`, so `Debug` writes a sentence.
impl fmt::Debug for GraphError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Read { path, error } => write!(f, "{} is unreadable: {error}", path.display()),
			Self::Syntax { file, line, what } => write!(f, "{file}:{line} holds {what}"),
			Self::MissingScope(scope) => write!(f, "the sources hold no module `{scope}`"),
		}
	}
}
