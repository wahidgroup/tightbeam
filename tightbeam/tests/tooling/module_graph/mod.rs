//! Rust admits a cycle among the modules of one crate, so this test keeps the
//! production edges of `transport/` acyclic. A production edge is a path
//! outside test code, macro code, and re-exports.

// The helpers keep the zero-panic lints, so only the final assert can panic.
#![deny(
	clippy::indexing_slicing,
	clippy::arithmetic_side_effects,
	clippy::string_slice,
	clippy::unwrap_used,
	clippy::expect_used,
	clippy::panic,
	clippy::unreachable,
	clippy::todo,
	clippy::unimplemented
)]

mod error;
mod graph;
mod lexer;
mod path;
mod resolve;
mod source;
mod walk;

use std::path::Path;

use error::GraphError;
use graph::ModuleGraph;
use path::ItemPath;
use source::SourceTree;

/// The production edges among the submodules of `transport` stay acyclic.
#[test]
fn transport_production_edges_are_acyclic() -> Result<(), GraphError> {
	let tree = SourceTree::load(Path::new(env!("CARGO_MANIFEST_DIR")).join("src"))?;
	let graph = ModuleGraph::build(&tree, ItemPath::module(&["transport"]))?;
	let cycles = graph.production_cycles();
	assert!(cycles.is_empty(), "{cycles}");
	Ok(())
}
