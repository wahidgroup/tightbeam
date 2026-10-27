//! The segments of a path, as a file writes it or as the resolver anchors it.

use core::fmt;

/// A path of segments, such as `crate::transport::io` or `super::Frame`.
///
/// A segment keeps its `r#` prefix until [`ItemPath::normal`] strips it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) struct ItemPath(Vec<String>);

impl ItemPath {
	/// The path of the crate root module.
	pub(super) fn crate_root() -> Self {
		Self(vec!["crate".to_owned()])
	}

	/// The path of a module below the crate root, one name per segment.
	pub(super) fn module(names: &[&str]) -> Self {
		Self::crate_root().join(&names.iter().map(|name| (*name).to_owned()).collect::<Vec<_>>())
	}

	pub(super) fn from_segments(segments: Vec<String>) -> Self {
		Self(segments)
	}

	pub(super) fn segments(&self) -> &[String] {
		&self.0
	}

	pub(super) fn len(&self) -> usize {
		self.0.len()
	}

	pub(super) fn get(&self, index: usize) -> Option<&str> {
		self.0.get(index).map(String::as_str)
	}

	pub(super) fn last(&self) -> Option<&str> {
		self.0.last().map(String::as_str)
	}

	/// The segments from `index` on, empty past the end.
	pub(super) fn tail(&self, index: usize) -> &[String] {
		self.0.get(index..).unwrap_or_default()
	}

	/// The first `length` segments, or the whole path when it is shorter.
	pub(super) fn prefix(&self, length: usize) -> Self {
		Self(self.0.iter().take(length).cloned().collect())
	}

	/// The path without its last segment. The empty path stays empty.
	pub(super) fn parent(&self) -> Self {
		self.prefix(self.len().saturating_sub(1))
	}

	pub(super) fn child(&self, name: &str) -> Self {
		self.join(&[name.to_owned()])
	}

	pub(super) fn join(&self, tail: &[String]) -> Self {
		Self(self.0.iter().chain(tail).cloned().collect())
	}

	pub(super) fn starts_with(&self, prefix: &Self) -> bool {
		self.0.starts_with(&prefix.0)
	}

	/// The path in the form of a module key.
	///
	/// The form strips `r#` from each segment past the first.
	pub(super) fn normal(&self) -> Self {
		let first = self.0.iter().take(1).cloned();
		let rest = self.0.iter().skip(1).map(|segment| strip_raw(segment).to_owned());
		Self(first.chain(rest).collect())
	}
}

impl fmt::Display for ItemPath {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.0.join("::"))
	}
}

/// The name a raw identifier such as `r#async` declares.
pub(super) fn strip_raw(name: &str) -> &str {
	name.strip_prefix("r#").unwrap_or(name)
}
