//! The module that defines the item a path names. The resolver anchors the
//! path at the crate root, then follows each `use` and glob to the definition.

use std::collections::{HashMap, HashSet};

use super::path::{strip_raw, ItemPath};
use super::source::SourceTree;

/// The depth at which a chain of `use` bindings ends its search.
const BINDING_DEPTH: usize = 4;

/// The depth past which a chain of re-exports ends at the module it reaches.
const REEXPORT_DEPTH: usize = 8;

/// The module that owns a resolved path, with the item it names there.
pub(super) struct Resolved {
	/// The module that defines the item, or the last module the walk reaches.
	pub(super) owner: ItemPath,
	/// The name of the item, or `None` when the path names the module itself.
	pub(super) item: Option<String>,
}

/// The resolver of the paths of one source tree.
pub(super) struct Resolver<'t> {
	tree: &'t SourceTree,
	children: HashMap<ItemPath, HashSet<String>>,
}

impl<'t> Resolver<'t> {
	pub(super) fn new(tree: &'t SourceTree) -> Self {
		let mut children: HashMap<ItemPath, HashSet<String>> = HashMap::new();
		for module in tree.modules() {
			if let Some(name) = module.last().filter(|_| module.len() > 1) {
				children.entry(module.parent()).or_default().insert(strip_raw(name).to_owned());
			}
		}

		Self { tree, children }
	}

	fn has_child(&self, module: &ItemPath, name: &str) -> bool {
		self.children.get(module).is_some_and(|names| names.contains(strip_raw(name)))
	}

	/// The path from the crate root that `written` in `module` names.
	pub(super) fn absolutize(&self, module: &ItemPath, written: &ItemPath) -> Option<ItemPath> {
		self.absolutize_at(module, written, 0)
	}

	fn absolutize_at(&self, module: &ItemPath, written: &ItemPath, depth: usize) -> Option<ItemPath> {
		let first = written.segments().first()?;
		match first.as_str() {
			"crate" | "$crate" => return Some(ItemPath::crate_root().join(written.tail(1))),
			"super" | "self" => return Some(Self::anchored(module, written)),
			_ => {}
		}

		if self.has_child(module, first) {
			return Some(module.join(written.segments()));
		}

		if depth >= BINDING_DEPTH {
			return None;
		}

		let next = depth.saturating_add(1);
		let bound = self
			.tree
			.bindings(module, strip_raw(first))
			.iter()
			.filter_map(|binding| self.absolutize_at(module, binding, next))
			.find(|target| self.tree.is_module(&target.normal()))
			.map(|target| target.join(written.tail(1)));
		bound.or_else(|| {
			self.tree
				.globs(module)
				.iter()
				.filter_map(|glob| self.absolutize_at(module, glob, next))
				.find(|opened| self.has_child(&opened.normal(), first))
				.map(|opened| opened.join(written.segments()))
		})
	}

	/// A `super::` or `self::` path from `module`, one module up per `super`.
	fn anchored(module: &ItemPath, written: &ItemPath) -> ItemPath {
		let segments = written.segments();
		let lead = segments
			.iter()
			.take_while(|segment| matches!(segment.as_str(), "super" | "self"))
			.count();

		let ups = segments.iter().take(lead).filter(|segment| segment.as_str() == "super").count();
		let base = (0..ups).fold(module.clone(), |base, _| base.parent());
		base.join(written.tail(lead))
	}

	/// The owner of the item that the path from the crate root names.
	pub(super) fn resolve(&self, path: &ItemPath) -> Resolved {
		self.resolve_at(path, 0)
	}

	fn resolve_at(&self, path: &ItemPath, depth: usize) -> Resolved {
		let path = path.normal();
		let mut owner = ItemPath::crate_root();
		for (index, segment) in path.segments().iter().enumerate().skip(1) {
			let child = owner.child(segment);
			if !self.tree.is_module(&child) {
				return self.resolve_item(owner, segment, path.tail(index.saturating_add(1)), depth);
			}

			owner = child;
		}

		Resolved { owner, item: None }
	}

	/// The owner of `name` in `owner`, with `rest` the segments after it.
	fn resolve_item(&self, owner: ItemPath, name: &str, rest: &[String], depth: usize) -> Resolved {
		if self.tree.defines(&owner, name) || depth > REEXPORT_DEPTH {
			return Resolved { owner, item: Some(name.to_owned()) };
		}

		let next = depth.saturating_add(1);
		let bound = self
			.tree
			.bindings(&owner, name)
			.iter()
			.find_map(|binding| self.absolutize(&owner, binding));
		if let Some(target) = bound {
			return self.resolve_at(&target.join(rest), next);
		}

		let through_glob = self
			.tree
			.globs(&owner)
			.iter()
			.filter_map(|glob| self.absolutize(&owner, glob))
			.map(|opened| self.resolve_at(&opened.child(name), next))
			.find(|resolved| {
				resolved
					.item
					.as_deref()
					.is_some_and(|item| self.tree.defines(&resolved.owner, item))
			});
		through_glob.unwrap_or_else(|| Resolved { owner, item: Some(name.to_owned()) })
	}
}
