//! The crate's sources, read from `lib.rs` down through each `mod`
//! declaration, whatever features the build enables.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::rc::Rc;

use super::error::GraphError;
use super::path::ItemPath;
use super::walk::FileWalk;

/// The syntax that writes a path at a site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Form {
	/// A leaf of a private `use` tree. A glob leaf ends in `*`.
	Use { glob: bool },
	/// A leaf of a `pub use` or a `pub(..) use` tree.
	Reexport { glob: bool },
	/// A path in code. A relative path starts at a plain name.
	Path { relative: bool },
}

impl Form {
	pub(super) fn is_glob(self) -> bool {
		matches!(self, Self::Use { glob: true } | Self::Reexport { glob: true })
	}

	pub(super) fn is_reexport(self) -> bool {
		matches!(self, Self::Reexport { .. })
	}

	pub(super) fn label(self) -> &'static str {
		match self {
			Self::Use { .. } => "use",
			Self::Reexport { .. } => "re-export",
			Self::Path { .. } => "path",
		}
	}
}

/// One path that a source file writes.
pub(super) struct Site {
	/// The module whose code holds the path.
	pub(super) module: Rc<ItemPath>,
	/// The segments as the file writes them.
	pub(super) written: ItemPath,
	/// The file, as an index for [`SourceTree::file_name`].
	pub(super) file: usize,
	/// The line of the leaf's last segment, or of the path's first segment.
	pub(super) line: usize,
	/// The syntax that writes the path.
	pub(super) form: Form,
	/// Whether `cfg(test)` covers the path or the file that holds it.
	pub(super) test: bool,
	/// Whether the path sits in a `macro_rules!` body, or follows a `$`.
	pub(super) in_macro: bool,
}

/// One identifier that a file writes outside a path and outside a `use` tree.
pub(super) struct NameUse {
	/// The module whose code holds the identifier.
	pub(super) module: Rc<ItemPath>,
	/// The line of the identifier.
	pub(super) line: usize,
	/// Whether the identifier sits in test code, as [`Site::test`] states it.
	pub(super) test: bool,
}

/// A `mod name;` declaration, which loads the file of a child module.
pub(super) struct Declaration {
	/// The path of the child module.
	pub(super) module: ItemPath,
	/// Whether the declaration is test code, so the child file is test code.
	pub(super) test: bool,
	/// The literal of a `#[path = ".."]` attribute on the declaration.
	pub(super) path_attribute: Option<String>,
}

impl Declaration {
	/// The files that can hold the child module, in the order of the search.
	fn candidates(&self, parent: &ModuleFile) -> Option<Vec<(PathBuf, Layout)>> {
		if let Some(path) = self.path_attribute.as_deref().filter(|path| !path.is_empty()) {
			return Some(vec![(parent.path.parent()?.join(path), Layout::Named)]);
		}

		let name = self.module.last()?;
		let directory = parent.child_directory()?;
		Some(vec![
			(directory.join(format!("{name}.rs")), Layout::Named),
			(directory.join(name).join("mod.rs"), Layout::Directory),
		])
	}
}

/// Where a module file keeps the files of its child modules.
#[derive(Clone, Copy)]
enum Layout {
	/// A `lib.rs` or a `mod.rs`, whose children sit beside it.
	Directory,
	/// A `name.rs`, whose children sit in `name/`.
	Named,
}

/// One module file that the walk reads.
struct ModuleFile {
	module: ItemPath,
	path: PathBuf,
	test: bool,
	layout: Layout,
}

impl ModuleFile {
	fn child_directory(&self) -> Option<PathBuf> {
		let directory = self.path.parent()?;
		match self.layout {
			Layout::Directory => Some(directory.to_path_buf()),
			Layout::Named => Some(directory.join(self.path.file_stem()?)),
		}
	}
}

/// The modules, names, and paths of the crate's sources.
#[derive(Default)]
pub(super) struct SourceTree {
	root: PathBuf,
	files: Vec<PathBuf>,
	/// Each module, mapped to whether it is inline in the file of its parent.
	modules: HashMap<ItemPath, bool>,
	items: HashMap<ItemPath, HashSet<String>>,
	bindings: HashMap<ItemPath, HashMap<String, Vec<ItemPath>>>,
	globs: HashMap<ItemPath, Vec<ItemPath>>,
	sites: Vec<Site>,
	names: HashMap<(usize, String), Vec<NameUse>>,
}

impl SourceTree {
	/// Reads the sources under `root` from `root/lib.rs` down.
	pub(super) fn load(root: PathBuf) -> Result<Self, GraphError> {
		let crate_root = ItemPath::crate_root();
		let lib = ModuleFile {
			module: crate_root.clone(),
			path: root.join("lib.rs"),
			test: false,
			layout: Layout::Directory,
		};

		let mut tree = Self { root, ..Self::default() };
		tree.modules.insert(crate_root, false);

		let mut pending = VecDeque::from([lib]);
		while let Some(file) = pending.pop_front() {
			let children = tree.read(&file)?;
			pending.extend(children);
		}

		Ok(tree)
	}

	/// Walks one file and returns the child module files it declares.
	fn read(&mut self, file: &ModuleFile) -> Result<Vec<ModuleFile>, GraphError> {
		let source =
			fs::read_to_string(&file.path).map_err(|error| GraphError::Read { path: file.path.clone(), error })?;

		let index = self.files.len();
		self.files.push(file.path.clone());

		let declarations = FileWalk::run(self, &source, index, file.module.clone(), file.test)?;
		Ok(declarations
			.into_iter()
			.filter_map(|declaration| self.locate(declaration, file))
			.collect())
	}

	/// The first candidate file of a declared child module that exists.
	fn locate(&mut self, declaration: Declaration, parent: &ModuleFile) -> Option<ModuleFile> {
		let candidates = declaration.candidates(parent)?;
		let (path, layout) = candidates.into_iter().find(|(path, _)| path.exists())?;
		self.modules.insert(declaration.module.clone(), false);
		Some(ModuleFile { module: declaration.module, path, test: declaration.test, layout })
	}

	pub(super) fn record_site(&mut self, site: Site) {
		self.sites.push(site);
	}

	pub(super) fn record_name(&mut self, file: usize, name: String, name_use: NameUse) {
		self.names.entry((file, name)).or_default().push(name_use);
	}

	/// Records an inline `mod name { .. }`.
	///
	/// A module that the tree holds keeps its record.
	pub(super) fn declare_inline(&mut self, module: ItemPath) {
		self.modules.entry(module).or_insert(true);
	}

	pub(super) fn define(&mut self, module: &ItemPath, name: &str) {
		self.items.entry(module.clone()).or_default().insert(name.to_owned());
	}

	pub(super) fn bind(&mut self, module: &ItemPath, name: &str, written: ItemPath) {
		self.bindings
			.entry(module.clone())
			.or_default()
			.entry(name.to_owned())
			.or_default()
			.push(written);
	}

	pub(super) fn bind_glob(&mut self, module: &ItemPath, written: ItemPath) {
		self.globs.entry(module.clone()).or_default().push(written);
	}

	pub(super) fn modules(&self) -> impl Iterator<Item = &ItemPath> {
		self.modules.keys()
	}

	pub(super) fn is_module(&self, path: &ItemPath) -> bool {
		self.modules.contains_key(path)
	}

	pub(super) fn is_inline(&self, path: &ItemPath) -> bool {
		self.modules.get(path).copied().unwrap_or(false)
	}

	/// Whether `module` defines an item, a macro, or a child module `name`.
	pub(super) fn defines(&self, module: &ItemPath, name: &str) -> bool {
		self.items.get(module).is_some_and(|names| names.contains(name))
	}

	/// The paths that `module` binds to `name` through `use`, in source order.
	pub(super) fn bindings(&self, module: &ItemPath, name: &str) -> &[ItemPath] {
		self.bindings
			.get(module)
			.and_then(|names| names.get(name))
			.map_or(&[], Vec::as_slice)
	}

	/// The paths of the glob `use` declarations of `module`, in source order.
	pub(super) fn globs(&self, module: &ItemPath) -> &[ItemPath] {
		self.globs.get(module).map_or(&[], Vec::as_slice)
	}

	pub(super) fn sites(&self) -> &[Site] {
		&self.sites
	}

	/// The uses of identifier `name` in `file`, in source order.
	pub(super) fn name_uses(&self, file: usize, name: &str) -> &[NameUse] {
		self.names.get(&(file, name.to_owned())).map_or(&[], Vec::as_slice)
	}

	/// The path of `file` under the source root, such as `transport/mod.rs`.
	pub(super) fn file_name(&self, file: usize) -> String {
		let path = self.files.get(file).map(|path| path.strip_prefix(&self.root).unwrap_or(path));
		path.map_or_else(String::new, |path| path.display().to_string())
	}
}
