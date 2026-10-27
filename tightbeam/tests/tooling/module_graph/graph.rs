//! The edges between the direct submodules of a scope module, and the cycles
//! among its production edges.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use super::error::GraphError;
use super::path::{strip_raw, ItemPath};
use super::resolve::{Resolved, Resolver};
use super::source::{Form, Site, SourceTree};

/// The scope module, or one direct submodule with each module below it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Node {
	Root,
	Child(String),
}

impl fmt::Display for Node {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Root => f.write_str("(root)"),
			Self::Child(name) => f.write_str(name),
		}
	}
}

/// The class of an edge. The graph keeps the production edges alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EdgeClass {
	Production,
	Macro,
	Reexport,
	Test,
}

/// How an edge reaches its target from its site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reach {
	/// The path at the site names the item.
	Site,
	/// The module of a re-export uses the name itself, first at `line`.
	///
	/// The edge is test code when each use is test code.
	ReexportUse { line: usize, test: bool },
}

/// A site in `source` whose path names an item of `target`.
#[derive(Clone)]
struct Edge<'t> {
	site: &'t Site,
	source: Node,
	target: Node,
	item: Option<String>,
	reach: Reach,
}

impl Edge<'_> {
	fn line(&self) -> usize {
		match self.reach {
			Reach::Site => self.site.line,
			Reach::ReexportUse { line, .. } => line,
		}
	}

	/// The file under the source root and the line of the edge.
	fn location(&self, tree: &SourceTree) -> (String, usize) {
		(tree.file_name(self.site.file), self.line())
	}

	fn class(&self) -> EdgeClass {
		let (test, reexport) = match self.reach {
			Reach::Site => (self.site.test, self.site.form.is_reexport()),
			Reach::ReexportUse { test, .. } => (test, false),
		};
		if test {
			EdgeClass::Test
		} else if reexport {
			EdgeClass::Reexport
		} else if self.site.in_macro {
			EdgeClass::Macro
		} else {
			EdgeClass::Production
		}
	}

	fn syntax(&self) -> &'static str {
		match self.reach {
			Reach::Site => self.site.form.label(),
			Reach::ReexportUse { .. } => "use of a re-export",
		}
	}
}

/// The scope module, which maps each module to a node and each site to an edge.
struct Scope<'t> {
	tree: &'t SourceTree,
	resolver: Resolver<'t>,
	root: ItemPath,
}

impl<'t> Scope<'t> {
	/// The node that holds `module`.
	///
	/// An inline module belongs to the node of the file that holds it.
	fn node_of(&self, module: &ItemPath) -> Option<Node> {
		if !module.starts_with(&self.root) {
			return None;
		}

		let mut file_module = module.clone();
		while file_module.len() > self.root.len() && self.tree.is_inline(&file_module) {
			file_module = file_module.parent();
		}

		let child = file_module.get(self.root.len());
		let node = child.filter(|name| !self.tree.is_inline(&self.root.child(name)));
		Some(node.map_or(Node::Root, |name| Node::Child(name.to_owned())))
	}

	/// The edge of a site whose path names an item of another node.
	fn edge(&self, site: &'t Site) -> Option<Edge<'t>> {
		let source = self.node_of(&site.module)?;
		let target = self.target_of(site)?;

		let Resolved { owner, item } = self.owner_of(site, &target);
		let target = self.node_of(&owner)?;

		(source != target).then_some(Edge { site, source, target, item, reach: Reach::Site })
	}

	/// The path from the crate root that the site names.
	///
	/// A relative code path counts when it names a module or starts at a child.
	fn target_of(&self, site: &Site) -> Option<ItemPath> {
		let target = self.resolver.absolutize(&site.module, &site.written)?;
		let names_module = |path: &ItemPath| self.tree.is_module(&path.normal());
		match site.form {
			Form::Path { relative: true } => {
				let child = target.prefix(site.module.len().saturating_add(1));
				(names_module(&target) || names_module(&child)).then_some(target)
			}
			Form::Path { relative: false } | Form::Use { .. } | Form::Reexport { .. } => Some(target),
		}
	}

	/// The module that owns the target. A glob owns the module it opens.
	fn owner_of(&self, site: &Site, target: &ItemPath) -> Resolved {
		let module = target.normal();
		if site.form.is_glob() && self.tree.is_module(&module) {
			return Resolved { owner: module, item: Some("*".to_owned()) };
		}

		self.resolver.resolve(target)
	}

	/// The edge from a named re-export whose own module uses the name.
	fn reexport_use(&self, edge: &Edge<'t>) -> Option<Edge<'t>> {
		let named = edge.site.form == Form::Reexport { glob: false };
		let name = edge.site.written.last().filter(|_| named)?;
		let uses: Vec<_> = self
			.tree
			.name_uses(edge.site.file, strip_raw(name))
			.iter()
			.filter(|name_use| self.node_of(&name_use.module).as_ref() == Some(&edge.source))
			.collect();

		let line = uses.first()?.line;
		let test = uses.iter().all(|name_use| name_use.test);
		Some(Edge { reach: Reach::ReexportUse { line, test }, ..edge.clone() })
	}
}

/// The production edges as an adjacency map.
struct Adjacency<'g>(BTreeMap<&'g Node, BTreeSet<&'g Node>>);

impl<'g> Adjacency<'g> {
	/// The nodes that `from` reaches through one edge or more.
	fn reachable(&self, from: &'g Node) -> BTreeSet<&'g Node> {
		let mut seen = BTreeSet::new();
		let mut stack = vec![from];
		while let Some(node) = stack.pop() {
			for &target in self.0.get(node).into_iter().flatten() {
				if seen.insert(target) {
					stack.push(target);
				}
			}
		}

		seen
	}

	/// The strongly connected components of more than one node.
	fn cycles(&self, nodes: &BTreeSet<&'g Node>) -> Vec<BTreeSet<&'g Node>> {
		let reach: BTreeMap<&Node, BTreeSet<&Node>> = nodes.iter().map(|&node| (node, self.reachable(node))).collect();
		let reaches = |from: &Node, to: &Node| reach.get(from).is_some_and(|targets| targets.contains(to));
		let component = |&node: &&'g Node| -> BTreeSet<&'g Node> {
			let mutual = nodes
				.iter()
				.copied()
				.filter(|&other| reaches(node, other) && reaches(other, node));
			mutual.chain([node]).collect()
		};

		let components: BTreeSet<BTreeSet<&Node>> = nodes.iter().map(component).collect();
		components.into_iter().filter(|component| component.len() > 1).collect()
	}
}

/// The edges between the direct submodules of one scope module.
pub(super) struct ModuleGraph<'t> {
	tree: &'t SourceTree,
	root: ItemPath,
	edges: Vec<Edge<'t>>,
}

impl<'t> ModuleGraph<'t> {
	/// The graph of the submodules of `root`.
	pub(super) fn build(tree: &'t SourceTree, root: ItemPath) -> Result<Self, GraphError> {
		if !tree.is_module(&root) {
			return Err(GraphError::MissingScope(root));
		}

		let scope = Scope { tree, resolver: Resolver::new(tree), root };
		let direct: Vec<Edge<'t>> = tree.sites().iter().filter_map(|site| scope.edge(site)).collect();
		let reexport_uses: Vec<Edge<'t>> = direct.iter().filter_map(|edge| scope.reexport_use(edge)).collect();
		let edges = direct.into_iter().chain(reexport_uses).collect();
		Ok(Self { tree, root: scope.root, edges })
	}

	/// The cycles among the production edges.
	pub(super) fn production_cycles(&self) -> Cycles<'_, 't> {
		let production = self.edges.iter().filter(|edge| edge.class() == EdgeClass::Production);
		let mut adjacency: BTreeMap<&Node, BTreeSet<&Node>> = BTreeMap::new();
		for edge in production {
			adjacency.entry(&edge.source).or_default().insert(&edge.target);
		}

		let nodes: BTreeSet<&Node> = self.edges.iter().flat_map(|edge| [&edge.source, &edge.target]).collect();
		let components = Adjacency(adjacency).cycles(&nodes);
		Cycles { graph: self, components }
	}
}

/// The production cycles of a graph, which print with their closing edges.
pub(super) struct Cycles<'g, 't> {
	graph: &'g ModuleGraph<'t>,
	components: Vec<BTreeSet<&'g Node>>,
}

impl Cycles<'_, '_> {
	pub(super) fn is_empty(&self) -> bool {
		self.components.is_empty()
	}
}

impl fmt::Display for Cycles<'_, '_> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let graph = self.graph;

		write!(f, "the production edges among the submodules of `{}` hold a cycle ", graph.root)?;
		writeln!(f, "in each component below, with the edges that close it:")?;

		for component in &self.components {
			let names: Vec<String> = component.iter().map(|node| format!("`{node}`")).collect();
			writeln!(f, "\n- {}", names.join(", "))?;

			let closes = |edge: &&Edge<'_>| {
				edge.class() == EdgeClass::Production
					&& component.contains(&edge.source)
					&& component.contains(&edge.target)
			};

			let mut edges: Vec<&Edge<'_>> = graph.edges.iter().filter(closes).collect();
			edges.sort_by_cached_key(|edge| (edge.source.clone(), edge.target.clone(), edge.location(graph.tree)));
			for edge in edges {
				let (source, target) = (&edge.source, &edge.target);
				let (file, line) = edge.location(graph.tree);
				let item = edge.item.as_deref().unwrap_or("the module");
				let (syntax, written) = (edge.syntax(), &edge.site.written);
				writeln!(
					f,
					"  - `{source}` uses `{target}`: `{item}` through the {syntax} `{written}` at {file}:{line}"
				)?;
			}
		}

		Ok(())
	}
}
