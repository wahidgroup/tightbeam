//! The walk of one source file. It keeps one frame per open brace, and reads
//! an item header at the item's first `{` or `;`.

use std::rc::Rc;

use super::error::GraphError;
use super::lexer::{Token, TokenKind, Tokens};
use super::path::{strip_raw, ItemPath};
use super::source::{Declaration, Form, NameUse, Site, SourceTree};

/// The words that start no path of their own in code.
const KEYWORDS: &[&str] = &[
	"as",
	"async",
	"await",
	"break",
	"const",
	"continue",
	"crate",
	"dyn",
	"else",
	"enum",
	"extern",
	"false",
	"fn",
	"for",
	"if",
	"impl",
	"in",
	"let",
	"loop",
	"match",
	"mod",
	"move",
	"mut",
	"pub",
	"ref",
	"return",
	"self",
	"Self",
	"static",
	"struct",
	"super",
	"trait",
	"true",
	"type",
	"unsafe",
	"use",
	"where",
	"while",
	"union",
	"macro_rules",
];

/// The keywords that start an item with a name.
const ITEM_KEYWORDS: &[&str] = &["struct", "enum", "union", "trait", "fn", "type", "const", "static", "mod"];

/// The tokens after a `}` that continue the statement of its block.
const CONTINUE_AFTER_BLOCK: &[&str] = &[
	";", ",", ".", "?", ")", "]", "}", "else", "as", "=>", "=", "+", "-", "*", "/", "&", "|", "<", ">", "!",
];

/// The level of a frame, which decides whether its names bind.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Level {
	/// The body of a file or of an inline `mod`.
	Module,
	/// Any other block: a function, an item body, or an expression.
	Code,
}

/// The state of one open block.
struct Frame {
	module: Rc<ItemPath>,
	test: bool,
	in_macro: bool,
	level: Level,
	/// The depth of open parentheses and brackets in the frame.
	depth: isize,
	/// The token indices of the statement that the frame reads.
	statement: Vec<usize>,
	/// Whether an outer `#[cfg(test)]` covers the statement.
	statement_test: bool,
	path_attribute: Option<String>,
	/// Whether the walk has read the header of the statement's item.
	classified: bool,
}

impl Frame {
	fn new(module: Rc<ItemPath>, test: bool, in_macro: bool, level: Level) -> Self {
		Self {
			module,
			test,
			in_macro,
			level,
			depth: 0,
			statement: Vec::new(),
			statement_test: false,
			path_attribute: None,
			classified: false,
		}
	}

	fn site_test(&self) -> bool {
		self.test || self.statement_test
	}

	/// Whether the items and the `use` leaves of the frame bind names.
	fn binds_names(&self) -> bool {
		self.level == Level::Module && !self.in_macro
	}

	fn define(&self, header: &ItemHeader, tree: &mut SourceTree) {
		if let Some(name) = header.defined_name().filter(|_| self.binds_names()) {
			tree.define(&self.module, name);
		}
	}

	fn end_statement(&mut self) {
		self.statement.clear();
		self.statement_test = false;
		self.path_attribute = None;
		self.classified = false;
	}
}

/// The open frames of a file. The file's own frame stays at the bottom.
struct Frames {
	root: Frame,
	nested: Vec<Frame>,
}

impl Frames {
	fn top(&self) -> &Frame {
		self.nested.last().unwrap_or(&self.root)
	}

	fn top_mut(&mut self) -> &mut Frame {
		self.nested.last_mut().unwrap_or(&mut self.root)
	}

	fn push(&mut self, frame: Frame) {
		self.nested.push(frame);
	}

	fn pop(&mut self) -> Option<Frame> {
		self.nested.pop()
	}
}

/// The header of an item, as the first tokens of its statement state it.
enum ItemHeader {
	Impl,
	Macro(String),
	Module(String),
	Named(String),
}

impl ItemHeader {
	fn defined_name(&self) -> Option<&str> {
		match self {
			Self::Impl => None,
			Self::Macro(name) | Self::Module(name) | Self::Named(name) => Some(name),
		}
	}
}

/// The tokens of one statement.
struct Statement<'s> {
	tokens: &'s Tokens,
	indices: &'s [usize],
}

impl<'s> Statement<'s> {
	fn text(&self, index: usize) -> &'s str {
		self.indices.get(index).map_or("", |&at| self.tokens.text(at))
	}

	fn kind(&self, index: usize) -> Option<TokenKind> {
		self.indices.get(index).and_then(|&at| self.tokens.kind(at))
	}

	fn len(&self) -> usize {
		self.indices.len()
	}

	/// The index past a leading `pub` or `pub(..)`, or 0.
	fn visibility_end(&self) -> usize {
		if self.text(0) != "pub" {
			return 0;
		}

		if self.text(1) != "(" {
			return 1;
		}

		(2..self.len())
			.find(|&index| self.text(index) == ")")
			.map_or(self.len(), |index| index.saturating_add(1))
	}

	/// Whether the statement is empty or only a visibility.
	fn is_visibility(&self) -> bool {
		self.visibility_end() == self.len()
	}

	fn skips_before_item(&self, index: usize) -> bool {
		matches!(self.text(index), "unsafe" | "async" | "default" | "extern")
			|| self.kind(index) == Some(TokenKind::Str)
	}

	fn skips_after_const(&self, index: usize) -> bool {
		matches!(self.text(index), "unsafe" | "async" | "extern") || self.kind(index) == Some(TokenKind::Str)
	}

	fn classify(&self) -> Option<ItemHeader> {
		let mut index = self.visibility_end();
		while index < self.len() && self.skips_before_item(index) {
			index = index.saturating_add(1);
		}

		if index >= self.len() {
			return None;
		}

		if self.text(index) == "const" && matches!(self.text(index.saturating_add(1)), "fn" | "unsafe" | "async") {
			index = index.saturating_add(1);
			while self.skips_after_const(index) {
				index = index.saturating_add(1);
			}
		}

		let keyword = self.text(index);
		let name = index.saturating_add(1);
		let named = self.kind(name) == Some(TokenKind::Ident);
		match keyword {
			"impl" => Some(ItemHeader::Impl),
			"macro_rules" => {
				let bang_name = index.saturating_add(2);
				(bang_name < self.len()).then(|| ItemHeader::Macro(self.text(bang_name).to_owned()))
			}
			"mod" if named => Some(ItemHeader::Module(strip_raw(self.text(name)).to_owned())),
			_ if named && ITEM_KEYWORDS.contains(&keyword) => {
				Some(ItemHeader::Named(strip_raw(self.text(name)).to_owned()))
			}
			_ => None,
		}
	}
}

/// The reader of a `cfg(..)` predicate.
struct CfgPredicate<'t> {
	tokens: &'t [Token],
	pos: usize,
}

impl<'t> CfgPredicate<'t> {
	/// Whether the predicate inside `cfg(..)` holds only under `test`.
	///
	/// An `all` needs one such part, and an `any` needs each part. Other
	/// forms and a cut predicate hold outside `test`.
	fn holds_only_under_test(tokens: &'t [Token]) -> bool {
		Self { tokens, pos: 0 }.predicate().unwrap_or(false)
	}

	fn is(&self, index: usize, text: &str) -> bool {
		self.tokens.get(index).is_some_and(|token| token.is(text))
	}

	fn advance(&mut self, by: usize) {
		self.pos = self.pos.saturating_add(by);
	}

	fn predicate(&mut self) -> Option<bool> {
		let tokens = self.tokens;
		let head = tokens.get(self.pos)?.text.as_str();

		self.advance(1);

		if matches!(head, "all" | "any" | "not") && self.is(self.pos, "(") {
			self.advance(1);

			let mut parts = Vec::new();
			while !tokens.get(self.pos)?.is(")") {
				parts.push(self.predicate()?);
				if self.is(self.pos, ",") {
					self.advance(1);
				}
			}

			self.advance(1);
			return Some(match head {
				"all" => parts.contains(&true),
				"any" => !parts.is_empty() && !parts.contains(&false),
				_ => false,
			});
		}

		if self.is(self.pos, "=") {
			self.advance(2);
			return Some(false);
		}

		Some(head == "test")
	}
}

/// One leaf of a `use` tree.
struct Leaf {
	segments: ItemPath,
	alias: Option<String>,
	glob: bool,
	line: usize,
}

impl Leaf {
	/// Binds the leaf in `module`, as a glob or under its alias or last name.
	fn bind(self, module: &ItemPath, tree: &mut SourceTree) {
		if self.glob {
			tree.bind_glob(module, self.segments);
		} else if let Some(name) = self.alias.as_deref().or_else(|| self.segments.last()).map(str::to_owned) {
			tree.bind(module, strip_raw(&name), self.segments);
		}
	}
}

/// The reader of one `use` tree, from the token after `use` to its `;`.
struct UseTree<'t> {
	tokens: &'t Tokens,
	pos: usize,
	leaves: Vec<Leaf>,
}

impl<'t> UseTree<'t> {
	/// The leaves of the tree at `start`, with the index past its `;`.
	fn read(tokens: &'t Tokens, start: usize) -> Option<(Vec<Leaf>, usize)> {
		let mut tree = Self { tokens, pos: start, leaves: Vec::new() };
		tree.subtree(&[])?;
		let semicolon = (tree.pos..tokens.len()).find(|&index| tokens.is(index, ";"))?;
		Some((tree.leaves, semicolon.saturating_add(1)))
	}

	fn advance(&mut self, by: usize) {
		self.pos = self.pos.saturating_add(by);
	}

	fn subtree(&mut self, prefix: &[String]) -> Option<()> {
		let tokens = self.tokens;
		let mut segments = prefix.to_vec();
		loop {
			let token = tokens.get(self.pos)?;
			if token.is("$") && tokens.is(self.pos.saturating_add(1), "crate") {
				segments.push("$crate".to_owned());
				self.advance(2);
			} else if token.is("::") && segments.is_empty() {
				self.advance(1);
				continue;
			} else if token.kind == TokenKind::Ident {
				segments.push(token.text.clone());
				self.advance(1);
			} else if token.is("*") {
				let segments = ItemPath::from_segments(segments);
				self.leaves.push(Leaf { segments, alias: None, glob: true, line: token.line });
				self.advance(1);
				return Some(());
			} else if token.is("{") {
				self.advance(1);
				return self.group(&segments);
			} else {
				return None;
			}

			if tokens.is(self.pos, "::") {
				self.advance(1);
				continue;
			}

			self.leaf(segments, token.line);
			return Some(());
		}
	}

	/// A leaf that ends in a name, with its `as` alias.
	///
	/// A trailing `self` names the module before it.
	fn leaf(&mut self, mut segments: Vec<String>, line: usize) {
		let tokens = self.tokens;
		let mut alias = None;
		if tokens.is(self.pos, "as") {
			alias = Some(tokens.text(self.pos.saturating_add(1)).to_owned());
			self.advance(2);
		}

		if segments.last().is_some_and(|segment| segment == "self") {
			segments.pop();
			alias = alias.or_else(|| segments.last().cloned());
		}

		let leaf = Leaf { segments: ItemPath::from_segments(segments), alias, glob: false, line };
		self.leaves.push(leaf);
	}

	fn group(&mut self, prefix: &[String]) -> Option<()> {
		while !self.tokens.is(self.pos, "}") {
			self.subtree(prefix)?;
			if self.tokens.is(self.pos, ",") {
				self.advance(1);
			}
		}

		self.advance(1);
		Some(())
	}
}

/// The first segment of a code path at `token`, after `previous`.
fn path_head(token: &Token, previous: &str) -> Option<String> {
	match token.text.as_str() {
		"crate" if previous == "$" => Some("$crate".to_owned()),
		"crate" | "super" | "self" => Some(token.text.clone()),
		text if token.kind == TokenKind::Ident && !KEYWORDS.contains(&text) => Some(text.to_owned()),
		_ => None,
	}
}

/// The walk of one file, which records its items, names, and paths.
pub(super) struct FileWalk<'a> {
	tree: &'a mut SourceTree,
	source: &'a str,
	tokens: Tokens,
	file: usize,
	frames: Frames,
	pos: usize,
	declarations: Vec<Declaration>,
}

impl<'a> FileWalk<'a> {
	/// Walks `source` in `module` and returns its `mod name;` declarations.
	pub(super) fn run(
		tree: &'a mut SourceTree,
		source: &'a str,
		file: usize,
		module: ItemPath,
		test: bool,
	) -> Result<Vec<Declaration>, GraphError> {
		let root = Frame::new(Rc::new(module), test, false, Level::Module);
		let frames = Frames { root, nested: Vec::new() };
		let tokens = Tokens::of(source);

		let mut walk = Self { tree, source, tokens, file, frames, pos: 0, declarations: Vec::new() };
		let end = walk.tokens.len().saturating_sub(1);
		while walk.pos < end {
			walk.step()?;
		}

		Ok(walk.declarations)
	}

	fn syntax(&self, at: usize, what: &'static str) -> GraphError {
		let line = self.tokens.get(at).map_or(0, |token| token.line);
		GraphError::Syntax { file: self.tree.file_name(self.file), line, what }
	}

	fn step(&mut self) -> Result<(), GraphError> {
		let at = self.pos;
		let tokens = &self.tokens;
		let next = at.saturating_add(1);
		let opens_attribute = tokens.is(at, "#")
			&& (tokens.is(next, "[") || (tokens.is(next, "!") && tokens.is(at.saturating_add(2), "[")));
		let starts_use =
			tokens.is(at, "use") && Statement { tokens, indices: &self.frames.top().statement }.is_visibility();
		if opens_attribute {
			self.attribute()
		} else if starts_use {
			self.use_declaration()
		} else if tokens.is(at, "{") {
			self.open_block();
			Ok(())
		} else if tokens.is(at, "}") {
			self.close_block()
		} else {
			self.code();
			Ok(())
		}
	}

	/// An outer `#[..]` or an inner `#![..]` attribute.
	///
	/// A test-only outer `cfg` marks the statement, and an inner one the frame.
	fn attribute(&mut self) -> Result<(), GraphError> {
		let at = self.pos;
		let inner = self.tokens.is(at.saturating_add(1), "!");
		let start = at.saturating_add(2).saturating_add(usize::from(inner));
		let close = self
			.tokens
			.closing_bracket(start)
			.ok_or_else(|| self.syntax(at, "an attribute without its closing bracket"))?;

		let body = self.tokens.range(start, close);
		let head = body.first().map(|token| token.text.as_str());
		let predicate = body.get(2..body.len().saturating_sub(1)).unwrap_or_default();
		let test = head == Some("cfg") && body.len() > 2 && CfgPredicate::holds_only_under_test(predicate);
		let path = body
			.first()
			.filter(|_| head == Some("path") && body.len() > 2)
			.map(|token| self.path_literal(token.line));

		let frame = self.frames.top_mut();
		if inner {
			frame.test |= test;
		} else {
			frame.statement_test |= test;
		}

		if let Some(path) = path {
			frame.path_attribute.get_or_insert(path);
		}

		self.pos = close.saturating_add(1);
		Ok(())
	}

	/// The `path = ".."` literal on `line`, or an empty string.
	fn path_literal(&self, line: usize) -> String {
		let text = self.source.lines().nth(line.saturating_sub(1)).unwrap_or_default();
		let literal = |at: usize| {
			let value = text
				.get(at.saturating_add(4)..)?
				.trim_start()
				.strip_prefix('=')?
				.trim_start()
				.strip_prefix('"')?;
			let end = value.find('"').filter(|&end| end > 0)?;
			value.get(..end).map(str::to_owned)
		};

		text.match_indices("path").find_map(|(at, _)| literal(at)).unwrap_or_default()
	}

	fn use_declaration(&mut self) -> Result<(), GraphError> {
		let at = self.pos;
		let (leaves, next) = UseTree::read(&self.tokens, at.saturating_add(1))
			.ok_or_else(|| self.syntax(at, "a use tree that the walk has no rule for"))?;

		let frame = self.frames.top_mut();
		let reexport = !frame.statement.is_empty();
		for leaf in leaves {
			let form = if reexport {
				Form::Reexport { glob: leaf.glob }
			} else {
				Form::Use { glob: leaf.glob }
			};
			self.tree.record_site(Site {
				module: Rc::clone(&frame.module),
				written: leaf.segments.clone(),
				file: self.file,
				line: leaf.line,
				form,
				test: frame.site_test(),
				in_macro: frame.in_macro,
			});
			if frame.binds_names() {
				leaf.bind(&frame.module, self.tree);
			}
		}

		frame.end_statement();
		self.pos = next;
		Ok(())
	}

	/// A `{`, which opens a frame.
	///
	/// An inline `mod` opens a module frame, and `macro_rules!` a macro frame.
	fn open_block(&mut self) {
		let at = self.pos;
		let frame = self.frames.top_mut();
		let header = (!frame.classified)
			.then(|| Statement { tokens: &self.tokens, indices: &frame.statement }.classify())
			.flatten();

		let mut child = Frame::new(Rc::clone(&frame.module), frame.site_test(), frame.in_macro, Level::Code);
		if let Some(header) = header {
			frame.classified = true;
			frame.define(&header, self.tree);
			match header {
				ItemHeader::Module(name) => {
					let module = frame.module.child(&name);
					self.tree.declare_inline(module.clone());
					child.module = Rc::new(module);
					child.level = Level::Module;
				}
				ItemHeader::Macro(_) => child.in_macro = true,
				ItemHeader::Impl | ItemHeader::Named(_) => {}
			}
		}

		frame.statement.push(at);
		self.frames.push(child);
		self.pos = at.saturating_add(1);
	}

	/// A `}`, which closes a frame.
	///
	/// The parent statement goes on when the next token continues it.
	fn close_block(&mut self) -> Result<(), GraphError> {
		let at = self.pos;
		if self.frames.pop().is_none() {
			return Err(self.syntax(at, "a closing brace without its block"));
		}

		let continues = CONTINUE_AFTER_BLOCK.contains(&self.tokens.text(at.saturating_add(1)));
		let parent = self.frames.top_mut();
		if parent.depth == 0 && !continues {
			parent.end_statement();
		} else {
			parent.statement.push(at);
		}

		self.pos = at.saturating_add(1);
		Ok(())
	}

	/// A `;` at depth 0, which ends the statement.
	///
	/// A `mod name;` declares a child module file.
	fn semicolon(&mut self) {
		let at = self.pos;
		let frame = self.frames.top_mut();
		let header = (!frame.classified)
			.then(|| Statement { tokens: &self.tokens, indices: &frame.statement }.classify())
			.flatten();
		if let Some(header) = header {
			frame.define(&header, self.tree);
			if let ItemHeader::Module(name) = header {
				self.declarations.push(Declaration {
					module: frame.module.child(&name),
					test: frame.site_test(),
					path_attribute: frame.path_attribute.clone(),
				});
			}
		}

		frame.end_statement();
		self.pos = at.saturating_add(1);
	}

	/// Any other token.
	///
	/// A path head records a site, and an identifier records a name use.
	fn code(&mut self) {
		let at = self.pos;
		let tokens = &self.tokens;
		let Some(token) = tokens.get(at) else {
			self.pos = at.saturating_add(1);
			return;
		};

		let frame = self.frames.top_mut();
		match token.text.as_str() {
			"(" | "[" => frame.depth = frame.depth.saturating_add(1),
			")" | "]" => frame.depth = frame.depth.saturating_sub(1),
			_ => {}
		}

		if token.is(";") && frame.depth == 0 {
			self.semicolon();
			return;
		}

		// A `,` in code ends the attributes of one field, variant, or arm.
		if token.is(",") && frame.depth == 0 && frame.level == Level::Code {
			frame.statement_test = false;
			frame.path_attribute = None;
		}

		let next = at.saturating_add(1);
		let previous = at.checked_sub(1).map_or("", |index| tokens.text(index));
		let starts_path = tokens.is(next, "::") && previous != "::" && previous != "in";
		if let Some(head) = path_head(token, previous).filter(|_| starts_path) {
			let mut segments = vec![head];
			let mut end = next;
			while tokens.is(end, "::") && tokens.kind(end.saturating_add(1)) == Some(TokenKind::Ident) {
				segments.push(tokens.text(end.saturating_add(1)).to_owned());
				end = end.saturating_add(2);
			}

			let relative = !matches!(
				segments.first().map(String::as_str),
				Some("crate" | "$crate" | "super" | "self")
			);

			self.tree.record_site(Site {
				module: Rc::clone(&frame.module),
				written: ItemPath::from_segments(segments),
				file: self.file,
				line: token.line,
				form: Form::Path { relative },
				test: frame.site_test(),
				in_macro: frame.in_macro || previous == "$",
			});

			frame.statement.extend(at..end);
			self.pos = end;
			return;
		}

		if token.kind == TokenKind::Ident {
			let name_use = NameUse { module: Rc::clone(&frame.module), line: token.line, test: frame.site_test() };
			self.tree.record_name(self.file, token.text.clone(), name_use);
		}

		frame.statement.push(at);
		self.pos = next;
	}
}
