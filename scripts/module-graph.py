#!/usr/bin/env python3
"""The module graph of `tightbeam/src/transport`, and the gate that keeps its
production edges acyclic.

The script reads the crate's Rust sources from `lib.rs` down, through every
`mod` declaration, and records:

- every module with its file and line count,
- every path that crosses from one submodule of `transport` into another: the
  leaves of each `use` tree, each path that starts with `crate::`, `$crate::`,
  `super::`, or `self::`, and each relative path into a child module,
- the strongly connected components of that graph, with the edges that close
  each one and a minimum set of edge pairs whose removal leaves it acyclic,
- every public trait of `transport` that an outside crate can implement, with
  each implementation the crate holds and where it sits.

An edge's target is the module that defines the named item. A `use` that
re-exports an item (`pub use`, `pub(crate) use`) is a re-export edge, listed
apart. A re-exported name that its own module also uses is a plain edge too.
An edge under `#[cfg(test)]`, or in a file a `#[cfg(test)]` declaration
loads, is a test edge, listed apart. An edge in a `macro_rules!` body is a
macro edge.

With `--check`, the script prints each strongly connected component of the
production edges and exits 1 when one exists. `make lint-graph` runs it at
depth 1.

Usage, from the repository root:

    python3 -I scripts/module-graph.py --depth 1 --check
    python3 -I scripts/module-graph.py --depth 1
    python3 -I scripts/module-graph.py --depth 2
    python3 -I scripts/module-graph.py --seams
"""

import argparse
import itertools
import json
import os
import re
import sys
from collections import defaultdict

ROOT = ("crate", "transport")
KEYWORDS = {
	"as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern", "false", "fn",
	"for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "self", "Self",
	"static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where", "while", "union", "macro_rules",
}
ITEM_KEYWORDS = {"struct", "enum", "union", "trait", "fn", "type", "const", "static", "mod"}
CONTINUE_AFTER_BLOCK = {";", ",", ".", "?", ")", "]", "}", "else", "as", "=>", "=", "+", "-", "*", "/", "&", "|", "<",
	">", "!"}


# 1. Tokens


class Tok:
	__slots__ = ("kind", "text", "line")

	def __init__(self, kind, text, line):
		self.kind = kind
		self.text = text
		self.line = line

	def __repr__(self):
		return f"{self.text}@{self.line}"


IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
RAW_STR_RE = re.compile(r"(?:b|c)?r(#*)\"")
NUM_RE = re.compile(r"[0-9][0-9A-Za-z_]*(?:\.[0-9][0-9A-Za-z_]*)?")


def tokenize(src):
	toks = []
	i = 0
	n = len(src)
	line = 1
	while i < n:
		c = src[i]
		if c == "\n":
			line += 1
			i += 1
			continue
		if c.isspace():
			i += 1
			continue
		if src.startswith("//", i):
			j = src.find("\n", i)
			i = n if j == -1 else j
			continue
		if src.startswith("/*", i):
			depth = 0
			while i < n:
				if src.startswith("/*", i):
					depth += 1
					i += 2
				elif src.startswith("*/", i):
					depth -= 1
					i += 2
					if depth == 0:
						break
				else:
					if src[i] == "\n":
						line += 1
					i += 1
			continue
		m = RAW_STR_RE.match(src, i)
		if m and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
			hashes = m.group(1)
			end = src.find('"' + hashes, m.end())
			end = n if end == -1 else end + 1 + len(hashes)
			line += src.count("\n", i, end)
			toks.append(Tok("str", "<str>", line))
			i = end
			continue
		if c == '"' or (c in "bc" and i + 1 < n and src[i + 1] == '"'):
			j = i + (2 if c != '"' else 1)
			while j < n and src[j] != '"':
				if src[j] == "\\":
					j += 1
				j += 1
			line_start = line
			line += src.count("\n", i, j + 1)
			toks.append(Tok("str", "<str>", line_start))
			i = j + 1
			continue
		if c == "'" or (c == "b" and i + 1 < n and src[i + 1] == "'"):
			j = i + (1 if c == "'" else 2)
			if j < n and src[j] == "\\":
				k = src.find("'", j + 2)
				toks.append(Tok("char", "<char>", line))
				i = k + 1
				continue
			if j + 1 < n and src[j + 1] == "'":
				toks.append(Tok("char", "<char>", line))
				i = j + 2
				continue
			if c == "'":
				m = IDENT_RE.match(src, j)
				if m:
					toks.append(Tok("life", "'" + m.group(0), line))
					i = m.end()
					continue
			toks.append(Tok("punct", c, line))
			i += 1
			continue
		if src.startswith("r#", i) and i + 2 < n and (src[i + 2].isalpha() or src[i + 2] == "_"):
			m = IDENT_RE.match(src, i + 2)
			toks.append(Tok("ident", "r#" + m.group(0), line))
			i = m.end()
			continue
		m = IDENT_RE.match(src, i)
		if m:
			toks.append(Tok("ident", m.group(0), line))
			i = m.end()
			continue
		m = NUM_RE.match(src, i)
		if m:
			toks.append(Tok("num", m.group(0), line))
			i = m.end()
			continue
		for p in ("::", "=>", "->"):
			if src.startswith(p, i):
				toks.append(Tok("punct", p, line))
				i += 2
				break
		else:
			toks.append(Tok("punct", c, line))
			i += 1
	return toks


# 2. Configuration predicates


def cfg_is_test(toks):
	"""Whether a `cfg(...)` predicate holds only under `test`."""

	pos = [0]

	def parse():
		t = toks[pos[0]]
		pos[0] += 1
		if t.text in ("all", "any", "not") and pos[0] < len(toks) and toks[pos[0]].text == "(":
			pos[0] += 1
			kids = []
			while toks[pos[0]].text != ")":
				kids.append(parse())
				if toks[pos[0]].text == ",":
					pos[0] += 1
			pos[0] += 1
			if t.text == "all":
				return any(kids)
			if t.text == "any":
				return bool(kids) and all(kids)
			return False
		if pos[0] < len(toks) and toks[pos[0]].text == "=":
			pos[0] += 2
			return False
		return t.text == "test"

	try:
		return parse()
	except IndexError:
		return False


# 3. The parse of one file


class Frame:
	def __init__(self, module, test, macro, kind):
		self.module = module
		self.test = test
		self.macro = macro
		self.kind = kind
		self.paren = 0
		self.stmt = []
		self.stmt_test = False
		self.stmt_attrs = []
		self.classified = False


class Crate:
	def __init__(self):
		self.modules = {}
		self.items = defaultdict(dict)
		self.bindings = defaultdict(lambda: defaultdict(list))
		self.globs = defaultdict(list)
		self.occurrences = []
		self.idents = defaultdict(list)
		self.traits = []
		self.impls = []


def module_dir(path, file, is_dir_owner):
	d = os.path.dirname(file)
	if is_dir_owner:
		return d
	stem = os.path.splitext(os.path.basename(file))[0]
	return os.path.join(d, stem)


def strip_raw(name):
	return name[2:] if name.startswith("r#") else name


def parse_use_tree(toks, i):
	"""Parse a use tree from `toks[i]` to its `;`; return (leaves, next index).

	A leaf is (segments, alias, is_glob)."""

	leaves = []

	def tree(prefix):
		nonlocal i
		segs = list(prefix)
		while True:
			t = toks[i]
			if t.text == "$" and toks[i + 1].text == "crate":
				segs.append("$crate")
				i += 2
			elif t.text == "::" and not segs:
				i += 1
				continue
			elif t.kind == "ident":
				segs.append(t.text)
				i += 1
			elif t.text == "*":
				leaves.append((segs, None, True, t.line))
				i += 1
				return
			elif t.text == "{":
				i += 1
				while toks[i].text != "}":
					tree(segs)
					if toks[i].text == ",":
						i += 1
				i += 1
				return
			else:
				raise ValueError(f"use tree at {t}")
			if toks[i].text == "::":
				i += 1
				continue
			alias = None
			if toks[i].text == "as":
				alias = toks[i + 1].text
				i += 2
			if segs and segs[-1] == "self":
				segs = segs[:-1]
				alias = alias or (segs[-1] if segs else None)
			leaves.append((segs, alias, False, t.line))
			return

	start_line = toks[i].line
	tree([])
	while toks[i].text != ";":
		i += 1
	return leaves, i + 1, start_line


def vis_of(stmt):
	if not stmt or stmt[0].text != "pub":
		return "private"
	if len(stmt) > 1 and stmt[1].text == "(":
		return "pub(" + stmt[2].text + ")"
	return "pub"


def skip_vis(stmt):
	if not stmt or stmt[0].text != "pub":
		return 0
	if len(stmt) > 1 and stmt[1].text == "(":
		j = 2
		while stmt[j].text != ")":
			j += 1
		return j + 1
	return 1


def classify(stmt):
	"""Return (kind, name, vis, header) for an item header, or None."""

	j = skip_vis(stmt)
	vis = vis_of(stmt)
	while j < len(stmt) and stmt[j].text in ("unsafe", "async", "default", "extern") or (
		j < len(stmt) and stmt[j].kind == "str"
	):
		j += 1
	if j >= len(stmt):
		return None
	t = stmt[j].text
	if t == "const" and j + 1 < len(stmt) and stmt[j + 1].text in ("fn", "unsafe", "async"):
		j += 1
		while stmt[j].text in ("unsafe", "async", "extern") or stmt[j].kind == "str":
			j += 1
		t = stmt[j].text
	if t == "impl":
		return ("impl", None, vis, stmt[j:])
	if t == "macro_rules" and j + 2 < len(stmt):
		return ("macro", stmt[j + 2].text, vis, stmt[j:])
	if t in ITEM_KEYWORDS and j + 1 < len(stmt) and stmt[j + 1].kind == "ident":
		return (t, strip_raw(stmt[j + 1].text), vis, stmt[j:])
	return None


def parse_file(crate, file, module, test, is_dir_owner, decls):
	with open(file, encoding="utf-8") as fh:
		src = fh.read()
	toks = tokenize(src)
	toks.append(Tok("eof", "<eof>", 10**9))
	frames = [Frame(module, test, False, "module")]
	i = 0
	n = len(toks) - 1

	def end_stmt(f):
		f.stmt = []
		f.stmt_test = False
		f.stmt_attrs = []
		f.classified = False

	def record_item(f, cls):
		kind, name, vis, header = cls
		if kind == "impl":
			crate.impls.append(
				{"module": f.module, "header": header, "file": file, "line": header[0].line,
				 "test": f.test or f.stmt_test, "macro": f.macro}
			)
			return
		if f.kind != "module" or f.macro:
			return
		doc_hidden = any(a == "doc(hidden)" for a in f.stmt_attrs)
		crate.items[f.module].setdefault(name, (kind, header[0].line, vis, file))
		if kind == "trait":
			crate.traits.append(
				{"module": f.module, "name": name, "header": header, "file": file, "line": header[0].line,
				 "vis": vis, "test": f.test or f.stmt_test, "doc_hidden": doc_hidden}
			)

	while i < n:
		f = frames[-1]
		t = toks[i]
		# Attributes, outer and inner.
		if t.text == "#" and (toks[i + 1].text == "[" or (toks[i + 1].text == "!" and toks[i + 2].text == "[")):
			inner = toks[i + 1].text == "!"
			j = i + (3 if inner else 2)
			depth = 1
			start = j
			while depth:
				if toks[j].text == "[":
					depth += 1
				elif toks[j].text == "]":
					depth -= 1
				j += 1
			body = toks[start:j - 1]
			if body and body[0].text == "cfg" and len(body) > 2:
				is_test = cfg_is_test(body[2:-1])
				if inner:
					f.test = f.test or is_test
				else:
					f.stmt_test = f.stmt_test or is_test
			if body and body[0].text == "path" and len(body) > 2:
				f.stmt_attrs.append("path=" + src_literal(src, body))
			if body and [b.text for b in body[:4]] == ["doc", "(", "hidden", ")"]:
				f.stmt_attrs.append("doc(hidden)")
			i = j
			continue
		# A `use` declaration.
		if t.text == "use" and (not f.stmt or skip_vis(f.stmt) == len(f.stmt)):
			vis = vis_of(f.stmt)
			leaves, i, line = parse_use_tree(toks, i + 1)
			for segs, alias, glob, leaf_line in leaves:
				kind = "reexport" if vis != "private" else "use"
				crate.occurrences.append(
					{"module": f.module, "segs": segs, "line": leaf_line, "file": file,
					 "test": f.test or f.stmt_test, "macro": f.macro, "kind": kind, "glob": glob}
				)
				if f.kind == "module" and not f.macro:
					if glob:
						crate.globs[f.module].append((segs, vis, f.test or f.stmt_test))
					else:
						name = alias or (segs[-1] if segs else None)
						if name:
							crate.bindings[f.module][strip_raw(name)].append(
								(segs, vis, leaf_line, f.test or f.stmt_test)
							)
			end_stmt(f)
			continue
		if t.text == "{":
			cls = None if f.classified else classify(f.stmt)
			kind = "block"
			child_module = f.module
			macro = f.macro
			if cls:
				f.classified = True
				record_item(f, cls)
				if cls[0] == "mod":
					kind = "module"
					child_module = f.module + (cls[1],)
					crate.modules.setdefault(
						child_module, {"file": file, "line": t.line, "test": f.test or f.stmt_test, "inline": True}
					)
				elif cls[0] == "macro":
					macro = True
				else:
					kind = cls[0]
			child = Frame(child_module, f.test or f.stmt_test, macro, kind)
			frames.append(child)
			f.stmt.append(t)
			f.stmt_open = f.paren
			i += 1
			continue
		if t.text == "}":
			frames.pop()
			parent = frames[-1]
			nxt = toks[i + 1].text
			if parent.paren == 0 and nxt not in CONTINUE_AFTER_BLOCK:
				end_stmt(parent)
			else:
				parent.stmt.append(t)
			i += 1
			continue
		if t.text in ("(", "["):
			f.paren += 1
		elif t.text in (")", "]"):
			f.paren -= 1
		if t.text == ";" and f.paren == 0:
			cls = None if f.classified else classify(f.stmt)
			if cls:
				record_item(f, cls)
				if cls[0] == "mod":
					path_attr = next((a[5:] for a in f.stmt_attrs if a.startswith("path=")), None)
					decls.append((f.module + (cls[1],), f.test or f.stmt_test, path_attr, t.line))
			end_stmt(f)
			i += 1
			continue
		if t.text == "," and f.paren == 0 and f.kind != "module":
			f.stmt_test = False
			f.stmt_attrs = []
		# Paths in code.
		prev = toks[i - 1].text if i else ""
		if toks[i + 1].text == "::" and prev != "::" and prev != "in":
			segs = None
			if t.text == "crate":
				segs = ["$crate" if prev == "$" else "crate"]
			elif t.text in ("super", "self"):
				segs = [t.text]
			elif t.kind == "ident" and t.text not in KEYWORDS:
				segs = [t.text]
			if segs is not None:
				j = i + 1
				while toks[j].text == "::" and toks[j + 1].kind == "ident":
					segs.append(toks[j + 1].text)
					j += 2
				crate.occurrences.append(
					{"module": f.module, "segs": segs, "line": t.line, "file": file,
					 "test": f.test or f.stmt_test, "macro": f.macro or prev == "$", "kind": "path",
					 "glob": False, "relative": segs[0] not in ("crate", "$crate", "super", "self")}
				)
				f.stmt.extend(toks[i:j])
				i = j
				continue
		if t.kind == "ident":
			crate.idents[(file, t.text)].append((f.module, t.line, f.test or f.stmt_test))
		f.stmt.append(t)
		i += 1
	return src.count("\n") + (0 if src.endswith("\n") else 1)


def src_literal(src, body):
	# The `#[path = "x"]` literal: the tokenizer drops string text, so read it
	# again from the source line.
	line = src.splitlines()[body[0].line - 1]
	m = re.search(r'path\s*=\s*"([^"]+)"', line)
	return m.group(1) if m else ""


def load_crate(src_root):
	crate = Crate()
	lib = os.path.join(src_root, "lib.rs")
	queue = [(("crate",), lib, False, True)]
	crate.modules[("crate",)] = {"file": lib, "line": 1, "test": False, "inline": False}
	lines = {}
	while queue:
		module, file, test, is_dir_owner = queue.pop(0)
		decls = []
		lines[file] = parse_file(crate, file, module, test, is_dir_owner, decls)
		crate.modules[module]["lines"] = lines[file]
		base = module_dir(module, file, is_dir_owner)
		for child, child_test, path_attr, line in decls:
			name = strip_raw(child[-1])
			if path_attr:
				cand = [(os.path.join(os.path.dirname(file), path_attr), False)]
			else:
				cand = [(os.path.join(base, name + ".rs"), False), (os.path.join(base, name, "mod.rs"), True)]
			for path, owner in cand:
				if os.path.exists(path):
					crate.modules[child] = {"file": path, "line": 1, "test": child_test, "inline": False,
						"decl": (file, line)}
					queue.append((child, path, child_test, owner))
					break
	return crate, lines


# 4. Name resolution


class Resolver:
	def __init__(self, crate):
		self.c = crate
		self.children = defaultdict(set)
		for m in crate.modules:
			if len(m) > 1:
				self.children[m[:-1]].add(strip_raw(m[-1]))

	def is_module(self, path):
		return tuple(path[:1]) + tuple(strip_raw(s) for s in path[1:]) in self.c.modules or tuple(path) in self.c.modules

	def norm(self, path):
		return tuple(strip_raw(s) if k else s for k, s in enumerate(path))

	def absolutize(self, module, segs, depth=0):
		"""The absolute path of `segs` as written in `module`, or None."""

		if not segs:
			return None
		s0 = segs[0]
		if s0 in ("crate", "$crate"):
			return ("crate",) + tuple(segs[1:])
		if s0 == "super" or s0 == "self":
			base = module
			k = 0
			while k < len(segs) and segs[k] in ("super", "self"):
				if segs[k] == "super":
					base = base[:-1]
				k += 1
			return base + tuple(segs[k:])
		if strip_raw(s0) in self.children[module]:
			return module + tuple(segs)
		if depth < 4:
			for b in self.c.bindings[module].get(strip_raw(s0), []):
				target = self.absolutize(module, b[0], depth + 1)
				if target and self.is_module(self.norm(target)):
					return target + tuple(segs[1:])
			for g, _vis, _test in self.c.globs[module]:
				gm = self.absolutize(module, g, depth + 1)
				if gm and strip_raw(s0) in self.children[self.norm(gm)]:
					return gm + tuple(segs)
		return None

	def resolve(self, path, depth=0, follow=True):
		"""Return (owning module, item name or None) for an absolute path.

		With `follow`, a re-exported name resolves to the module that defines
		it. Without it, the walk stops at the first module that binds it."""

		path = self.norm(path)
		cur = ("crate",)
		k = 1
		while k < len(path):
			s = path[k]
			if cur + (s,) in self.c.modules:
				cur = cur + (s,)
				k += 1
				continue
			if s in self.c.items[cur] or not follow or depth > 8:
				return cur, s
			for b in self.c.bindings[cur].get(s, []):
				target = self.absolutize(cur, b[0])
				if target:
					return self.resolve(target + tuple(path[k + 1:]), depth + 1)
			for g, _vis, _test in self.c.globs[cur]:
				gm = self.absolutize(cur, g)
				if not gm:
					continue
				owner, item = self.resolve(gm + (s,), depth + 1)
				if item and item in self.c.items[owner]:
					return owner, item
			return cur, s
		return cur, None


def in_transport(m):
	return tuple(m[:2]) == ROOT


def node_of(modules, m, depth, scope):
	"""The graph node of module `m`: its ancestor `depth` levels below `scope`.

	An inline module (`mod tests { .. }`, a private shim) belongs to the node
	of the file that holds it."""

	if tuple(m[:len(scope)]) != scope:
		return None
	m = tuple(m)
	while len(m) > len(scope) and modules.get(m, {}).get("inline"):
		m = m[:-1]
	rest = m[len(scope):]
	if not rest:
		return "(root)"
	node = scope + rest[:depth]
	while len(node) > len(scope) and modules.get(node, {}).get("inline"):
		node = node[:-1]
	if node == scope:
		return "(root)"
	return "::".join(node[len(scope):])


# 5. Edges


def load_plan(path):
	"""A move plan: items that change their defining module, line ranges whose
	paths change their source module, and sites a public change deletes."""

	if not path:
		return None
	with open(path) as fh:
		raw = json.load(fh)
	plan = {"items": {}, "lines": [], "drops": set()}
	for move in raw["moves"]:
		to = ("crate",) + tuple(move["to"].split("::"))
		for owner, item in move.get("items", []):
			plan["items"][(("crate",) + tuple(owner.split("::")), item)] = to
		for file, first, last in move.get("lines", []):
			plan["lines"].append((file, first, last, to))
	for file, line in raw.get("drops", []):
		plan["drops"].add((file, line))
	return plan


def apply_plan(plan, occ, src_mod, src_root):
	if not plan:
		return src_mod
	rel_file = os.path.relpath(occ["file"], src_root)
	if (rel_file, occ["line"]) in plan["drops"]:
		return None
	for file, first, last, to in plan["lines"]:
		if file == rel_file and first <= occ["line"] <= last:
			return to
	return src_mod


def edges(crate, res, scope, depth, plan=None, src_root="tightbeam/src"):
	out = []
	for occ in crate.occurrences:
		src_mod = apply_plan(plan, occ, occ["module"], src_root)
		if src_mod is None or not in_transport(occ["module"]):
			continue
		if occ["kind"] == "path" and occ.get("relative"):
			target = res.absolutize(occ["module"], occ["segs"])
			if target is None or not res.is_module(res.norm(target[:len(target) - 0])):
				# A relative path counts only when its first segment is a child
				# module, reached directly or through a module-level glob.
				target = target if target and res.norm(target[: len(occ["module"]) + 1]) in crate.modules else None
				if target is None:
					continue
		else:
			target = res.absolutize(occ["module"], occ["segs"])
		if target is None:
			continue
		if occ["glob"]:
			owner, item = res.norm(target), "*"
			if owner not in crate.modules:
				owner, item = res.resolve(target)
		else:
			owner, item = res.resolve(target)
		if plan and (owner, item) in plan["items"]:
			owner = plan["items"][(owner, item)]
		a = node_of(crate.modules, src_mod, depth, scope)
		b = node_of(crate.modules, owner, depth, scope)
		if a is None or b is None or a == b:
			continue
		out.append(dict(occ, src=a, dst=b, item=item, owner="::".join(owner[1:]), target="::".join(target[1:])))
	# A re-exported name its own module uses reaches the defining module too.
	for occ in list(out):
		if occ["kind"] != "reexport" or occ["glob"]:
			continue
		name = occ["segs"][-1] if occ["segs"] else None
		if not name:
			continue
		home = node_of(crate.modules, occ["module"], depth, scope)
		uses = [u for u in crate.idents[(occ["file"], strip_raw(name))]
			if node_of(crate.modules, u[0], depth, scope) == home]
		# One derived edge per source node, after the plan moves the lines
		# that use the name.
		by_src = defaultdict(list)
		for module, line, test in uses:
			moved = apply_plan(plan, dict(occ, line=line), module, src_root)
			if moved is None:
				continue
			by_src[node_of(crate.modules, moved, depth, scope)].append((line, test))
		for src, hits in by_src.items():
			if src is None or src == occ["dst"]:
				continue
			out.append(dict(occ, src=src, kind="use-of-reexport", line=hits[0][0], test=all(t for _, t in hits)))
	return out


# 6. Components


def sccs(nodes, adj):
	index = {}
	low = {}
	stack = []
	on = set()
	result = []
	counter = [0]

	def strong(v):
		index[v] = low[v] = counter[0]
		counter[0] += 1
		stack.append(v)
		on.add(v)
		for w in adj.get(v, ()):
			if w not in index:
				strong(w)
				low[v] = min(low[v], low[w])
			elif w in on:
				low[v] = min(low[v], index[w])
		if low[v] == index[v]:
			comp = []
			while True:
				w = stack.pop()
				on.discard(w)
				comp.append(w)
				if w == v:
					break
			result.append(sorted(comp))

	sys.setrecursionlimit(10000)
	for v in sorted(nodes):
		if v not in index:
			strong(v)
	return [c for c in result if len(c) > 1]


def min_feedback(comp, weight):
	"""A minimum-weight set of directed pairs whose removal leaves `comp`
	acyclic, by dynamic programming over orderings (Held-Karp shape)."""

	nodes = list(comp)
	k = len(nodes)
	if k > 20:
		return None
	idx = {v: i for i, v in enumerate(nodes)}
	w = [[0] * k for _ in range(k)]
	for (a, b), x in weight.items():
		if a in idx and b in idx:
			w[idx[a]][idx[b]] = x
	# Order: a dependency comes before its user, so an edge a -> b is kept when
	# b is placed before a, and removed when b comes after a.
	full = 1 << k
	dp = [None] * full
	choice = [None] * full
	dp[0] = 0
	for s in range(full):
		if dp[s] is None:
			continue
		for v in range(k):
			if s & (1 << v):
				continue
			# v is placed after every node in s: v's edges into nodes not yet
			# placed point forward, so they are removed.
			cost = dp[s] + sum(w[v][u] for u in range(k) if not s & (1 << u) and u != v)
			t = s | (1 << v)
			if dp[t] is None or cost < dp[t]:
				dp[t] = cost
				choice[t] = v
	order = []
	s = full - 1
	while s:
		v = choice[s]
		order.append(v)
		s &= ~(1 << v)
	order.reverse()
	pos = {v: p for p, v in enumerate(order)}
	removed = [(nodes[a], nodes[b], w[a][b]) for a in range(k) for b in range(k)
		if w[a][b] and pos[b] > pos[a]]
	return dp[full - 1], [nodes[v] for v in order], removed


# 7. Seams


def generic_names(header):
	names = set()
	if len(header) > 1 and header[1].text == "<":
		depth = 0
		prev = "<"
		for t in header[1:]:
			if t.text == "<":
				depth += 1
			elif t.text == ">":
				depth -= 1
				if depth == 0:
					break
			elif depth == 1 and prev in ("<", ",") and t.kind == "ident" and t.text != "const":
				names.add(t.text)
			elif depth == 1 and prev == "const" and t.kind == "ident":
				names.add(t.text)
			if t.kind != "life":
				prev = t.text
	return names


def split_impl(header):
	"""Return (trait segments, type head, generic names) of an impl header."""

	gens = generic_names(header)
	j = 1
	if len(header) > 1 and header[1].text == "<":
		depth = 0
		while True:
			if header[j].text == "<":
				depth += 1
			elif header[j].text == ">":
				depth -= 1
				if depth == 0:
					j += 1
					break
			j += 1
	depth = 0
	for k in range(j, len(header)):
		t = header[k].text
		if t == "<":
			depth += 1
		elif t == ">":
			depth -= 1
		elif t == "for" and depth == 0:
			trait = []
			d = 0
			for x in header[j:k]:
				if x.text == "<" or x.text == "(":
					d += 1
				elif x.text == ">" or x.text == ")":
					d -= 1
				elif d == 0 and (x.kind == "ident" or x.text == "$"):
					trait.append(x.text)
			head = None
			for x in header[k + 1:]:
				if x.text in ("where", "{"):
					break
				if x.kind == "ident" and x.text not in ("mut", "dyn", "crate", "self", "super"):
					head = x.text
					break
				if x.text == "$":
					head = "$"
			path_head = []
			for x in header[k + 1:]:
				if x.text in ("where", "{", "<"):
					break
				if x.kind == "ident":
					path_head.append(x.text)
			ty = " ".join(x.text for x in header[k + 1:] if x.text not in ("{",)).split(" where ")[0]
			return [s for s in trait if s != "$"], head, gens, ty
	return None, None, gens, None


def seams(crate, res):
	out = []
	trait_names = defaultdict(list)
	for tr in crate.traits:
		trait_names[tr["name"]].append(tr)
	for tr in crate.traits:
		if not in_transport(tr["module"]) or tr["test"]:
			continue
		hdr = [t.text for t in tr["header"]]
		colon = hdr.index(":") if ":" in hdr else None
		supers = hdr[colon + 1:] if colon is not None else []
		if "where" in supers:
			supers = supers[:supers.index("where")]
		tr["supers"] = [s for s in supers if s not in ("+", "'static", "Sized", "<", ">", ",", "::")]
	by_name = {tr["name"]: tr for tr in crate.traits if in_transport(tr["module"]) and not tr["test"]}

	def sealed(tr, seen=()):
		if tr["name"] in seen:
			return False
		sup = tr.get("supers", [])
		if "Sealed" in sup or "Admitted" in sup:
			return True
		return any(s in by_name and sealed(by_name[s], seen + (tr["name"],)) for s in sup)

	impls = []
	for im in crate.impls:
		trait, head, gens, ty = split_impl([t for t in im["header"]])
		if not trait:
			continue
		impls.append(dict(im, trait=trait, head=head, gens=gens, ty=ty))
	for tr in crate.traits:
		if not in_transport(tr["module"]) or tr["test"]:
			continue
		row = dict(tr)
		row["sealed"] = sealed(tr)
		row["public"] = public_reach(crate, res, tr)
		found = []
		for im in impls:
			if im["trait"][-1] != tr["name"]:
				continue
			if len(im["trait"]) > 1:
				target = res.absolutize(im["module"], im["trait"])
				if target:
					owner, item = res.resolve(target)
					if owner != tr["module"]:
						continue
			elif len(trait_names[tr["name"]]) > 1:
				owners = set()
				for b in crate.bindings[im["module"]].get(tr["name"], []):
					target = res.absolutize(im["module"], b[0])
					if target:
						owners.add(res.resolve(target)[0])
				if owners and tr["module"] not in owners and im["module"] != tr["module"]:
					continue
			blanket = im["head"] in im["gens"] or im["head"] == "$" and False
			found.append(
				{"module": "::".join(im["module"][1:]), "file": im["file"], "line": im["line"], "test": im["test"],
				 "macro": im["macro"], "blanket": blanket, "type": im["ty"], "head": im["head"]}
			)
		row["impls"] = found
		out.append(row)
	return out


def public_reach(crate, res, tr):
	"""Whether an outside crate can name the trait: its module chain is public
	and it is `pub`, or a public module re-exports it with `pub use`."""

	if tr["vis"] != "pub":
		return False

	def chain_public(m):
		for k in range(2, len(m) + 1):
			decl = m[:k]
			parent = decl[:-1]
			item = crate.items[parent].get(strip_raw(decl[-1]))
			if not item or item[2] != "pub":
				return False
		return True

	if chain_public(tr["module"]):
		return True
	for m in crate.modules:
		if not chain_public(m):
			continue
		for name, binds in crate.bindings[m].items():
			for segs, vis, _line, _test in binds:
				if vis != "pub":
					continue
				target = res.absolutize(m, segs)
				if target and res.resolve(target)[0] == tr["module"] and res.resolve(target)[1] == tr["name"]:
					return True
	return False


# 8. Output


def rel(path, base):
	return os.path.relpath(path, base)


def main():
	ap = argparse.ArgumentParser()
	ap.add_argument("--src", default="tightbeam/src")
	ap.add_argument("--depth", type=int, default=1)
	ap.add_argument("--scope", default="transport", help="the module whose children are the nodes")
	ap.add_argument("--seams", action="store_true")
	ap.add_argument("--check", action="store_true", help="exit 1 when the production edges hold a cycle")
	ap.add_argument("--json")
	ap.add_argument("--plan", help="a JSON move plan to apply before the graph is built")
	args = ap.parse_args()
	crate, lines = load_crate(args.src)
	res = Resolver(crate)
	base = os.path.join(args.src, "transport")
	scope = ("crate",) + tuple(args.scope.split("::"))

	if args.seams:
		rows = seams(crate, res)
		print("| Trait | Trait file | Sealed | Public | Implementations (module, file:line, kind) |")
		print("| --- | --- | --- | --- | --- |")
		for r in sorted(rows, key=lambda r: (r["file"], r["line"])):
			imps = "; ".join(
				f"`{i['type']}` in `{i['module']}` ({rel(i['file'], args.src)}:{i['line']}"
				+ (", blanket" if i["blanket"] else "") + (", test" if i["test"] else "")
				+ (", macro" if i["macro"] else "") + ")"
				for i in r["impls"]
			)
			print(f"| `{r['name']}` | {rel(r['file'], args.src)}:{r['line']} | {r['sealed']} | {r['public']} "
				f"| {imps or 'none'} |")
		if args.json:
			with open(args.json, "w") as fh:
				json.dump([{k: v for k, v in r.items() if k != "header"} | {"module": "::".join(r["module"])}
					for r in rows], fh, indent=1, default=str)
		return

	es = edges(crate, res, scope, args.depth, load_plan(args.plan), args.src)
	nodes = sorted({e["src"] for e in es} | {e["dst"] for e in es})
	pair = defaultdict(lambda: defaultdict(list))
	for e in es:
		cls = "test" if e["test"] else ("reexport" if e["kind"] == "reexport" else ("macro" if e["macro"] else "prod"))
		pair[(e["src"], e["dst"])][cls].append(e)

	def graph(classes):
		adj = defaultdict(set)
		weight = defaultdict(int)
		witems = defaultdict(set)
		for (a, b), d in pair.items():
			n = sum(len(d[k]) for k in classes)
			if n:
				adj[a].add(b)
				weight[(a, b)] = n
				witems[(a, b)] = {e["item"] for k in classes for e in d[k]}
		return adj, weight, witems

	if args.check:
		adj, weight, witems = graph(("prod",))
		comps = sccs(nodes, adj)
		print(f"{args.scope} at depth {args.depth}: {len(nodes)} nodes, {len(comps)} production cycles")
		for c in comps:
			fb = min_feedback(c, {k: len(witems[k]) for k in weight if k[0] in c and k[1] in c})
			cut = "; ".join(f"{a} -> {b} ({', '.join(sorted(map(str, witems[(a, b)])))})" for a, b, _x in fb[2]) \
				if fb else "a component past 20 modules, which `--depth 1` without `--check` lists"
			print(f"- {{{', '.join(c)}}}, acyclic without: {cut}", file=sys.stderr)
		return 1 if comps else 0

	# Modules of the scope.
	print("## Modules\n")
	print("| Module | File | Lines | Test only |")
	print("| --- | --- | --- | --- |")
	for m in sorted(crate.modules):
		if tuple(m[:len(scope)]) != scope:
			continue
		info = crate.modules[m]
		if info.get("inline"):
			continue
		print(f"| `{'::'.join(m[1:])}` | {rel(info['file'], args.src)} | {info.get('lines', '')} | "
			f"{'yes' if info['test'] else ''} |")
	print(f"\n## Edges at depth {args.depth} under `{args.scope}`: {len(es)} sites\n")
	print("| From | To | Prod | Macro | Re-export | Test | Items (prod and macro) |")
	print("| --- | --- | --- | --- | --- | --- | --- |")
	for (a, b), d in sorted(pair.items()):
		items = sorted({e["item"] or "(module)" for k in ("prod", "macro") for e in d[k]})
		print(f"| {a} | {b} | {len(d['prod'])} | {len(d['macro'])} | {len(d['reexport'])} | {len(d['test'])} "
			f"| {', '.join(items)} |")

	for label, classes in (("production (prod)", ("prod",)), ("production and macro", ("prod", "macro")),
			("production, macro, and re-export", ("prod", "macro", "reexport")),
			("every edge, tests included", ("prod", "macro", "reexport", "test"))):
		adj, weight, witems = graph(classes)
		comps = sccs(nodes, adj)
		print(f"\n## Strongly connected components, {label}: {len(comps)}\n")
		if not comps:
			# Each node's layer is the length of its longest dependency chain.
			level = {}

			def depth_of(v):
				if v not in level:
					level[v] = 0
					level[v] = 1 + max((depth_of(w) for w in adj.get(v, ())), default=-1)
				return level[v]

			for v in nodes:
				depth_of(v)
			for k in range(max(level.values(), default=-1) + 1):
				print(f"- layer {k}: {', '.join(sorted(v for v in nodes if level[v] == k))}")
		for c in comps:
			print(f"- {{{', '.join(c)}}}")
			cw = {k: len(witems[k]) for k in weight if k[0] in c and k[1] in c}
			fb = min_feedback(c, cw)
			if fb:
				cost, order, removed = fb
				print(f"  - layer order, dependencies first: {' < '.join(order)}")
				print(f"  - minimum feedback by distinct items: {cost}: "
					+ "; ".join(f"{a} -> {b} ({x}: {', '.join(sorted(map(str, witems[(a, b)])))})"
						for a, b, x in removed))

	print("\n## Edge sites\n")
	print("| From | To | Class | Kind | Item | Site | Path |")
	print("| --- | --- | --- | --- | --- | --- | --- |")
	for (a, b), d in sorted(pair.items()):
		for cls in ("prod", "macro", "reexport", "test"):
			for e in sorted(d[cls], key=lambda e: (e["file"], e["line"])):
				print(f"| {a} | {b} | {cls} | {e['kind']} | `{e['item']}` | {rel(e['file'], args.src)}:{e['line']} "
					f"| `{'::'.join(e['segs'])}` |")
	if args.json:
		with open(args.json, "w") as fh:
			json.dump([{k: (list(v) if isinstance(v, tuple) else v) for k, v in e.items()} for e in es], fh, indent=1)


if __name__ == "__main__":
	sys.exit(main())
