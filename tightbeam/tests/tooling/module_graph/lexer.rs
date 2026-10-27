//! The tokens of one source file. A literal is one token, and the lexer drops
//! each comment, so the walk reads code alone.

/// The class of a token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TokenKind {
	/// An identifier, a keyword, or a raw identifier such as `r#async`.
	Ident,
	/// A lifetime or a loop label, such as `'a`.
	Lifetime,
	/// A string literal of any form, raw, byte, or C.
	Str,
	/// A character or byte literal.
	Char,
	/// A number literal.
	Num,
	/// A punctuation mark. The marks `::`, `=>`, and `->` are one token each.
	Punct,
	/// The token past the last one in the file.
	End,
}

/// One token with the line it starts on.
#[derive(Clone, Debug)]
pub(super) struct Token {
	/// The class of the token.
	pub(super) kind: TokenKind,
	/// The source text of the token.
	///
	/// A string or a character literal holds a placeholder.
	pub(super) text: String,
	/// The line of the token, which starts at 1.
	pub(super) line: usize,
}

impl Token {
	pub(super) fn is(&self, text: &str) -> bool {
		self.text == text
	}
}

/// The tokens of one file, which end with one [`TokenKind::End`] token.
///
/// A read past the end yields an empty text and no token.
pub(super) struct Tokens(Vec<Token>);

impl Tokens {
	pub(super) fn of(source: &str) -> Self {
		let mut lexer = Lexer { chars: source.chars().collect(), pos: 0, line: 1, tokens: Vec::new() };
		while lexer.pos < lexer.chars.len() {
			lexer.step();
		}
		lexer.push(TokenKind::End, String::new(), usize::MAX);
		Self(lexer.tokens)
	}

	pub(super) fn len(&self) -> usize {
		self.0.len()
	}

	pub(super) fn get(&self, index: usize) -> Option<&Token> {
		self.0.get(index)
	}

	pub(super) fn text(&self, index: usize) -> &str {
		self.get(index).map_or("", |token| token.text.as_str())
	}

	pub(super) fn kind(&self, index: usize) -> Option<TokenKind> {
		self.get(index).map(|token| token.kind)
	}

	pub(super) fn is(&self, index: usize, text: &str) -> bool {
		self.text(index) == text
	}

	/// The tokens from `start` up to `end`, empty when the range is outside.
	pub(super) fn range(&self, start: usize, end: usize) -> &[Token] {
		self.0.get(start..end).unwrap_or_default()
	}

	/// The index of the `]` that closes the bracket opened before `start`.
	pub(super) fn closing_bracket(&self, start: usize) -> Option<usize> {
		let mut depth = 1_usize;
		(start..self.len()).find(|&index| {
			match self.text(index) {
				"[" => depth = depth.saturating_add(1),
				"]" => depth = depth.saturating_sub(1),
				_ => {}
			}
			depth == 0
		})
	}
}

/// The scan of one source text, one character at a time.
///
/// Each step consumes one token, one comment, or one whitespace character.
struct Lexer {
	chars: Vec<char>,
	pos: usize,
	line: usize,
	tokens: Vec<Token>,
}

impl Lexer {
	fn at(&self, index: usize) -> Option<char> {
		self.chars.get(index).copied()
	}

	fn is_at(&self, index: usize, c: char) -> bool {
		self.at(index) == Some(c)
	}

	fn starts_with(&self, index: usize, pattern: &str) -> bool {
		pattern
			.chars()
			.enumerate()
			.all(|(offset, c)| self.is_at(index.saturating_add(offset), c))
	}

	fn find(&self, from: usize, pattern: &str) -> Option<usize> {
		(from..self.chars.len()).find(|&index| self.starts_with(index, pattern))
	}

	fn newlines(&self, from: usize, to: usize) -> usize {
		let end = to.min(self.chars.len());
		self.chars
			.get(from..end)
			.map_or(0, |chars| chars.iter().filter(|&&c| c == '\n').count())
	}

	/// The index past the run of characters from `from` that `matches` holds.
	fn run_end(&self, from: usize, matches: impl Fn(char) -> bool) -> usize {
		(from..self.chars.len())
			.find(|&index| !self.at(index).is_some_and(&matches))
			.unwrap_or(self.chars.len())
	}

	/// The end of an ASCII identifier that starts at `from`.
	fn ident_end(&self, from: usize) -> Option<usize> {
		let first = self.at(from)?;
		let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
		(first.is_ascii_alphabetic() || first == '_').then(|| self.run_end(from.saturating_add(1), word))
	}

	/// The end of a number at `from`, with one fraction part at most.
	fn number_end(&self, from: usize) -> Option<usize> {
		let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
		let first = self.at(from)?;
		let whole = first.is_ascii_digit().then(|| self.run_end(from.saturating_add(1), word))?;
		let fraction = self.is_at(whole, '.') && self.at(whole.saturating_add(1)).is_some_and(|c| c.is_ascii_digit());
		if !fraction {
			return Some(whole);
		}

		Some(self.run_end(whole.saturating_add(2), word))
	}

	/// The body start and the hash count of a raw string at `from`.
	fn raw_string_open(&self, from: usize) -> Option<(usize, usize)> {
		let prefixed = matches!(self.at(from), Some('b' | 'c')) && self.is_at(from.saturating_add(1), 'r');
		let r = from.saturating_add(usize::from(prefixed));
		let hashes = r.saturating_add(1);
		let quote = self.run_end(hashes, |c| c == '#');
		let after_word = from
			.checked_sub(1)
			.and_then(|index| self.at(index))
			.is_some_and(|c| c.is_alphanumeric() || c == '_');

		(self.is_at(r, 'r') && self.is_at(quote, '"') && !after_word)
			.then(|| (quote.saturating_add(1), quote.saturating_sub(hashes)))
	}

	fn push(&mut self, kind: TokenKind, text: String, line: usize) {
		self.tokens.push(Token { kind, text, line });
	}

	fn step(&mut self) {
		let pos = self.pos;
		let Some(c) = self.at(pos) else {
			return;
		};

		let next = self.at(pos.saturating_add(1));
		if c == '\n' {
			self.line = self.line.saturating_add(1);
			self.pos = pos.saturating_add(1);
		} else if c.is_whitespace() {
			self.pos = pos.saturating_add(1);
		} else if self.starts_with(pos, "//") {
			self.pos = self.find(pos, "\n").unwrap_or(self.chars.len());
		} else if self.starts_with(pos, "/*") {
			self.block_comment();
		} else if let Some((body, hashes)) = self.raw_string_open(pos) {
			self.raw_string(body, hashes);
		} else if c == '"' || (matches!(c, 'b' | 'c') && next == Some('"')) {
			self.string(c);
		} else if c == '\'' || (c == 'b' && next == Some('\'')) {
			self.quote(c);
		} else if let Some(end) = self.raw_ident_end(pos) {
			let text = self.chars.get(pos..end).unwrap_or_default().iter().collect();
			self.push(TokenKind::Ident, text, self.line);
			self.pos = end;
		} else if let Some(end) = self.ident_end(pos) {
			let text = self.chars.get(pos..end).unwrap_or_default().iter().collect();
			self.push(TokenKind::Ident, text, self.line);
			self.pos = end;
		} else if let Some(end) = self.number_end(pos) {
			let text = self.chars.get(pos..end).unwrap_or_default().iter().collect();
			self.push(TokenKind::Num, text, self.line);
			self.pos = end;
		} else if let Some(mark) = ["::", "=>", "->"].into_iter().find(|mark| self.starts_with(pos, mark)) {
			self.push(TokenKind::Punct, mark.to_owned(), self.line);
			self.pos = pos.saturating_add(2);
		} else {
			self.push(TokenKind::Punct, c.to_string(), self.line);
			self.pos = pos.saturating_add(1);
		}
	}

	/// The end of a raw identifier such as `r#async` at `from`.
	fn raw_ident_end(&self, from: usize) -> Option<usize> {
		let name = from.saturating_add(2);
		let opens = self.starts_with(from, "r#") && self.at(name).is_some_and(|c| c.is_alphabetic() || c == '_');
		opens.then(|| self.ident_end(name)).flatten()
	}

	fn block_comment(&mut self) {
		let mut depth = 0_usize;
		while self.pos < self.chars.len() {
			if self.starts_with(self.pos, "/*") {
				depth = depth.saturating_add(1);
				self.pos = self.pos.saturating_add(2);
			} else if self.starts_with(self.pos, "*/") {
				depth = depth.saturating_sub(1);
				self.pos = self.pos.saturating_add(2);
				if depth == 0 {
					return;
				}
			} else {
				if self.is_at(self.pos, '\n') {
					self.line = self.line.saturating_add(1);
				}
				self.pos = self.pos.saturating_add(1);
			}
		}
	}

	/// A raw string whose body starts at `body`.
	///
	/// The token takes the line where the string ends.
	fn raw_string(&mut self, body: usize, hashes: usize) {
		let closing: String = core::iter::once('"').chain(core::iter::repeat_n('#', hashes)).collect();
		let end = self
			.find(body, &closing)
			.map_or(self.chars.len(), |index| index.saturating_add(1).saturating_add(hashes));
		self.line = self.line.saturating_add(self.newlines(self.pos, end));
		self.push(TokenKind::Str, "<str>".to_owned(), self.line);
		self.pos = end;
	}

	/// A string, a byte string, or a C string that starts with `c`.
	///
	/// The token takes the line where the string starts.
	fn string(&mut self, c: char) {
		let open = self.pos.saturating_add(usize::from(c != '"'));
		let mut index = open.saturating_add(1);
		while index < self.chars.len() && !self.is_at(index, '"') {
			if self.is_at(index, '\\') {
				index = index.saturating_add(1);
			}
			index = index.saturating_add(1);
		}

		let line = self.line;
		let end = index.saturating_add(1);
		self.line = self.line.saturating_add(self.newlines(self.pos, end));
		self.push(TokenKind::Str, "<str>".to_owned(), line);
		self.pos = end;
	}

	/// A character, a byte, or a lifetime that starts with `c`.
	fn quote(&mut self, c: char) {
		let open = self.pos.saturating_add(usize::from(c != '\''));
		let body = open.saturating_add(1);
		if self.is_at(body, '\\') {
			self.push(TokenKind::Char, "<char>".to_owned(), self.line);
			self.pos = self
				.find(body.saturating_add(2), "'")
				.map_or(self.chars.len(), |index| index.saturating_add(1));
		} else if self.is_at(body.saturating_add(1), '\'') {
			self.push(TokenKind::Char, "<char>".to_owned(), self.line);
			self.pos = body.saturating_add(2);
		} else if let Some(end) = self.ident_end(body).filter(|_| c == '\'') {
			let name: String = self.chars.get(body..end).unwrap_or_default().iter().collect();
			self.push(TokenKind::Lifetime, format!("'{name}"), self.line);
			self.pos = end;
		} else {
			self.push(TokenKind::Punct, c.to_string(), self.line);
			self.pos = self.pos.saturating_add(1);
		}
	}
}
