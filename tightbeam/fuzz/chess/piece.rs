use tightbeam::urn::Urn;

use super::events;

/// The kind of a chess piece, whose value is the board code of the white piece.
///
/// The board stores each square as a `u8` code from 0 to 12:
/// - 0 is an empty square.
/// - 1 to 6 are the white pieces: pawn 1, rook 2, knight 3, bishop 4, queen 5, king 6.
/// - 7 to 12 are the black pieces: pawn 7, rook 8, knight 9, bishop 10, queen 11, king 12.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PieceKind {
	Pawn = 1,
	Rook = 2,
	Knight = 3,
	Bishop = 4,
	Queen = 5,
	King = 6,
}

/// The side of a piece, whose value is its offset in the board code.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
	White = 0,
	Black = 6,
}

/// A chess piece, whose board code is the sum of its kind and its color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Piece {
	/// The kind of the piece, which decides how it moves.
	pub kind: PieceKind,
	/// The side that owns the piece.
	pub color: Color,
}

impl Piece {
	/// The white piece of `kind`.
	pub const fn as_white(kind: PieceKind) -> Self {
		Self { kind, color: Color::White }
	}

	/// The black piece of `kind`.
	pub const fn as_black(kind: PieceKind) -> Self {
		Self { kind, color: Color::Black }
	}

	/// The piece that the board code `value` names, or `None` for an empty
	/// square or a code past 12.
	pub const fn from_u8(value: u8) -> Option<Self> {
		match value {
			0 => None,
			1 => Some(Self { kind: PieceKind::Pawn, color: Color::White }),
			2 => Some(Self { kind: PieceKind::Rook, color: Color::White }),
			3 => Some(Self { kind: PieceKind::Knight, color: Color::White }),
			4 => Some(Self { kind: PieceKind::Bishop, color: Color::White }),
			5 => Some(Self { kind: PieceKind::Queen, color: Color::White }),
			6 => Some(Self { kind: PieceKind::King, color: Color::White }),
			7 => Some(Self { kind: PieceKind::Pawn, color: Color::Black }),
			8 => Some(Self { kind: PieceKind::Rook, color: Color::Black }),
			9 => Some(Self { kind: PieceKind::Knight, color: Color::Black }),
			10 => Some(Self { kind: PieceKind::Bishop, color: Color::Black }),
			11 => Some(Self { kind: PieceKind::Queen, color: Color::Black }),
			12 => Some(Self { kind: PieceKind::King, color: Color::Black }),
			_ => None,
		}
	}
}

impl From<Piece> for u8 {
	fn from(piece: Piece) -> Self {
		piece.kind as u8 + piece.color as u8
	}
}

// The twelve pieces, one constant for each kind and color.
pub const WHITE_PAWN: Piece = Piece::as_white(PieceKind::Pawn);
pub const WHITE_ROOK: Piece = Piece::as_white(PieceKind::Rook);
pub const WHITE_KNIGHT: Piece = Piece::as_white(PieceKind::Knight);
pub const WHITE_BISHOP: Piece = Piece::as_white(PieceKind::Bishop);
pub const WHITE_QUEEN: Piece = Piece::as_white(PieceKind::Queen);
pub const WHITE_KING: Piece = Piece::as_white(PieceKind::King);

pub const BLACK_PAWN: Piece = Piece::as_black(PieceKind::Pawn);
pub const BLACK_ROOK: Piece = Piece::as_black(PieceKind::Rook);
pub const BLACK_KNIGHT: Piece = Piece::as_black(PieceKind::Knight);
pub const BLACK_BISHOP: Piece = Piece::as_black(PieceKind::Bishop);
pub const BLACK_QUEEN: Piece = Piece::as_black(PieceKind::Queen);
pub const BLACK_KING: Piece = Piece::as_black(PieceKind::King);

// The move patterns of each kind of piece.

/// The four directions of a rook move, along a row or a column.
pub const ROOK_DIRECTIONS: &[(i8, i8)] = &[(0, 1), (0, -1), (1, 0), (-1, 0)];
/// The four directions of a bishop move, along a diagonal.
pub const BISHOP_DIRECTIONS: &[(i8, i8)] = &[(1, 1), (1, -1), (-1, 1), (-1, -1)];
/// The eight directions of a queen move, which are the rook and the bishop
/// directions together.
pub const QUEEN_DIRECTIONS: &[(i8, i8)] = &[(0, 1), (0, -1), (1, 0), (-1, 0), (1, 1), (1, -1), (-1, 1), (-1, -1)];
/// The eight L-shaped offsets of a knight move.
pub const KNIGHT_OFFSETS: &[(i8, i8)] = &[(2, 1), (2, -1), (-2, 1), (-2, -1), (1, 2), (1, -2), (-1, 2), (-1, -2)];

impl PieceKind {
	/// The directions of a piece that moves along lines (rook, bishop, queen),
	/// or `None` for a pawn, a knight, or a king.
	pub fn as_move_directions(&self) -> Option<&'static [(i8, i8)]> {
		match self {
			PieceKind::Rook => Some(ROOK_DIRECTIONS),
			PieceKind::Bishop => Some(BISHOP_DIRECTIONS),
			PieceKind::Queen => Some(QUEEN_DIRECTIONS),
			_ => None,
		}
	}

	/// The fixed offsets of a knight move, or `None` for any other kind.
	pub fn as_move_offsets(&self) -> Option<&'static [(i8, i8)]> {
		match self {
			PieceKind::Knight => Some(KNIGHT_OFFSETS),
			_ => None,
		}
	}

	/// The event URN that a move of this kind records.
	pub fn as_kind_event(&self) -> Urn<'static> {
		match self {
			PieceKind::Pawn => events::PAWN_MOVE,
			PieceKind::Rook => events::ROOK_MOVE,
			PieceKind::Knight => events::KNIGHT_MOVE,
			PieceKind::Bishop => events::BISHOP_MOVE,
			PieceKind::Queen => events::QUEEN_MOVE,
			PieceKind::King => events::KING_MOVE,
		}
	}
}

impl Color {
	/// The start row of a pawn of this color.
	pub fn to_pawn_start_row(self) -> u8 {
		match self {
			Color::White => 1,
			Color::Black => 6,
		}
	}

	/// The row offset of one forward step of a pawn of this color.
	///
	/// White starts on rows 0 and 1, so its pawns move toward row 7 (positive).
	/// Black starts on rows 6 and 7, so its pawns move toward row 0 (negative).
	pub fn to_pawn_forward_direction(self) -> i8 {
		match self {
			Color::White => 1,
			Color::Black => -1,
		}
	}
}

impl Piece {
	/// Whether this piece is white.
	pub fn is_white(&self) -> bool {
		matches!(self.color, Color::White)
	}

	/// The start row of this piece, or `None` when it is not a pawn.
	pub fn to_pawn_start_row(self) -> Option<u8> {
		match self.kind {
			PieceKind::Pawn => Some(self.color.to_pawn_start_row()),
			_ => None,
		}
	}

	/// The row offset of one forward step of this piece, or `None` when it is
	/// not a pawn.
	pub fn to_pawn_forward_direction(self) -> Option<i8> {
		match self.kind {
			PieceKind::Pawn => Some(self.color.to_pawn_forward_direction()),
			_ => None,
		}
	}

	/// The event URN that a move of this piece records.
	pub fn as_kind_event(&self) -> Urn<'static> {
		self.kind.as_kind_event()
	}
}
