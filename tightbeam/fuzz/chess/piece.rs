/// Chess piece representation
///
/// Pieces are stored as u8 in the board (0-12):
/// - 0 = empty square
/// - 1-6 = white pieces (pawn=1, rook=2, knight=3, bishop=4, queen=5, king=6)
/// - 7-12 = black pieces (pawn=7, rook=8, knight=9, bishop=10, queen=11, king=12)
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

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
	White = 0,
	Black = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Piece {
	pub kind: PieceKind,
	pub color: Color,
}

impl Piece {
	/// Create a white piece
	pub const fn as_white(kind: PieceKind) -> Self {
		Self { kind, color: Color::White }
	}

	/// Create a black piece
	pub const fn as_black(kind: PieceKind) -> Self {
		Self { kind, color: Color::Black }
	}

	/// Convert u8 to `Option<Piece>` (0 = empty, 1-12 = pieces)
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

// Convenience constants for common pieces
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

// ============================================================================
// PIECE-SPECIFIC MOVE PATTERNS
// ============================================================================

/// Rook move directions: horizontal and vertical
pub const ROOK_DIRECTIONS: &[(i8, i8)] = &[(0, 1), (0, -1), (1, 0), (-1, 0)];
/// Bishop move directions: diagonal
pub const BISHOP_DIRECTIONS: &[(i8, i8)] = &[(1, 1), (1, -1), (-1, 1), (-1, -1)];
/// Queen move directions: all 8 directions (rook + bishop)
pub const QUEEN_DIRECTIONS: &[(i8, i8)] = &[(0, 1), (0, -1), (1, 0), (-1, 0), (1, 1), (1, -1), (-1, 1), (-1, -1)];
/// Knight move offsets: 8 L-shaped moves
pub const KNIGHT_OFFSETS: &[(i8, i8)] = &[(2, 1), (2, -1), (-2, 1), (-2, -1), (1, 2), (1, -2), (-1, 2), (-1, -2)];

impl PieceKind {
	/// Get move directions for pieces that move along lines (rook, bishop, queen)
	/// Returns None for pieces that don't use line moves (pawn, knight, king)
	pub fn as_move_directions(&self) -> Option<&'static [(i8, i8)]> {
		match self {
			PieceKind::Rook => Some(ROOK_DIRECTIONS),
			PieceKind::Bishop => Some(BISHOP_DIRECTIONS),
			PieceKind::Queen => Some(QUEEN_DIRECTIONS),
			_ => None,
		}
	}

	/// Get move offsets for pieces with fixed move patterns (knight)
	/// Returns None for pieces that don't use fixed offsets
	pub fn as_move_offsets(&self) -> Option<&'static [(i8, i8)]> {
		match self {
			PieceKind::Knight => Some(KNIGHT_OFFSETS),
			_ => None,
		}
	}

	/// Get the event label for this piece kind
	pub fn as_kind_label(&self) -> &'static str {
		match self {
			PieceKind::Pawn => "pawn_move",
			PieceKind::Rook => "rook_move",
			PieceKind::Knight => "knight_move",
			PieceKind::Bishop => "bishop_move",
			PieceKind::Queen => "queen_move",
			PieceKind::King => "king_move",
		}
	}
}

impl Color {
	/// Get the starting row for a pawn of this color
	pub fn to_pawn_start_row(self) -> u8 {
		match self {
			Color::White => 1,
			Color::Black => 6,
		}
	}

	/// Get the forward direction for a pawn of this color (row offset per move)
	/// White pawns move up (negative), black pawns move down (positive)
	pub fn to_pawn_forward_direction(self) -> i8 {
		match self {
			Color::White => -1,
			Color::Black => 1,
		}
	}
}

impl Piece {
	/// Check if this piece is white
	pub fn is_white(&self) -> bool {
		matches!(self.color, Color::White)
	}

	/// Get the starting row for a pawn (only valid for pawns)
	pub fn to_pawn_start_row(self) -> Option<u8> {
		match self.kind {
			PieceKind::Pawn => Some(self.color.to_pawn_start_row()),
			_ => None,
		}
	}

	/// Get the forward direction for a pawn (only valid for pawns)
	pub fn to_pawn_forward_direction(self) -> Option<i8> {
		match self.kind {
			PieceKind::Pawn => Some(self.color.to_pawn_forward_direction()),
			_ => None,
		}
	}

	/// Get the event label for this piece
	pub fn as_kind_label(&self) -> &'static str {
		self.kind.as_kind_label()
	}
}
