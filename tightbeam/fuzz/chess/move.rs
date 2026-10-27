#![allow(dead_code)]

use super::board::ChessMoveRequest;
use super::piece::PieceKind;

/// A chess move from one square to another, with an optional promotion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct ChessMove {
	pub(crate) from_row: u8,
	pub(crate) from_col: u8,
	pub(crate) to_row: u8,
	pub(crate) to_col: u8,
	/// The kind of piece that a pawn on the last row becomes, or `None` for a
	/// move with no promotion.
	pub(crate) promotion: Option<PieceKind>,
}

impl From<(u8, u8, u8, u8)> for ChessMove {
	/// The move that four input bytes name. The low three bits of each byte
	/// give a coordinate, and the bits above them in the byte of the target
	/// row give the board code of a promotion piece.
	fn from(bytes: (u8, u8, u8, u8)) -> Self {
		Self {
			from_row: bytes.0 % 8,
			from_col: bytes.1 % 8,
			to_row: bytes.2 % 8,
			to_col: bytes.3 % 8,
			promotion: PieceKind::from_promotion_code(bytes.2 >> 3),
		}
	}
}

impl From<&ChessMoveRequest> for ChessMove {
	fn from(request: &ChessMoveRequest) -> Self {
		Self {
			from_row: request.from_row,
			from_col: request.from_col,
			to_row: request.to_row,
			to_col: request.to_col,
			promotion: PieceKind::from_promotion_code(request.promotion),
		}
	}
}

impl ChessMove {
	/// The move from the square `from` to the square `to`, each a row and a
	/// column, with no promotion.
	pub(crate) const fn between(from: (u8, u8), to: (u8, u8)) -> Self {
		Self { from_row: from.0, from_col: from.1, to_row: to.0, to_col: to.1, promotion: None }
	}

	/// This move, with a pawn that becomes a piece of `kind`.
	pub(crate) const fn promoting_to(self, kind: PieceKind) -> Self {
		Self { promotion: Some(kind), ..self }
	}

	/// Converts this move to the `ChessMoveRequest` that the client sends.
	pub(crate) fn to_request(self) -> ChessMoveRequest {
		ChessMoveRequest {
			from_row: self.from_row,
			from_col: self.from_col,
			to_row: self.to_row,
			to_col: self.to_col,
			promotion: self.promotion.map_or(0, u8::from),
		}
	}
}
