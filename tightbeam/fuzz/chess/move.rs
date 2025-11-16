#![allow(dead_code)]

use super::board::ChessMoveRequest;

/// Represents a chess move (pure data structure)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChessMove {
	pub(crate) from_row: u8,
	pub(crate) from_col: u8,
	pub(crate) to_row: u8,
	pub(crate) to_col: u8,
}

impl Default for ChessMove {
	fn default() -> Self {
		Self { from_row: 0, from_col: 0, to_row: 0, to_col: 0 }
	}
}

impl From<(u8, u8, u8, u8)> for ChessMove {
	fn from(bytes: (u8, u8, u8, u8)) -> Self {
		Self {
			from_row: bytes.0 % 8,
			from_col: bytes.1 % 8,
			to_row: bytes.2 % 8,
			to_col: bytes.3 % 8,
		}
	}
}

impl ChessMove {
	/// Convert to ChessMoveRequest for sending over the wire
	pub(crate) fn to_request(&self) -> ChessMoveRequest {
		ChessMoveRequest {
			from_row: self.from_row,
			from_col: self.from_col,
			to_row: self.to_row,
			to_col: self.to_col,
		}
	}
}
