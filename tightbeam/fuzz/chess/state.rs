#![allow(unexpected_cfgs)]

use tightbeam::matrix::{Matrix, MatrixDyn, MatrixError, MatrixLike};
use tightbeam::urn::Urn;

use super::board::ChessMoveError;
use super::constants::MAX_MOVES_TO_FIND;
use super::piece;
use super::r#move::ChessMove;

/// The chess board of one game.
///
/// A `Matrix<8>` holds the 8x8 board, one piece code for each square, and
/// `ChessMatchManager` counts the moves at the protocol level.
#[derive(Clone)]
pub struct ChessGameState {
	board: Matrix<8>, // Row 0 is White's back row.
}

impl Default for ChessGameState {
	fn default() -> Self {
		Self::new()
	}
}

impl ChessGameState {
	pub fn new() -> Self {
		let mut board = Matrix::<8>::new();

		// The standard starting position puts White on rows 0 and 1.
		board.set(0, 0, piece::WHITE_ROOK.into());
		board.set(0, 1, piece::WHITE_KNIGHT.into());
		board.set(0, 2, piece::WHITE_BISHOP.into());
		board.set(0, 3, piece::WHITE_QUEEN.into());
		board.set(0, 4, piece::WHITE_KING.into());
		board.set(0, 5, piece::WHITE_BISHOP.into());
		board.set(0, 6, piece::WHITE_KNIGHT.into());
		board.set(0, 7, piece::WHITE_ROOK.into());

		for col in 0..8 {
			board.set(1, col, piece::WHITE_PAWN.into());
		}

		// Black starts on rows 6 and 7.
		for col in 0..8 {
			board.set(6, col, piece::BLACK_PAWN.into());
		}

		board.set(7, 0, piece::BLACK_ROOK.into());
		board.set(7, 1, piece::BLACK_KNIGHT.into());
		board.set(7, 2, piece::BLACK_BISHOP.into());
		board.set(7, 3, piece::BLACK_QUEEN.into());
		board.set(7, 4, piece::BLACK_KING.into());
		board.set(7, 5, piece::BLACK_BISHOP.into());
		board.set(7, 6, piece::BLACK_KNIGHT.into());
		board.set(7, 7, piece::BLACK_ROOK.into());

		Self { board }
	}

	// Move generation lists the legal moves of one side.

	/// The first [`MAX_MOVES_TO_FIND`] legal moves of the side that
	/// `is_white_turn` names, in board order.
	pub(crate) fn to_valid_moves(&self, is_white_turn: bool) -> Vec<ChessMove> {
		let mut moves = Vec::new();
		for from_row in 0..8 {
			for from_col in 0..8 {
				let Some(piece) = piece::Piece::from_u8(self.board.get(from_row, from_col)) else {
					continue; // The square is empty.
				};

				if piece.is_white() != is_white_turn {
					continue; // The piece belongs to the other side.
				}

				// A candidate move is legal when it leaves the king of the
				// moving side out of check.
				let candidates = self.to_piece_moves(from_row, from_col, piece);
				for (to_row, to_col) in candidates {
					let chess_move = ChessMove { from_row, from_col, to_row, to_col };
					if !self.is_exposing_king(&chess_move, is_white_turn) {
						moves.push(chess_move);
						// The cap bounds the cost of a fuzz run.
						if moves.len() >= MAX_MOVES_TO_FIND {
							return moves;
						}
					}
				}
			}
		}
		moves
	}

	/// The legal move at index `seed % count` of [`Self::to_valid_moves`], or
	/// `None` when the side has no legal move (checkmate or stalemate).
	pub(crate) fn to_random_valid_move(&self, is_white_turn: bool, seed: u64) -> Option<ChessMove> {
		let valid_moves = self.to_valid_moves(is_white_turn);
		if valid_moves.is_empty() {
			return None;
		}

		// The seed picks the move, so a fuzz input replays the same game.
		let index = (seed as usize) % valid_moves.len();
		Some(valid_moves[index])
	}

	/// The squares that `piece` on (`from_row`, `from_col`) can reach, before
	/// the check test.
	fn to_piece_moves(&self, from_row: u8, from_col: u8, piece: piece::Piece) -> Vec<(u8, u8)> {
		let mut candidates = Vec::new();

		match piece.kind {
			piece::PieceKind::Pawn => {
				let forward = piece.color.to_pawn_forward_direction();
				let start_row = piece.color.to_pawn_start_row();

				// A pawn steps forward onto an empty square.
				if let Some(forward_row) = Self::to_valid_coord(from_row as i8 + forward) {
					if self.is_empty(forward_row, from_col) {
						candidates.push((forward_row, from_col));
						// From its start row, a pawn may step two squares when
						// both are empty.
						if from_row == start_row {
							if let Some(double_row) = Self::to_valid_coord(from_row as i8 + forward * 2) {
								if self.is_empty(double_row, from_col) {
									candidates.push((double_row, from_col));
								}
							}
						}
					}
				}

				// A pawn captures one square diagonally forward.
				for col_offset in [-1i8, 1i8] {
					if let (Some(capture_row), Some(capture_col)) = (
						Self::to_valid_coord(from_row as i8 + forward),
						Self::to_valid_coord(from_col as i8 + col_offset),
					) {
						if self.can_capture(capture_row, capture_col, piece) {
							candidates.push((capture_row, capture_col));
						}
					}
				}
			}
			piece::PieceKind::Rook | piece::PieceKind::Bishop | piece::PieceKind::Queen => {
				// A rook, a bishop, and a queen move along lines.
				if let Some(directions) = piece.kind.as_move_directions() {
					self.add_line_moves(&mut candidates, from_row, from_col, piece, directions);
				}
			}
			piece::PieceKind::Knight => {
				// A knight jumps to fixed offsets.
				if let Some(offsets) = piece.kind.as_move_offsets() {
					for (row_offset, col_offset) in offsets.iter().copied() {
						self.try_add_move(&mut candidates, from_row, from_col, row_offset, col_offset, piece);
					}
				}
			}
			piece::PieceKind::King => {
				// A king steps to one of the eight adjacent squares.
				for row_offset in -1..=1 {
					for col_offset in -1..=1 {
						if row_offset == 0 && col_offset == 0 {
							continue;
						}
						self.try_add_move(&mut candidates, from_row, from_col, row_offset, col_offset, piece);
					}
				}
			}
		}

		candidates
	}

	/// The coordinate `coord` as a `u8`, or `None` when it is off the board,
	/// outside `0..8`.
	fn to_valid_coord(coord: i8) -> Option<u8> {
		if (0..8).contains(&coord) {
			Some(coord as u8)
		} else {
			None
		}
	}

	/// Whether the square is empty.
	fn is_empty(&self, row: u8, col: u8) -> bool {
		piece::Piece::from_u8(self.board.get(row, col)).is_none()
	}

	/// Whether the square holds a piece of the other side, which `piece` can
	/// capture.
	fn can_capture(&self, row: u8, col: u8, piece: piece::Piece) -> bool {
		if let Some(dest_piece) = piece::Piece::from_u8(self.board.get(row, col)) {
			dest_piece.color != piece.color
		} else {
			false
		}
	}

	/// Whether `piece` can move to the square, which is empty or holds a piece
	/// of the other side.
	fn can_move_to(&self, row: u8, col: u8, piece: piece::Piece) -> bool {
		if let Some(dest_piece) = piece::Piece::from_u8(self.board.get(row, col)) {
			dest_piece.color != piece.color
		} else {
			true // The square is empty.
		}
	}

	/// Adds the square at the offset from (`from_row`, `from_col`) when it is
	/// on the board and `piece` can move to it.
	fn try_add_move(
		&self,
		candidates: &mut Vec<(u8, u8)>,
		from_row: u8,
		from_col: u8,
		row_offset: i8,
		col_offset: i8,
		piece: piece::Piece,
	) {
		if let (Some(to_row), Some(to_col)) = (
			Self::to_valid_coord(from_row as i8 + row_offset),
			Self::to_valid_coord(from_col as i8 + col_offset),
		) {
			if self.can_move_to(to_row, to_col, piece) {
				candidates.push((to_row, to_col));
			}
		}
	}

	/// Adds every square along each of `directions` up to the first piece, and
	/// the square of that piece when `piece` can capture it.
	fn add_line_moves(
		&self,
		candidates: &mut Vec<(u8, u8)>,
		from_row: u8,
		from_col: u8,
		piece: piece::Piece,
		directions: impl AsRef<[(i8, i8)]>,
	) {
		let directions = directions.as_ref();
		for &(row_step, col_step) in directions {
			let mut current_row = from_row as i8;
			let mut current_col = from_col as i8;

			loop {
				current_row += row_step;
				current_col += col_step;

				let Some(to_row) = Self::to_valid_coord(current_row) else {
					break; // The line leaves the board.
				};
				let Some(to_col) = Self::to_valid_coord(current_col) else {
					break; // The line leaves the board.
				};

				if self.is_empty(to_row, to_col) {
					candidates.push((to_row, to_col));
				} else {
					// A piece of the other side is a capture.
					if self.can_capture(to_row, to_col, piece) {
						candidates.push((to_row, to_col));
					}
					break; // Any piece ends the line.
				}
			}
		}
	}

	// Move validation checks one requested move.

	/// Checks `chess_move` for the side that `is_white_turn` names, as
	/// [`Self::is_move_valid`] decides it.
	///
	/// # Errors
	///
	/// - [`ChessMoveError::InvalidMove`] -- the move is illegal on this board.
	pub(crate) fn check_move(&self, chess_move: &ChessMove, is_white_turn: bool) -> Result<(), ChessMoveError> {
		if !self.is_move_valid(chess_move, is_white_turn) {
			return Err(ChessMoveError::InvalidMove);
		}

		Ok(())
	}

	/// Whether `chess_move` is legal on this board for the side that
	/// `is_white_turn` names.
	pub(crate) fn is_move_valid(&self, chess_move: &ChessMove, is_white_turn: bool) -> bool {
		// Every coordinate must be on the board.
		if chess_move.from_row >= 8 || chess_move.from_col >= 8 || chess_move.to_row >= 8 || chess_move.to_col >= 8 {
			return false;
		}

		// The source square must hold a piece.
		let Some(piece) = piece::Piece::from_u8(self.board.get(chess_move.from_row, chess_move.from_col)) else {
			return false;
		};

		// The piece must belong to the side to move.
		if piece.is_white() != is_white_turn {
			return false;
		}

		// A move onto a piece of the same side is illegal.
		if let Some(dest_piece) = piece::Piece::from_u8(self.board.get(chess_move.to_row, chess_move.to_col)) {
			if dest_piece.color == piece.color {
				return false; // The square holds a piece of the same side.
			}
		}

		// Each kind of piece moves by its own rule.
		let row_diff = chess_move.to_row as i8 - chess_move.from_row as i8;
		let col_diff = chess_move.to_col as i8 - chess_move.from_col as i8;
		let row_diff_abs = row_diff.unsigned_abs();
		let col_diff_abs = col_diff.unsigned_abs();

		let piece_valid = match piece.kind {
			piece::PieceKind::Pawn => {
				// A pawn may make the moves that generation lists for it, so
				// the two agree on its direction, its double step, and its
				// capture.
				let candidates = self.to_piece_moves(chess_move.from_row, chess_move.from_col, piece);
				candidates.contains(&(chess_move.to_row, chess_move.to_col))
			}
			piece::PieceKind::Rook => {
				// A rook moves along a row or a column, over empty squares.
				if row_diff_abs == 0 || col_diff_abs == 0 {
					self.is_path_clear(chess_move.from_row, chess_move.from_col, chess_move.to_row, chess_move.to_col)
				} else {
					false
				}
			}
			piece::PieceKind::Knight => {
				// A knight moves two squares one way and one square across.
				(row_diff_abs == 2 && col_diff_abs == 1) || (row_diff_abs == 1 && col_diff_abs == 2)
			}
			piece::PieceKind::Bishop => {
				// A bishop moves along a diagonal, over empty squares.
				if row_diff_abs == col_diff_abs {
					self.is_path_clear(chess_move.from_row, chess_move.from_col, chess_move.to_row, chess_move.to_col)
				} else {
					false
				}
			}
			piece::PieceKind::Queen => {
				// A queen moves along a row, a column, or a diagonal, over
				// empty squares.
				if row_diff_abs == 0 || col_diff_abs == 0 || row_diff_abs == col_diff_abs {
					self.is_path_clear(chess_move.from_row, chess_move.from_col, chess_move.to_row, chess_move.to_col)
				} else {
					false
				}
			}
			piece::PieceKind::King => {
				// A king moves one square in any direction.
				row_diff_abs <= 1 && col_diff_abs <= 1
			}
		};

		if !piece_valid {
			return false;
		}

		// A move that leaves the king of the moving side in check is illegal.
		!self.is_exposing_king(chess_move, is_white_turn)
	}

	/// Whether `chess_move` leaves the king of the moving side in check.
	fn is_exposing_king(&self, chess_move: &ChessMove, is_white_turn: bool) -> bool {
		// The board after the move decides, so a line that the move opens
		// counts, and a piece that the move captures stops its attack.
		let mut after = self.clone();
		after.apply_move(chess_move);

		after.is_in_check(is_white_turn)
	}

	/// Whether every square strictly between the two squares is empty.
	fn is_path_clear(&self, from_row: u8, from_col: u8, to_row: u8, to_col: u8) -> bool {
		let row_step = if to_row > from_row {
			1
		} else if to_row < from_row {
			-1
		} else {
			0
		};
		let col_step = if to_col > from_col {
			1
		} else if to_col < from_col {
			-1
		} else {
			0
		};

		let mut current_row = from_row as i8 + row_step;
		let mut current_col = from_col as i8 + col_step;
		let mut iterations = 0;
		const MAX_ITERATIONS: i32 = 8; // A bound past the longest line on the board.

		while (current_row != to_row as i8 || current_col != to_col as i8) && iterations < MAX_ITERATIONS {
			iterations += 1;

			// The conversion keeps each read on the board.
			let Some(cr) = Self::to_valid_coord(current_row) else {
				return false; // A path off the board is blocked.
			};
			let Some(cc) = Self::to_valid_coord(current_col) else {
				return false; // A path off the board is blocked.
			};

			if piece::Piece::from_u8(self.board.get(cr, cc)).is_some() {
				return false; // A piece blocks the path.
			}

			current_row += row_step;
			current_col += col_step;
		}

		// A path that reaches the iteration bound is blocked.
		if iterations >= MAX_ITERATIONS {
			return false;
		}

		true
	}

	/// Whether a piece of the side that `attacker_is_white` names attacks the
	/// target square.
	pub(crate) fn can_attack_square(&self, target_row: u8, target_col: u8, attacker_is_white: bool) -> bool {
		for row in 0..8 {
			for col in 0..8 {
				let Some(piece) = piece::Piece::from_u8(self.board.get(row, col)) else {
					continue;
				};

				if piece.is_white() != attacker_is_white {
					continue; // The piece belongs to the other side.
				}

				if self.can_piece_attack_square(row, col, target_row, target_col, piece) {
					return true;
				}
			}
		}
		false
	}

	/// Whether `piece` on (`from_row`, `from_col`) attacks the square
	/// (`to_row`, `to_col`).
	fn can_piece_attack_square(&self, from_row: u8, from_col: u8, to_row: u8, to_col: u8, piece: piece::Piece) -> bool {
		// Unlike `is_move_valid`, the test reads only the geometry and the
		// path, so it holds for either side to move and any piece on the target
		// square.
		let row_diff = to_row as i8 - from_row as i8;
		let col_diff = to_col as i8 - from_col as i8;
		let row_diff_abs = row_diff.unsigned_abs();
		let col_diff_abs = col_diff.unsigned_abs();

		match piece.kind {
			piece::PieceKind::Pawn => {
				// A pawn attacks one square diagonally forward.
				row_diff_abs == 1 && col_diff_abs == 1 && row_diff == piece.color.to_pawn_forward_direction()
			}
			piece::PieceKind::Rook => {
				// A rook attacks along a row or a column, over empty squares.
				if (row_diff_abs == 0 || col_diff_abs == 0) && (row_diff_abs > 0 || col_diff_abs > 0) {
					self.is_path_clear(from_row, from_col, to_row, to_col)
				} else {
					false
				}
			}
			piece::PieceKind::Knight => {
				// A knight attacks two squares one way and one square across.
				(row_diff_abs == 2 && col_diff_abs == 1) || (row_diff_abs == 1 && col_diff_abs == 2)
			}
			piece::PieceKind::Bishop => {
				// A bishop attacks along a diagonal, over empty squares.
				if row_diff_abs == col_diff_abs && row_diff_abs > 0 {
					self.is_path_clear(from_row, from_col, to_row, to_col)
				} else {
					false
				}
			}
			piece::PieceKind::Queen => {
				// A queen attacks along a row, a column, or a diagonal, over
				// empty squares.
				if (row_diff_abs == 0 || col_diff_abs == 0 || row_diff_abs == col_diff_abs)
					&& (row_diff_abs > 0 || col_diff_abs > 0)
				{
					self.is_path_clear(from_row, from_col, to_row, to_col)
				} else {
					false
				}
			}
			piece::PieceKind::King => {
				// A king attacks the eight adjacent squares.
				row_diff_abs <= 1 && col_diff_abs <= 1 && (row_diff_abs > 0 || col_diff_abs > 0)
			}
		}
	}

	// Move application updates the board.

	/// Moves the piece on the source square of `chess_move` to its target
	/// square and empties the source square.
	pub(crate) fn apply_move(&mut self, chess_move: &ChessMove) {
		let piece = self.board.get(chess_move.from_row, chess_move.from_col);
		self.board_mut().set(chess_move.to_row, chess_move.to_col, piece);
		self.board_mut().set(chess_move.from_row, chess_move.from_col, 0u8); // The source square empties.
	}

	// Game state queries read check, checkmate, and stalemate.

	/// Whether the king of the side that `is_white_turn` names is in check.
	pub fn is_in_check(&self, is_white_turn: bool) -> bool {
		let king_pos = match self.find_king(is_white_turn) {
			Some(pos) => pos,
			None => return false, // A legal game holds both kings.
		};

		// A side is in check when a piece of the other side attacks its king.
		self.can_attack_square(king_pos.0, king_pos.1, !is_white_turn)
	}

	/// Whether the side that `is_white_turn` names is in stalemate.
	pub fn is_stalemate(&self, is_white_turn: bool) -> bool {
		// A side in stalemate has no legal move, and its king is out of check.
		self.to_valid_moves(is_white_turn).is_empty() && !self.is_in_check(is_white_turn)
	}

	/// Whether the side that `is_white_turn` names is in checkmate.
	pub fn is_checkmate(&self, is_white_turn: bool) -> bool {
		// A side in checkmate has no legal move, and its king is in check.
		self.to_valid_moves(is_white_turn).is_empty() && self.is_in_check(is_white_turn)
	}

	/// The game status of the side that `is_white_turn` names, from its legal
	/// moves and its check.
	pub(crate) fn determine_game_status(&self, is_white_turn: bool) -> super::board::GameStatusCode {
		let valid_moves = self.to_valid_moves(is_white_turn);
		let is_in_check = self.is_in_check(is_white_turn);

		if valid_moves.is_empty() && is_in_check {
			super::board::GameStatusCode::Checkmate
		} else if valid_moves.is_empty() {
			super::board::GameStatusCode::Stalemate
		} else {
			super::board::GameStatusCode::InProgress
		}
	}

	// Accessors read and write the board.

	pub fn count_pieces(&self) -> usize {
		// The count skips both kings, which every legal game holds.
		let mut count = 0;
		for row in 0..8 {
			for col in 0..8 {
				if let Some(piece) = piece::Piece::from_u8(self.board.get(row, col)) {
					if piece.kind != piece::PieceKind::King {
						count += 1;
					}
				}
			}
		}
		count
	}

	/// The square of the king of the side that `is_white` names, or `None` when
	/// the board holds no such king.
	pub(crate) fn find_king(&self, is_white: bool) -> Option<(u8, u8)> {
		let king_piece = if is_white {
			piece::WHITE_KING
		} else {
			piece::BLACK_KING
		};
		let king_u8: u8 = king_piece.into();

		for row in 0..8 {
			for col in 0..8 {
				if self.board.get(row, col) == king_u8 {
					return Some((row, col));
				}
			}
		}
		None
	}

	pub fn board(&self) -> &Matrix<8> {
		&self.board
	}

	pub fn board_mut(&mut self) -> &mut Matrix<8> {
		&mut self.board
	}

	/// The kind event URN of the piece on the square, or `None` for an empty
	/// square.
	pub(crate) fn piece_kind_at(&self, row: u8, col: u8) -> Option<Urn<'static>> {
		piece::Piece::from_u8(self.board.get(row, col)).map(|p| p.as_kind_event())
	}

	/// Replaces the board with the piece codes of `matrix`.
	///
	/// # Errors
	///
	/// - [`tightbeam::TightBeamError::InvalidBody`] -- `matrix` is not 8x8.
	#[allow(dead_code)]
	pub(crate) fn update_board_from_matrix(&mut self, matrix: &MatrixDyn) -> Result<(), tightbeam::TightBeamError> {
		// The board is 8x8, and the constructor of `MatrixDyn` already holds
		// `data.len() == n * n`, so the dimension is the whole check.
		if matrix.n() != 8 {
			return Err(tightbeam::TightBeamError::InvalidBody);
		}

		for row in 0..8 {
			for col in 0..8 {
				self.board_mut().set(row, col, matrix.get(row, col));
			}
		}

		Ok(())
	}
}

impl TryFrom<&ChessGameState> for MatrixDyn {
	type Error = MatrixError;

	fn try_from(state: &ChessGameState) -> Result<Self, Self::Error> {
		let mut matrix = MatrixDyn::try_from(8u8)?;
		for row in 0..8 {
			for col in 0..8 {
				matrix.set(row, col, state.board().get(row, col));
			}
		}

		Ok(matrix)
	}
}

#[cfg(test)]
mod tests {
	use tightbeam::tb_cases;

	use super::*;

	/// A board that holds `pieces` and nothing else.
	fn position(pieces: &[(u8, u8, piece::Piece)]) -> ChessGameState {
		let mut board = Matrix::<8>::new();
		for &(row, col, piece) in pieces {
			board.set(row, col, piece.into());
		}

		ChessGameState { board }
	}

	// A pawn on its start row opens one or two squares toward the other side.
	tb_cases! {
		fn a_pawn_opening_is_legal((opening, is_white_turn): (ChessMove, bool)) -> Result<(), ChessMoveError> {
			ChessGameState::new().check_move(&opening, is_white_turn)?;
			Ok(())
		}
		cases {
			white_one_square => (ChessMove { from_row: 1, from_col: 4, to_row: 2, to_col: 4 }, true),
			white_two_squares => (ChessMove { from_row: 1, from_col: 4, to_row: 3, to_col: 4 }, true),
			black_one_square => (ChessMove { from_row: 6, from_col: 4, to_row: 5, to_col: 4 }, false),
			black_two_squares => (ChessMove { from_row: 6, from_col: 4, to_row: 4, to_col: 4 }, false),
		}
	}

	/// The double step of a pawn passes over an empty square, so a knight on
	/// c3 blocks the pawn on c2.
	#[test]
	fn a_pawn_cannot_jump_a_piece() -> Result<(), ChessMoveError> {
		let mut state = ChessGameState::new();
		let knight_to_c3 = ChessMove { from_row: 0, from_col: 1, to_row: 2, to_col: 2 };
		state.check_move(&knight_to_c3, true)?;
		state.apply_move(&knight_to_c3);
		let over_the_knight = ChessMove { from_row: 1, from_col: 2, to_row: 3, to_col: 2 };

		let refusal = state.check_move(&over_the_knight, true);
		assert!(matches!(refusal, Err(ChessMoveError::InvalidMove)));
		Ok(())
	}

	/// A pawn that shields its king from a rook cannot leave the file to
	/// capture, so a rook that steps onto the file pins it there.
	#[test]
	fn a_pinned_pawn_cannot_capture() -> Result<(), ChessMoveError> {
		let mut state = position(&[
			(0, 4, piece::WHITE_KING),
			(1, 4, piece::WHITE_PAWN),
			(2, 3, piece::BLACK_KNIGHT),
			(7, 5, piece::BLACK_ROOK),
			(7, 0, piece::BLACK_KING),
		]);
		let pin = ChessMove { from_row: 7, from_col: 5, to_row: 7, to_col: 4 };
		state.check_move(&pin, false)?;
		state.apply_move(&pin);
		let capture = ChessMove { from_row: 1, from_col: 4, to_row: 2, to_col: 3 };

		let refusal = state.check_move(&capture, true);
		assert!(matches!(refusal, Err(ChessMoveError::InvalidMove)));
		Ok(())
	}

	/// A knight's check holds whatever stands between, so a move that leaves
	/// the king in it is illegal.
	#[test]
	fn a_move_that_ignores_a_knight_check_is_illegal() -> Result<(), ChessMoveError> {
		let mut state = position(&[
			(0, 0, piece::WHITE_ROOK),
			(0, 4, piece::WHITE_KING),
			(4, 2, piece::BLACK_KNIGHT),
			(7, 7, piece::BLACK_KING),
		]);
		let check = ChessMove { from_row: 4, from_col: 2, to_row: 2, to_col: 3 };
		state.check_move(&check, false)?;
		state.apply_move(&check);
		let rook_step = ChessMove { from_row: 0, from_col: 0, to_row: 1, to_col: 0 };

		let refusal = state.check_move(&rook_step, true);
		assert!(matches!(refusal, Err(ChessMoveError::InvalidMove)));
		Ok(())
	}

	/// A black pawn attacks the two squares diagonally toward row 0, so the
	/// white king cannot step onto either of them.
	#[test]
	fn a_king_cannot_step_into_a_pawn_attack() -> Result<(), ChessMoveError> {
		let mut state = position(&[(0, 4, piece::WHITE_KING), (3, 4, piece::BLACK_PAWN), (7, 0, piece::BLACK_KING)]);
		let advance = ChessMove { from_row: 3, from_col: 4, to_row: 2, to_col: 4 };
		state.check_move(&advance, false)?;
		state.apply_move(&advance);
		let into_the_attack = ChessMove { from_row: 0, from_col: 4, to_row: 1, to_col: 3 };

		let refusal = state.check_move(&into_the_attack, true);
		assert!(matches!(refusal, Err(ChessMoveError::InvalidMove)));
		Ok(())
	}
}
