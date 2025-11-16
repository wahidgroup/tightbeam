#![allow(unexpected_cfgs)]

use super::piece;
use tightbeam::matrix::{Matrix, MatrixDyn, MatrixError, MatrixLike};

/// Chess game state management
///
/// Uses Matrix<8> (8x8 chess board)
/// Turn and move count are derived from Frame.metadata.order:
/// - Turn: order % 2 == 0 = white, order % 2 == 1 = black
/// - Move count: order (monotonically incrementing)
#[derive(Clone)]
pub struct ChessGameState {
	board: Matrix<8>,       // 8x8 chess board
	last_capture_move: u64, // Track when last capture occurred
}

impl Default for ChessGameState {
	fn default() -> Self {
		Self::new()
	}
}

impl ChessGameState {
	pub fn new() -> Self {
		let mut board = Matrix::<8>::new();

		// Initialize standard chess starting position
		// White pieces (row 0-1)
		board.set(0, 0, piece::WHITE_ROOK);
		board.set(0, 1, piece::WHITE_KNIGHT);
		board.set(0, 2, piece::WHITE_BISHOP);
		board.set(0, 3, piece::WHITE_QUEEN);
		board.set(0, 4, piece::WHITE_KING);
		board.set(0, 5, piece::WHITE_BISHOP);
		board.set(0, 6, piece::WHITE_KNIGHT);
		board.set(0, 7, piece::WHITE_ROOK);
		for col in 0..8 {
			board.set(1, col, piece::WHITE_PAWN);
		}

		// Black pieces (row 6-7)
		for col in 0..8 {
			board.set(6, col, piece::BLACK_PAWN);
		}
		board.set(7, 0, piece::BLACK_ROOK);
		board.set(7, 1, piece::BLACK_KNIGHT);
		board.set(7, 2, piece::BLACK_BISHOP);
		board.set(7, 3, piece::BLACK_QUEEN);
		board.set(7, 4, piece::BLACK_KING);
		board.set(7, 5, piece::BLACK_BISHOP);
		board.set(7, 6, piece::BLACK_KNIGHT);
		board.set(7, 7, piece::BLACK_ROOK);

		Self { board, last_capture_move: 0 }
	}

	pub fn validate_move(&self, from_row: u8, from_col: u8, to_row: u8, to_col: u8, is_white_turn: bool) -> bool {
		// Basic validation: bounds checking
		if from_row >= 8 || from_col >= 8 || to_row >= 8 || to_col >= 8 {
			return false;
		}

		// Check if source square has a piece
		let piece = self.board.get(from_row, from_col);
		if piece::is_empty(piece) {
			return false;
		}

		// Check if it's the correct player's turn
		let is_white_piece = piece::is_white(piece);
		if is_white_piece != is_white_turn {
			return false;
		}

		// Check if destination square is not occupied by own piece
		let dest_piece = self.board.get(to_row, to_col);
		if !piece::is_empty(dest_piece) {
			let dest_is_white = piece::is_white(dest_piece);
			if dest_is_white == is_white_piece {
				return false; // Can't capture own piece
			}
		}

		// Piece-specific movement validation
		let row_diff = to_row as i8 - from_row as i8;
		let col_diff = to_col as i8 - from_col as i8;
		let row_diff_abs = row_diff.unsigned_abs();
		let col_diff_abs = col_diff.unsigned_abs();

		match piece {
			piece::WHITE_PAWN | piece::BLACK_PAWN => {
				let _forward = if is_white_piece {
					-1i8
				} else {
					1i8
				};
				let start_row = if is_white_piece {
					1
				} else {
					6
				};

				// Pawn moves forward only
				if (is_white_piece && row_diff >= 0) || (!is_white_piece && row_diff <= 0) {
					return false; // Must move forward
				}

				// Capture: diagonal forward by 1
				if col_diff_abs == 1 && row_diff_abs == 1 {
					return !piece::is_empty(dest_piece); // Must capture
				}

				// Forward move: straight forward
				if col_diff_abs == 0 {
					if !piece::is_empty(dest_piece) {
						return false; // Can't capture forward
					}
					// Can move 1 or 2 squares from start row
					if from_row == start_row {
						return row_diff_abs == 1 || row_diff_abs == 2;
					} else {
						return row_diff_abs == 1;
					}
				}

				false
			}
			piece::WHITE_ROOK | piece::BLACK_ROOK => {
				// Rook moves horizontally or vertically only
				if row_diff_abs == 0 || col_diff_abs == 0 {
					// Check if path is clear
					return self.is_path_clear(from_row, from_col, to_row, to_col);
				}
				false
			}
			piece::WHITE_KNIGHT | piece::BLACK_KNIGHT => {
				// Knight moves in L-shape: 2 squares in one direction, 1 square perpendicular
				(row_diff_abs == 2 && col_diff_abs == 1) || (row_diff_abs == 1 && col_diff_abs == 2)
			}
			piece::WHITE_BISHOP | piece::BLACK_BISHOP => {
				// Bishop moves diagonally only
				if row_diff_abs == col_diff_abs {
					return self.is_path_clear(from_row, from_col, to_row, to_col);
				}
				false
			}
			piece::WHITE_QUEEN | piece::BLACK_QUEEN => {
				// Queen moves horizontally, vertically, or diagonally
				if row_diff_abs == 0 || col_diff_abs == 0 || row_diff_abs == col_diff_abs {
					return self.is_path_clear(from_row, from_col, to_row, to_col);
				}
				false
			}
			piece::WHITE_KING | piece::BLACK_KING => {
				// King moves one square in any direction
				row_diff_abs <= 1 && col_diff_abs <= 1
			}
			_ => false,
		}
	}

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
		while current_row != to_row as i8 || current_col != to_col as i8 {
			if !piece::is_empty(self.board.get(current_row as u8, current_col as u8)) {
				return false; // Path blocked
			}
			current_row += row_step;
			current_col += col_step;
		}

		true
	}

	pub fn make_move(&mut self, from_row: u8, from_col: u8, to_row: u8, to_col: u8) {
		let piece = self.board.get(from_row, from_col);
		let captured_piece = self.board.get(to_row, to_col);
		self.board.set(to_row, to_col, piece);
		self.board.set(from_row, from_col, piece::EMPTY);
		// Track captures for endgame detection
		if !piece::is_empty(captured_piece) {
			// This will be updated by the caller with the actual move count
		}
	}

	pub fn make_move_with_count(&mut self, from_row: u8, from_col: u8, to_row: u8, to_col: u8, move_count: u64) {
		let captured_piece = self.board.get(to_row, to_col);
		self.make_move(from_row, from_col, to_row, to_col);
		if !piece::is_empty(captured_piece) {
			self.last_capture_move = move_count;
		}
	}

	pub fn count_pieces(&self) -> usize {
		// Count non-empty squares (excluding kings which are always present)
		let mut count = 0;
		for row in 0..8 {
			for col in 0..8 {
				let piece = self.board.get(row, col);
				if !piece::is_empty(piece) && piece != piece::WHITE_KING && piece != piece::BLACK_KING {
					count += 1;
				}
			}
		}
		count
	}

	pub fn should_force_endgame(&self, move_count: u64) -> bool {
		// Force endgame if:
		// - Game has gone 10+ moves (very aggressive)
		// - (No captures in last 5 moves OR still many pieces on board)
		// Very aggressive thresholds to activate early and frequently
		let moves_since_capture = move_count.saturating_sub(self.last_capture_move);
		move_count > 10 && (moves_since_capture > 5 || self.count_pieces() > 12)
	}

	pub fn evaluate_move_for_endgame(
		&self,
		from_row: u8,
		from_col: u8,
		to_row: u8,
		to_col: u8,
		is_white_turn: bool,
	) -> u32 {
		// Score moves for endgame-forcing potential
		// Higher score = better for forcing endgame
		let mut score = 0u32;

		// Prefer captures (trading pieces simplifies the board)
		let dest_piece = self.board.get(to_row, to_col);
		if !piece::is_empty(dest_piece) {
			// Prefer capturing valuable pieces (queen > rook > bishop/knight > pawn)
			score += match dest_piece {
				piece::WHITE_QUEEN | piece::BLACK_QUEEN => 100,
				piece::WHITE_ROOK | piece::BLACK_ROOK => 50,
				piece::WHITE_BISHOP | piece::BLACK_BISHOP | piece::WHITE_KNIGHT | piece::BLACK_KNIGHT => 30,
				piece::WHITE_PAWN | piece::BLACK_PAWN => 10,
				_ => 0,
			};
		}

		// Prefer moves that put opponent in check (creates checkmate opportunities)
		let mut test_state = self.clone();
		test_state.make_move(from_row, from_col, to_row, to_col);
		if test_state.is_in_check(!is_white_turn) {
			score += 20; // Bonus for putting opponent in check
		}

		// Prefer moving pieces toward center/opponent (more aggressive)
		// This is a simple heuristic - moves toward opponent's side
		if is_white_turn {
			if to_row < 4 {
				score += 5; // Moving toward black's side
			}
		} else if to_row > 3 {
			score += 5; // Moving toward white's side
		}

		score
	}

	fn find_king(&self, is_white: bool) -> Option<(u8, u8)> {
		let king_piece = if is_white {
			piece::WHITE_KING
		} else {
			piece::BLACK_KING
		};

		for row in 0..8 {
			for col in 0..8 {
				if self.board.get(row, col) == king_piece {
					return Some((row, col));
				}
			}
		}
		None
	}

	fn can_attack_square(&self, target_row: u8, target_col: u8, attacker_is_white: bool) -> bool {
		// Check if any piece of the attacker's color can attack the target square
		for row in 0..8 {
			for col in 0..8 {
				let piece = self.board.get(row, col);
				if piece::is_empty(piece) {
					continue;
				}

				let piece_is_white = piece::is_white(piece);
				if piece_is_white != attacker_is_white {
					continue; // Not attacker's piece
				}

				// Check if this piece can attack the target square
				if self.can_piece_attack_square(row, col, target_row, target_col, piece) {
					return true;
				}
			}
		}
		false
	}

	fn can_piece_attack_square(&self, from_row: u8, from_col: u8, to_row: u8, to_col: u8, piece: u8) -> bool {
		// Check if this specific piece can attack the target square
		// This is similar to validate_move but doesn't check turn or destination occupancy
		let row_diff = to_row as i8 - from_row as i8;
		let col_diff = to_col as i8 - from_col as i8;
		let row_diff_abs = row_diff.unsigned_abs();
		let col_diff_abs = col_diff.unsigned_abs();

		match piece {
			piece::WHITE_PAWN | piece::BLACK_PAWN => {
				let is_white_piece = piece::is_white(piece);
				// Pawns attack diagonally forward
				row_diff_abs == 1
					&& col_diff_abs == 1
					&& ((is_white_piece && row_diff < 0) || (!is_white_piece && row_diff > 0))
			}
			piece::WHITE_ROOK | piece::BLACK_ROOK => {
				// Rook attacks horizontally or vertically
				if (row_diff_abs == 0 || col_diff_abs == 0) && (row_diff_abs > 0 || col_diff_abs > 0) {
					return self.is_path_clear(from_row, from_col, to_row, to_col);
				}
				false
			}
			piece::WHITE_KNIGHT | piece::BLACK_KNIGHT => {
				// Knight attacks in L-shape
				(row_diff_abs == 2 && col_diff_abs == 1) || (row_diff_abs == 1 && col_diff_abs == 2)
			}
			piece::WHITE_BISHOP | piece::BLACK_BISHOP => {
				// Bishop attacks diagonally
				if row_diff_abs == col_diff_abs && row_diff_abs > 0 {
					return self.is_path_clear(from_row, from_col, to_row, to_col);
				}
				false
			}
			piece::WHITE_QUEEN | piece::BLACK_QUEEN => {
				// Queen attacks horizontally, vertically, or diagonally
				if (row_diff_abs == 0 || col_diff_abs == 0 || row_diff_abs == col_diff_abs)
					&& (row_diff_abs > 0 || col_diff_abs > 0)
				{
					return self.is_path_clear(from_row, from_col, to_row, to_col);
				}
				false
			}
			piece::WHITE_KING | piece::BLACK_KING => {
				// King attacks one square in any direction
				row_diff_abs <= 1 && col_diff_abs <= 1 && (row_diff_abs > 0 || col_diff_abs > 0)
			}
			_ => false,
		}
	}

	pub fn is_in_check(&self, is_white_turn: bool) -> bool {
		// Find the king's position
		let king_pos = match self.find_king(is_white_turn) {
			Some(pos) => pos,
			None => return false, // No king found (shouldn't happen in valid game)
		};

		// Check if any opponent piece can attack the king's square
		self.can_attack_square(king_pos.0, king_pos.1, !is_white_turn)
	}

	pub fn would_move_leave_king_in_check(
		&mut self,
		from_row: u8,
		from_col: u8,
		to_row: u8,
		to_col: u8,
		is_white_turn: bool,
	) -> bool {
		// Temporarily make the move and check if king is in check
		// This is more efficient than cloning the entire state
		let piece = self.board.get(from_row, from_col);
		let dest_piece = self.board.get(to_row, to_col);

		// Make the move temporarily
		self.board.set(to_row, to_col, piece);
		self.board.set(from_row, from_col, piece::EMPTY);

		// Check if king is in check
		let in_check = self.is_in_check(is_white_turn);

		// Restore the board
		self.board.set(from_row, from_col, piece);
		self.board.set(to_row, to_col, dest_piece);

		in_check
	}

	pub fn get_valid_moves(&mut self, is_white_turn: bool) -> Vec<(u8, u8, u8, u8)> {
		// Generate all valid moves for current player
		// A move is valid if it:
		// 1. Follows piece movement rules
		// 2. Doesn't leave the king in check
		let mut moves = Vec::new();
		for from_row in 0..8 {
			for from_col in 0..8 {
				let piece = self.board.get(from_row, from_col);
				if piece::is_empty(piece) {
					continue;
				}

				let is_white_piece = piece::is_white(piece);
				if is_white_piece != is_white_turn {
					continue; // Not current player's piece
				}

				// Try all possible destination squares
				for to_row in 0..8 {
					for to_col in 0..8 {
						if self.validate_move(from_row, from_col, to_row, to_col, is_white_turn) {
							// Check if this move would leave the king in check
							// Use a mutable reference to temporarily modify the board
							if !self.would_move_leave_king_in_check(from_row, from_col, to_row, to_col, is_white_turn) {
								moves.push((from_row, from_col, to_row, to_col));
							}
						}
					}
				}
			}
		}
		moves
	}

	pub fn is_stalemate(&mut self, is_white_turn: bool, _move_count: u64) -> bool {
		// Stalemate: no valid moves available AND king is NOT in check
		self.get_valid_moves(is_white_turn).is_empty() && !self.is_in_check(is_white_turn)
	}

	pub fn is_checkmate(&mut self, is_white_turn: bool, _move_count: u64) -> bool {
		// Checkmate: no valid moves available AND king IS in check
		self.get_valid_moves(is_white_turn).is_empty() && self.is_in_check(is_white_turn)
	}

	pub fn board(&self) -> &Matrix<8> {
		&self.board
	}

	pub fn board_mut(&mut self) -> &mut Matrix<8> {
		&mut self.board
	}

	pub fn last_capture_move(&self) -> u64 {
		self.last_capture_move
	}

	pub fn set_last_capture_move(&mut self, move_count: u64) {
		self.last_capture_move = move_count;
	}
}

impl From<&ChessGameState> for tightbeam::Asn1Matrix {
	fn from(state: &ChessGameState) -> Self {
		// Encode Matrix<8>: board only (8x8 chess board)
		let mut data = Vec::with_capacity(64);
		for row in 0..8 {
			for col in 0..8 {
				data.push(state.board.get(row, col));
			}
		}

		Self { n: 8, data }
	}
}

impl TryFrom<&tightbeam::Asn1Matrix> for ChessGameState {
	type Error = tightbeam::TightBeamError;

	fn try_from(matrix: &tightbeam::Asn1Matrix) -> Result<Self, Self::Error> {
		// Require Matrix<8> format (8x8 chess board)
		if matrix.n != 8 || matrix.data.len() != 64 {
			return Err(tightbeam::TightBeamError::InvalidBody);
		}

		let mut board = Matrix::<8>::new();
		for row in 0..8 {
			for col in 0..8 {
				let idx = (row as usize * 8) + col as usize;
				board.set(row, col, matrix.data[idx]);
			}
		}

		Ok(Self {
			board,
			last_capture_move: 0, // Initialize - will be updated as moves are made
		})
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

pub fn piece_kind_for_move(state: &ChessGameState, row: u8, col: u8) -> Option<&'static str> {
	let piece = state.board().get(row, col);
	super::piece::kind_label(piece)
}
