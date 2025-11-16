#![allow(unexpected_cfgs)]

use tightbeam::matrix::{Matrix, MatrixDyn, MatrixError, MatrixLike};

use super::constants::MAX_MOVES_TO_FIND;
use super::piece;
use super::r#move::ChessMove;

/// Chess game state management
///
/// Uses Matrix<8> (8x8 chess board)
/// Move counting is handled at the protocol level (ChessMatchManager)
#[derive(Clone)]
pub struct ChessGameState {
	board: Matrix<8>, // 8x8 chess board
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

		// Black pieces (row 6-7)
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

	// ============================================================================
	// MOVE GENERATION
	// ============================================================================

	/// Generate all valid moves for current player
	pub(crate) fn to_valid_moves(&self, is_white_turn: bool) -> Vec<ChessMove> {
		let mut moves = Vec::new();
		// Iterate only through pieces that belong to current player
		for from_row in 0..8 {
			for from_col in 0..8 {
				let Some(piece) = piece::Piece::from_u8(self.board.get(from_row, from_col)) else {
					continue; // Empty square
				};

				if piece.is_white() != is_white_turn {
					continue; // Not current player's piece
				}

				// Generate candidate moves based on piece type
				// Validate each candidate move (check check)
				let candidates = self.to_piece_moves(from_row, from_col, piece);
				for (to_row, to_col) in candidates {
					let chess_move = ChessMove { from_row, from_col, to_row, to_col };
					if !self.is_exposing_king(&chess_move, is_white_turn) {
						moves.push(chess_move);
						// Early exit if we have enough moves
						if moves.len() >= MAX_MOVES_TO_FIND {
							return moves;
						}
					}
				}
			}
		}
		moves
	}

	/// Generate random valid move for current player
	/// Returns None if no valid moves exist (checkmate/stalemate)
	pub(crate) fn to_random_valid_move(&self, is_white_turn: bool, seed: u64) -> Option<ChessMove> {
		let valid_moves = self.to_valid_moves(is_white_turn);
		if valid_moves.is_empty() {
			return None;
		}

		// Deterministic selection based on seed for reproducible fuzzing
		let index = (seed as usize) % valid_moves.len();
		Some(valid_moves[index])
	}

	/// Generate candidate moves for a specific piece
	fn to_piece_moves(&self, from_row: u8, from_col: u8, piece: piece::Piece) -> Vec<(u8, u8)> {
		let mut candidates = Vec::new();

		match piece.kind {
			piece::PieceKind::Pawn => {
				let forward = piece.color.to_pawn_forward_direction();
				let start_row = piece.color.to_pawn_start_row();

				// Forward move(s)
				if let Some(forward_row) = Self::to_valid_coord(from_row as i8 + forward) {
					if self.is_empty(forward_row, from_col) {
						candidates.push((forward_row, from_col));
						// Double move from start row
						if from_row == start_row {
							if let Some(double_row) = Self::to_valid_coord(from_row as i8 + forward * 2) {
								if self.is_empty(double_row, from_col) {
									candidates.push((double_row, from_col));
								}
							}
						}
					}
				}

				// Diagonal captures
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
				// Pieces that move along lines (rook, bishop, queen)
				if let Some(directions) = piece.kind.as_move_directions() {
					self.add_line_moves(&mut candidates, from_row, from_col, piece, directions);
				}
			}
			piece::PieceKind::Knight => {
				// Knight uses fixed offsets
				if let Some(offsets) = piece.kind.as_move_offsets() {
					for (row_offset, col_offset) in offsets.iter().copied() {
						self.try_add_move(&mut candidates, from_row, from_col, row_offset, col_offset, piece);
					}
				}
			}
			piece::PieceKind::King => {
				// 8 adjacent squares
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

	/// Convert i8 coordinate to valid u8 if in bounds [0, 8)
	fn to_valid_coord(coord: i8) -> Option<u8> {
		if coord >= 0 && coord < 8 {
			Some(coord as u8)
		} else {
			None
		}
	}

	/// Check if square is empty
	fn is_empty(&self, row: u8, col: u8) -> bool {
		piece::Piece::from_u8(self.board.get(row, col)).is_none()
	}

	/// Check if square contains an opponent piece that can be captured
	fn can_capture(&self, row: u8, col: u8, piece: piece::Piece) -> bool {
		if let Some(dest_piece) = piece::Piece::from_u8(self.board.get(row, col)) {
			dest_piece.color != piece.color
		} else {
			false
		}
	}

	/// Check if square is valid for a move (empty or contains opponent piece)
	fn can_move_to(&self, row: u8, col: u8, piece: piece::Piece) -> bool {
		if let Some(dest_piece) = piece::Piece::from_u8(self.board.get(row, col)) {
			dest_piece.color != piece.color
		} else {
			true // Empty square
		}
	}

	/// Try to add a move if coordinates are valid and square is moveable
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

	/// Add moves along a line (for rook, bishop, queen)
	fn add_line_moves(
		&self,
		candidates: &mut Vec<(u8, u8)>,
		from_row: u8,
		from_col: u8,
		piece: piece::Piece,
		directions: &[(i8, i8)],
	) {
		for &(row_step, col_step) in directions {
			let mut current_row = from_row as i8;
			let mut current_col = from_col as i8;

			loop {
				current_row += row_step;
				current_col += col_step;

				let Some(to_row) = Self::to_valid_coord(current_row) else {
					break; // Out of bounds
				};
				let Some(to_col) = Self::to_valid_coord(current_col) else {
					break; // Out of bounds
				};

				if self.is_empty(to_row, to_col) {
					candidates.push((to_row, to_col));
				} else {
					// Can capture opponent piece, then stop
					if self.can_capture(to_row, to_col, piece) {
						candidates.push((to_row, to_col));
					}
					break; // Blocked by any piece
				}
			}
		}
	}

	// ============================================================================
	// MOVE VALIDATION
	// ============================================================================

	/// Check if move is valid for the given game state
	pub(crate) fn is_move_valid(&self, chess_move: &ChessMove, is_white_turn: bool) -> bool {
		// Basic validation: bounds checking
		if chess_move.from_row >= 8 || chess_move.from_col >= 8 || chess_move.to_row >= 8 || chess_move.to_col >= 8 {
			return false;
		}

		// Check if source square has a piece
		let Some(piece) = piece::Piece::from_u8(self.board.get(chess_move.from_row, chess_move.from_col)) else {
			return false;
		};

		// Check if it's the correct player's turn
		if piece.is_white() != is_white_turn {
			return false;
		}

		// Check if destination square is not occupied by own piece
		if let Some(dest_piece) = piece::Piece::from_u8(self.board.get(chess_move.to_row, chess_move.to_col)) {
			if dest_piece.color == piece.color {
				return false; // Can't capture own piece
			}
		}

		// Piece-specific movement validation
		let row_diff = chess_move.to_row as i8 - chess_move.from_row as i8;
		let col_diff = chess_move.to_col as i8 - chess_move.from_col as i8;
		let row_diff_abs = row_diff.unsigned_abs();
		let col_diff_abs = col_diff.unsigned_abs();

		let piece_valid = match piece.kind {
			piece::PieceKind::Pawn => {
				// Pawn moves forward only
				if (piece.is_white() && row_diff >= 0) || (!piece.is_white() && row_diff <= 0) {
					return false; // Must move forward
				}

				// Capture: diagonal forward by 1
				if col_diff_abs == 1 && row_diff_abs == 1 {
					return piece::Piece::from_u8(self.board.get(chess_move.to_row, chess_move.to_col)).is_some();
					// Must capture
				}

				// Forward move: straight forward
				if col_diff_abs == 0 {
					if piece::Piece::from_u8(self.board.get(chess_move.to_row, chess_move.to_col)).is_some() {
						return false; // Can't capture forward
					}
					// Can move 1 or 2 squares from start row
					if chess_move.from_row == piece.color.to_pawn_start_row() {
						row_diff_abs == 1 || row_diff_abs == 2
					} else {
						row_diff_abs == 1
					}
				} else {
					false
				}
			}
			piece::PieceKind::Rook => {
				// Rook moves horizontally or vertically only
				if row_diff_abs == 0 || col_diff_abs == 0 {
					// Check if path is clear
					self.is_path_clear(chess_move.from_row, chess_move.from_col, chess_move.to_row, chess_move.to_col)
				} else {
					false
				}
			}
			piece::PieceKind::Knight => {
				// Knight moves in L-shape: 2 squares in one direction, 1 square perpendicular
				(row_diff_abs == 2 && col_diff_abs == 1) || (row_diff_abs == 1 && col_diff_abs == 2)
			}
			piece::PieceKind::Bishop => {
				// Bishop moves diagonally only
				if row_diff_abs == col_diff_abs {
					self.is_path_clear(chess_move.from_row, chess_move.from_col, chess_move.to_row, chess_move.to_col)
				} else {
					false
				}
			}
			piece::PieceKind::Queen => {
				// Queen moves horizontally, vertically, or diagonally
				if row_diff_abs == 0 || col_diff_abs == 0 || row_diff_abs == col_diff_abs {
					self.is_path_clear(chess_move.from_row, chess_move.from_col, chess_move.to_row, chess_move.to_col)
				} else {
					false
				}
			}
			piece::PieceKind::King => {
				// King moves one square in any direction
				row_diff_abs <= 1 && col_diff_abs <= 1
			}
		};

		if !piece_valid {
			return false;
		}

		// Check if move would expose king to check
		!self.is_exposing_king(chess_move, is_white_turn)
	}

	/// Check if this move would expose the king to check
	fn is_exposing_king(&self, chess_move: &ChessMove, is_white_turn: bool) -> bool {
		// Check if king would be in check after making this move
		// We simulate the move by checking with modified square values
		let Some(piece) = piece::Piece::from_u8(self.board.get(chess_move.from_row, chess_move.from_col)) else {
			return false;
		};
		let piece_u8: u8 = piece.into();
		let attacker_is_white = !is_white_turn;

		// Find the king's position (may change if moving the king)
		let king_pos = match self.find_king(is_white_turn) {
			Some(pos) => pos,
			None => return false, // No king found
		};

		// If moving the king, check the destination square
		let target_row = if king_pos.0 == chess_move.from_row && king_pos.1 == chess_move.from_col {
			chess_move.to_row
		} else {
			king_pos.0
		};
		let target_col = if king_pos.0 == chess_move.from_row && king_pos.1 == chess_move.from_col {
			chess_move.to_col
		} else {
			king_pos.1
		};

		// Check if any opponent piece can attack the king's square
		// Account for the temporary move: from square is empty, to square has the piece
		self.can_attack_square_with_move(
			target_row,
			target_col,
			attacker_is_white,
			chess_move.from_row,
			chess_move.from_col,
			chess_move.to_row,
			chess_move.to_col,
			piece_u8,
		)
	}

	/// Check if path is clear between two squares
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
			if piece::Piece::from_u8(self.board.get(current_row as u8, current_col as u8)).is_some() {
				return false; // Path blocked
			}
			current_row += row_step;
			current_col += col_step;
		}

		true
	}

	/// Check if a square can be attacked by opponent pieces
	pub(crate) fn can_attack_square(&self, target_row: u8, target_col: u8, attacker_is_white: bool) -> bool {
		// Check if any piece of the attacker's color can attack the target square
		for row in 0..8 {
			for col in 0..8 {
				let Some(piece) = piece::Piece::from_u8(self.board.get(row, col)) else {
					continue;
				};

				if piece.is_white() != attacker_is_white {
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

	/// Check if a specific piece can attack a square
	fn can_piece_attack_square(&self, from_row: u8, from_col: u8, to_row: u8, to_col: u8, piece: piece::Piece) -> bool {
		// Check if this specific piece can attack the target square
		// This is similar to validate_move but doesn't check turn or destination occupancy
		let row_diff = to_row as i8 - from_row as i8;
		let col_diff = to_col as i8 - from_col as i8;
		let row_diff_abs = row_diff.unsigned_abs();
		let col_diff_abs = col_diff.unsigned_abs();

		match piece.kind {
			piece::PieceKind::Pawn => {
				// Pawns attack diagonally forward
				row_diff_abs == 1
					&& col_diff_abs == 1
					&& ((piece.is_white() && row_diff < 0) || (!piece.is_white() && row_diff > 0))
			}
			piece::PieceKind::Rook => {
				// Rook attacks horizontally or vertically
				if (row_diff_abs == 0 || col_diff_abs == 0) && (row_diff_abs > 0 || col_diff_abs > 0) {
					self.is_path_clear(from_row, from_col, to_row, to_col)
				} else {
					false
				}
			}
			piece::PieceKind::Knight => {
				// Knight attacks in L-shape
				(row_diff_abs == 2 && col_diff_abs == 1) || (row_diff_abs == 1 && col_diff_abs == 2)
			}
			piece::PieceKind::Bishop => {
				// Bishop attacks diagonally
				if row_diff_abs == col_diff_abs && row_diff_abs > 0 {
					self.is_path_clear(from_row, from_col, to_row, to_col)
				} else {
					false
				}
			}
			piece::PieceKind::Queen => {
				// Queen attacks horizontally, vertically, or diagonally
				if (row_diff_abs == 0 || col_diff_abs == 0 || row_diff_abs == col_diff_abs)
					&& (row_diff_abs > 0 || col_diff_abs > 0)
				{
					self.is_path_clear(from_row, from_col, to_row, to_col)
				} else {
					false
				}
			}
			piece::PieceKind::King => {
				// King attacks adjacent squares
				row_diff_abs <= 1 && col_diff_abs <= 1 && (row_diff_abs > 0 || col_diff_abs > 0)
			}
		}
	}

	/// Check if a square can be attacked, accounting for a temporary move
	fn can_attack_square_with_move(
		&self,
		target_row: u8,
		target_col: u8,
		attacker_is_white: bool,
		move_from_row: u8,
		move_from_col: u8,
		move_to_row: u8,
		move_to_col: u8,
		moved_piece: u8,
	) -> bool {
		// Check all squares for attacker pieces, accounting for the temporary move
		for row in 0..8 {
			for col in 0..8 {
				// Determine what piece is actually on this square (accounting for the move)
				let piece_opt = if row == move_from_row && col == move_from_col {
					None // Piece moved from here
				} else if row == move_to_row && col == move_to_col {
					piece::Piece::from_u8(moved_piece) // Piece moved here
				} else {
					piece::Piece::from_u8(self.board.get(row, col))
				};

				let Some(piece) = piece_opt else {
					continue;
				};

				if piece.is_white() != attacker_is_white {
					continue; // Not attacker's piece
				}

				// Check if this piece can attack the target square
				// Account for the temporary move when checking path
				if self.can_piece_attack_with_move(
					row,
					col,
					piece,
					target_row,
					target_col,
					move_from_row,
					move_from_col,
					move_to_row,
					move_to_col,
					moved_piece,
				) {
					return true;
				}
			}
		}
		false
	}

	/// Check if a piece can attack a square, accounting for a temporary move
	fn can_piece_attack_with_move(
		&self,
		from_row: u8,
		from_col: u8,
		piece: piece::Piece,
		to_row: u8,
		to_col: u8,
		move_from_row: u8,
		move_from_col: u8,
		move_to_row: u8,
		move_to_col: u8,
		moved_piece: u8,
	) -> bool {
		// Use the same attack logic as can_attack_square, but account for the temporary move
		if !self.can_piece_attack_square(from_row, from_col, to_row, to_col, piece) {
			return false;
		}

		// Check if path is clear, accounting for the temporary move
		self.is_path_clear_with_move(
			from_row,
			from_col,
			to_row,
			to_col,
			move_from_row,
			move_from_col,
			move_to_row,
			move_to_col,
			moved_piece,
		)
	}

	/// Check if path is clear, accounting for a temporary move
	fn is_path_clear_with_move(
		&self,
		from_row: u8,
		from_col: u8,
		to_row: u8,
		to_col: u8,
		move_from_row: u8,
		move_from_col: u8,
		move_to_row: u8,
		move_to_col: u8,
		moved_piece: u8,
	) -> bool {
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
			let cr = current_row as u8;
			let cc = current_col as u8;

			// Determine what piece is actually on this square (accounting for the move)
			let piece_opt = if cr == move_from_row && cc == move_from_col {
				None // Piece moved from here
			} else if cr == move_to_row && cc == move_to_col {
				piece::Piece::from_u8(moved_piece) // Piece moved here
			} else {
				piece::Piece::from_u8(self.board.get(cr, cc))
			};

			if piece_opt.is_some() {
				return false; // Path blocked
			}
			current_row += row_step;
			current_col += col_step;
		}

		true
	}

	// ============================================================================
	// MOVE APPLICATION
	// ============================================================================

	/// Apply this move to the game state
	pub(crate) fn apply_move(&mut self, chess_move: &ChessMove) {
		let piece = self.board.get(chess_move.from_row, chess_move.from_col);
		self.board_mut().set(chess_move.to_row, chess_move.to_col, piece);
		self.board_mut().set(chess_move.from_row, chess_move.from_col, 0u8); // Empty square
	}

	// ============================================================================
	// GAME STATE QUERIES
	// ============================================================================

	/// Check if the current player's king is in check
	pub fn is_in_check(&self, is_white_turn: bool) -> bool {
		// Find the king's position
		let king_pos = match self.find_king(is_white_turn) {
			Some(pos) => pos,
			None => return false, // No king found (shouldn't happen in valid game)
		};

		// Check if any opponent piece can attack the king's square
		self.can_attack_square(king_pos.0, king_pos.1, !is_white_turn)
	}

	/// Check if the current position is stalemate
	pub fn is_stalemate(&self, is_white_turn: bool) -> bool {
		// Stalemate: no valid moves available AND king is NOT in check
		self.to_valid_moves(is_white_turn).is_empty() && !self.is_in_check(is_white_turn)
	}

	/// Check if the current position is checkmate
	pub fn is_checkmate(&self, is_white_turn: bool) -> bool {
		// Checkmate: no valid moves available AND king IS in check
		self.to_valid_moves(is_white_turn).is_empty() && self.is_in_check(is_white_turn)
	}

	/// Determine game status based on valid moves and check state
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

	// ============================================================================
	// STATE ACCESSORS AND MUTATORS
	// ============================================================================

	pub fn count_pieces(&self) -> usize {
		// Count non-empty squares (excluding kings which are always present)
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

	/// Find the king's position for a given color
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

	/// Get the piece kind label at a specific square
	pub(crate) fn piece_kind_at(&self, row: u8, col: u8) -> Option<&'static str> {
		piece::Piece::from_u8(self.board.get(row, col)).map(|p| p.as_kind_label())
	}

	/// Update board state from matrix
	#[allow(dead_code)]
	pub(crate) fn update_board_from_matrix(
		&mut self,
		matrix: &tightbeam::Asn1Matrix,
	) -> Result<(), tightbeam::TightBeamError> {
		// Require Matrix<8> format (8x8 chess board)
		if matrix.n != 8 || matrix.data.len() != 64 {
			return Err(tightbeam::TightBeamError::InvalidBody);
		}

		// Update board state from matrix
		for row in 0..8 {
			for col in 0..8 {
				let idx = (row as usize * 8) + col as usize;
				self.board_mut().set(row, col, matrix.data[idx]);
			}
		}

		Ok(())
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
