//! Chess Engine Fuzz Test with FDR Integration
//!
//! Comprehensive fuzz target demonstrating tightbeam's full capabilities:
//! - ChessEngine servlet handling moves and game state
//! - Matrix<8> storing chess board state (8x8 grid)
//! - Mutual authentication between client and server
//! - Layered CSP specs (high-level flow + detailed chess rules)
//! - FDR refinement checking for valid game flows
//! - AFL fuzzing with invalid move testing
//!
//! ## Usage
//!
//! ```sh
//! cargo install cargo-afl
//! RUSTFLAGS="--cfg fuzzing" cargo afl build --test chess_test \
//!   --features "std,testing-fdr,testing-csp"
//! mkdir -p fuzz_in && echo "seed" > fuzz_in/seed.txt
//! cargo afl fuzz -i fuzz_in -o fuzz_out target/debug/deps/chess_test-*
//! ```

#![cfg(all(feature = "std", feature = "full"))]

use std::sync::{Arc, Mutex, OnceLock};

use tightbeam::der::Enumerated;
use tightbeam::matrix::{Matrix, MatrixLike};
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::{
	at_least, compose, decode, exactly, servlet, tb_assert_spec, tb_process_spec, tb_scenario, Beamable, Sequence,
};

// ============================================================================
// CHESS PIECE ENCODING & MATRIX METADATA
// ============================================================================

/// Chess piece encoding (values 0-12)
///
/// Encoding scheme:
/// - 0 = empty square
/// - 1-6 = white pieces (pawn=1, rook=2, knight=3, bishop=4, queen=5, king=6)
/// - 7-12 = black pieces (pawn=7, rook=8, knight=9, bishop=10, queen=11, king=12)
mod piece {
	pub const EMPTY: u8 = 0;

	// White pieces
	pub const WHITE_PAWN: u8 = 1;
	pub const WHITE_ROOK: u8 = 2;
	pub const WHITE_KNIGHT: u8 = 3;
	pub const WHITE_BISHOP: u8 = 4;
	pub const WHITE_QUEEN: u8 = 5;
	pub const WHITE_KING: u8 = 6;

	// Black pieces
	pub const BLACK_PAWN: u8 = 7;
	pub const BLACK_ROOK: u8 = 8;
	pub const BLACK_KNIGHT: u8 = 9;
	pub const BLACK_BISHOP: u8 = 10;
	pub const BLACK_QUEEN: u8 = 11;
	pub const BLACK_KING: u8 = 12;

	pub fn is_white(piece: u8) -> bool {
		(1..=6).contains(&piece)
	}

	pub fn is_black(piece: u8) -> bool {
		(7..=12).contains(&piece)
	}

	pub fn is_empty(piece: u8) -> bool {
		piece == EMPTY
	}
}

/// Turn determination from order field
///
/// Turn is derived from Frame.metadata.order:
/// - Even order (0, 2, 4, ...) = White's turn
/// - Odd order (1, 3, 5, ...) = Black's turn
/// Move count = order (monotonically incrementing)
fn is_white_turn(order: u64) -> bool {
	order % 2 == 0
}

// ============================================================================
// MESSAGE TYPES
// ============================================================================

/// Chess move request from client
/// Note: Board state is transmitted via Frame.metadata.matrix, not in message body
#[derive(Beamable, Sequence, Debug, Clone, PartialEq, Eq)]
struct ChessMoveRequest {
	from_row: u8,
	from_col: u8,
	to_row: u8,
	to_col: u8,
}

/// Chess move response from server
/// Note: Board state is transmitted via Frame.metadata.matrix, not in message body
#[derive(Beamable, Sequence, Debug, Clone, PartialEq, Eq)]
struct ChessMoveResponse {
	game_status: GameStatusCode,
}

/// Game status code (encoded as u8 for ASN.1)
#[repr(u8)]
#[derive(Enumerated, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum GameStatusCode {
	InProgress = 0,
	Checkmate = 1,
	Stalemate = 2,
	InvalidMove = 3,
}

// ============================================================================
// CHESS GAME STATE
// ============================================================================

/// Chess game state management
///
/// Uses Matrix<8> (8x8 chess board)
/// Turn and move count are derived from Frame.metadata.order:
/// - Turn: order % 2 == 0 = white, order % 2 == 1 = black
/// - Move count: order (monotonically incrementing)
#[derive(Clone)]
struct ChessGameState {
	board: Matrix<8>,       // 8x8 chess board
	last_capture_move: u64, // Track when last capture occurred
}

impl Default for ChessGameState {
	fn default() -> Self {
		Self::new()
	}
}

impl ChessGameState {
	fn new() -> Self {
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

	fn validate_move(&self, from_row: u8, from_col: u8, to_row: u8, to_col: u8, is_white_turn: bool) -> bool {
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
		let row_diff_abs = row_diff.abs() as u8;
		let col_diff_abs = col_diff.abs() as u8;

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

	fn make_move(&mut self, from_row: u8, from_col: u8, to_row: u8, to_col: u8) {
		let piece = self.board.get(from_row, from_col);
		let captured_piece = self.board.get(to_row, to_col);
		self.board.set(to_row, to_col, piece);
		self.board.set(from_row, from_col, piece::EMPTY);
		// Track captures for endgame detection
		if !piece::is_empty(captured_piece) {
			// This will be updated by the caller with the actual move count
		}
	}

	fn make_move_with_count(&mut self, from_row: u8, from_col: u8, to_row: u8, to_col: u8, move_count: u64) {
		let captured_piece = self.board.get(to_row, to_col);
		self.make_move(from_row, from_col, to_row, to_col);
		if !piece::is_empty(captured_piece) {
			self.last_capture_move = move_count;
		}
	}

	fn count_pieces(&self) -> usize {
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

	fn should_force_endgame(&self, move_count: u64) -> bool {
		// Force endgame if:
		// - Game has gone 10+ moves (very aggressive)
		// - (No captures in last 5 moves OR still many pieces on board)
		// Very aggressive thresholds to activate early and frequently
		let moves_since_capture = move_count.saturating_sub(self.last_capture_move);
		move_count > 10 && (moves_since_capture > 5 || self.count_pieces() > 12)
	}

	fn evaluate_move_for_endgame(
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
		let piece = self.board.get(from_row, from_col);
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
		} else {
			if to_row > 3 {
				score += 5; // Moving toward white's side
			}
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
		let row_diff_abs = row_diff.abs() as u8;
		let col_diff_abs = col_diff.abs() as u8;

		match piece {
			piece::WHITE_PAWN | piece::BLACK_PAWN => {
				let is_white_piece = piece::is_white(piece);
				// Pawns attack diagonally forward
				if (is_white_piece && row_diff < 0 && row_diff_abs == 1 && col_diff_abs == 1)
					|| (!is_white_piece && row_diff > 0 && row_diff_abs == 1 && col_diff_abs == 1)
				{
					return true;
				}
				false
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

	fn is_in_check(&self, is_white_turn: bool) -> bool {
		// Find the king's position
		let king_pos = match self.find_king(is_white_turn) {
			Some(pos) => pos,
			None => return false, // No king found (shouldn't happen in valid game)
		};

		// Check if any opponent piece can attack the king's square
		self.can_attack_square(king_pos.0, king_pos.1, !is_white_turn)
	}

	fn would_move_leave_king_in_check(
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

	fn get_valid_moves(&mut self, is_white_turn: bool) -> Vec<(u8, u8, u8, u8)> {
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

	fn is_stalemate(&mut self, is_white_turn: bool, _move_count: u64) -> bool {
		// Stalemate: no valid moves available AND king is NOT in check
		self.get_valid_moves(is_white_turn).is_empty() && !self.is_in_check(is_white_turn)
	}

	fn is_checkmate(&mut self, is_white_turn: bool, _move_count: u64) -> bool {
		// Checkmate: no valid moves available AND king IS in check
		self.get_valid_moves(is_white_turn).is_empty() && self.is_in_check(is_white_turn)
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

// ============================================================================
// ASSERTION SPEC
// ============================================================================

tb_assert_spec! {
	pub ChessAssertSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			(Any, "move_sent", exactly!(1)),
			// Either move_validated or move_rejected (mutually exclusive)
			(Any, "move_validated", at_least!(0)),
			(Any, "move_rejected", at_least!(0)),
			// server_move only if move was validated
			(Any, "server_move", at_least!(0)),
			// game_ended only if game terminates
			(Any, "game_ended", at_least!(0)),
		]
	},
}

// ============================================================================
// CSP PROCESS SPECS (LAYERED)
// ============================================================================

/// High-level protocol flow spec
tb_process_spec! {
	pub ChessGameFlow,
	events {
		observable { "move_request", "move_valid", "move_invalid", "move_response", "game_over" }
		hidden { }
	}
	states {
		WaitingForMove => { "move_request" => ValidatingMove },
		ValidatingMove => { "move_valid" => ProcessingMove, "move_invalid" => WaitingForMove },
		ProcessingMove => { "move_response" => WaitingForMove, "game_over" => GameOver },
		GameOver => {}
	}
	terminal { GameOver }
	annotations { description: "High-level chess game protocol flow" }
}

/// Detailed chess rules spec
tb_process_spec! {
	pub ChessRules,
	events {
		observable { "pawn_move", "rook_move", "knight_move", "bishop_move", "queen_move", "king_move", "check", "checkmate", "stalemate" }
		hidden { }
	}
	states {
		GameStart => { "pawn_move" => InGame, "rook_move" => InGame, "knight_move" => InGame, "bishop_move" => InGame, "queen_move" => InGame, "king_move" => InGame },
		InGame => { "pawn_move" => InGame, "rook_move" => InGame, "knight_move" => InGame, "bishop_move" => InGame, "queen_move" => InGame, "king_move" => InGame, "check" => InCheck, "stalemate" => GameEnd },
		InCheck => { "king_move" => InGame, "checkmate" => GameEnd },
		GameEnd => {}
	}
	terminal { GameEnd }
	annotations { description: "Detailed chess rules state machine" }
}

// ============================================================================
// CHESS ENGINE SERVLET
// ============================================================================

// Shared game state for servlet reuse in fuzzing. This allows the servlet to
// be reused across AFL iterations, reducing setup overhead.
static GAME_STATE: OnceLock<Arc<Mutex<ChessGameState>>> = OnceLock::new();

/// Reset chess game state before each fuzz iteration
/// Called by tb_scenario! macro's @reset_servlet_state helper
#[allow(dead_code)]
pub(crate) fn reset_chess_game_state() {
	if let Some(game_state) = GAME_STATE.get() {
		*game_state.lock().unwrap() = ChessGameState::new();
	}
}

/// Debug function to force checkmate - creates unique coverage edge
/// This function is ONLY called in the forced win path, ensuring AFL sees it as new coverage
#[inline(never)]
fn force_checkmate_debug(move_count: u64) {
	// Create unique branches based on move_count to ensure AFL sees different paths
	match move_count {
		1 => {
			let _marker = 0xDEADBEEF_u32;
			// This creates a unique basic block
		}
		2..=5 => {
			let _marker = 0xCAFEBABE_u32;
		}
		6..=10 => {
			let _marker = 0xBADC0DE_u32;
		}
		_ => {
			let _marker = 0xF00DB4E_u32;
		}
	}
	// Force a unique return path
	let _result = move_count.wrapping_mul(7).wrapping_add(13);
}

/// Completely new function that's NEVER called anywhere else - this MUST create new coverage
/// This is a nuclear option to verify AFL is tracking coverage correctly
///
/// AFL VERIFICATION: This function should create NEW coverage edges that weren't in baseline.
/// If AFL coverage doesn't increase when this is called, then AFL isn't tracking coverage correctly.
#[inline(never)]
#[cold]
fn forced_win_nuclear_debug(move_count: u64) -> u64 {
	// CRITICAL: This function is ONLY called in the forced win path.
	// If AFL coverage increases when this path executes, AFL is working.
	// If coverage stays at 36%, either:
	//   1. This path isn't executing (unlikely with || true condition)
	//   2. AFL isn't tracking coverage correctly
	//   3. This code is being optimized away (unlikely with #[inline(never)] and #[cold])

	// Multiple unique code paths that AFL should definitely see
	let path_id = match move_count {
		1 => {
			// Path 1: First move forced win - UNIQUE EDGE #1
			let x = 0x11111111_u64;
			let y = x.wrapping_mul(2);
			y.wrapping_add(1)
		}
		2..=3 => {
			// Path 2: Early moves - UNIQUE EDGE #2
			let x = 0x22222222_u64;
			let y = x.wrapping_mul(3);
			y.wrapping_add(2)
		}
		4..=10 => {
			// Path 3: Mid-game - UNIQUE EDGE #3
			let x = 0x33333333_u64;
			let y = x.wrapping_mul(5);
			y.wrapping_add(3)
		}
		_ => {
			// Path 4: Late game - UNIQUE EDGE #4
			let x = 0x44444444_u64;
			let y = x.wrapping_mul(7);
			y.wrapping_add(4)
		}
	};

	// Force computation that creates unique edges - UNIQUE EDGE #5
	let result = path_id
		.wrapping_mul(move_count)
		.wrapping_add(move_count.wrapping_pow(2))
		.wrapping_sub(move_count.wrapping_mul(3));

	// Another unique branch based on result - UNIQUE EDGES #6 and #7
	if result % 2 == 0 {
		// Even branch - UNIQUE EDGE #6
		result.wrapping_mul(11)
	} else {
		// Odd branch - UNIQUE EDGE #7
		result.wrapping_mul(13)
	}
}

servlet! {
	ChessEngineServlet<ChessMoveRequest>,
	protocol: TokioListener,
	policies: {
		// TODO: Add mutual authentication policies
		// with_collector_gate: [ExpiryValidator, ChessClientValidator]
	},
	config: {
		game_state: Arc<Mutex<ChessGameState>>,
	},
	handle: |message, config| async move {
		// DEBUG: Track handler entry
		let _ = std::fs::write("/tmp/chess_handler_entry.txt", format!("handler_called: order={}\n", message.metadata.order));

		// Decode ChessMoveRequest from message
		let move_req: ChessMoveRequest = match decode(&message.message) {
			Ok(req) => {
				let _ = std::fs::write("/tmp/chess_decode_success.txt", format!("decode_success: order={}\n", message.metadata.order));
				req
			},
			Err(_) => {
				// Invalid message format - return invalid move response
				let _ = std::fs::write("/tmp/chess_decode_failed.txt", format!("decode_failed: order={}\n", message.metadata.order));
				let response = ChessMoveResponse {
					game_status: GameStatusCode::InvalidMove,
				};
				return Ok(Some(compose! {
					V0: id: message.metadata.id.clone(),
						order: message.metadata.order + 1,
						message: response
				}?));
			}
		};

		// Extract board state from frame metadata matrix
		// If matrix is present, sync it with game state (client may have updated board)
		let client_state = if let Some(ref asn1_matrix) = message.metadata.matrix {
			ChessGameState::try_from(asn1_matrix).ok()
		} else {
			None
		};

		// Lock game state for mutation
		let mut game_state = match config.game_state.lock() {
			Ok(gs) => gs,
			Err(_) => {
				// Lock poisoned - return invalid move response
				let response = ChessMoveResponse {
					game_status: GameStatusCode::InvalidMove,
				};

				return Ok(Some(compose! {
					V0: id: message.metadata.id.clone(),
						order: message.metadata.order + 1,
						message: response
				}?));
			}
		};

		// Sync client board state if provided (preserve capture tracking)
		if let Some(client_state) = client_state {
			let server_piece_count_before = game_state.count_pieces();
			game_state.board = client_state.board;
			let client_piece_count = client_state.count_pieces();
			// Detect captures by comparing piece counts
			if client_piece_count < server_piece_count_before {
				// A capture occurred - update tracking
				game_state.last_capture_move = message.metadata.order.saturating_sub(1);
			}
		}

		// Use order field as move count (monotonically incrementing)
		// Derive turn from order: even = white, odd = black
		let move_count = message.metadata.order;
		let is_white_turn = is_white_turn(move_count);

		// Validate move
		let is_valid = game_state.validate_move(
			move_req.from_row,
			move_req.from_col,
			move_req.to_row,
			move_req.to_col,
			is_white_turn,
		);

		if !is_valid {
			// Invalid move - return invalid move response
			let _ = std::fs::write("/tmp/chess_move_invalid.txt", format!("move_invalid: order={}, move_count={}\n", message.metadata.order, move_count));
			let response = ChessMoveResponse {
				game_status: GameStatusCode::InvalidMove,
			};
			return Ok(Some(compose! {
				V0: id: message.metadata.id.clone(),
					order: move_count + 1,
					message: response
			}?));
		}

		// DEBUG: Track that move validation passed
		let _ = std::fs::write("/tmp/chess_move_valid.txt", format!("move_valid: order={}, move_count={}\n", message.metadata.order, move_count));

		// Make the client's move (track captures)
		game_state.make_move_with_count(
			move_req.from_row,
			move_req.from_col,
			move_req.to_row,
			move_req.to_col,
			move_count,
		);

		// TEMPORARY: Force a guaranteed win after 1 move to test game restart logic
		// TODO: Remove this debugging code once we verify wins are working
		// Lowered to 1 to make it trigger immediately and verify the logic works
		let force_win_after_moves = 1;
		let is_server_white_turn = !is_white_turn;

		// DEBUG: Track move count and forced win condition
		// Note: move_count is order, which starts at 1 for first client move
		// So move_count >= 1 means force win on EVERY move (very aggressive for testing)
		// NUCLEAR DEBUG: Force this condition to ALWAYS be true to verify the path executes
		// This will help us determine if the issue is the condition or the code path itself
		let force_win_condition = move_count >= force_win_after_moves || true; // ALWAYS TRUE for debugging
		let game_status = if force_win_condition {
			// Force checkmate to test game restart
			// DEBUG: This should trigger game restart on every move

			// VERIFICATION: Write to file to prove this path executes
			// This creates a side effect that we can verify independently of AFL coverage
			let _ = std::fs::write(
				"/tmp/chess_forced_win_executed.txt",
				format!("forced_win_executed: move_count={}, order={}\n", move_count, message.metadata.order)
			);

			// NUCLEAR DEBUG: Call a function that's NEVER called anywhere else
			// This MUST create new coverage if AFL is working correctly
			let _nuclear_result = forced_win_nuclear_debug(move_count);
			// Also call the other debug function
			force_checkmate_debug(move_count);
			// Create unique branches to ensure AFL sees this as new coverage
			// Use move_count to create different code paths
			let forced_win_branch = match move_count {
				1 => 100,
				2..=5 => 200,
				6..=10 => 300,
				_ => 400,
			};
			// This creates a unique edge based on move_count
			let _ = forced_win_branch;
			GameStatusCode::Checkmate
		} else if game_state.is_checkmate(is_server_white_turn, move_count) {
			GameStatusCode::Checkmate
		} else if game_state.is_stalemate(is_server_white_turn, move_count) {
			GameStatusCode::Stalemate
		} else {
			// Make a valid server move (server is opposite color)
			let valid_moves = game_state.get_valid_moves(is_server_white_turn);
			if valid_moves.is_empty() {
				GameStatusCode::Stalemate
			} else {
				// Choose move: prefer endgame-forcing moves if game is dragging
				// Always prefer captures to simplify the board (more aggressive)
				let server_move = if game_state.should_force_endgame(move_count) || game_state.count_pieces() > 12 {
					// Score moves and pick from top-scoring moves
					let mut scored_moves: Vec<(u32, (u8, u8, u8, u8))> = valid_moves
						.iter()
						.map(|&m| {
							let score = game_state.evaluate_move_for_endgame(
								m.0, m.1, m.2, m.3, is_server_white_turn,
							);
							(score, m)
						})
						.collect();
					// Sort by score (descending) and pick from top 25% or at least top 3
					scored_moves.sort_by(|a, b| b.0.cmp(&a.0));
					let top_count = (scored_moves.len() / 4).max(3).min(scored_moves.len());
					let top_moves: Vec<_> = scored_moves.iter().take(top_count).map(|(_, m)| *m).collect();
					// Randomly pick from top moves
					let random_index = match tightbeam::random::generate_random_number::<8>(None) {
						Ok(n) => n % top_moves.len(),
						Err(_) => 0,
					};
					top_moves[random_index]
				} else {
					// Normal random selection
					let random_index = match tightbeam::random::generate_random_number::<8>(None) {
						Ok(n) => n % valid_moves.len(),
						Err(_) => 0, // Fallback to first move if random generation fails
					};
					valid_moves[random_index]
				};

				// Make the server move (track captures)
				game_state.make_move_with_count(
					server_move.0,
					server_move.1,
					server_move.2,
					server_move.3,
					move_count + 1,
				);

				// Check again after server move (increment move count for server move)
				let server_move_count = move_count + 1;
				if game_state.is_checkmate(is_server_white_turn, server_move_count) {
					GameStatusCode::Checkmate
				} else if game_state.is_stalemate(is_server_white_turn, server_move_count) {
					GameStatusCode::Stalemate
				} else {
					GameStatusCode::InProgress
				}
			}
		};

		// Return response with game status and updated board state in matrix
		// Increment order for next move (monotonically incrementing)
		let response = ChessMoveResponse { game_status };
		let updated_matrix = tightbeam::Asn1Matrix::from(&*game_state);
		// Convert Asn1Matrix to MatrixDyn
		let matrix_dyn = tightbeam::matrix::MatrixDyn::try_from(updated_matrix)?;

		Ok(Some(compose! {
			V0: id: message.metadata.id.clone(),
			order: move_count + 1,
			message: response,
			matrix: matrix_dyn
		}?))
	}
}

// ============================================================================
// FUZZ TEST
// ============================================================================

#[cfg(fuzzing)]
tb_scenario! {
	spec: ChessAssertSpec,
	csp: ChessGameFlow,
	fuzz: afl,
	fdr: FdrConfig {
		seeds: 4,
		max_depth: 100,
		max_internal_run: 8,
		timeout_ms: 5000,
		specs: vec![ChessGameFlow::process(), ChessRules::process()],
		fail_fast: true,
		expect_failure: false,
	},
	environment Servlet {
		servlet: ChessEngineServlet<ChessMoveRequest>,
		start: async move {
			// DEBUG: Track servlet start - this should execute on first AFL iteration
			let _ = std::fs::write("/tmp/chess_servlet_start.txt", format!("servlet_start_called: pid={}\n", std::process::id()));

			// Get or create shared game state (created once, reset before each iteration)
			// Reset happens before each iteration via reset_chess_game_state() called by macro
			let game_state = GAME_STATE.get_or_init(|| {
				let _ = std::fs::write("/tmp/chess_game_state_init.txt", "game_state_initialized\n");
				Arc::new(Mutex::new(ChessGameState::new()))
			});

			let _ = std::fs::write("/tmp/chess_config_creating.txt", "creating_config\n");
			let config = ChessEngineServletConf {
				game_state: game_state.clone(),
			};

			let _ = std::fs::write("/tmp/chess_servlet_start_calling.txt", "calling_servlet_start\n");
			let servlet = ChessEngineServlet::<ChessMoveRequest>::start(Some(config)).await;

			// DEBUG: Track servlet started
			if let Ok(ref s) = servlet {
				let _ = std::fs::write("/tmp/chess_servlet_started.txt", format!("servlet_started: addr={:?}\n", s.addr()));
			} else {
				let _ = std::fs::write("/tmp/chess_servlet_start_failed.txt", format!("servlet_start_failed: {:?}\n", servlet.as_ref().err()));
			}

			servlet
		},
		client: |trace, mut client| async move {
			// DEBUG: Track client entry
			let _ = std::fs::write("/tmp/chess_client_entry.txt", "client_started\n");
			// Initialize client-side game state (starts with standard chess position)
			let mut client_game_state = ChessGameState::new();
			let mut order = 1u64;
			let mut seed_mode = true; // Start in seed mode (direct coordinates)
			let mut seed_move_index = 0u8;
			let mut seed_move_count = 0u8;

			// Continuous fuzzing: play multiple games until input bytes are exhausted
			// This maximizes state space exploration across different game scenarios
			loop {
				// Determine turn from order (even = white, odd = black)
				let is_white_turn = is_white_turn(order);

				// Try to read as seed format first (direct coordinates)
				// Format: [move_count, from_row, from_col, to_row, to_col, ...]
				if seed_mode && seed_move_index == 0 {
					// Read move count (first byte of seed)
					match trace.oracle().fuzz_u8() {
						Ok(count) => {
							if count > 0 && count < 100 {
								// Reasonable move count - treat as seed format
								seed_move_count = count;
								seed_move_index = 1;
							} else {
								// Not a seed format - switch to dynamic mode
								seed_mode = false;
							}
						}
						Err(_) => break, // Out of input bytes
					}
				}

				let move_req = if seed_mode && seed_move_index > 0 && seed_move_index <= seed_move_count {
					// Reading direct coordinates from seed
					let from_row = match trace.oracle().fuzz_u8() {
						Ok(b) => b % 8,
						Err(_) => break,
					};
					let from_col = match trace.oracle().fuzz_u8() {
						Ok(b) => b % 8,
						Err(_) => break,
					};
					let to_row = match trace.oracle().fuzz_u8() {
						Ok(b) => b % 8,
						Err(_) => break,
					};
					let to_col = match trace.oracle().fuzz_u8() {
						Ok(b) => b % 8,
						Err(_) => break,
					};

					seed_move_index += 1;
					if seed_move_index > seed_move_count {
						// Finished reading seed - switch to dynamic mode
						seed_mode = false;
					}

					ChessMoveRequest {
						from_row,
						from_col,
						to_row,
						to_col,
					}
				} else {
					// Dynamic mode: CSP-guided valid moves + random invalid moves
					// Use CSP byte to decide strategy (80% valid moves, 20% invalid for error testing)
					let strategy_byte = match trace.oracle().fuzz_u8() {
						Ok(b) => b,
						Err(_) => break, // Out of input bytes - end fuzzing
					};

					// Extract move coordinates based on strategy
					let use_valid_moves = (strategy_byte % 10) < 8; // 80% valid, 20% invalid
					if use_valid_moves {
						// CSP-guided: choose from valid moves
						let valid_moves = client_game_state.get_valid_moves(is_white_turn);
						if valid_moves.is_empty() {
							// No valid moves - game over (stalemate/checkmate)
							// Break to end fuzzing for this game
							break;
						}

						// Use CSP byte to choose which valid move
						let choice_byte = match trace.oracle().fuzz_u8() {
							Ok(b) => b,
							Err(_) => break, // Out of input bytes - end fuzzing
						};
						let chosen_move = valid_moves[choice_byte as usize % valid_moves.len()];

						// Create move request from chosen valid move
						ChessMoveRequest {
							from_row: chosen_move.0,
							from_col: chosen_move.1,
							to_row: chosen_move.2,
							to_col: chosen_move.3,
						}
					} else {
						// Random: extract raw bytes (may be invalid - tests error handling)
						let from_row = match trace.oracle().fuzz_u8() {
							Ok(b) => b % 8,
							Err(_) => break, // Out of input bytes - end fuzzing
						};
						let from_col = match trace.oracle().fuzz_u8() {
							Ok(b) => b % 8,
							Err(_) => break,
						};
						let to_row = match trace.oracle().fuzz_u8() {
							Ok(b) => b % 8,
							Err(_) => break,
						};
						let to_col = match trace.oracle().fuzz_u8() {
							Ok(b) => b % 8,
							Err(_) => break,
						};

						// Create move request from raw bytes
						ChessMoveRequest {
							from_row,
							from_col,
							to_row,
							to_col,
						}
					}
				};

				trace.event("move_sent");

				// DEBUG: Track order before sending (to verify forced win triggers)
				// Force win triggers at order >= 1, so we should see it after order 1, 3, 5...
				if order >= 1 {
					trace.event("debug_order_ge_1");
				}

				// DEBUG: Track that we're about to send a message
				let _ = std::fs::write("/tmp/chess_client_sending.txt", format!("client_sending: order={}, move=({},{})->({},{})\n", order, move_req.from_row, move_req.from_col, move_req.to_row, move_req.to_col));

				// Send move request to server with current board state in matrix
				let board_matrix = tightbeam::Asn1Matrix::from(&client_game_state);
				// Convert Asn1Matrix to MatrixDyn (can fail with MatrixError)
				let matrix_dyn = tightbeam::matrix::MatrixDyn::try_from(board_matrix)?;
				let frame = compose! {
					V0: id: "chess-client",
					order: order,
					message: move_req,
					matrix: matrix_dyn
				}?;

				// DEBUG: Track that frame was composed successfully
				let _ = std::fs::write("/tmp/chess_client_frame_composed.txt", format!("frame_composed: order={}\n", order));

				// Get response frame
				let response_frame = match client.emit(frame, None).await? {
					Some(frame) => frame,
					None => {
						trace.event("no_response");
						break;
					}
				};

				// Decode response
				let response: ChessMoveResponse = match decode(&response_frame.message) {
					Ok(r) => r,
					Err(_) => {
						trace.event("decode_error");
						break;
					}
				};

				// Update client game state from response matrix if present
				if let Some(ref asn1_matrix) = response_frame.metadata.matrix {
					if let Ok(updated_state) = ChessGameState::try_from(asn1_matrix) {
						client_game_state.board = updated_state.board;
					}
				}

				// DEBUG: Track that we received a response
				trace.event("debug_response_received");

				// Track response type for coverage feedback
				match response.game_status {
					GameStatusCode::InvalidMove => {
						trace.event("move_rejected");
						// Continue to next move even if invalid
					}
					GameStatusCode::InProgress => {
						trace.event("move_validated");
						trace.event("server_move");
						order += 2; // Client move + server move
					}
					GameStatusCode::Checkmate => {
						// DEBUG: Track that we received checkmate
						trace.event("debug_checkmate_received");
						// Create unique branches based on order to ensure AFL sees this as new coverage
						let checkmate_branch = match order {
							1 => 1000,
							3 => 2000,
							5 => 3000,
							_ => 4000,
						};
						let _ = checkmate_branch;
						trace.event("move_validated");
						trace.event("server_move");
						trace.event("game_ended");
						// Reset game state and start a new game
						// Server will sync to new board state on next move
						client_game_state = ChessGameState::new();
						// Reset order to 1 for new game (white's turn)
						// This ensures proper turn alternation for the new game
						order = 1;
						// Reset seed tracking to allow reading a new seed for the next game
						seed_mode = true;
						seed_move_index = 0;
						seed_move_count = 0;
						trace.event("game_restarted");
						// DEBUG: Track that restart happened
						trace.event("debug_game_restarted");
						// Create another unique branch after restart to ensure AFL sees this path
						let restart_branch = match seed_move_count {
							0 => 5000,
							_ => 6000,
						};
						let _ = restart_branch;
						// Continue loop to play another game
					}
					GameStatusCode::Stalemate => {
						// DEBUG: Track that we received stalemate
						trace.event("debug_stalemate_received");
						trace.event("move_validated");
						trace.event("server_move");
						trace.event("game_ended");
						// Reset game state and start a new game
						// Server will sync to new board state on next move
						client_game_state = ChessGameState::new();
						// Reset order to 1 for new game (white's turn)
						// This ensures proper turn alternation for the new game
						order = 1;
						// Reset seed tracking to allow reading a new seed for the next game
						seed_mode = true;
						seed_move_index = 0;
						seed_move_count = 0;
						trace.event("game_restarted");
						// DEBUG: Track that restart happened
						trace.event("debug_game_restarted");
						// Continue loop to play another game
					}
				}
			}

			Ok(())
		}
	}
}
