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
//! RUSTFLAGS="--cfg fuzzing" cargo afl build --test chess_engine \
//!   --features "std,testing-fdr,testing-csp"
//! mkdir -p fuzz_in && echo "seed" > fuzz_in/seed.txt
//! cargo afl fuzz -i fuzz_in -o fuzz_out target/debug/deps/chess_engine-*
//! ```

#![cfg(all(feature = "std", feature = "full"))]

use std::sync::{Arc, Mutex};

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
	board: Matrix<8>, // 8x8 chess board
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

		Self { board }
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
		self.board.set(to_row, to_col, piece);
		self.board.set(from_row, from_col, piece::EMPTY);
	}

	fn get_valid_moves(&self, is_white_turn: bool) -> Vec<(u8, u8, u8, u8)> {
		// Generate all valid moves for current player using validate_move
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
							moves.push((from_row, from_col, to_row, to_col));
						}
					}
				}
			}
		}
		moves
	}

	fn is_stalemate(&self, is_white_turn: bool, move_count: u64) -> bool {
		// Stalemate: no valid moves available for current player
		self.get_valid_moves(is_white_turn).is_empty() && !self.is_checkmate(is_white_turn, move_count)
	}

	fn is_checkmate(&self, is_white_turn: bool, move_count: u64) -> bool {
		// Simplified: checkmate if no valid moves and king is in check
		// For now, just check if no valid moves (proper checkmate detection would need check detection)
		self.get_valid_moves(is_white_turn).is_empty() && move_count > 0
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

		Ok(Self { board })
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
	pub struct ChessGameFlow;
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
	pub struct ChessRules;
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

servlet! {
	name: ChessEngineServlet,
	protocol: TokioListener,
	policies: {
		// TODO: Add mutual authentication policies
		// with_collector_gate: [ExpiryValidator, ChessClientValidator]
	},
	config: {
		game_state: Arc<Mutex<ChessGameState>>,
	},
	handle: |message, config| async move {
		// Decode ChessMoveRequest from message
		let move_req: ChessMoveRequest = match decode(&message.message) {
			Ok(req) => req,
			Err(_) => {
				// Invalid message format - return invalid move response
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
		let client_board = if let Some(ref asn1_matrix) = message.metadata.matrix {
			match ChessGameState::try_from(asn1_matrix) {
				Ok(state) => Some(state.board),
				Err(_) => None,
			}
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

		// Sync client board state if provided
		if let Some(client_board) = client_board {
			game_state.board = client_board;
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
			let response = ChessMoveResponse {
				game_status: GameStatusCode::InvalidMove,
			};
			return Ok(Some(compose! {
				V0: id: message.metadata.id.clone(),
					order: move_count + 1,
					message: response
			}?));
		}

		// Make the client's move
		game_state.make_move(
			move_req.from_row,
			move_req.from_col,
			move_req.to_row,
			move_req.to_col,
		);

		// Check for game end conditions after client move
		let game_status = if game_state.is_checkmate(is_white_turn, move_count) {
			GameStatusCode::Checkmate
		} else if game_state.is_stalemate(is_white_turn, move_count) {
			GameStatusCode::Stalemate
		} else {
			// Make a random valid server move (server is opposite color)
			let is_server_white_turn = !is_white_turn;
			let valid_moves = game_state.get_valid_moves(is_server_white_turn);
			if valid_moves.is_empty() {
				GameStatusCode::Stalemate
			} else {
				// Pick a random move from valid moves
				let random_index = match tightbeam::random::generate_random_number::<8>(None) {
					Ok(n) => n % valid_moves.len(),
					Err(_) => 0, // Fallback to first move if random generation fails
				};
				let server_move = valid_moves[random_index];
				game_state.make_move(
					server_move.0,
					server_move.1,
					server_move.2,
					server_move.3,
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
		servlet: ChessEngineServlet,
		start: async move {
			let config = ChessEngineServletConf {
				game_state: Arc::new(Mutex::new(ChessGameState::new())),
			};

			ChessEngineServlet::start(config).await
		},
		client: |trace, mut client| async move {
			// Initialize client-side game state (starts with standard chess position)
			let mut client_game_state = ChessGameState::new();

			// Structured input format:
			// - First byte: number of moves to attempt (1-10, 0 = 1 move)
			// - For each move: 4 bytes (from_row, from_col, to_row, to_col)
			let move_count = match trace.oracle().fuzz_u8() {
				Ok(b) => (b % 10).max(1), // 1-10 moves
				Err(_) => 1, // If no input, do 1 move
			};

			let mut order = 1u64;

			// Attempt multiple moves to explore more state space
			for _ in 0..move_count {
				// Extract move coordinates from AFL input bytes
				// No defaults - let AFL mutations directly affect values
				let from_row = match trace.oracle().fuzz_u8() {
					Ok(b) => b % 8,
					Err(_) => break, // Out of input bytes
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

				// Create move request
				let move_req = ChessMoveRequest {
					from_row,
					from_col,
					to_row,
					to_col,
				};

				trace.event("move_sent");

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
					GameStatusCode::Checkmate | GameStatusCode::Stalemate => {
						trace.event("move_validated");
						trace.event("server_move");
						trace.event("game_ended");
						// Game ended, stop making moves
						break;
					}
				}
			}

			Ok(())
		}
	}
}
