use std::sync::{Arc, Mutex, OnceLock};

use super::state::ChessGameState;
use tightbeam::der::Enumerated;
use tightbeam::testing::macros::TraceCollector;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::{at_least, compose, decode, exactly, servlet, tb_assert_spec, tb_process_spec, Beamable, Sequence};

// ============================================================================
// MESSAGE TYPES
// ============================================================================

/// Chess move request from client
/// Note: Board state is transmitted via Frame.metadata.matrix, not in message body
#[derive(Beamable, Sequence, Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChessMoveRequest {
	pub(crate) from_row: u8,
	pub(crate) from_col: u8,
	pub(crate) to_row: u8,
	pub(crate) to_col: u8,
}

/// Chess move response from server
/// Note: Board state is transmitted via Frame.metadata.matrix, not in message body
#[derive(Beamable, Sequence, Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChessMoveResponse {
	pub(crate) game_status: GameStatusCode,
}

/// Game status code (encoded as u8 for ASN.1)
#[repr(u8)]
#[derive(Enumerated, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum GameStatusCode {
	InProgress = 0,
	Checkmate = 1,
	Stalemate = 2,
	InvalidMove = 3,
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Turn determination from order field
///
/// Turn is derived from Frame.metadata.order:
/// - Even order (0, 2, 4, ...) = White's turn
/// - Odd order (1, 3, 5, ...) = Black's turn
/// Move count = order (monotonically incrementing)
pub(crate) fn is_white_turn(order: u64) -> bool {
	order % 2 == 0
}

/// Helper function to create an invalid move response
pub(crate) fn create_invalid_move_response(
	id: Vec<u8>,
	order: u64,
) -> Result<tightbeam::Frame, tightbeam::TightBeamError> {
	let response = ChessMoveResponse { game_status: GameStatusCode::InvalidMove };
	compose! {
		V0: id: id,
		order: order + 1,
		message: response
	}
}

/// Reset game state and tracking variables for a new game
#[allow(dead_code)]
pub(crate) fn restart_game(
	client_game_state: &mut ChessGameState,
	order: &mut u64,
	seed_mode: &mut bool,
	seed_move_index: &mut u8,
	seed_move_count: &mut u8,
	trace: &TraceCollector,
) {
	trace.event("move_validated");
	trace.event("server_move");
	trace.event("game_ended");
	// Reset game state and start a new game
	// Server will sync to new board state on next move
	*client_game_state = ChessGameState::new();
	// Reset order to 1 for new game (white's turn)
	// This ensures proper turn alternation for the new game
	*order = 1;
	// Reset seed tracking to allow reading a new seed for the next game
	*seed_mode = true;
	*seed_move_index = 0;
	*seed_move_count = 0;
	trace.event("game_restarted");
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

// Shared game state for servlet reuse in fuzzing. This allows the servlet to
// be reused across AFL iterations, reducing setup overhead.
pub(crate) static GAME_STATE: OnceLock<Arc<Mutex<ChessGameState>>> = OnceLock::new();

/// Reset chess game state before each fuzz iteration
/// Called by tb_scenario! macro's @reset_servlet_state helper
#[allow(dead_code)]
pub(crate) fn reset_chess_game_state() {
	if let Some(game_state) = GAME_STATE.get() {
		*game_state.lock().unwrap() = ChessGameState::new();
	}
}

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
				return Ok(Some(create_invalid_move_response(
					message.metadata.id.clone(),
					message.metadata.order,
				)?));
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
				return Ok(Some(create_invalid_move_response(
					message.metadata.id.clone(),
					message.metadata.order,
				)?));
			}
		};

		// Sync client board state if provided (preserve capture tracking)
		if let Some(client_state) = client_state {
			let server_piece_count_before = game_state.count_pieces();
			*game_state.board_mut() = client_state.board().clone();
			let client_piece_count = client_state.count_pieces();
			// Detect captures by comparing piece counts
			if client_piece_count < server_piece_count_before {
				// A capture occurred - update tracking
				game_state.set_last_capture_move(message.metadata.order.saturating_sub(1));
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
			return Ok(Some(create_invalid_move_response(
				message.metadata.id.clone(),
				move_count,
			)?));
		}

		// Make the client's move (track captures)
		game_state.make_move_with_count(
			move_req.from_row,
			move_req.from_col,
			move_req.to_row,
			move_req.to_col,
			move_count,
		);

		let is_server_white_turn = !is_white_turn;

		// Check game status after client move
		let game_status = if game_state.is_checkmate(is_server_white_turn, move_count) {
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
