use std::sync::{Arc, Mutex};

use super::state::{piece_kind_for_move, ChessGameState};
use super::utils::is_white_turn;
use tightbeam::der::Enumerated;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::{compose, decode, servlet, Beamable, Sequence};

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

servlet! {
	/// Chess engine servlet for processing chess moves
	pub ChessEngineServlet<ChessMoveRequest>,
	protocol: TokioListener,
	policies: {
		// TODO: Add mutual authentication policies
		// with_collector_gate: [ExpiryValidator, ChessClientValidator]
	},
	config: {
		game_state: Arc<Mutex<ChessGameState>>,
	},
	handle: |message, trace, config| async move {
		let message_id = message.metadata.id.clone();
		let invalid_move = |trace: TraceCollector, id: Vec<u8>, order: u64|
			-> Result<Option<tightbeam::Frame>, tightbeam::TightBeamError> {
			trace.event("server_response_emitted");
			Ok(Some(create_invalid_move_response(id, order)?))
		};

		trace.event("server_move_received");

		// Decode ChessMoveRequest from message
		let move_req: ChessMoveRequest = match decode(&message.message) {
			Ok(req) => req,
			Err(_) => {
				// Invalid message format - return invalid move response
				trace.event("server_decode_failure");
				return invalid_move(trace, message_id, message.metadata.order);
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
				trace.event("server_state_lock_poisoned");
				return invalid_move(trace, message_id, message.metadata.order);
			}
		};

		// Sync client board state if provided (preserve capture tracking)
		if let Some(client_state) = client_state {
			let server_piece_count_before = game_state.count_pieces();
			*game_state.board_mut() = *client_state.board();

			// Detect captures by comparing piece counts
			let client_piece_count = client_state.count_pieces();
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
			trace.event("server_move_invalid");
			return invalid_move(trace, message_id, move_count);
		}

		trace.event("server_move_validated");

		if let Some(kind) = piece_kind_for_move(&game_state, move_req.from_row, move_req.from_col) {
			trace.event(kind);
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
				// Use move_count as deterministic seed for reproducible fuzzing
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
					// Deterministic selection based on move_count for reproducible fuzzing
					let index = (move_count as usize) % top_moves.len();
					top_moves[index]
				} else {
					// Deterministic selection based on move_count for reproducible fuzzing
					let index = (move_count as usize) % valid_moves.len();
					valid_moves[index]
				};

				// Make the server move (track captures)
				game_state.make_move_with_count(
					server_move.0,
					server_move.1,
					server_move.2,
					server_move.3,
					move_count + 1,
				);

				trace.event("server_move_generated");

				if let Some(kind) = piece_kind_for_move(&game_state, server_move.0, server_move.1) {
					trace.event(kind);
				}

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

		if matches!(game_status, GameStatusCode::Checkmate | GameStatusCode::Stalemate) {
			trace.event("server_game_ended");
		}

		// Return response with game status and updated board state in matrix
		// Increment order for next move (monotonically incrementing)
		let response = ChessMoveResponse { game_status };
		let updated_matrix = tightbeam::Asn1Matrix::from(&*game_state);
		// Convert Asn1Matrix to MatrixDyn
		let matrix_dyn = tightbeam::matrix::MatrixDyn::try_from(updated_matrix)?;

		trace.event("server_response_emitted");

		Ok(Some(compose! {
			V0: id: message_id,
			order: move_count + 1,
			message: response,
			matrix: matrix_dyn
		}?))
	}
}
