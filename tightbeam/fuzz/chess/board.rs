use std::sync::{Arc, Mutex};

use tightbeam::asn1::Frame;
use tightbeam::der::Enumerated;
use tightbeam::error::TightBeamError;
use tightbeam::matrix::{MatrixDyn, MatrixError};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::{compose, decode, servlet, Beamable, Sequence};

use super::r#move::ChessMove;
use super::state::ChessGameState;

// ============================================================================
// MATCH MANAGER
// ============================================================================

/// Manages chess match state and game lifecycle
/// Server maintains authoritative board state - client's board state is ignored
#[derive(Default)]
pub(crate) struct ChessMatchManager {
	game_state: Arc<Mutex<ChessGameState>>,
	last_order: Arc<Mutex<u64>>,
}

impl ChessMatchManager {
	/// Process a move request, returning the game status
	/// Returns Ok(status) if successful, Err(()) if lock poisoned or invalid move
	pub(crate) fn process_move(
		&self,
		move_req: &ChessMoveRequest,
		move_count: u64,
		trace: &TraceCollector,
	) -> Result<GameStatusCode, ()> {
		let mut game_state = match self.game_state.lock() {
			Ok(gs) => gs,
			Err(_) => {
				trace.event("server_state_lock_poisoned");
				return Err(());
			}
		};

		let mut last_order = match self.last_order.lock() {
			Ok(lo) => lo,
			Err(_) => {
				trace.event("server_state_lock_poisoned");
				return Err(());
			}
		};

		// Detect new game: if order resets to 1 and we've seen higher orders, reset board
		if move_count == 1 && *last_order > 1 {
			// New game started - reset server's authoritative board state
			*game_state = ChessGameState::new();
			trace.event("server_game_ended");
			trace.event("server_game_restarted");
		}
		*last_order = move_count;

		// Determine whose turn it is based on the updated last_order
		let is_white_turn = *last_order % 2 == 0;
		drop(last_order);

		// Validate move
		let client_move = ChessMove {
			from_row: move_req.from_row,
			from_col: move_req.from_col,
			to_row: move_req.to_row,
			to_col: move_req.to_col,
		};

		if !game_state.is_move_valid(&client_move, is_white_turn) {
			trace.event("server_move_invalid");
			return Err(());
		}

		trace.event("server_move_validated");

		// Emit piece kind event for client move
		if let Some(kind) = game_state.piece_kind_at(move_req.from_row, move_req.from_col) {
			trace.event(kind);
		}

		// Make the client's move
		game_state.apply_move(&client_move);

		// Compute valid moves once and reuse for checkmate/stalemate checks
		let is_server_turn = !is_white_turn;
		let valid_moves = game_state.to_valid_moves(is_server_turn);

		let game_status: GameStatusCode = if valid_moves.is_empty() {
			game_state.determine_game_status(is_server_turn)
		} else {
			// Generate random valid server move
			let server_move = match game_state.to_random_valid_move(is_server_turn, move_count) {
				Some(mv) => mv,
				None => {
					// No valid moves (shouldn't happen since we checked above, but handle gracefully)
					return Ok(game_state.determine_game_status(is_server_turn));
				}
			};

			// Make the server move (track captures)
			game_state.apply_move(&server_move);

			trace.event("server_move_generated");

			// Emit piece kind event for server move
			if let Some(kind) = game_state.piece_kind_at(server_move.from_row, server_move.from_col) {
				trace.event(kind);
			}

			// Check game status after server move (check if client is in checkmate/stalemate)
			game_state.determine_game_status(is_white_turn)
		};

		if matches!(game_status, GameStatusCode::Checkmate | GameStatusCode::Stalemate) {
			trace.event("server_game_ended");
		}

		Ok(game_status)
	}

	/// Get the current game state as a matrix for response
	pub(crate) fn game_state_matrix(&self) -> Result<MatrixDyn, TightBeamError> {
		let game_state = self
			.game_state
			.lock()
			.map_err(|_| TightBeamError::MatrixError(MatrixError::InvalidN(0)))?;

		Ok(MatrixDyn::try_from(&*game_state)?)
	}
}

// ============================================================================
// MESSAGE TYPES
// ============================================================================

/// Chess move request from client
/// Note: Board state is transmitted via Frame.metadata.matrix
#[derive(Beamable, Sequence, Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChessMoveRequest {
	pub(crate) from_row: u8,
	pub(crate) from_col: u8,
	pub(crate) to_row: u8,
	pub(crate) to_col: u8,
}

/// Chess move response from server
/// Note: Board state is transmitted via Frame.metadata.matrix
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
pub(crate) fn create_invalid_move_response(id: Vec<u8>, order: u64) -> Result<Frame, TightBeamError> {
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
		manager: ChessMatchManager,
	},
	handle: |message, trace, config| async move {
		let message_id = message.metadata.id.clone();
		let invalid_move = |trace: TraceCollector, id: Vec<u8>, order: u64|
			-> Result<Option<Frame>, TightBeamError> {
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

		// Use order field as move count (monotonically incrementing)
		// Process move through manager (handles validation, moves, and game status)
		let move_count = message.metadata.order;
		let game_status = match config.manager.process_move(&move_req, move_count, &trace) {
			Ok(status) => status,
			Err(_) => {
				return invalid_move(trace, message_id, move_count);
			}
		};

		// Get current board state as matrix for response
		let matrix = match config.manager.game_state_matrix() {
			Ok(m) => m,
			Err(_) => {
				return invalid_move(trace, message_id, move_count);
			}
		};

		// Return response with game status and updated board state
		let response = ChessMoveResponse { game_status };
		trace.event("server_response_emitted");

		Ok(Some(compose! {
			V0: id: message_id,
			order: move_count + 1,
			message: response,
			matrix: matrix
		}?))
	}
}
