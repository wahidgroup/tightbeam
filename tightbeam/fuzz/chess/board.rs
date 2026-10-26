use std::sync::{Arc, Mutex};

use tightbeam::asn1::Frame;
use tightbeam::der::Enumerated;
use tightbeam::der::Sequence;
use tightbeam::error::TightBeamError;
use tightbeam::matrix::MatrixDyn;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::{compose, decode, servlet, Beamable, Errorizable};

use super::events;
use super::r#move::ChessMove;
use super::state::ChessGameState;

// The match manager holds the server's authoritative game.

/// The chess match state and the game lifecycle on the server.
///
/// The server keeps the authoritative board and reads only the move of a
/// request.
#[derive(Default, Clone)]
pub(crate) struct ChessMatchManager {
	game_state: Arc<Mutex<ChessGameState>>,
	last_order: Arc<Mutex<u64>>,
}

impl ChessMatchManager {
	/// Applies the client's move and, when the server has a valid move, the
	/// server move that `move_count` picks, then returns the game status.
	///
	/// # Errors
	///
	/// - [`ChessMoveError::InvalidMove`] -- the client's move is illegal on the authoritative board.
	/// - [`ChessMoveError::TightBeam`] -- a state lock is poisoned, or
	///   [`TraceCollector::event`] refuses an event.
	pub(crate) fn process_move(
		&self,
		move_req: &ChessMoveRequest,
		move_count: u64,
		trace: &TraceCollector,
	) -> Result<GameStatusCode, ChessMoveError> {
		let mut game_state = match self.game_state.lock() {
			Ok(gs) => gs,
			Err(_) => {
				trace.event(events::SERVER_STATE_LOCK_POISONED)?;
				return Err(TightBeamError::LockPoisoned.into());
			}
		};

		let mut last_order = match self.last_order.lock() {
			Ok(lo) => lo,
			Err(_) => {
				trace.event(events::SERVER_STATE_LOCK_POISONED)?;
				return Err(TightBeamError::LockPoisoned.into());
			}
		};

		// An order of 1 after higher orders starts a new game, so the server
		// resets its authoritative board.
		if move_count == 1 && *last_order > 1 {
			*game_state = ChessGameState::new();
			trace.event(events::SERVER_GAME_ENDED)?;
			trace.event(events::SERVER_GAME_RESTARTED)?;
		}

		*last_order = move_count;

		// An odd order is White's turn, so White moves first.
		let is_white_turn = *last_order % 2 == 1;
		drop(last_order);

		let client_move = ChessMove::from(move_req);

		if let Err(refusal) = game_state.check_move(&client_move, is_white_turn) {
			trace.event(events::SERVER_MOVE_INVALID)?;
			return Err(refusal);
		}

		trace.event(events::SERVER_MOVE_VALIDATED)?;

		if let Some(kind) = game_state.piece_kind_at(move_req.from_row, move_req.from_col) {
			trace.event(kind)?;
		}

		game_state.apply_move(&client_move);

		// A server with no valid move ends the game in checkmate or stalemate.
		let is_server_turn = !is_white_turn;
		let valid_moves = game_state.to_valid_moves(is_server_turn);
		let game_status: GameStatusCode = if valid_moves.is_empty() {
			game_state.determine_game_status(is_server_turn)
		} else {
			let server_move = match game_state.to_random_valid_move(is_server_turn, move_count) {
				Some(mv) => mv,
				None => {
					// The check above leaves a valid move, so this arm is a
					// guard that reports the game status.
					return Ok(game_state.determine_game_status(is_server_turn));
				}
			};

			// `apply_move` empties the source square, so the lookup of the
			// piece that moves runs before the move.
			let server_piece = game_state.piece_kind_at(server_move.from_row, server_move.from_col);
			game_state.apply_move(&server_move);

			trace.event(events::SERVER_MOVE_GENERATED)?;

			if let Some(kind) = server_piece {
				trace.event(kind)?;
			}

			// After the server move, the status tells whether the client is in
			// checkmate or stalemate.
			game_state.determine_game_status(is_white_turn)
		};

		if matches!(game_status, GameStatusCode::Checkmate | GameStatusCode::Stalemate) {
			trace.event(events::SERVER_GAME_ENDED)?;
		}

		Ok(game_status)
	}

	/// The current game state as a matrix, for the response.
	///
	/// # Errors
	///
	/// - [`TightBeamError::LockPoisoned`] -- the game state lock is poisoned.
	/// - [`TightBeamError::MatrixError`] -- the board does not convert to a matrix.
	pub(crate) fn game_state_matrix(&self) -> Result<MatrixDyn, TightBeamError> {
		let game_state = self.game_state.lock().map_err(|_| TightBeamError::LockPoisoned)?;
		Ok(MatrixDyn::try_from(&*game_state)?)
	}
}

/// The failures of [`ChessMatchManager::process_move`].
#[derive(Errorizable, Debug)]
pub(crate) enum ChessMoveError {
	/// The client's move is illegal on the authoritative board.
	#[error("Invalid move")]
	InvalidMove,

	/// A state lock is poisoned, or the trace refuses an event.
	#[error("TightBeam error: {0}")]
	#[from]
	TightBeam(TightBeamError),
}

// The client and the servlet exchange these message types.

/// The chess move that the client requests.
///
/// The board state travels in the `metadata.matrix` of the frame.
#[derive(Beamable, Sequence, Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChessMoveRequest {
	pub(crate) from_row: u8,
	pub(crate) from_col: u8,
	pub(crate) to_row: u8,
	pub(crate) to_col: u8,
	/// The white board code of the piece that a pawn on the last row becomes,
	/// or 0 for a move with no promotion.
	pub(crate) promotion: u8,
}

/// The chess move response of the server.
///
/// The board state travels in the `metadata.matrix` of the frame.
#[derive(Beamable, Sequence, Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChessMoveResponse {
	pub(crate) game_status: GameStatusCode,
}

/// The game status code, encoded as a `u8` for ASN.1.
#[repr(u8)]
#[derive(Enumerated, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum GameStatusCode {
	InProgress = 0,
	Checkmate = 1,
	Stalemate = 2,
	InvalidMove = 3,
}

// The servlet answers a refused move through this function.

/// Builds the `InvalidMove` response frame to the request `id`, at the order
/// after `order`.
///
/// # Errors
///
/// - [`TightBeamError`] -- the errors of [`compose!`].
pub(crate) fn create_invalid_move_response(id: impl Into<Vec<u8>>, order: u64) -> Result<Frame, TightBeamError> {
	let id: Vec<u8> = id.into();
	let response = ChessMoveResponse { game_status: GameStatusCode::InvalidMove };
	compose! {
		V0: id: id,
		order: order + 1,
		message: response
	}
}

/// The configuration of the chess engine servlet.
pub struct ChessEngineServletConfig {
	/// The match manager that holds the authoritative game.
	pub manager: ChessMatchManager,
}

servlet! {
	/// The chess engine servlet, which plays each requested move against the
	/// authoritative board.
	pub ChessEngineServlet<ChessMoveRequest, EnvConfig = ChessEngineServletConfig>,
	protocol: TokioListener,
	handle: raw |message, ctx| async move {
		let trace = &ctx.trace();
		let config: &ChessEngineServletConfig = ctx.env_config();
		let message_id = message.metadata().id().to_vec();
		let invalid_move = |trace: Arc<TraceCollector>, id: Vec<u8>, order: u64|
			-> Result<Option<Frame>, TightBeamError> {
			trace.event(events::SERVER_RESPONSE_EMITTED)?;
			Ok(Some(create_invalid_move_response(id, order)?))
		};

		trace.event(events::SERVER_MOVE_RECEIVED)?;

		let move_req: ChessMoveRequest = match decode(message.message()) {
			Ok(req) => req,
			Err(_) => {
				// An undecodable request gets the invalid-move response.
				trace.event(events::SERVER_DECODE_FAILURE)?;
				return invalid_move(Arc::clone(trace), message_id, message.metadata().order());
			}
		};

		// The frame order counts the moves and increases with each request.
		let move_count = message.metadata().order();
		let game_status = match config.manager.process_move(&move_req, move_count, trace) {
			Ok(status) => status,
		Err(_e) => {
			return invalid_move(Arc::clone(trace), message_id, move_count);
		}
	};

	let matrix = match config.manager.game_state_matrix() {
		Ok(m) => m,
		Err(_) => {
			return invalid_move(Arc::clone(trace), message_id, move_count);
			}
		};

		let response = ChessMoveResponse { game_status };

		trace.event(events::SERVER_RESPONSE_EMITTED)?;

		Ok(Some(compose! {
			V3: id: message_id,
			order: move_count + 1,
			message: response,
			matrix: matrix
		}?))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The white knight move from b1 to c3.
	const KNIGHT_TO_C3: ChessMoveRequest =
		ChessMoveRequest { from_row: 0, from_col: 1, to_row: 2, to_col: 2, promotion: 0 };

	/// The black knight move from b8 to c6.
	const KNIGHT_TO_C6: ChessMoveRequest =
		ChessMoveRequest { from_row: 7, from_col: 1, to_row: 5, to_col: 2, promotion: 0 };

	/// The server's reply records the kind of the piece it moves.
	///
	/// The server plays the move at index `order % count` of its list of legal
	/// moves, and the list for Black holds its pawns ahead of its back row. At
	/// order 1 that is the pawn move from a7 to a5, the one pawn move of the
	/// exchange.
	#[test]
	fn the_server_move_records_its_piece_kind() -> Result<(), ChessMoveError> {
		let manager = ChessMatchManager::default();
		let trace = TraceCollector::new();

		manager.process_move(&KNIGHT_TO_C3, 1, &trace)?;

		assert_eq!(trace.recorded(events::PAWN_MOVE), 1);
		Ok(())
	}

	/// White moves first, so a black move at the first order is invalid.
	#[test]
	fn black_cannot_move_first() {
		let manager = ChessMatchManager::default();
		let trace = TraceCollector::new();

		let refusal = manager.process_move(&KNIGHT_TO_C6, 1, &trace);
		assert!(matches!(refusal, Err(ChessMoveError::InvalidMove)));
	}

	/// A manager whose game lock a thread poisoned when it panicked.
	fn poisoned_manager() -> ChessMatchManager {
		let manager = ChessMatchManager::default();
		let game_state = Arc::clone(&manager.game_state);
		let holder = std::thread::spawn(move || {
			let _held = game_state.lock();
			panic!("the holder panics while it holds the game lock");
		});
		holder.join().expect_err("the holder thread panics");

		manager
	}

	/// The game matrix of a poisoned game lock fails as `LockPoisoned`.
	#[test]
	fn a_poisoned_game_lock_fails_as_lock_poisoned() {
		let manager = poisoned_manager();
		let matrix = manager.game_state_matrix();
		assert!(matches!(matrix, Err(TightBeamError::LockPoisoned)));
	}

	/// Plays the moves of `seed` on a new game, as the fuzz client sends them:
	/// one move of four bytes at each odd order, and the server answers each.
	fn play_seed(seed: &[u8]) -> Result<(), ChessMoveError> {
		let manager = ChessMatchManager::default();
		let trace = TraceCollector::new();
		for (index, bytes) in seed.chunks_exact(4).enumerate() {
			let chess_move = ChessMove::from((bytes[0], bytes[1], bytes[2], bytes[3]));
			let order = 1 + 2 * index as u64;
			manager.process_move(&chess_move.to_request(), order, &trace)?;
		}

		Ok(())
	}

	// Each canonical seed plays legal moves for White from the start of a
	// game.
	tightbeam::tb_cases! {
		fn a_seed_plays_legal_white_moves(seed: &[u8]) -> Result<(), ChessMoveError> {
			play_seed(seed)?;
			Ok(())
		}
		cases {
			pawn => include_bytes!("seeds/basic/seed_pawn.txt"),
			knight => include_bytes!("seeds/basic/seed_knight.txt"),
			bishop => include_bytes!("seeds/basic/seed_bishop.txt"),
			rook => include_bytes!("seeds/basic/seed_rook.txt"),
			queen => include_bytes!("seeds/basic/seed_queen.txt"),
			king => include_bytes!("seeds/basic/seed_king.txt"),
		}
	}

	/// A client move from an empty square fails as an invalid move.
	#[test]
	fn an_illegal_client_move_is_an_invalid_move() {
		let manager = ChessMatchManager::default();
		let trace = TraceCollector::new();
		let from_an_empty_square = ChessMoveRequest { from_row: 4, from_col: 4, to_row: 5, to_col: 4, promotion: 0 };

		let refusal = manager.process_move(&from_an_empty_square, 1, &trace);
		assert!(matches!(refusal, Err(ChessMoveError::InvalidMove)));
	}
}
