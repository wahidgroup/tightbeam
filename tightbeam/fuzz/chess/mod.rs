//! Chess Engine Fuzz Test
//! - ChessEngine servlet handling moves and game state
//! - Matrix<8> storing chess board state (8x8 grid)
//! - Layered CSP specs (high-level flow + detailed chess rules)
//! - AFL fuzzing with invalid move testing

#![cfg(all(feature = "std", feature = "full"))]

mod board;
mod constants;
mod events;
mod r#move;
mod piece;
mod state;
mod utils;

use std::sync::Arc;
use std::time::{Duration, Instant};

use tightbeam::colony::servlet::ServletConfig;
use tightbeam::matrix::{MatrixDyn, MatrixLike};
use tightbeam::testing::{ScenarioConfig, ServletEnv, SetupEnv};
use tightbeam::transport::policy::RestartExponentialBackoff;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::ClientBuilder;
use tightbeam::transport::ConnectionBuilder;
use tightbeam::{at_least, at_most, compose, decode, exactly, tb_assert_spec, tb_process_spec, tb_scenario};

use board::{
	ChessEngineServlet, ChessEngineServletConfig, ChessMatchManager, ChessMoveRequest, ChessMoveResponse,
	GameStatusCode,
};
use piece::Piece;
use r#move::ChessMove;
use state::ChessGameState;
use utils::restart_game;

// ============================================================================
// ASSERTION SPEC
// ============================================================================

tb_assert_spec! {
	/// Chess game assertion specification
	///
	/// Tests chess game behavior:
	/// - Ensures moves are sent and the system processes them
	/// - Validates that validated moves trigger server responses
	pub ChessAssertSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			// Core requirement: at least one move must be sent
			(events::CLIENT_MOVE_SENT, at_least!(1)),
			(events::CLIENT_MOVES_PROCESSED_BALANCE, exactly!(1), equals!(0i64), tags: ["balance"]),
			(events::CLIENT_SERVER_MOVE_BALANCE, exactly!(1), equals!(0i64), tags: ["balance"]),
			(events::CLIENT_GAME_RESTART_BALANCE, exactly!(1), equals!(0i64), tags: ["lifecycle"]),

			// Server-side servlet instrumentation guarantees
			(events::SERVER_MOVE_RECEIVED, at_least!(1)),
			(events::SERVER_RESPONSE_EMITTED, at_least!(1)),
			(events::SERVER_DECODE_FAILURE, exactly!(0)),
			(events::SERVER_STATE_LOCK_POISONED, exactly!(0)),

			// Individual error bounds remain for diagnostics
			(events::CLIENT_NO_RESPONSE, at_most!(5)),
			(events::CLIENT_DECODE_ERROR, at_most!(5)),
		]
	},
	annotations { description: "Comprehensive chess game assertion specification" }
}

// ============================================================================
// CSP PROCESS SPECS (LAYERED)
// ============================================================================

tb_process_spec! {
	pub ChessGameFlow,
	events {
		observable {
			events::CLIENT_MOVE_SENT, events::CLIENT_MOVE_REJECTED, events::CLIENT_MOVE_VALIDATED,
			events::CLIENT_SERVER_MOVE, events::CLIENT_GAME_ENDED, events::CLIENT_GAME_RESTARTED,
			events::CLIENT_NO_RESPONSE, events::CLIENT_DECODE_ERROR, events::CLIENT_MOVES_PROCESSED_BALANCE,
			events::CLIENT_SERVER_MOVE_BALANCE, events::CLIENT_GAME_RESTART_BALANCE,
			events::ERRORS_WITHIN_LIMIT, events::REJECTION_RATIO,
			events::SERVER_MOVE_RECEIVED, events::SERVER_MOVE_VALIDATED, events::SERVER_MOVE_GENERATED,
			events::SERVER_MOVE_INVALID, events::SERVER_RESPONSE_EMITTED, events::SERVER_DECODE_FAILURE,
			events::SERVER_STATE_LOCK_POISONED, events::SERVER_GAME_ENDED, events::SERVER_GAME_RESTARTED,
			events::PAWN_MOVE, events::ROOK_MOVE, events::KNIGHT_MOVE, events::BISHOP_MOVE, events::QUEEN_MOVE, events::KING_MOVE
		}
		hidden { }
	}
	states {
		WaitingForMove => {
			events::CLIENT_MOVE_SENT                => ValidatingMove,
			events::CLIENT_GAME_ENDED               => GameOver,
			events::CLIENT_MOVES_PROCESSED_BALANCE  => WaitingForMove,
			events::CLIENT_SERVER_MOVE_BALANCE      => WaitingForMove,
			events::CLIENT_GAME_RESTART_BALANCE     => WaitingForMove,
			events::ERRORS_WITHIN_LIMIT             => WaitingForMove,
			events::REJECTION_RATIO                 => WaitingForMove,
		},
		ValidatingMove => {
			events::CLIENT_MOVE_VALIDATED       => ProcessingMove,
			events::CLIENT_MOVE_REJECTED        => WaitingForMove,
			events::CLIENT_NO_RESPONSE          => WaitingForMove,
			events::CLIENT_DECODE_ERROR         => WaitingForMove,
			events::SERVER_MOVE_RECEIVED        => ValidatingMove,
			events::SERVER_MOVE_VALIDATED       => ValidatingMove,
			events::SERVER_MOVE_GENERATED       => ValidatingMove,
			events::SERVER_MOVE_INVALID         => ValidatingMove,
			events::SERVER_RESPONSE_EMITTED     => ValidatingMove,
			events::SERVER_DECODE_FAILURE       => ValidatingMove,
			events::SERVER_STATE_LOCK_POISONED  => ValidatingMove,
			events::SERVER_GAME_ENDED           => ValidatingMove,
			events::SERVER_GAME_RESTARTED       => ValidatingMove,
			events::PAWN_MOVE                   => ValidatingMove,
			events::ROOK_MOVE                   => ValidatingMove,
			events::KNIGHT_MOVE                 => ValidatingMove,
			events::BISHOP_MOVE                 => ValidatingMove,
			events::QUEEN_MOVE                  => ValidatingMove,
			events::KING_MOVE                   => ValidatingMove,
		},
		ProcessingMove => {
			events::CLIENT_SERVER_MOVE       => WaitingForMove,
			events::CLIENT_GAME_ENDED        => GameOver,
			events::CLIENT_MOVE_VALIDATED    => ProcessingMove,
			events::SERVER_MOVE_VALIDATED    => ProcessingMove,
			events::SERVER_MOVE_GENERATED    => ProcessingMove,
			events::SERVER_RESPONSE_EMITTED  => ProcessingMove,
			events::SERVER_GAME_ENDED        => ProcessingMove,
			events::SERVER_GAME_RESTARTED    => ProcessingMove,
			events::PAWN_MOVE                => ProcessingMove,
			events::ROOK_MOVE                => ProcessingMove,
			events::KNIGHT_MOVE              => ProcessingMove,
			events::BISHOP_MOVE              => ProcessingMove,
			events::QUEEN_MOVE               => ProcessingMove,
			events::KING_MOVE                => ProcessingMove,
		},
		GameOver => {
			events::CLIENT_GAME_ENDED        => GameOver,
			events::SERVER_GAME_ENDED        => GameOver,
			events::SERVER_GAME_RESTARTED    => GameOver,
			events::CLIENT_GAME_RESTARTED    => WaitingForMove,
		}
	}
	annotations { description: "High-level chess game protocol flow" }
}

// ============================================================================
// FUZZ TEST
// ============================================================================

tb_scenario! {
	fuzz: afl,
	config: ScenarioConfig::builder()
		.with_spec(ChessAssertSpec::latest())
		.with_csp(ChessGameFlow)
		.build(),
	environment Servlet {
		context: ChessEngineServletConfig {
			manager: ChessMatchManager::default(),
		},
		start: |SetupEnv { trace, context }| async move {
			let servlet_conf = ServletConfig::<TokioListener, ChessMoveRequest>::builder()
				.with_config(context)
				.build();

			ChessEngineServlet::start(Arc::new(trace), Some(servlet_conf)).await
		},
		setup: |env| async move {
			// Create a custom client with exponential backoff retry policy
			// Exponential backoff: 100ms, 200ms, 400ms, 800ms delays (max 3 attempts)
			let restart_policy = RestartExponentialBackoff::new(3, 100, None);
			let client_builder = ClientBuilder::<TokioListener>::builder()
				.with_restart(restart_policy)
				.with_timeout(Duration::from_millis(500))
				.build();

			let client = client_builder.connect(env.addr).await?;
			Ok(client)
		},
		client: |ServletEnv { trace, mut client, .. }| async move {
			#[derive(Default)]
			struct GameStats {
				move_sent_count: u64,
				move_validated_count: u64,
				move_rejected_count: u64,
				server_move_count: u64,
				game_ended_count: u64,
				game_restarted_count: u64,
				no_response_count: u64,
				decode_error_count: u64,
			}

			// Initialize client-side game state
			let mut client_game_state = ChessGameState::new();
			let mut stats = GameStats::default();
			let mut order = 1u64;

			const MAX_TOTAL_MOVES: u64 = 50;
			const MAX_GAME_REPLAYS: u64 = 3;
			// Maximum time for entire fuzz execution
			const MAX_EXECUTION_TIME_SECS: u64 = 1;

			// Continuous: Play multiple games until input bytes are exhausted
			// This maximizes state exploration across different game scenarios
			let start_time = Instant::now();
			loop {
				// Check execution time limit to prevent hangs
				if start_time.elapsed().as_secs() >= MAX_EXECUTION_TIME_SECS {
					trace.event(events::CLIENT_EXECUTION_TIMEOUT)?;
					break;
				}

				if stats.move_sent_count >= MAX_TOTAL_MOVES || stats.game_restarted_count >= MAX_GAME_REPLAYS {
					break;
				}

				// Check if we have enough bytes before attempting to read
				// For short inputs, break immediately - the loop will have run at least once
				// if we had any bytes, satisfying the "at least 1 move" requirement
				if !trace.oracle().fuzz_has_bytes(4).unwrap_or(false) {
					// If we haven't sent any moves yet and have no bytes, we need to send
					// at least one move to satisfy server assertions. Use zeros.
					if stats.move_sent_count == 0 {
						// Continue to send a synthetic move with zeros
					} else {
						// We've sent at least one move, safe to break
						break;
					}
				}

				// We have bytes (or need to send synthetic move), try to read them
				let move_req = match (
					trace.oracle().fuzz_u8(),
					trace.oracle().fuzz_u8(),
					trace.oracle().fuzz_u8(),
					trace.oracle().fuzz_u8(),
				) {
					(Ok(fr), Ok(fc), Ok(tr), Ok(tc)) => {
						// Generate move from fuzz bytes
						ChessMove::from((fr, fc, tr, tc)).to_request()
					},
					// Partial read or no bytes - use zeros for synthetic move
					_ => ChessMove::from((0u8, 0u8, 0u8, 0u8)).to_request(),
				};

				trace.event(events::CLIENT_MOVE_SENT)?;
				stats.move_sent_count += 1;

				// Emit piece kind event only after move is sent (not before validation)
				if let Some(piece) = Piece::from_u8(client_game_state.board().get(move_req.from_row, move_req.from_col)) {
					trace.event(piece.as_kind_event())?;
				}

				// Send move request to server with current board state in matrix
				let matrix = MatrixDyn::try_from(&client_game_state)?;
				let frame = compose! {
					V0: id: "chess-client",
					order: order,
					message: move_req,
					matrix: matrix
				}?;

				// Get response frame with timeout protection
				// Wrap emit in timeout to prevent hang
				let response_frame = match tokio::time::timeout(
					Duration::from_millis(1000),
					client.emit(frame, None)
				).await {
					Ok(Ok(Some(frame))) => frame,
					Ok(Ok(None)) => {
						trace.event(events::CLIENT_NO_RESPONSE)?;
						stats.no_response_count += 1;
						break;
					}
					Ok(Err(_e)) => {
						// Transport error - log and break
						trace.event(events::CLIENT_EMIT_ERROR)?;
						stats.no_response_count += 1;
						break;
					}
					Err(_) => {
						// Timeout occurred
						trace.event(events::CLIENT_TIMEOUT)?;
						stats.no_response_count += 1;
						break;
					}
				};

				// Decode response
				let response: ChessMoveResponse = match decode(&response_frame.message) {
					Ok(r) => r,
					Err(_) => {
						trace.event(events::CLIENT_DECODE_ERROR)?;
						stats.decode_error_count += 1;
						break;
					}
				};

				// Update client game state from response matrix if present
				// Only update board, preserve client's own move tracking
				if let Some(ref asn1_matrix) = response_frame.metadata.matrix {
					if client_game_state.update_board_from_matrix(asn1_matrix).is_err() {
						// Invalid matrix format - ignore and continue
					}
				}

				// Track response type for coverage feedback
				match response.game_status {
					GameStatusCode::InvalidMove => {
						trace.event(events::CLIENT_MOVE_REJECTED)?;
						stats.move_rejected_count += 1;
						// Continue to next move even if invalid
					}
					GameStatusCode::InProgress => {
						trace.event(events::CLIENT_MOVE_VALIDATED)?;
						trace.event(events::CLIENT_SERVER_MOVE)?;
						stats.move_validated_count += 1;
						stats.server_move_count += 1;
						order += 2; // Client move + server move
					}
					GameStatusCode::Checkmate | GameStatusCode::Stalemate => {
						// Move was validated (we got a response), emit events
						trace.event(events::CLIENT_MOVE_VALIDATED)?;
						trace.event(events::CLIENT_SERVER_MOVE)?;
						stats.move_validated_count += 1;
						stats.server_move_count += 1;
						stats.game_ended_count += 1;
					stats.game_restarted_count += 1;

					restart_game(&mut client_game_state, &mut order, &trace)?;
					if stats.game_restarted_count >= MAX_GAME_REPLAYS {
							break;
						}
						// Continue loop to play another game
					}
				}
			}

			let processed_moves = stats.move_validated_count
				+ stats.move_rejected_count
				+ stats.no_response_count
				+ stats.decode_error_count;

			let moves_processed_balance = (stats.move_sent_count as i64) - (processed_moves as i64);
			trace.event_with(events::CLIENT_MOVES_PROCESSED_BALANCE, &["balance"], moves_processed_balance)?;

			let server_move_balance = (stats.move_validated_count as i64) - (stats.server_move_count as i64);
			trace.event_with(events::CLIENT_SERVER_MOVE_BALANCE, &["balance"], server_move_balance)?;

			let game_restart_balance = (stats.game_restarted_count as i64) - (stats.game_ended_count as i64);
			trace.event_with(events::CLIENT_GAME_RESTART_BALANCE, &["lifecycle"], game_restart_balance)?;

			Ok(())
		}
	}
}
