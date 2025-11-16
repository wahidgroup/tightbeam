//! Chess Engine Fuzz Test
//! - ChessEngine servlet handling moves and game state
//! - Matrix<8> storing chess board state (8x8 grid)
//! - Layered CSP specs (high-level flow + detailed chess rules)
//! - AFL fuzzing with invalid move testing

#![allow(unused_imports)]
#![allow(unexpected_cfgs)]
#![cfg(all(feature = "std", feature = "full"))]

mod board;
mod constants;
mod r#move;
mod piece;
mod state;
mod utils;

use std::sync::{Arc, Mutex};

use tightbeam::matrix::MatrixLike;
use tightbeam::{at_least, at_most, compose, decode, exactly, tb_assert_spec, tb_process_spec, tb_scenario};

use board::{
	ChessEngineServlet, ChessEngineServletConf, ChessMatchManager, ChessMoveRequest, ChessMoveResponse, GameStatusCode,
};
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
		gate: Accepted,
		assertions: [
			// Core requirement: at least one move must be sent
			("client_move_sent", at_least!(1)),
			("client_moves_processed_balance", exactly!(1), equals!(0i64), tags: ["balance"]),
			("client_server_move_balance", exactly!(1), equals!(0i64), tags: ["balance"]),
			("client_game_restart_balance", exactly!(1), equals!(0i64), tags: ["lifecycle"]),

			// Server-side servlet instrumentation guarantees
			("server_move_received", at_least!(1)),
			("server_response_emitted", at_least!(1)),
			("server_decode_failure", exactly!(0)),
			("server_state_lock_poisoned", exactly!(0)),

			// Individual error bounds remain for diagnostics
			("client_no_response", at_most!(5)),
			("client_decode_error", at_most!(5)),
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
			"client_move_sent", "client_move_rejected", "client_move_validated",
			"client_server_move", "client_game_ended", "client_game_restarted",
			"client_no_response", "client_decode_error", "client_moves_processed_balance",
			"client_server_move_balance", "client_game_restart_balance",
			"errors_within_limit", "rejection_ratio",
			"server_move_received", "server_move_validated", "server_move_generated",
			"server_move_invalid", "server_response_emitted", "server_decode_failure",
			"server_state_lock_poisoned", "server_game_ended",
			"pawn_move", "rook_move", "knight_move", "bishop_move", "queen_move", "king_move"
		}
		hidden { }
	}
	states {
		WaitingForMove => {
			"client_move_sent"                => ValidatingMove,
			"client_game_ended"               => GameOver,
			"client_moves_processed_balance"  => WaitingForMove,
			"client_server_move_balance"      => WaitingForMove,
			"client_game_restart_balance"     => WaitingForMove,
			"errors_within_limit"             => WaitingForMove,
			"rejection_ratio"                 => WaitingForMove,
		},
		ValidatingMove => {
			"client_move_validated"       => ProcessingMove,
			"client_move_rejected"        => WaitingForMove,
			"client_no_response"          => WaitingForMove,
			"client_decode_error"         => WaitingForMove,
			"server_move_received"        => ValidatingMove,
			"server_move_validated"       => ValidatingMove,
			"server_move_generated"       => ValidatingMove,
			"server_move_invalid"         => ValidatingMove,
			"server_response_emitted"     => ValidatingMove,
			"server_decode_failure"       => ValidatingMove,
			"server_state_lock_poisoned"  => ValidatingMove,
			"server_game_ended"           => ValidatingMove,
			"pawn_move"                   => ValidatingMove,
			"rook_move"                   => ValidatingMove,
			"knight_move"                 => ValidatingMove,
			"bishop_move"                 => ValidatingMove,
			"queen_move"                  => ValidatingMove,
			"king_move"                   => ValidatingMove,
		},
		ProcessingMove => {
			"client_server_move"       => WaitingForMove,
			"client_game_ended"        => GameOver,
			"client_move_validated"    => ProcessingMove,
			"server_move_validated"    => ProcessingMove,
			"server_move_generated"    => ProcessingMove,
			"server_response_emitted"  => ProcessingMove,
			"server_game_ended"        => ProcessingMove,
			"pawn_move"                => ProcessingMove,
			"rook_move"                => ProcessingMove,
			"knight_move"              => ProcessingMove,
			"bishop_move"              => ProcessingMove,
			"queen_move"               => ProcessingMove,
			"king_move"                => ProcessingMove,
		},
		GameOver => {
			"client_game_restarted"  => WaitingForMove,
			"client_server_move"     => GameOver,
			"client_move_validated"  => GameOver,
		}
	}
	terminal { GameOver }
	annotations { description: "High-level chess game protocol flow" }
}

// ============================================================================
// FUZZ TEST
// ============================================================================

tb_scenario! {
	fuzz: afl,
	spec: ChessAssertSpec,
	csp: ChessGameFlow,
	environment Servlet {
		servlet: ChessEngineServlet,
		start: |trace| async move {
			let config = Arc::new(ChessEngineServletConf {
				manager: ChessMatchManager::default(),
			});

			ChessEngineServlet::start(trace, config).await
		},
		client: |trace, mut client| async move {
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

			// Continuous: Play multiple games until input bytes are exhausted
			// This maximizes state exploration across different game scenarios
			loop {
				if stats.move_sent_count >= MAX_TOTAL_MOVES || stats.game_restarted_count >= MAX_GAME_REPLAYS {
					break;
				}

				// Check if we have enough bytes before attempting to read
				if !trace.oracle().fuzz_has_bytes(4).unwrap_or(false) {
					// No bytes available, break immediately
					break;
				}

				// We have bytes, try to read them
				let move_req = match (
					trace.oracle().fuzz_u8(),
					trace.oracle().fuzz_u8(),
					trace.oracle().fuzz_u8(),
					trace.oracle().fuzz_u8(),
				) {
					(Ok(fr), Ok(fc), Ok(tr), Ok(tc)) => {
						// Generate move from fuzz bytes (no validation - we want to test invalid moves too)
						ChessMove::from((fr, fc, tr, tc)).to_request()
					},
					_ => break, // Should not happen if fuzz_has_bytes was true
				};

				trace.event("client_move_sent");
				stats.move_sent_count += 1;

				// Emit piece kind event only after move is sent (not before validation)
				if let Some(piece) = piece::Piece::from_u8(client_game_state.board().get(move_req.from_row, move_req.from_col)) {
					trace.event(piece.as_kind_label());
				}

				// Send move request to server with current board state in matrix
				let matrix = tightbeam::matrix::MatrixDyn::try_from(&client_game_state)?;
				let frame = compose! {
					V0: id: "chess-client",
					order: order,
					message: move_req,
					matrix: matrix
				}?;

				// Get response frame
				let response_frame = match client.emit(frame, None).await? {
					Some(frame) => frame,
					None => {
						trace.event("client_no_response");
						stats.no_response_count += 1;
						break;
					}
				};

				// Decode response
				let response: ChessMoveResponse = match decode(&response_frame.message) {
					Ok(r) => r,
					Err(_) => {
						trace.event("client_decode_error");
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
						trace.event("client_move_rejected");
						stats.move_rejected_count += 1;
						// Continue to next move even if invalid
					}
					GameStatusCode::InProgress => {
						trace.event("client_move_validated");
						trace.event("client_server_move");
						stats.move_validated_count += 1;
						stats.server_move_count += 1;
						order += 2; // Client move + server move
					}
					GameStatusCode::Checkmate | GameStatusCode::Stalemate => {
						// Move was validated (we got a response), emit events
						trace.event("client_move_validated");
						trace.event("client_server_move");
						stats.move_validated_count += 1;
						stats.server_move_count += 1;
						stats.game_ended_count += 1;
						stats.game_restarted_count += 1;

						restart_game(&mut client_game_state, &mut order, &trace);
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
			let server_move_balance = (stats.move_validated_count as i64) - (stats.server_move_count as i64);
			let game_restart_balance = (stats.game_restarted_count as i64) - (stats.game_ended_count as i64);
			trace.event_with("client_moves_processed_balance", &["balance"], moves_processed_balance);
			trace.event_with("client_server_move_balance", &["balance"], server_move_balance);
			trace.event_with("client_game_restart_balance", &["lifecycle"], game_restart_balance);

			Ok(())
		}
	}
}
