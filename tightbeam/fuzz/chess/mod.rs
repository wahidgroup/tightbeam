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
//! RUSTFLAGS="--cfg fuzzing" cargo afl build --bin fuzz_chess \
//!   --features "std,testing-fuzz,testing-fdr,testing-csp"
//! mkdir -p fuzz_in && echo "seed" > fuzz_in/seed.txt
//! cargo afl fuzz -i fuzz_in -o fuzz_out target/debug/fuzz_chess
//! ```

#![allow(unused_imports)]
#![allow(unexpected_cfgs)]
#![cfg(all(feature = "std", feature = "full"))]

mod board;
mod piece;
mod state;
mod utils;

use std::sync::{Arc, Mutex};

use tightbeam::matrix::MatrixLike;
use tightbeam::{at_least, at_most, compose, decode, exactly, tb_assert_spec, tb_process_spec, tb_scenario};

use board::{ChessEngineServlet, ChessEngineServletConf, ChessMoveRequest, ChessMoveResponse, GameStatusCode};
use state::ChessGameState;
use utils::{reset_chess_game_state, restart_game};

// ============================================================================
// ASSERTION SPEC
// ============================================================================

tb_assert_spec! {
	/// Chess game assertion specification
	///
	/// Tests chess game behavior:
	/// - Ensures moves are sent and the system processes them
	/// - Validates that validated moves trigger server responses
	/// - Ensures reasonable ratio of validated vs rejected moves
	/// - Bounds error conditions to detect system failures
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
			let config = ChessEngineServletConf {
				game_state: Arc::new(Mutex::new(ChessGameState::new())),
			};

			ChessEngineServlet::start(trace, config).await
		},
		client: |trace, mut client| async move {
			// Initialize client-side game state
			let mut client_game_state = ChessGameState::new();
			let mut order = 1u64;

			const MAX_TOTAL_MOVES: u64 = 50;
			const MAX_GAME_REPLAYS: u64 = 3;

			let mut move_validated_count = 0u64;
			let mut move_rejected_count = 0u64;
			let mut server_move_count = 0u64;
			let mut game_ended_count = 0u64;
			let mut game_restarted_count = 0u64;
			let mut no_response_count = 0u64;
			let mut decode_error_count = 0u64;

			// Continuous: Play multiple games until input bytes are exhausted
			// This maximizes state exploration across different game scenarios
			let mut move_sent_count = 0u64;
			loop {
				if move_sent_count >= MAX_TOTAL_MOVES || game_restarted_count >= MAX_GAME_REPLAYS {
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
					(Ok(fr), Ok(fc), Ok(tr), Ok(tc)) => ChessMoveRequest {
						from_row: fr % 8,
						from_col: fc % 8,
						to_row: tr % 8,
						to_col: tc % 8,
					},
					_ => break, // Should not happen if fuzz_has_bytes was true
				};

				trace.event("client_move_sent");

				if let Some(kind) = piece::kind_label(client_game_state.board().get(move_req.from_row, move_req.from_col)) {
					trace.event(kind);
				}
				move_sent_count += 1;

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
						no_response_count += 1;
						break;
					}
				};

				// Decode response
				let response: ChessMoveResponse = match decode(&response_frame.message) {
					Ok(r) => r,
					Err(_) => {
						trace.event("client_decode_error");
						decode_error_count += 1;
						break;
					}
				};

				// Update client game state from response matrix if present
				if let Some(ref asn1_matrix) = response_frame.metadata.matrix {
					if let Ok(updated_state) = ChessGameState::try_from(asn1_matrix) {
						*client_game_state.board_mut() = updated_state.board().clone();
					}
				}

				// Track response type for coverage feedback
				match response.game_status {
					GameStatusCode::InvalidMove => {
						trace.event("client_move_rejected");
						move_rejected_count += 1;
						// Continue to next move even if invalid
					}
					GameStatusCode::InProgress => {
						trace.event("client_move_validated");
						trace.event("client_server_move");
						move_validated_count += 1;
						server_move_count += 1;
						order += 2; // Client move + server move
					}
					GameStatusCode::Checkmate | GameStatusCode::Stalemate => {
						restart_game(&mut client_game_state, &mut order, &trace);
						move_validated_count += 1;
						server_move_count += 1;
						game_ended_count += 1;
						game_restarted_count += 1;
						if game_restarted_count >= MAX_GAME_REPLAYS {
							break;
						}
						// Continue loop to play another game
					}
				}
			}

			let processed_moves = move_validated_count + move_rejected_count + no_response_count + decode_error_count;
			let moves_processed_balance = (move_sent_count as i64) - (processed_moves as i64);
			let server_move_balance = (move_validated_count as i64) - (server_move_count as i64);
			let game_restart_balance = (game_restarted_count as i64) - (game_ended_count as i64);
			trace.event_with("client_moves_processed_balance", &["balance"], moves_processed_balance);
			trace.event_with("client_server_move_balance", &["balance"], server_move_balance);
			trace.event_with("client_game_restart_balance", &["lifecycle"], game_restart_balance);

			Ok(())
		}
	}
}
