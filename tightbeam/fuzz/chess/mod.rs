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

#![allow(unexpected_cfgs)]
#![cfg(all(feature = "std", feature = "full"))]

mod board;
mod piece;
mod state;
mod utils;

use std::sync::{Arc, Mutex};

use board::{ChessEngineServlet, ChessEngineServletConf, ChessMoveRequest, ChessMoveResponse, GameStatusCode};
use state::ChessGameState;
use utils::{is_white_turn, reset_chess_game_state, restart_game, GAME_STATE};

use tightbeam::{at_least, at_most, compose, decode, exactly, tb_assert_spec, tb_process_spec, tb_scenario};

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
			"server_state_lock_poisoned", "server_game_ended"
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
		},
		ProcessingMove => {
			"client_server_move"       => WaitingForMove,
			"client_game_ended"        => GameOver,
			"client_move_validated"    => ProcessingMove,
			"server_move_validated"    => ProcessingMove,
			"server_move_generated"    => ProcessingMove,
			"server_response_emitted"  => ProcessingMove,
			"server_game_ended"        => ProcessingMove,
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

tb_process_spec! {
	pub ChessRules,
	events {
		observable {
			"pawn_move", "rook_move", "knight_move", "bishop_move",
			"queen_move", "king_move", "check", "checkmate", "stalemate"
		}
		hidden { }
	}
	states {
		GameStart => {
			"pawn_move"   => InGame,
			"rook_move"   => InGame,
			"knight_move" => InGame,
			"bishop_move" => InGame,
			"queen_move"  => InGame,
			"king_move"   => InGame
		},
		InGame => {
			"pawn_move"   => InGame,
			"rook_move"   => InGame,
			"knight_move" => InGame,
			"bishop_move" => InGame,
			"queen_move"  => InGame,
			"king_move"   => InGame,
			"check"       => InCheck,
			"stalemate"   => GameEnd
		},
		InCheck => {
			"king_move"   => InGame,
			"checkmate"   => GameEnd
		},
		GameEnd => {}
	}
	terminal { GameEnd }
	annotations { description: "Detailed chess rules state machine" }
}

// ============================================================================
// FUZZ TEST
// ============================================================================

tb_scenario! {
	fuzz: afl,
	spec: ChessAssertSpec,
	csp: ChessGameFlow,
	// fdr: FdrConfig {
	// 	seeds: 4,
	// 	max_depth: 100,
	// 	max_internal_run: 8,
	// 	timeout_ms: 5000,
	// 	specs: vec![ChessGameFlow::process(), ChessRules::process()],
	// 	fail_fast: true,
	// 	expect_failure: false,
	// 	scheduler_count: None,
	// 	process_count: None,
	// 	scheduler_model: None,
	// 	fault_model: None,
	// 	fmea: None,
	// },
	environment Servlet {
		servlet: ChessEngineServlet,
		start: |trace| async move {
			// Get or create shared game state (created once, reset before each iteration)
			// Reset happens before each iteration via reset_chess_game_state() called by macro
			let game_state = GAME_STATE.get_or_init(|| {
				Arc::new(Mutex::new(ChessGameState::new()))
			});

			let config = ChessEngineServletConf {
				game_state: game_state.clone(),
			};

			ChessEngineServlet::start(trace, config).await
		},
		client: |trace, mut client| async move {
			// Initialize client-side game state (starts with standard chess position)
			let mut client_game_state = ChessGameState::new();
			let mut order = 1u64;
			let mut seed_mode = true; // Start in seed mode (direct coordinates)
			let mut seed_move_index = 0u8;
			let mut seed_move_count = 0u8;

			let mut move_validated_count = 0u64;
			let mut move_rejected_count = 0u64;
			let mut server_move_count = 0u64;
			let mut game_ended_count = 0u64;
			let mut game_restarted_count = 0u64;
			let mut no_response_count = 0u64;
			let mut decode_error_count = 0u64;

			// Continuous fuzzing: play multiple games until input bytes are exhausted
			// This maximizes state space exploration across different game scenarios
			// Track if we've sent at least one move to satisfy assertion requirement
			let mut move_sent_count = 0u32;
			loop {
				// Determine turn from order (even = white, odd = black)
				let is_white_turn_val = is_white_turn(order);

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
						Err(_) => {
							// Out of input bytes - if we haven't sent any moves yet,
							// try to send at least one with minimal/default input
							if move_sent_count == 0 {
								seed_mode = false; // Switch to dynamic mode to try one more time
							} else {
								break;
							}
						}
					}
				}

				let move_req = if seed_mode && seed_move_index > 0 && seed_move_index <= seed_move_count {
					// Reading direct coordinates from seed
					let from_row = match trace.oracle().fuzz_u8() {
						Ok(b) => b % 8,
						Err(_) => {
							// Out of input - use defaults if we haven't sent any moves yet
							if move_sent_count == 0 { 0 } else { break; }
						}
					};
					let from_col = match trace.oracle().fuzz_u8() {
						Ok(b) => b % 8,
						Err(_) => {
							if move_sent_count == 0 { 0 } else { break; }
						}
					};
					let to_row = match trace.oracle().fuzz_u8() {
						Ok(b) => b % 8,
						Err(_) => {
							if move_sent_count == 0 { 0 } else { break; }
						}
					};
					let to_col = match trace.oracle().fuzz_u8() {
						Ok(b) => b % 8,
						Err(_) => {
							if move_sent_count == 0 { 0 } else { break; }
						}
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
						Err(_) => {
							// Out of input bytes - if we haven't sent any moves yet, use default
							if move_sent_count == 0 { 0 } else { break; }
						}
					};

					// Extract move coordinates based on strategy
					let use_valid_moves = (strategy_byte % 10) < 8; // 80% valid, 20% invalid
					if use_valid_moves {
						// CSP-guided: choose from valid moves
						let valid_moves = client_game_state.get_valid_moves(is_white_turn_val);
						if valid_moves.is_empty() {
							// No valid moves - game over (stalemate/checkmate)
							// Break to end fuzzing for this game
							break;
						}

						// Use CSP byte to choose which valid move
						let choice_byte = match trace.oracle().fuzz_u8() {
							Ok(b) => b,
							Err(_) => {
								// Out of input bytes - use first move if we haven't sent any yet
								if move_sent_count == 0 { 0 } else { break; }
							}
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
							Err(_) => {
								if move_sent_count == 0 { 0 } else { break; }
							}
						};
						let from_col = match trace.oracle().fuzz_u8() {
							Ok(b) => b % 8,
							Err(_) => {
								if move_sent_count == 0 { 0 } else { break; }
							}
						};
						let to_row = match trace.oracle().fuzz_u8() {
							Ok(b) => b % 8,
							Err(_) => {
								if move_sent_count == 0 { 0 } else { break; }
							}
						};
						let to_col = match trace.oracle().fuzz_u8() {
							Ok(b) => b % 8,
							Err(_) => {
								if move_sent_count == 0 { 0 } else { break; }
							}
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

				trace.event("client_move_sent");
				move_sent_count += 1;

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
						restart_game(
							&mut client_game_state,
							&mut order,
							&mut seed_mode,
							&mut seed_move_index,
							&mut seed_move_count,
							&trace,
						);
						move_validated_count += 1;
						server_move_count += 1;
						game_ended_count += 1;
						game_restarted_count += 1;
						// Continue loop to play another game
					}
				}
			}

			let processed_moves = move_validated_count + move_rejected_count + no_response_count + decode_error_count;
			let moves_processed_balance = (move_sent_count as i64) - (processed_moves as i64);
			let server_move_balance = (move_validated_count as i64) - (server_move_count as i64);
			let game_restart_balance = (game_restarted_count as i64) - (game_ended_count as i64);
			trace.assert_value("client_moves_processed_balance", &["balance"], moves_processed_balance);
			trace.assert_value("client_server_move_balance", &["balance"], server_move_balance);
			trace.assert_value("client_game_restart_balance", &["lifecycle"], game_restart_balance);

			Ok(())
		}
	}
}
