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

#![cfg(all(feature = "std", feature = "full"))]

mod board;
mod piece;
mod state;

#[allow(unused_imports)]
use board::{
	create_invalid_move_response, is_white_turn, reset_chess_game_state, restart_game, ChessAssertSpec,
	ChessEngineServlet, ChessEngineServletConf, ChessGameFlow, ChessMoveRequest, ChessMoveResponse, ChessRules,
	GameStatusCode, GAME_STATE,
};
#[allow(unused_imports)]
use state::ChessGameState;
#[allow(unused_imports)]
use std::sync::{Arc, Mutex};
#[allow(unused_imports)]
use tightbeam::{compose, decode, tb_scenario};

// ============================================================================
// FUZZ TEST
// ============================================================================

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
			// Get or create shared game state (created once, reset before each iteration)
			// Reset happens before each iteration via reset_chess_game_state() called by macro
			let game_state = GAME_STATE.get_or_init(|| {
				Arc::new(Mutex::new(ChessGameState::new()))
			});

			let config = ChessEngineServletConf {
				game_state: game_state.clone(),
			};

			ChessEngineServlet::start(config).await
		},
		client: |trace, mut client| async move {
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
						let valid_moves = client_game_state.get_valid_moves(is_white_turn_val);
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
						*client_game_state.board_mut() = updated_state.board().clone();
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
						restart_game(
							&mut client_game_state,
							&mut order,
							&mut seed_mode,
							&mut seed_move_index,
							&mut seed_move_count,
							&trace,
						);
						// Continue loop to play another game
					}
				}
			}

			Ok(())
		}
	}
}
