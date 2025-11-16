use std::sync::{Arc, Mutex, OnceLock};

use super::state::ChessGameState;
use tightbeam::trace::TraceCollector;

pub(crate) static GAME_STATE: OnceLock<Arc<Mutex<ChessGameState>>> = OnceLock::new();

pub(crate) fn is_white_turn(order: u64) -> bool {
	order % 2 == 0
}

#[allow(dead_code)]
pub(crate) fn reset_chess_game_state() {
	if let Some(game_state) = GAME_STATE.get() {
		*game_state.lock().unwrap() = ChessGameState::new();
	}
}

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
	*client_game_state = ChessGameState::new();
	*order = 1;
	*seed_mode = true;
	*seed_move_index = 0;
	*seed_move_count = 0;
	trace.event("game_restarted");
}
