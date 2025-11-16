use super::state::ChessGameState;
use tightbeam::trace::TraceCollector;

pub(crate) fn is_white_turn(order: u64) -> bool {
	order % 2 == 0
}

#[allow(dead_code)]
pub(crate) fn reset_chess_game_state() {
	let _ = ChessGameState::new();
}

#[allow(dead_code)]
pub(crate) fn restart_game(client_game_state: &mut ChessGameState, order: &mut u64, trace: &TraceCollector) {
	trace.event("client_move_validated");
	trace.event("client_server_move");
	trace.event("client_game_ended");
	*client_game_state = ChessGameState::new();
	*order = 1;
	trace.event("client_game_restarted");
}
