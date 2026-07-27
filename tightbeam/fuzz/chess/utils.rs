use tightbeam::trace::TraceCollector;

use super::events;
use super::state::ChessGameState;

/// Restart the game by resetting state and emitting game lifecycle events
/// Client-specific utility for managing game restarts
#[allow(dead_code)]
pub(crate) fn restart_game(
	client_game_state: &mut ChessGameState,
	order: &mut u64,
	trace: &TraceCollector,
) -> Result<(), tightbeam::TightBeamError> {
	trace.event(events::CLIENT_GAME_ENDED)?;

	*client_game_state = ChessGameState::new();
	*order = 1;

	trace.event(events::CLIENT_GAME_RESTARTED)?;
	Ok(())
}
