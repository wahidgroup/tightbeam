//! Chess fuzz scenario event inventory.
//!
//! One URN per emit site, domain-scoped under `event:chess/` so trace
//! assertions and CSP alphabets key on full URN identity.

#![allow(dead_code)]

use tightbeam::utils::urn::Urn;

const FUZZ_NID: &str = "fuzz";

// Client-side game flow
pub(crate) const CLIENT_MOVE_SENT: Urn<'static> = tightbeam::urn!(FUZZ_NID, "event:chess/client-move-sent");
pub(crate) const CLIENT_MOVE_REJECTED: Urn<'static> = tightbeam::urn!(FUZZ_NID, "event:chess/client-move-rejected");
pub(crate) const CLIENT_MOVE_VALIDATED: Urn<'static> = tightbeam::urn!(FUZZ_NID, "event:chess/client-move-validated");
pub(crate) const CLIENT_SERVER_MOVE: Urn<'static> = tightbeam::urn!(FUZZ_NID, "event:chess/client-server-move");
pub(crate) const CLIENT_GAME_ENDED: Urn<'static> = tightbeam::urn!(FUZZ_NID, "event:chess/client-game-ended");
pub(crate) const CLIENT_GAME_RESTARTED: Urn<'static> = tightbeam::urn!(FUZZ_NID, "event:chess/client-game-restarted");
pub(crate) const CLIENT_NO_RESPONSE: Urn<'static> = tightbeam::urn!(FUZZ_NID, "event:chess/client-no-response");
pub(crate) const CLIENT_DECODE_ERROR: Urn<'static> = tightbeam::urn!(FUZZ_NID, "event:chess/client-decode-error");
pub(crate) const CLIENT_EMIT_ERROR: Urn<'static> = tightbeam::urn!(FUZZ_NID, "event:chess/client-emit-error");
pub(crate) const CLIENT_TIMEOUT: Urn<'static> = tightbeam::urn!(FUZZ_NID, "event:chess/client-timeout");
pub(crate) const CLIENT_EXECUTION_TIMEOUT: Urn<'static> =
	tightbeam::urn!(FUZZ_NID, "event:chess/client-execution-timeout");

// Client-side balance/lifecycle summaries
#[rustfmt::skip]
pub(crate) const CLIENT_MOVES_PROCESSED_BALANCE: Urn<'static> = tightbeam::urn!(FUZZ_NID, "event:chess/client-moves-processed-balance");
pub(crate) const CLIENT_SERVER_MOVE_BALANCE: Urn<'static> =
	tightbeam::urn!(FUZZ_NID, "event:chess/client-server-move-balance");
pub(crate) const CLIENT_GAME_RESTART_BALANCE: Urn<'static> =
	tightbeam::urn!(FUZZ_NID, "event:chess/client-game-restart-balance");
pub(crate) const ERRORS_WITHIN_LIMIT: Urn<'static> = tightbeam::urn!(FUZZ_NID, "event:chess/errors-within-limit");
pub(crate) const REJECTION_RATIO: Urn<'static> = tightbeam::urn!(FUZZ_NID, "event:chess/rejection-ratio");

// Server-side servlet instrumentation
pub(crate) const SERVER_MOVE_RECEIVED: Urn<'static> = tightbeam::urn!(FUZZ_NID, "event:chess/server-move-received");
pub(crate) const SERVER_MOVE_VALIDATED: Urn<'static> = tightbeam::urn!(FUZZ_NID, "event:chess/server-move-validated");
pub(crate) const SERVER_MOVE_GENERATED: Urn<'static> = tightbeam::urn!(FUZZ_NID, "event:chess/server-move-generated");
pub(crate) const SERVER_MOVE_INVALID: Urn<'static> = tightbeam::urn!(FUZZ_NID, "event:chess/server-move-invalid");
pub(crate) const SERVER_RESPONSE_EMITTED: Urn<'static> =
	tightbeam::urn!(FUZZ_NID, "event:chess/server-response-emitted");
pub(crate) const SERVER_DECODE_FAILURE: Urn<'static> = tightbeam::urn!(FUZZ_NID, "event:chess/server-decode-failure");
pub(crate) const SERVER_STATE_LOCK_POISONED: Urn<'static> =
	tightbeam::urn!(FUZZ_NID, "event:chess/server-state-lock-poisoned");
pub(crate) const SERVER_GAME_ENDED: Urn<'static> = tightbeam::urn!(FUZZ_NID, "event:chess/server-game-ended");
pub(crate) const SERVER_GAME_RESTARTED: Urn<'static> = tightbeam::urn!(FUZZ_NID, "event:chess/server-game-restarted");

// Piece movement kinds
pub(crate) const PAWN_MOVE: Urn<'static> = tightbeam::urn!(FUZZ_NID, "event:chess/pawn-move");
pub(crate) const ROOK_MOVE: Urn<'static> = tightbeam::urn!(FUZZ_NID, "event:chess/rook-move");
pub(crate) const KNIGHT_MOVE: Urn<'static> = tightbeam::urn!(FUZZ_NID, "event:chess/knight-move");
pub(crate) const BISHOP_MOVE: Urn<'static> = tightbeam::urn!(FUZZ_NID, "event:chess/bishop-move");
pub(crate) const QUEEN_MOVE: Urn<'static> = tightbeam::urn!(FUZZ_NID, "event:chess/queen-move");
pub(crate) const KING_MOVE: Urn<'static> = tightbeam::urn!(FUZZ_NID, "event:chess/king-move");
