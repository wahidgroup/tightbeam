#![allow(dead_code)]

/// Maximum number of moves to find before early exit in move generation
pub(crate) const MAX_MOVES_TO_FIND: usize = 100;

/// Maximum total moves allowed in a fuzz test run
pub(crate) const MAX_TOTAL_MOVES: u64 = 50;

/// Maximum number of game replays allowed in a fuzz test run
pub(crate) const MAX_GAME_REPLAYS: u64 = 3;
