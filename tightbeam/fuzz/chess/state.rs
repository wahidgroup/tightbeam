#![allow(unexpected_cfgs)]

use std::ops::RangeInclusive;

use tightbeam::matrix::{Matrix, MatrixDyn, MatrixError, MatrixLike};
use tightbeam::urn::Urn;

use super::board::ChessMoveError;
use super::constants::MAX_MOVES_TO_FIND;
use super::piece;
use super::r#move::ChessMove;

/// One of the two castling moves of a side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CastlingSide {
	/// The castling toward the rook on column 7.
	King,
	/// The castling toward the rook on column 0.
	Queen,
}

impl CastlingSide {
	/// The column that the king starts on.
	const KING_FROM_COL: u8 = 4;

	/// Both castling moves, the king side first.
	const ALL: [Self; 2] = [Self::King, Self::Queen];

	/// The castling that takes the king from its start column to `to_col`, or
	/// `None` for any other column.
	fn of_king_target(to_col: u8) -> Option<Self> {
		Self::ALL.into_iter().find(|side| side.king_to_col() == to_col)
	}

	/// The column that the king lands on.
	const fn king_to_col(self) -> u8 {
		match self {
			Self::King => 6,
			Self::Queen => 2,
		}
	}

	/// The column that the rook starts on.
	const fn rook_from_col(self) -> u8 {
		match self {
			Self::King => 7,
			Self::Queen => 0,
		}
	}

	/// The column that the rook lands on, the square the king crosses.
	const fn rook_to_col(self) -> u8 {
		match self {
			Self::King => 5,
			Self::Queen => 3,
		}
	}

	/// The columns between the king and the rook, each of which must be
	/// empty.
	fn between_cols(self) -> RangeInclusive<u8> {
		match self {
			Self::King => 5..=6,
			Self::Queen => 1..=3,
		}
	}
}

/// The castling moves that each side keeps.
///
/// A move of the king ends both castlings of its side, and a move from or onto
/// the start square of a rook ends the castling of that rook.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CastlingRights([bool; 4]);

impl CastlingRights {
	/// Every castling of both sides, as at the start of a game.
	const ALL: Self = Self([true; 4]);

	/// The slot of the castling of `color` toward `side`.
	fn slot(color: piece::Color, side: CastlingSide) -> usize {
		let color_slot = match color {
			piece::Color::White => 0,
			piece::Color::Black => 2,
		};
		let side_slot = match side {
			CastlingSide::King => 0,
			CastlingSide::Queen => 1,
		};

		color_slot + side_slot
	}

	/// Whether `color` keeps its castling toward `side`.
	fn allows(self, color: piece::Color, side: CastlingSide) -> bool {
		self.0[Self::slot(color, side)]
	}

	/// Ends each castling whose king or rook starts on the square (`row`,
	/// `col`), which a move leaves or reaches.
	fn end_at(&mut self, row: u8, col: u8) {
		for color in [piece::Color::White, piece::Color::Black] {
			if row != color.to_back_row() {
				continue;
			}

			for side in CastlingSide::ALL {
				if col == CastlingSide::KING_FROM_COL || col == side.rook_from_col() {
					self.0[Self::slot(color, side)] = false;
				}
			}
		}
	}
}

/// What a legal move does beyond the move of its piece, which the board reads
/// from the piece and its squares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MoveKind {
	/// The piece moves, and it captures any piece on the target square.
	Plain,
	/// A pawn steps two squares, so the square it passes is open to an en
	/// passant capture on the next move.
	DoubleStep,
	/// A pawn takes en passant the pawn that passed it on a double step.
	EnPassant,
	/// The king castles toward the rook of the side, which crosses it.
	Castle(CastlingSide),
}

/// The chess board of one game.
///
/// A `Matrix<8>` holds the 8x8 board, one piece code for each square, and
/// `ChessMatchManager` counts the moves at the protocol level.
#[derive(Clone)]
pub struct ChessGameState {
	board: Matrix<8>, // Row 0 is White's back row.
	/// The castling moves that each side keeps.
	castling: CastlingRights,
	/// The square that the double step of the last move passed, which a pawn
	/// of the other side can take en passant on the next move alone.
	en_passant: Option<(u8, u8)>,
}

impl Default for ChessGameState {
	fn default() -> Self {
		Self::new()
	}
}

impl ChessGameState {
	pub fn new() -> Self {
		let mut board = Matrix::<8>::new();

		// The standard starting position puts White on rows 0 and 1.
		board.set(0, 0, piece::WHITE_ROOK.into());
		board.set(0, 1, piece::WHITE_KNIGHT.into());
		board.set(0, 2, piece::WHITE_BISHOP.into());
		board.set(0, 3, piece::WHITE_QUEEN.into());
		board.set(0, 4, piece::WHITE_KING.into());
		board.set(0, 5, piece::WHITE_BISHOP.into());
		board.set(0, 6, piece::WHITE_KNIGHT.into());
		board.set(0, 7, piece::WHITE_ROOK.into());

		for col in 0..8 {
			board.set(1, col, piece::WHITE_PAWN.into());
		}

		// Black starts on rows 6 and 7.
		for col in 0..8 {
			board.set(6, col, piece::BLACK_PAWN.into());
		}

		board.set(7, 0, piece::BLACK_ROOK.into());
		board.set(7, 1, piece::BLACK_KNIGHT.into());
		board.set(7, 2, piece::BLACK_BISHOP.into());
		board.set(7, 3, piece::BLACK_QUEEN.into());
		board.set(7, 4, piece::BLACK_KING.into());
		board.set(7, 5, piece::BLACK_BISHOP.into());
		board.set(7, 6, piece::BLACK_KNIGHT.into());
		board.set(7, 7, piece::BLACK_ROOK.into());

		Self { board, castling: CastlingRights::ALL, en_passant: None }
	}

	// Move generation lists the legal moves of one side.

	/// The first [`MAX_MOVES_TO_FIND`] legal moves of the side that
	/// `is_white_turn` names, in board order.
	pub(crate) fn to_valid_moves(&self, is_white_turn: bool) -> Vec<ChessMove> {
		let mut moves = Vec::new();
		for from_row in 0..8 {
			for from_col in 0..8 {
				let Some(piece) = piece::Piece::from_u8(self.board.get(from_row, from_col)) else {
					continue; // The square is empty.
				};

				if piece.is_white() != is_white_turn {
					continue; // The piece belongs to the other side.
				}

				// A candidate that leaves its own king out of check is legal.
				let candidates = self.to_piece_moves(from_row, from_col, piece);
				for chess_move in candidates {
					if !self.is_exposing_king(&chess_move, is_white_turn) {
						moves.push(chess_move);
						// The cap bounds the cost of a fuzz run.
						if moves.len() >= MAX_MOVES_TO_FIND {
							return moves;
						}
					}
				}
			}
		}
		moves
	}

	/// The legal move at index `seed % count` of [`Self::to_valid_moves`], or
	/// `None` when the side has no legal move (checkmate or stalemate).
	pub(crate) fn to_random_valid_move(&self, is_white_turn: bool, seed: u64) -> Option<ChessMove> {
		let valid_moves = self.to_valid_moves(is_white_turn);
		if valid_moves.is_empty() {
			return None;
		}

		// The seed picks the move, so a fuzz input replays the same game.
		let index = (seed as usize) % valid_moves.len();
		Some(valid_moves[index])
	}

	/// The moves of `piece` on (`from_row`, `from_col`), before the check
	/// test.
	fn to_piece_moves(&self, from_row: u8, from_col: u8, piece: piece::Piece) -> Vec<ChessMove> {
		let mut candidates = Vec::new();

		match piece.kind {
			piece::PieceKind::Pawn => {
				let forward = piece.color.to_pawn_forward_direction();
				let start_row = piece.color.to_pawn_start_row();

				// A pawn steps forward onto an empty square.
				if let Some(forward_row) = Self::to_valid_coord(from_row as i8 + forward) {
					if self.is_empty(forward_row, from_col) {
						self.add_pawn_move(&mut candidates, from_row, from_col, forward_row, from_col, piece);
						// From its start row, a pawn may step two squares when
						// both are empty.
						if from_row == start_row {
							if let Some(double_row) = Self::to_valid_coord(from_row as i8 + forward * 2) {
								if self.is_empty(double_row, from_col) {
									candidates.push(ChessMove::between((from_row, from_col), (double_row, from_col)));
								}
							}
						}
					}
				}

				// A pawn captures one square diagonally forward, and takes en
				// passant the pawn of the other side beside it that passed
				// that square on the last move.
				for col_offset in [-1i8, 1i8] {
					if let (Some(capture_row), Some(capture_col)) = (
						Self::to_valid_coord(from_row as i8 + forward),
						Self::to_valid_coord(from_col as i8 + col_offset),
					) {
						let is_passed_square = self.en_passant == Some((capture_row, capture_col));
						let is_en_passant = is_passed_square && self.can_capture(from_row, capture_col, piece);
						if self.can_capture(capture_row, capture_col, piece) || is_en_passant {
							self.add_pawn_move(&mut candidates, from_row, from_col, capture_row, capture_col, piece);
						}
					}
				}
			}
			piece::PieceKind::Rook | piece::PieceKind::Bishop | piece::PieceKind::Queen => {
				// A rook, a bishop, and a queen move along lines.
				if let Some(directions) = piece.kind.as_move_directions() {
					self.add_line_moves(&mut candidates, from_row, from_col, piece, directions);
				}
			}
			piece::PieceKind::Knight => {
				// A knight jumps to fixed offsets.
				if let Some(offsets) = piece.kind.as_move_offsets() {
					for (row_offset, col_offset) in offsets.iter().copied() {
						self.try_add_move(&mut candidates, from_row, from_col, row_offset, col_offset, piece);
					}
				}
			}
			piece::PieceKind::King => {
				// A king steps to one of the eight adjacent squares.
				for row_offset in -1..=1 {
					for col_offset in -1..=1 {
						if row_offset == 0 && col_offset == 0 {
							continue;
						}
						self.try_add_move(&mut candidates, from_row, from_col, row_offset, col_offset, piece);
					}
				}

				// A king castles two columns toward a rook.
				for side in CastlingSide::ALL {
					if self.can_castle(piece.color, side) {
						let target = (from_row, side.king_to_col());
						candidates.push(ChessMove::between((from_row, from_col), target));
					}
				}
			}
		}

		candidates
	}

	/// Whether the king of `color` can castle toward `side`.
	///
	/// A castle needs each of these:
	/// - The side keeps that castling.
	/// - The king and the rook stand on their start squares.
	/// - The squares between them are empty.
	/// - No piece of the other side attacks the king's square or a square the king crosses or lands on.
	fn can_castle(&self, color: piece::Color, side: CastlingSide) -> bool {
		let back_row = color.to_back_row();
		let king = u8::from(piece::Piece { kind: piece::PieceKind::King, color });
		let rook = u8::from(piece::Piece { kind: piece::PieceKind::Rook, color });
		let is_attacker_white = color == piece::Color::Black;

		let pieces_in_place = self.board.get(back_row, CastlingSide::KING_FROM_COL) == king
			&& self.board.get(back_row, side.rook_from_col()) == rook;
		let path_empty = side.between_cols().all(|col| self.is_empty(back_row, col));
		let king_path = [CastlingSide::KING_FROM_COL, side.rook_to_col(), side.king_to_col()];
		let path_safe = king_path
			.into_iter()
			.all(|col| !self.can_attack_square(back_row, col, is_attacker_white));

		self.castling.allows(color, side) && pieces_in_place && path_empty && path_safe
	}

	/// Adds the move of the pawn `piece` to the square (`to_row`, `to_col`),
	/// once for each promotion kind when the square is on the promotion row.
	fn add_pawn_move(
		&self,
		candidates: &mut Vec<ChessMove>,
		from_row: u8,
		from_col: u8,
		to_row: u8,
		to_col: u8,
		piece: piece::Piece,
	) {
		let pawn_move = ChessMove::between((from_row, from_col), (to_row, to_col));
		if to_row == piece.color.to_promotion_row() {
			candidates.extend(piece::PieceKind::PROMOTIONS.map(|kind| pawn_move.promoting_to(kind)));
		} else {
			candidates.push(pawn_move);
		}
	}

	/// The coordinate `coord` as a `u8`, or `None` when it is off the board,
	/// outside `0..8`.
	fn to_valid_coord(coord: i8) -> Option<u8> {
		if (0..8).contains(&coord) {
			Some(coord as u8)
		} else {
			None
		}
	}

	/// Whether the square is empty.
	fn is_empty(&self, row: u8, col: u8) -> bool {
		piece::Piece::from_u8(self.board.get(row, col)).is_none()
	}

	/// Whether the square holds a piece of the other side, which `piece` can
	/// capture.
	fn can_capture(&self, row: u8, col: u8, piece: piece::Piece) -> bool {
		if let Some(dest_piece) = piece::Piece::from_u8(self.board.get(row, col)) {
			dest_piece.color != piece.color
		} else {
			false
		}
	}

	/// Whether `piece` can move to the square, which is empty or holds a piece
	/// of the other side.
	fn can_move_to(&self, row: u8, col: u8, piece: piece::Piece) -> bool {
		if let Some(dest_piece) = piece::Piece::from_u8(self.board.get(row, col)) {
			dest_piece.color != piece.color
		} else {
			true // The square is empty.
		}
	}

	/// Adds the move to the square at the offset from (`from_row`,
	/// `from_col`) when it is on the board and `piece` can move to it.
	fn try_add_move(
		&self,
		candidates: &mut Vec<ChessMove>,
		from_row: u8,
		from_col: u8,
		row_offset: i8,
		col_offset: i8,
		piece: piece::Piece,
	) {
		if let (Some(to_row), Some(to_col)) = (
			Self::to_valid_coord(from_row as i8 + row_offset),
			Self::to_valid_coord(from_col as i8 + col_offset),
		) {
			if self.can_move_to(to_row, to_col, piece) {
				candidates.push(ChessMove::between((from_row, from_col), (to_row, to_col)));
			}
		}
	}

	/// Adds the move to every square along each of `directions` up to the
	/// first piece, and to the square of that piece when `piece` can capture
	/// it.
	fn add_line_moves(
		&self,
		candidates: &mut Vec<ChessMove>,
		from_row: u8,
		from_col: u8,
		piece: piece::Piece,
		directions: impl AsRef<[(i8, i8)]>,
	) {
		let directions = directions.as_ref();
		for &(row_step, col_step) in directions {
			let mut current_row = from_row as i8;
			let mut current_col = from_col as i8;

			loop {
				current_row += row_step;
				current_col += col_step;

				let Some(to_row) = Self::to_valid_coord(current_row) else {
					break; // The line leaves the board.
				};
				let Some(to_col) = Self::to_valid_coord(current_col) else {
					break; // The line leaves the board.
				};

				let line_move = ChessMove::between((from_row, from_col), (to_row, to_col));
				if self.is_empty(to_row, to_col) {
					candidates.push(line_move);
				} else {
					// A piece of the other side is a capture.
					if self.can_capture(to_row, to_col, piece) {
						candidates.push(line_move);
					}
					break; // Any piece ends the line.
				}
			}
		}
	}

	// Move validation checks one requested move.

	/// Checks `chess_move` for the side that `is_white_turn` names, as
	/// [`Self::is_move_valid`] decides it.
	///
	/// # Errors
	///
	/// - [`ChessMoveError::InvalidMove`] -- the move is illegal on this board.
	pub(crate) fn check_move(&self, chess_move: &ChessMove, is_white_turn: bool) -> Result<(), ChessMoveError> {
		if !self.is_move_valid(chess_move, is_white_turn) {
			return Err(ChessMoveError::InvalidMove);
		}

		Ok(())
	}

	/// Whether `chess_move` is legal on this board for the side that
	/// `is_white_turn` names.
	pub(crate) fn is_move_valid(&self, chess_move: &ChessMove, is_white_turn: bool) -> bool {
		// Every coordinate must be on the board.
		if chess_move.from_row >= 8 || chess_move.from_col >= 8 || chess_move.to_row >= 8 || chess_move.to_col >= 8 {
			return false;
		}

		// The source square must hold a piece.
		let Some(piece) = piece::Piece::from_u8(self.board.get(chess_move.from_row, chess_move.from_col)) else {
			return false;
		};

		// The piece must belong to the side to move.
		if piece.is_white() != is_white_turn {
			return false;
		}

		// A piece may make the moves that generation lists for it, so the two
		// share one rule for each kind of piece and each special move.
		let candidates = self.to_piece_moves(chess_move.from_row, chess_move.from_col, piece);
		if !candidates.contains(chess_move) {
			return false;
		}

		// A move that leaves its own king in check is illegal.
		!self.is_exposing_king(chess_move, is_white_turn)
	}

	/// Whether `chess_move` leaves its own king in check.
	fn is_exposing_king(&self, chess_move: &ChessMove, is_white_turn: bool) -> bool {
		// The board after the move decides, so a line that the move opens
		// counts, and a piece that the move captures stops its attack.
		let mut after = self.clone();
		after.apply_move(chess_move);
		after.is_in_check(is_white_turn)
	}

	/// Whether every square strictly between the two squares is empty.
	fn is_path_clear(&self, from_row: u8, from_col: u8, to_row: u8, to_col: u8) -> bool {
		let row_step = if to_row > from_row {
			1
		} else if to_row < from_row {
			-1
		} else {
			0
		};
		let col_step = if to_col > from_col {
			1
		} else if to_col < from_col {
			-1
		} else {
			0
		};

		let mut current_row = from_row as i8 + row_step;
		let mut current_col = from_col as i8 + col_step;
		let mut iterations = 0;
		const MAX_ITERATIONS: i32 = 8; // A bound past the longest line on the board.

		while (current_row != to_row as i8 || current_col != to_col as i8) && iterations < MAX_ITERATIONS {
			iterations += 1;

			// The conversion keeps each read on the board.
			let Some(cr) = Self::to_valid_coord(current_row) else {
				return false; // A path off the board is blocked.
			};
			let Some(cc) = Self::to_valid_coord(current_col) else {
				return false; // A path off the board is blocked.
			};

			if piece::Piece::from_u8(self.board.get(cr, cc)).is_some() {
				return false; // A piece blocks the path.
			}

			current_row += row_step;
			current_col += col_step;
		}

		// A path that reaches the iteration bound is blocked.
		if iterations >= MAX_ITERATIONS {
			return false;
		}

		true
	}

	/// Whether a piece of the side that `attacker_is_white` names attacks the
	/// target square.
	pub(crate) fn can_attack_square(&self, target_row: u8, target_col: u8, attacker_is_white: bool) -> bool {
		for row in 0..8 {
			for col in 0..8 {
				let Some(piece) = piece::Piece::from_u8(self.board.get(row, col)) else {
					continue;
				};

				if piece.is_white() != attacker_is_white {
					continue; // The piece belongs to the other side.
				}

				if self.can_piece_attack_square(row, col, target_row, target_col, piece) {
					return true;
				}
			}
		}
		false
	}

	/// Whether `piece` on (`from_row`, `from_col`) attacks the square
	/// (`to_row`, `to_col`).
	fn can_piece_attack_square(&self, from_row: u8, from_col: u8, to_row: u8, to_col: u8, piece: piece::Piece) -> bool {
		// Unlike `is_move_valid`, the test reads only the geometry and the
		// path, so it holds for either side to move and any piece on the target
		// square.
		let row_diff = to_row as i8 - from_row as i8;
		let col_diff = to_col as i8 - from_col as i8;
		let row_diff_abs = row_diff.unsigned_abs();
		let col_diff_abs = col_diff.unsigned_abs();

		match piece.kind {
			piece::PieceKind::Pawn => {
				// A pawn attacks one square diagonally forward.
				row_diff_abs == 1 && col_diff_abs == 1 && row_diff == piece.color.to_pawn_forward_direction()
			}
			piece::PieceKind::Rook => {
				// A rook attacks along a row or a column, over empty squares.
				if (row_diff_abs == 0 || col_diff_abs == 0) && (row_diff_abs > 0 || col_diff_abs > 0) {
					self.is_path_clear(from_row, from_col, to_row, to_col)
				} else {
					false
				}
			}
			piece::PieceKind::Knight => {
				// A knight attacks two squares one way and one square across.
				(row_diff_abs == 2 && col_diff_abs == 1) || (row_diff_abs == 1 && col_diff_abs == 2)
			}
			piece::PieceKind::Bishop => {
				// A bishop attacks along a diagonal, over empty squares.
				if row_diff_abs == col_diff_abs && row_diff_abs > 0 {
					self.is_path_clear(from_row, from_col, to_row, to_col)
				} else {
					false
				}
			}
			piece::PieceKind::Queen => {
				// A queen attacks along a row, a column, or a diagonal, over
				// empty squares.
				if (row_diff_abs == 0 || col_diff_abs == 0 || row_diff_abs == col_diff_abs)
					&& (row_diff_abs > 0 || col_diff_abs > 0)
				{
					self.is_path_clear(from_row, from_col, to_row, to_col)
				} else {
					false
				}
			}
			piece::PieceKind::King => {
				// A king attacks the eight adjacent squares.
				row_diff_abs <= 1 && col_diff_abs <= 1 && (row_diff_abs > 0 || col_diff_abs > 0)
			}
		}
	}

	// Move application updates the board.

	/// What the legal move `chess_move` does beyond the move of its piece.
	fn kind_of(&self, chess_move: &ChessMove) -> MoveKind {
		let moving = piece::Piece::from_u8(self.board.get(chess_move.from_row, chess_move.from_col));
		let row_span = chess_move.from_row.abs_diff(chess_move.to_row);
		let col_span = chess_move.from_col.abs_diff(chess_move.to_col);
		let target = (chess_move.to_row, chess_move.to_col);

		match moving.map(|piece| piece.kind) {
			Some(piece::PieceKind::Pawn) if row_span == 2 => MoveKind::DoubleStep,
			Some(piece::PieceKind::Pawn) if col_span == 1 && self.en_passant == Some(target) => MoveKind::EnPassant,
			Some(piece::PieceKind::King) if col_span == 2 => {
				CastlingSide::of_king_target(chess_move.to_col).map_or(MoveKind::Plain, MoveKind::Castle)
			}
			_ => MoveKind::Plain,
		}
	}

	/// Moves the piece on the source square of `chess_move` to its target
	/// square and empties the source square.
	///
	/// The move also does what its [`MoveKind`] names, and a promotion puts the
	/// promoted piece on the target square. The castling rights and the en
	/// passant square then follow the move.
	pub(crate) fn apply_move(&mut self, chess_move: &ChessMove) {
		let kind = self.kind_of(chess_move);
		let code = self.board.get(chess_move.from_row, chess_move.from_col);
		let landing = match (chess_move.promotion, piece::Piece::from_u8(code)) {
			(Some(kind), Some(pawn)) => u8::from(piece::Piece { kind, color: pawn.color }),
			_ => code,
		};

		match kind {
			MoveKind::EnPassant => self.board_mut().set(chess_move.from_row, chess_move.to_col, 0u8),
			MoveKind::Castle(side) => {
				let rook = self.board.get(chess_move.from_row, side.rook_from_col());
				self.board_mut().set(chess_move.from_row, side.rook_to_col(), rook);
				self.board_mut().set(chess_move.from_row, side.rook_from_col(), 0u8);
			}
			MoveKind::Plain | MoveKind::DoubleStep => {}
		}

		self.board_mut().set(chess_move.to_row, chess_move.to_col, landing);
		self.board_mut().set(chess_move.from_row, chess_move.from_col, 0u8); // The source square empties.

		self.castling.end_at(chess_move.from_row, chess_move.from_col);
		self.castling.end_at(chess_move.to_row, chess_move.to_col);
		self.en_passant = match kind {
			MoveKind::DoubleStep => Some((chess_move.from_row.midpoint(chess_move.to_row), chess_move.from_col)),
			_ => None,
		};
	}

	// Game state queries read check, checkmate, and stalemate.

	/// Whether the king of the side that `is_white_turn` names is in check.
	pub fn is_in_check(&self, is_white_turn: bool) -> bool {
		let king_pos = match self.find_king(is_white_turn) {
			Some(pos) => pos,
			None => return false, // A legal game holds both kings.
		};

		// A side is in check when a piece of the other side attacks its king.
		self.can_attack_square(king_pos.0, king_pos.1, !is_white_turn)
	}

	/// Whether the side that `is_white_turn` names is in stalemate.
	pub fn is_stalemate(&self, is_white_turn: bool) -> bool {
		// A side in stalemate has no legal move, and its king is out of check.
		self.to_valid_moves(is_white_turn).is_empty() && !self.is_in_check(is_white_turn)
	}

	/// Whether the side that `is_white_turn` names is in checkmate.
	pub fn is_checkmate(&self, is_white_turn: bool) -> bool {
		// A side in checkmate has no legal move, and its king is in check.
		self.to_valid_moves(is_white_turn).is_empty() && self.is_in_check(is_white_turn)
	}

	/// The game status of the side that `is_white_turn` names, from its legal
	/// moves and its check.
	pub(crate) fn determine_game_status(&self, is_white_turn: bool) -> super::board::GameStatusCode {
		let valid_moves = self.to_valid_moves(is_white_turn);
		let is_in_check = self.is_in_check(is_white_turn);
		if valid_moves.is_empty() && is_in_check {
			super::board::GameStatusCode::Checkmate
		} else if valid_moves.is_empty() {
			super::board::GameStatusCode::Stalemate
		} else {
			super::board::GameStatusCode::InProgress
		}
	}

	// Accessors read and write the board.

	pub fn count_pieces(&self) -> usize {
		// The count skips both kings, which every legal game holds.
		let mut count = 0;
		for row in 0..8 {
			for col in 0..8 {
				if let Some(piece) = piece::Piece::from_u8(self.board.get(row, col)) {
					if piece.kind != piece::PieceKind::King {
						count += 1;
					}
				}
			}
		}
		count
	}

	/// The square of the king of the side that `is_white` names, or `None` when
	/// the board holds no such king.
	pub(crate) fn find_king(&self, is_white: bool) -> Option<(u8, u8)> {
		let king_piece = if is_white {
			piece::WHITE_KING
		} else {
			piece::BLACK_KING
		};

		let king_u8: u8 = king_piece.into();
		for row in 0..8 {
			for col in 0..8 {
				if self.board.get(row, col) == king_u8 {
					return Some((row, col));
				}
			}
		}
		None
	}

	pub fn board(&self) -> &Matrix<8> {
		&self.board
	}

	pub fn board_mut(&mut self) -> &mut Matrix<8> {
		&mut self.board
	}

	/// The kind event URN of the piece on the square, or `None` for an empty
	/// square.
	pub(crate) fn piece_kind_at(&self, row: u8, col: u8) -> Option<Urn<'static>> {
		piece::Piece::from_u8(self.board.get(row, col)).map(|p| p.as_kind_event())
	}

	/// Replaces the board with the piece codes of `matrix`.
	///
	/// The matrix carries the squares alone, so the castling rights and the en
	/// passant square keep their values.
	///
	/// # Errors
	///
	/// - [`tightbeam::TightBeamError::InvalidBody`] -- `matrix` is not 8x8.
	#[allow(dead_code)]
	pub(crate) fn update_board_from_matrix(&mut self, matrix: &MatrixDyn) -> Result<(), tightbeam::TightBeamError> {
		// The board is 8x8, and the constructor of `MatrixDyn` already holds
		// `data.len() == n * n`, so the dimension is the whole check.
		if matrix.n() != 8 {
			return Err(tightbeam::TightBeamError::InvalidBody);
		}

		for row in 0..8 {
			for col in 0..8 {
				self.board_mut().set(row, col, matrix.get(row, col));
			}
		}

		Ok(())
	}
}

impl TryFrom<&ChessGameState> for MatrixDyn {
	type Error = MatrixError;

	fn try_from(state: &ChessGameState) -> Result<Self, Self::Error> {
		MatrixDyn::try_from(state.board())
	}
}

#[cfg(test)]
mod tests {
	use tightbeam::tb_cases;

	use super::*;

	/// A board that holds `pieces` and nothing else.
	fn position(pieces: &[(u8, u8, piece::Piece)]) -> ChessGameState {
		let mut board = Matrix::<8>::new();
		for &(row, col, piece) in pieces {
			board.set(row, col, piece.into());
		}

		ChessGameState { board, castling: CastlingRights::ALL, en_passant: None }
	}

	// A pawn on its start row opens one or two squares toward the other side.
	tb_cases! {
		fn a_pawn_opening_is_legal((opening, is_white_turn): (ChessMove, bool)) -> Result<(), ChessMoveError> {
			ChessGameState::new().check_move(&opening, is_white_turn)?;
			Ok(())
		}
		cases {
			white_one_square => (ChessMove::between((1, 4), (2, 4)), true),
			white_two_squares => (ChessMove::between((1, 4), (3, 4)), true),
			black_one_square => (ChessMove::between((6, 4), (5, 4)), false),
			black_two_squares => (ChessMove::between((6, 4), (4, 4)), false),
		}
	}

	/// The double step of a pawn passes over an empty square, so a knight on
	/// c3 blocks the pawn on c2.
	#[test]
	fn a_pawn_cannot_jump_a_piece() -> Result<(), ChessMoveError> {
		let mut state = ChessGameState::new();
		let knight_to_c3 = ChessMove::between((0, 1), (2, 2));

		state.check_move(&knight_to_c3, true)?;
		state.apply_move(&knight_to_c3);

		let over_the_knight = ChessMove::between((1, 2), (3, 2));
		let refusal = state.check_move(&over_the_knight, true);
		assert!(matches!(refusal, Err(ChessMoveError::InvalidMove)));
		Ok(())
	}

	/// A pawn that shields its king from a rook cannot leave the file to
	/// capture, so a rook that steps onto the file pins it there.
	#[test]
	fn a_pinned_pawn_cannot_capture() -> Result<(), ChessMoveError> {
		let mut state = position(&[
			(0, 4, piece::WHITE_KING),
			(1, 4, piece::WHITE_PAWN),
			(2, 3, piece::BLACK_KNIGHT),
			(7, 5, piece::BLACK_ROOK),
			(7, 0, piece::BLACK_KING),
		]);
		let pin = ChessMove::between((7, 5), (7, 4));
		state.check_move(&pin, false)?;
		state.apply_move(&pin);

		let capture = ChessMove::between((1, 4), (2, 3));
		let refusal = state.check_move(&capture, true);
		assert!(matches!(refusal, Err(ChessMoveError::InvalidMove)));
		Ok(())
	}

	/// A knight's check holds whatever stands between, so a move that leaves
	/// the king in it is illegal.
	#[test]
	fn a_move_that_ignores_a_knight_check_is_illegal() -> Result<(), ChessMoveError> {
		let mut state = position(&[
			(0, 0, piece::WHITE_ROOK),
			(0, 4, piece::WHITE_KING),
			(4, 2, piece::BLACK_KNIGHT),
			(7, 7, piece::BLACK_KING),
		]);
		let check = ChessMove::between((4, 2), (2, 3));
		state.check_move(&check, false)?;
		state.apply_move(&check);
		let rook_step = ChessMove::between((0, 0), (1, 0));

		let refusal = state.check_move(&rook_step, true);
		assert!(matches!(refusal, Err(ChessMoveError::InvalidMove)));
		Ok(())
	}

	/// A board with each king and each rook on its start square, and nothing
	/// else.
	fn castling_position() -> ChessGameState {
		position(&[
			(0, 0, piece::WHITE_ROOK),
			(0, 4, piece::WHITE_KING),
			(0, 7, piece::WHITE_ROOK),
			(7, 0, piece::BLACK_ROOK),
			(7, 4, piece::BLACK_KING),
			(7, 7, piece::BLACK_ROOK),
		])
	}

	/// The castling position after the white moves `moves`.
	fn castling_position_after(moves: &[ChessMove]) -> ChessGameState {
		let mut state = castling_position();
		for chess_move in moves {
			state.check_move(chess_move, true).expect("each setup move is legal");
			state.apply_move(chess_move);
		}

		state
	}

	// A castle moves the king two columns toward a rook, and the rook lands on
	// the square that the king crosses.
	tb_cases! {
		fn a_castle_moves_the_rook_across_the_king(
			(castle, is_white_turn, rook_square): (ChessMove, bool, (u8, u8))
		) -> Result<(), ChessMoveError> {
			let mut state = castling_position();
			state.check_move(&castle, is_white_turn)?;
			state.apply_move(&castle);

			let landed = piece::Piece::from_u8(state.board().get(rook_square.0, rook_square.1));
			assert_eq!(landed.map(|piece| piece.kind), Some(piece::PieceKind::Rook));
			Ok(())
		}
		cases {
			white_king_side => (ChessMove::between((0, 4), (0, 6)), true, (0, 5)),
			white_queen_side => (ChessMove::between((0, 4), (0, 2)), true, (0, 3)),
			black_king_side => (ChessMove::between((7, 4), (7, 6)), false, (7, 5)),
			black_queen_side => (ChessMove::between((7, 4), (7, 2)), false, (7, 3)),
		}
	}

	/// A board with the white king and the king-side rook on their start
	/// squares, the black king on a8, and `extra`.
	fn king_side_castle_with(extra: (u8, u8, piece::Piece)) -> ChessGameState {
		position(&[
			(0, 4, piece::WHITE_KING),
			(0, 7, piece::WHITE_ROOK),
			(7, 0, piece::BLACK_KING),
			extra,
		])
	}

	// A castle needs its rights, an empty path, and a king that no piece
	// attacks on its square or on a square it crosses or lands on.
	tb_cases! {
		fn an_illegal_castle_is_refused((state, castle): (ChessGameState, ChessMove)) {
			let refusal = state.check_move(&castle, true);
			assert!(matches!(refusal, Err(ChessMoveError::InvalidMove)));
		}
		cases {
			out_of_check => (king_side_castle_with((7, 4, piece::BLACK_ROOK)), ChessMove::between((0, 4), (0, 6))),
			through_an_attack => (king_side_castle_with((7, 5, piece::BLACK_ROOK)), ChessMove::between((0, 4), (0, 6))),
			into_an_attack => (king_side_castle_with((7, 6, piece::BLACK_ROOK)), ChessMove::between((0, 4), (0, 6))),
			past_a_piece => (king_side_castle_with((0, 6, piece::WHITE_KNIGHT)), ChessMove::between((0, 4), (0, 6))),
			after_the_king_moved => (
				castling_position_after(&[ChessMove::between((0, 4), (1, 4)), ChessMove::between((1, 4), (0, 4))]),
				ChessMove::between((0, 4), (0, 6)),
			),
			after_the_rook_moved => (
				castling_position_after(&[ChessMove::between((0, 0), (1, 0)), ChessMove::between((1, 0), (0, 0))]),
				ChessMove::between((0, 4), (0, 2)),
			),
		}
	}

	/// The board after Black's pawn on d7 steps two squares past White's
	/// pawn on e5.
	fn after_a_double_step_past_a_pawn() -> ChessGameState {
		let mut state = position(&[
			(0, 4, piece::WHITE_KING),
			(4, 4, piece::WHITE_PAWN),
			(6, 3, piece::BLACK_PAWN),
			(7, 4, piece::BLACK_KING),
		]);

		let double_step = ChessMove::between((6, 3), (4, 3));
		state.check_move(&double_step, false).expect("the double step is legal");
		state.apply_move(&double_step);

		state
	}

	/// A pawn of the other side takes en passant a pawn that passes it on a
	/// double step, and the capture empties the square of the passed pawn.
	#[test]
	fn an_en_passant_capture_removes_the_passed_pawn() -> Result<(), ChessMoveError> {
		let mut state = after_a_double_step_past_a_pawn();
		let en_passant = ChessMove::between((4, 4), (5, 3));
		state.check_move(&en_passant, true)?;
		state.apply_move(&en_passant);

		assert_eq!(state.board().get(4, 3), 0);
		Ok(())
	}

	/// The en passant capture is open on the next move alone, so a move of
	/// each side closes it.
	#[test]
	fn an_en_passant_capture_lasts_one_move() -> Result<(), ChessMoveError> {
		let mut state = after_a_double_step_past_a_pawn();
		let white_king_step = ChessMove::between((0, 4), (1, 4));
		state.check_move(&white_king_step, true)?;
		state.apply_move(&white_king_step);

		let black_king_step = ChessMove::between((7, 4), (6, 4));
		state.check_move(&black_king_step, false)?;
		state.apply_move(&black_king_step);

		let refusal = state.check_move(&ChessMove::between((4, 4), (5, 3)), true);
		assert!(matches!(refusal, Err(ChessMoveError::InvalidMove)));
		Ok(())
	}

	/// The square that a double step passes is open to the other side alone,
	/// so a pawn of the same side takes nothing there.
	#[test]
	fn a_pawn_takes_en_passant_beside_a_pawn_of_the_other_side() -> Result<(), ChessMoveError> {
		let mut state = position(&[
			(0, 4, piece::WHITE_KING),
			(1, 3, piece::WHITE_PAWN),
			(1, 4, piece::WHITE_PAWN),
			(7, 4, piece::BLACK_KING),
		]);

		let double_step = ChessMove::between((1, 4), (3, 4));
		state.check_move(&double_step, true)?;
		state.apply_move(&double_step);

		let refusal = state.check_move(&ChessMove::between((1, 3), (2, 4)), true);
		assert!(matches!(refusal, Err(ChessMoveError::InvalidMove)));
		Ok(())
	}

	/// A board with a white pawn one step from the last row.
	fn before_a_promotion() -> ChessGameState {
		position(&[(0, 4, piece::WHITE_KING), (6, 0, piece::WHITE_PAWN), (7, 4, piece::BLACK_KING)])
	}

	// A pawn that reaches the last row becomes the piece its move names.
	tb_cases! {
		fn a_promotion_replaces_the_pawn(kind: piece::PieceKind) -> Result<(), ChessMoveError> {
			let mut state = before_a_promotion();
			let promotion = ChessMove::between((6, 0), (7, 0)).promoting_to(kind);
			state.check_move(&promotion, true)?;
			state.apply_move(&promotion);
			assert_eq!(state.board().get(7, 0), u8::from(piece::Piece::as_white(kind)));
			Ok(())
		}
		cases {
			queen => piece::PieceKind::Queen,
			rook => piece::PieceKind::Rook,
			bishop => piece::PieceKind::Bishop,
			knight => piece::PieceKind::Knight,
		}
	}

	/// A pawn move onto the last row names the piece the pawn becomes.
	#[test]
	fn a_promotion_names_its_piece() {
		let state = before_a_promotion();
		let refusal = state.check_move(&ChessMove::between((6, 0), (7, 0)), true);
		assert!(matches!(refusal, Err(ChessMoveError::InvalidMove)));
	}

	/// A move that does not reach the last row names no promotion.
	#[test]
	fn a_promotion_on_another_move_is_illegal() {
		let state = ChessGameState::new();
		let knight_to_c3 = ChessMove::between((0, 1), (2, 2)).promoting_to(piece::PieceKind::Queen);

		let refusal = state.check_move(&knight_to_c3, true);
		assert!(matches!(refusal, Err(ChessMoveError::InvalidMove)));
	}

	/// A black pawn attacks the two squares diagonally toward row 0, so the
	/// white king cannot step onto either of them.
	#[test]
	fn a_king_cannot_step_into_a_pawn_attack() -> Result<(), ChessMoveError> {
		let mut state = position(&[(0, 4, piece::WHITE_KING), (3, 4, piece::BLACK_PAWN), (7, 0, piece::BLACK_KING)]);
		let advance = ChessMove::between((3, 4), (2, 4));
		state.check_move(&advance, false)?;
		state.apply_move(&advance);

		let into_the_attack = ChessMove::between((0, 4), (1, 3));
		let refusal = state.check_move(&into_the_attack, true);
		assert!(matches!(refusal, Err(ChessMoveError::InvalidMove)));
		Ok(())
	}
}
