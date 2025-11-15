/// Chess piece encoding (values 0-12)
///
/// Encoding scheme:
/// - 0 = empty square
/// - 1-6 = white pieces (pawn=1, rook=2, knight=3, bishop=4, queen=5, king=6)
/// - 7-12 = black pieces (pawn=7, rook=8, knight=9, bishop=10, queen=11, king=12)
pub const EMPTY: u8 = 0;

// White pieces
pub const WHITE_PAWN: u8 = 1;
pub const WHITE_ROOK: u8 = 2;
pub const WHITE_KNIGHT: u8 = 3;
pub const WHITE_BISHOP: u8 = 4;
pub const WHITE_QUEEN: u8 = 5;
pub const WHITE_KING: u8 = 6;

// Black pieces
pub const BLACK_PAWN: u8 = 7;
pub const BLACK_ROOK: u8 = 8;
pub const BLACK_KNIGHT: u8 = 9;
pub const BLACK_BISHOP: u8 = 10;
pub const BLACK_QUEEN: u8 = 11;
pub const BLACK_KING: u8 = 12;

pub fn is_white(piece: u8) -> bool {
	(1..=6).contains(&piece)
}

pub fn is_black(piece: u8) -> bool {
	(7..=12).contains(&piece)
}

pub fn is_empty(piece: u8) -> bool {
	piece == EMPTY
}

