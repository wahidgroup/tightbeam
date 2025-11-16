# Chess Fuzz Test Seeds

This directory holds the **canonical** input corpus for the chess fuzz target.
Every file is binary and follows the same layout:

- Byte `0`: number of moves (0–255)
- Bytes `1+`: move quadruples `[from_row, from_col, to_row, to_col]`
- Each coordinate is a single byte `0..=7` that indexes the board rows/cols

Example (pawn double-step):

```
[0x01, 0x06, 0x04, 0x04, 0x04]
  │     └────┬────┘
  │          └─ move 1: (6,4) → (4,4)
  └─ total moves: 1
```

## Current Seeds

We now keep a **minimal, high-signal** corpus: one short, deterministic demo
for each chess piece. All seeds live under `basic/`.

| File | Moves | Purpose |
| --- | --- | --- |
| `seed_pawn.txt` | 1 | Pawn double-step from e2 to e4 |
| `seed_knight.txt` | 1 | Kingside knight hop g1→f3 |
| `seed_bishop.txt` | 2 | Opens the diagonal (pawn d2→d4) then bishop c1→f4 |
| `seed_rook.txt` | 2 | Clears the a-file pawn and advances the rook |
| `seed_queen.txt` | 2 | Frees the queen’s pawn then develops the queen vertically |
| `seed_king.txt` | 2 | Moves the king’s pawn then slides the king forward |

These seeds are intentionally tiny so AFL can mutate them quickly while still
demonstrating legal movement for every piece.

## Usage

1. Copy this directory into `built/fuzz/in/` before running AFL (the helper
   scripts can do this automatically).
2. AFL will mutate these deterministic inputs to explore deeper states.

## Adding Seeds

If you add a new canonical seed, please:

1. Follow the byte layout above.
2. Keep it deterministic (no randomness-dependent behavior).
3. Document the file in the table so future contributors know its intent.

