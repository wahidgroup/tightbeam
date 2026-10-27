# Chess Fuzz Test Seeds

This directory holds the **canonical** input corpus for the chess fuzz target. Every file is binary, and each move takes four bytes:

- Bytes `4n` to `4n + 3`: move `n`, counted from 0, as `[from_row, from_col, to_row, to_col]`
- The low three bits of each byte give a coordinate `0..=7` that indexes a board row or column
- The bits above them in the `to_row` byte give the white board code of the piece a pawn on the last row becomes: 2 for a rook, 3 for a knight, 4 for a bishop, or 5 for a queen

The client reads moves until fewer than four bytes remain. It plays White, which starts on rows 0 and 1 and moves first. Row `r` is rank `r + 1`, and column `c` is file `a + c`.

Example (pawn double-step from e2 to e4):

```
[0x01, 0x04, 0x03, 0x04]   move 0: from (1,4) to (3,4)
```

## Current Seeds

The corpus is **minimal**: one short, deterministic seed for each chess piece. All seeds live under `basic/`.

| File              | Moves | Purpose                                                  |
| ----------------- | ----- | -------------------------------------------------------- |
| `seed_pawn.txt`   | 1     | Pawn double-step from e2 to e4                           |
| `seed_knight.txt` | 1     | Queenside knight from b1 to c3                           |
| `seed_bishop.txt` | 2     | Opens the diagonal (pawn d2 to d4), then bishop c1 to e3 |
| `seed_rook.txt`   | 2     | Advances the a-file pawn (a2 to a4), then rook a1 to a3  |
| `seed_queen.txt`  | 2     | Frees the queen’s pawn (d2 to d3), then queen d1 to d2   |
| `seed_king.txt`   | 2     | Moves the king’s pawn (e2 to e3), then king e1 to e2     |

Each seed holds one or two moves, so AFL mutates it quickly, and together the seeds show a legal move for every piece.

## Usage

1. Copy the seed files into `built/fuzz/in/fuzz_chess/` before you start AFL. `scripts/fuzz-test.sh` and `scripts/analyze_fuzz.sh` make this copy themselves.
2. AFL mutates these deterministic inputs to reach deeper game states.

## Adding Seeds

To add a canonical seed:

1. Follow the byte layout above.
2. Keep it deterministic, so that its bytes alone decide its moves.
3. Add a row for the file to the table, with its moves and its purpose.
