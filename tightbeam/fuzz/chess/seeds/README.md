# Chess Fuzz Test Seeds

This directory holds the **canonical** input corpus for the chess fuzz target. Every file is binary, and each move takes four bytes:

- Bytes `4n` to `4n + 3`: move `n`, counted from 0, as `[from_row, from_col, to_row, to_col]`
- Each coordinate is a single byte `0..=7` that indexes a board row or column

The client reads moves until fewer than four bytes remain. It plays Black, which starts on rows 6 and 7 and moves first in this harness. Row `r` is rank `r + 1`, and column `c` is file `a + c`.

Example (pawn double-step from e7 to e5):

```
[0x06, 0x04, 0x04, 0x04]   move 0: from (6,4) to (4,4)
```

## Current Seeds

The corpus is **minimal**: one short, deterministic seed for each chess piece. All seeds live under `basic/`.

| File | Moves | Purpose |
| --- | --- | --- |
| `seed_pawn.txt` | 1 | Pawn double-step from e7 to e5 |
| `seed_knight.txt` | 1 | Queenside knight from b8 to c6 |
| `seed_bishop.txt` | 2 | Opens the diagonal (pawn d7 to d5), then bishop c8 to e6 |
| `seed_rook.txt` | 2 | Advances the a-file pawn (a7 to a5), then rook a8 to a6 |
| `seed_queen.txt` | 2 | Frees the queen’s pawn (d7 to d6), then queen d8 to d7 |
| `seed_king.txt` | 2 | Moves the king’s pawn (e7 to e6), then king e8 to e7 |

Each seed holds one or two moves, so AFL mutates it quickly, and together the seeds show a legal move for every piece.

## Usage

1. Copy the seed files into `built/fuzz/in/fuzz_chess/` before you start AFL. `scripts/fuzz-test.sh` and `scripts/analyze_fuzz.sh` make this copy themselves.
2. AFL mutates these deterministic inputs to reach deeper game states.

## Adding Seeds

To add a canonical seed:

1. Follow the byte layout above.
2. Keep it deterministic, so that its bytes alone decide its moves.
3. Add a row for the file to the table, with its moves and its purpose.
