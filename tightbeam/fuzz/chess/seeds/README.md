# Chess Fuzz Test Seeds

This directory contains seed files for the chess engine fuzz test.

## Seed Format

Each seed file contains binary data interpreted as chess moves:
- **First byte**: Number of moves (0-255)
- **Subsequent bytes**: Move coordinates encoded as `[from_row, from_col, to_row, to_col]` repeated

### Move Coordinate Encoding
- Each coordinate is a single byte (0-7) representing the 8x8 chess board
- Format: `[from_row, from_col, to_row, to_col]` per move
- Total bytes per move: 4 bytes
- Total bytes for N moves: `1 + (N * 4)` bytes

### Example
```
[0x05, 0x01, 0x00, 0x03, 0x00, ...]
  │     └─────┬─────┘
  │           └─ Move 1: from (1,0) to (3,0)
  └─ 5 moves total
```

## Seed Categories

### `basic/`
Standard seeds for general fuzzing:
- `seed_small.txt`: 1 move (4 bytes)
- `seed_medium.txt`: 5 moves (20 bytes)
- `seed_large.txt`: 10 moves (40 bytes)
- `seed_very_large.txt`: 20 moves (80 bytes)
- `seed_extra_large.txt`: 40 moves (160 bytes)

### `game_ending/`
Seeds designed to reach game-ending states:
- `seed_scholars_mate.txt`: Scholar's mate pattern (4 moves, checkmate sequence)
- `seed_fools_mate.txt`: Fool's mate pattern (2 moves, fastest checkmate)
- `seed_near_checkmate.txt`: Complex position near checkmate (16 moves)
- `seed_stalemate.txt`: Moves leading to stalemate-like positions (12 moves)
- `seed_king_corner.txt`: King pushed to corner (vulnerable position, 8 moves)

## Usage

The `analyze_chess_fuzz.sh` script automatically:
1. Copies all seeds from this directory to `built/fuzz/in/`
2. Runs AFL fuzzing with these seeds
3. AFL mutates these seeds to explore new paths

## Adding New Seeds

1. Create seed file in appropriate category directory
2. Follow the format: `1 byte (move count) + (move_count * 4) bytes (coordinates)`
3. Use descriptive names indicating the seed's purpose
4. Document any special characteristics in this README

