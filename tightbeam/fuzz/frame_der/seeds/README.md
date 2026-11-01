# Frame Fuzz Seeds

Binary corpus for `fuzz_frame_der`. Each file is the DER of one `Frame` from `TestFrame`.

| File                  | Frame                                   |
| --------------------- | --------------------------------------- |
| `frame_v0.bin`        | `TestFrame::v0`, a V0 frame             |
| `frame_integrity.bin` | `TestFrame::with_integrity`, a V1 frame |
| `frame_priority.bin`  | `TestFrame::prioritized`, a V2 frame    |
