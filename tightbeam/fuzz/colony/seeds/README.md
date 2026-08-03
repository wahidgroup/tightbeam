# Colony Fuzz Seeds

Binary corpus for `fuzz_colony`. Each file is a sequence of action records. Every record is two bytes:

- Byte `0`: opcode (`% 16` selects export/grant/gate/policy/csr/lifecycle/stress/advertise/cross-org/stream/duplex/anon/foreign/failover/work)
- Byte `1`: selector (org index, target type, relay bit, size clamps)

## Seeds

| File                       | Purpose                                     |
| -------------------------- | ------------------------------------------- |
| `seed_export_work.bin`     | Mutate export then send unary work          |
| `seed_csr_grant.bin`       | Grant CSR type then submit a CSR            |
| `seed_stress.bin`          | Short stress burst against public work      |
| `seed_advertise_xorg.bin`  | One-shot peer ad then cross-org peer-ping   |
| `seed_policy_gate.bin`     | Arm GatePolicy reject then unary work       |
| `seed_stream.bin`          | Open a routed stream to stream-echo         |
| `seed_firstparty_work.bin` | Own-org work to the unexported private type |
| `seed_grant_foreign.bin`   | Grant beta on alpha then beta dials private |
| `seed_denygate_work.bin`   | Deny own SPKI then work the exported public |

## Usage

Copy into `built/fuzz/in/` before `cargo afl fuzz`, or let the helper scripts stage `$FUZZ_BASE/colony/seeds`.
