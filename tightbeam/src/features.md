# Features

| Task | Features |
| --- | --- |
| Compose, encode, and decode frames | `builder`, `std` |
| Take the whole production stack | `full` |
| Carry frames over a connection | `transport`, `tcp`, `async-transport`, `transport-multiplex` |
| Authenticate and key a connection | `transport-cms`, `transport-ecies` |
| Gate and route frames | `policy`, `transport-policy`, `router` |
| Run a colony of clusters, hives, drones, and servlets | `colony` |
| Select cryptographic primitives | `crypto`, `random`, `zeroize`, `digest`, `sha3`, `aead`, `aes-gcm`, `signature`, `secp256k1`, `x509`, `kdf`, `ecdh`, `ecies` |
| Drive a transport from an async runtime | `tokio`, `futures` |
| Reach a browser on `wasm32-unknown-unknown` | `wasm` |
| Record traces, timings, and logs | `instrument`, `time`, `logging` |
| Write hexadecimal literals in a specification | `hex`, `constants` |
| Verify protocol behavior from a test | `testing`, then `testing-csp`, `testing-fdr`, `testing-timing`, `testing-schedulability`, `testing-fault`, or `testing-fmea` |
| Fuzz a target with AFL | `testing-fuzz`, `testing-fuzz-ijon` |
| Compress frame payloads | `compress`, `zstd` |
| Spread verification work across cores | `rayon` |
| Read a standards vocabulary | `standards`, `standards-rfc` |
| Experiment with post-quantum key agreement | `unstable-pqxdh`, `kem` |
