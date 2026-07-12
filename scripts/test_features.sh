#!/bin/bash
# Feature combination tests - edit this file to add/modify combinations
# Run with: make test-all or ./scripts/test_features.sh
set -e

echo "=== Feature Combination Tests ==="

# Most steps are `cargo check` (compilation only). Steps that carry behavioral
# tests (the transport backends, and the full default build) run `cargo test`
# so non-default feature sets are actually exercised, not just compiled.

# 1. Minimal: std + derive (no zeroize/crypto/builder)
echo "[1/19] Check: Minimal std + derive"
cargo check --package tightbeam-rs --no-default-features --features "std,derive"

# 2. Minimal: std + crypto (crypto core without aead/digest/x509)
echo "[2/19] Check: Minimal std + crypto"
cargo check --package tightbeam-rs --no-default-features --features "std,crypto"

# 3. Minimal: std + derive + builder (frame builder without aead/digest/signature)
echo "[3/19] Check: Minimal std + derive + builder"
cargo check --package tightbeam-rs --no-default-features --features "std,derive,builder"

# 4. Bare transport feature (no derive/tcp pulled transitively): a published
# feature MUST build standalone.
echo "[4/19] Check: Bare transport (no_std)"
cargo check --package tightbeam-rs --no-default-features --features "transport"

# 5. Bare transport feature with std.
echo "[5/19] Check: Bare transport + std"
cargo check --package tightbeam-rs --no-default-features --features "std,transport"

# 6. Transport CMS (core secure messaging)
echo "[6/19] Test: Transport CMS"
cargo test --package tightbeam-rs --no-default-features --features "std,transport-cms,testing"

# 7. Transport ECIES (lighter alternative)
echo "[7/19] Test: Transport ECIES"
cargo test --package tightbeam-rs --no-default-features --features "std,transport-ecies,testing"

# 8. Transport CMS + ECIES + TCP + Async (full transport stack)
echo "[8/19] Check: Transport Full + TCP + Async"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,transport-ecies,tcp,tokio,testing"

# 9. CMS-only TCP (no ECIES): the decoupled build the driver split enables
echo "[9/19] Test: Transport CMS-only + TCP + Async"
cargo test --package tightbeam-rs --no-default-features --features "std,transport-cms,tcp,tokio,testing"

# 10. Transport CMS + Derive enabled
echo "[10/19] Check: Transport CMS + Derive"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,derive,testing"

# 11. Testing framework features
echo "[11/19] Check: Testing CSP/FDR"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,testing,testing-csp,testing-fdr"

# 12. Testing timing/schedulability (requires CSP)
echo "[12/19] Check: Testing Timing"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,testing,testing-csp,testing-timing,testing-schedulability"

# 13. Colony (full cluster features)
echo "[13/19] Check: Colony"
cargo check --package tightbeam-rs --no-default-features --features "colony,testing"

# 14. no_std: builder (alloc-only, no std)
echo "[14/19] Check: no_std builder"
cargo check --package tightbeam-rs --no-default-features --features "builder"

# 15. no_std: transport-ecies (alloc-only, no std)
echo "[15/19] Check: no_std transport-ecies"
cargo check --package tightbeam-rs --no-default-features --features "transport-ecies"

# 16. Downstream consumer cfg-leak regression (derive must not emit feature cfgs)
echo "[16/19] Check: Consumer cfg-leak regression"
cargo check --package tightbeam-consumer-test

# 17. Instrument standalone (digest cfg regression: instrument must pull digest)
echo "[17/19] Check: Instrument standalone"
cargo check --package tightbeam-rs --no-default-features --features "std,instrument"

# 18. Full (default features) - run tests
echo "[18/19] Test: Full (default features)"
make test

# 19. wasm32 browser transport core: async-transport compiles the generic
# AsyncProtocolStream + TcpTransport without tokio.
echo "[19/19] Check: wasm32 transport-ecies + async-transport (no tokio)"
if rustup target list --installed | grep -q '^wasm32-unknown-unknown$'; then
	cargo check --target wasm32-unknown-unknown --package tightbeam-rs --no-default-features --features "std,transport-ecies,async-transport,wasm"
else
	echo "  FAIL: wasm32-unknown-unknown target missing (run: make setup)" >&2
	exit 1
fi

echo "=== All feature tests passed ==="
