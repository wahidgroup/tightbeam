#!/bin/bash
# Feature combination tests - edit this file to add/modify combinations
# Run with: make test-all or ./scripts/test_features.sh
set -e

echo "=== Feature Combination Tests ==="

# Check compilation for each feature combination
# Note: cargo check verifies compilation; tests are run only with full features

# 1. Minimal: std + derive (no zeroize/crypto/builder)
echo "[1/16] Check: Minimal std + derive"
cargo check --package tightbeam-rs --no-default-features --features "std,derive"

# 2. Minimal: std + crypto (crypto core without aead/digest/x509)
echo "[2/16] Check: Minimal std + crypto"
cargo check --package tightbeam-rs --no-default-features --features "std,crypto"

# 3. Minimal: std + derive + builder (frame builder without aead/digest/signature)
echo "[3/16] Check: Minimal std + derive + builder"
cargo check --package tightbeam-rs --no-default-features --features "std,derive,builder"

# 4. Transport CMS (core secure messaging)
echo "[4/16] Check: Transport CMS"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,testing"

# 5. Transport ECIES (lighter alternative)
echo "[5/16] Check: Transport ECIES"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-ecies,testing"

# 6. Transport CMS + ECIES + TCP + Async (full transport stack)
echo "[6/16] Check: Transport Full + TCP + Async"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,transport-ecies,tcp,tokio,testing"

# 7. Transport CMS + Derive enabled
echo "[7/16] Check: Transport CMS + Derive"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,derive,testing"

# 8. Testing framework features
echo "[8/16] Check: Testing CSP/FDR"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,testing,testing-csp,testing-fdr"

# 9. Testing timing/schedulability (requires CSP)
echo "[9/16] Check: Testing Timing"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,testing,testing-csp,testing-timing,testing-schedulability"

# 10. Colony (full cluster features)
echo "[10/16] Check: Colony"
cargo check --package tightbeam-rs --no-default-features --features "colony,testing"

# 11. no_std: builder (alloc-only, no std)
echo "[11/16] Check: no_std builder"
cargo check --package tightbeam-rs --no-default-features --features "builder"

# 12. no_std: transport-ecies (alloc-only, no std)
echo "[12/16] Check: no_std transport-ecies"
cargo check --package tightbeam-rs --no-default-features --features "transport-ecies"

# 13. Downstream consumer cfg-leak regression (derive must not emit feature cfgs)
echo "[13/16] Check: Consumer cfg-leak regression"
cargo check --package tightbeam-consumer-test

# 14. Instrument standalone (digest cfg regression: instrument must pull digest)
echo "[14/16] Check: Instrument standalone"
cargo check --package tightbeam-rs --no-default-features --features "std,instrument"

# 15. Full (default features) - run tests
echo "[15/16] Test: Full (default features)"
make test

# 16. wasm32 browser transport core: async-transport compiles the generic
# AsyncProtocolStream + TcpTransport without tokio. Guards the browser
# transport refactor against regressions.
echo "[16/16] Check: wasm32 transport-ecies + async-transport (no tokio)"
if rustup target list --installed | grep -q '^wasm32-unknown-unknown$'; then
	cargo check --target wasm32-unknown-unknown --package tightbeam-rs --no-default-features --features "std,transport-ecies,async-transport,wasm"
else
	echo "  FAIL: wasm32-unknown-unknown target missing (run: rustup target add wasm32-unknown-unknown)" >&2
	exit 1
fi

echo "=== All feature tests passed ==="
