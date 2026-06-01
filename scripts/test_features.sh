#!/bin/bash
# Feature combination tests - edit this file to add/modify combinations
# Run with: make test-all or ./scripts/test_features.sh
set -e

echo "=== Feature Combination Tests ==="

# Check compilation for each feature combination
# Note: cargo check verifies compilation; tests are run only with full features

# 1. Minimal: std + derive (no zeroize/crypto/builder)
echo "[1/12] Check: Minimal std + derive"
cargo check --package tightbeam-rs --no-default-features --features "std,derive"

# 2. Minimal: std + crypto (crypto core without aead/digest/x509)
echo "[2/12] Check: Minimal std + crypto"
cargo check --package tightbeam-rs --no-default-features --features "std,crypto"

# 3. Minimal: std + derive + builder (frame builder without aead/digest/signature)
echo "[3/12] Check: Minimal std + derive + builder"
cargo check --package tightbeam-rs --no-default-features --features "std,derive,builder"

# 4. Transport CMS (core secure messaging)
echo "[4/12] Check: Transport CMS"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,testing"

# 5. Transport ECIES (lighter alternative)
echo "[5/12] Check: Transport ECIES"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-ecies,testing"

# 6. Transport CMS + ECIES + TCP + Async (full transport stack)
echo "[6/12] Check: Transport Full + TCP + Async"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,transport-ecies,tcp,tokio,testing"

# 7. Transport CMS + Derive enabled
echo "[7/12] Check: Transport CMS + Derive"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,derive,testing"

# 8. Testing framework features
echo "[8/12] Check: Testing CSP/FDR"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,testing,testing-csp,testing-fdr"

# 9. Testing timing/schedulability (requires CSP)
echo "[9/12] Check: Testing Timing"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,testing,testing-csp,testing-timing,testing-schedulability"

# 10. Colony (full cluster features)
echo "[10/12] Check: Colony"
cargo check --package tightbeam-rs --no-default-features --features "colony,testing"

# 11. Downstream consumer cfg-leak regression (derive must not emit feature cfgs)
echo "[11/12] Check: Consumer cfg-leak regression"
cargo check --package tightbeam-consumer-test

# 12. Full (default features) - run tests
echo "[12/12] Test: Full (default features)"
make test

echo "=== All feature tests passed ==="
