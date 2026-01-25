#!/bin/bash
# Feature combination tests - edit this file to add/modify combinations
# Run with: make test-all or ./scripts/test_features.sh
set -e

echo "=== Feature Combination Tests ==="

# Check compilation for each feature combination
# Note: cargo check verifies compilation; tests are run only with full features

# 1. Transport CMS (core secure messaging)
echo "[1/8] Check: Transport CMS"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,testing"

# 2. Transport ECIES (lighter alternative)
echo "[2/8] Check: Transport ECIES"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-ecies,testing"

# 3. Transport CMS + ECIES + TCP + Async (full transport stack)
echo "[3/8] Check: Transport Full + TCP + Async"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,transport-ecies,tcp,tokio,testing"

# 4. Transport CMS + Derive enabled
echo "[4/8] Check: Transport CMS + Derive"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,derive,testing"

# 5. Testing framework features
echo "[5/8] Check: Testing CSP/FDR"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,testing,testing-csp,testing-fdr"

# 6. Testing timing/schedulability (requires CSP)
echo "[6/8] Check: Testing Timing"
cargo check --package tightbeam-rs --no-default-features --features "std,transport-cms,testing,testing-csp,testing-timing,testing-schedulability"

# 7. Colony (full cluster features)
echo "[7/8] Check: Colony"
cargo check --package tightbeam-rs --no-default-features --features "colony,testing"

# 8. Full (default features) - run tests
echo "[8/8] Test: Full (default features)"
make test

echo "=== All feature tests passed ==="
