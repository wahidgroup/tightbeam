#!/usr/bin/env bash
set -euo pipefail

# Build AFL-instrumented fuzz targets (requires cargo-afl).

if ! command -v cargo-afl >/dev/null 2>&1; then
	echo "Error: cargo-afl not found. Install with: cargo install cargo-afl" >&2
	exit 1
fi

echo "Building AFL-instrumented fuzz targets..."
for target in simple_workflow complex_workflow verification; do
	echo "  - fuzz_${target}"
	RUSTFLAGS="--cfg fuzzing" cargo afl build --bin "fuzz_${target}" --features "std,testing-fuzz"
done

echo "  - fuzz_chess"
RUSTFLAGS="--cfg fuzzing" cargo afl build --bin fuzz_chess --features "std,testing-fuzz,testing-fdr,testing-csp"

echo ""
echo "Fuzz targets built successfully!"
echo ""

if [ -d tightbeam/fuzz ]; then
	echo "Available fuzz targets in tightbeam/fuzz/:"
	ls -1 tightbeam/fuzz | sed 's/^/  - /'
else
	echo "No fuzz directory found at tightbeam/fuzz."
fi
echo ""
