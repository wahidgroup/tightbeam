#!/usr/bin/env bash
set -euo pipefail

# Build every AFL-instrumented fuzz target declared in tightbeam/Cargo.toml.
#
# The target list and each target's feature set come from `cargo metadata`, so
# `required-features` on the `[[bin]]` block is the single home for both. A new
# fuzz target is built here the moment it is declared, with no edit to this file.

if ! command -v cargo-afl >/dev/null 2>&1; then
	echo "Error: cargo-afl not found. Run: make setup" >&2
	exit 1
fi

mapfile -t TARGETS < <(
	cargo metadata --no-deps --format-version 1 |
		jq -r '.packages[].targets[]
			| select(.kind[] == "bin")
			| select(.name | startswith("fuzz_"))
			| "\(.name)\t\(.["required-features"] // [] | join(","))"' |
		sort
)

if [ "${#TARGETS[@]}" -eq 0 ]; then
	echo "Error: no fuzz_* binary is declared in tightbeam/Cargo.toml" >&2
	exit 1
fi

echo "Building ${#TARGETS[@]} AFL-instrumented fuzz target(s)..."
for entry in "${TARGETS[@]}"; do
	NAME="${entry%%$'\t'*}"
	FEATURES="${entry#*$'\t'}"
	echo "  - $NAME ($FEATURES)"
	RUSTFLAGS="--cfg fuzzing" cargo afl build --bin "$NAME" --features "$FEATURES"
done

echo ""
echo "Fuzz targets built successfully."
