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

# The AFL runtime that cargo-afl links carries the IJON entry points. A target
# without them was not built against that runtime, so AFL would fuzz it blind.
IJON_SYMBOLS=(ijon_max ijon_set ijon_hashint __afl_ijon_map_size __afl_area_ptr)
TARGET_DIR="$(cargo metadata --no-deps --format-version 1 | jq -r .target_directory)"

echo "Building ${#TARGETS[@]} AFL-instrumented fuzz target(s)..."
for entry in "${TARGETS[@]}"; do
	NAME="${entry%%$'\t'*}"
	FEATURES="${entry#*$'\t'}"
	echo "  - $NAME ($FEATURES)"
	RUSTFLAGS="--cfg fuzzing" cargo afl build --bin "$NAME" --features "$FEATURES"

	SYMBOLS="$(nm "$TARGET_DIR/debug/$NAME" | awk '{print $NF}')"
	for symbol in "${IJON_SYMBOLS[@]}"; do
		if ! grep -qx -- "$symbol" <<<"$SYMBOLS"; then
			echo "Error: $NAME lacks the AFL IJON symbol $symbol" >&2
			exit 1
		fi
	done
done

echo ""
echo "Fuzz targets built successfully."
