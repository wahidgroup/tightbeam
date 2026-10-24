#!/usr/bin/env bash
set -euo pipefail

# Print one path or name of the fuzz layout. The binaries sit in the directory
# Cargo builds into, and the output holds one directory per target under
# built/fuzz/out. The forms are:
#
#   fuzz-run.sh                  the run to analyze, as an absolute path
#   fuzz-run.sh --target PATH    the target name owning a crash or hang file
#   fuzz-run.sh --bin-dir        the directory the fuzz binaries build into

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/built/fuzz/out"

if [ "${1:-}" = "--bin-dir" ]; then
	# Cargo names the directory for this workspace, so the path honours
	# CARGO_TARGET_DIR and build.target-dir.
	TARGET_DIR="$(cargo metadata --manifest-path "$ROOT/Cargo.toml" --no-deps --format-version 1 | jq -r .target_directory)"
	printf '%s\n' "$TARGET_DIR/debug"
	exit 0
fi

if [ "${1:-}" = "--target" ]; then
	if [ "$#" -ne 2 ]; then
		echo "usage: $(basename "$0") --target <crash-or-hang-path>" >&2
		exit 2
	fi

	# Resolve the path so a relative one answers as an absolute one does.
	FILE="$(cd "$(dirname "$2")" 2>/dev/null && pwd || true)/$(basename "$2")"
	case "$FILE" in
		"$OUT"/*)
			REST="${FILE#"$OUT"/}"
			printf '%s\n' "${REST%%/*}"
			exit 0
			;;
		*)
			echo "ERROR: $2 is not inside $OUT." >&2
			exit 1
			;;
	esac
fi

if [ -n "${FUZZ_TARGET:-}" ]; then
	printf '%s\n' "$OUT/$FUZZ_TARGET/default"
	exit 0
fi

mapfile -t RUNS < <(find "$OUT" -mindepth 2 -maxdepth 2 -type d -name default 2>/dev/null | sort)

case "${#RUNS[@]}" in
	1)
		printf '%s\n' "${RUNS[0]}"
		;;
	0)
		printf '%s\n' "$OUT/<target>/default"
		;;
	*)
		echo "Error: several fuzz runs present. Set FUZZ_TARGET to one of:" >&2
		printf '  %s\n' "${RUNS[@]}" >&2
		exit 1
		;;
esac
