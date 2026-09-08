#!/usr/bin/env bash
set -euo pipefail

# Print the absolute path of the fuzz run to analyze:
#   fuzz-run.sh
#
# Fuzz output is one directory per target under built/fuzz/out. With a single
# target the run is unambiguous, otherwise the caller names it with FUZZ_TARGET.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/built/fuzz/out"

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
