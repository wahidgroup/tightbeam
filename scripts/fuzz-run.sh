#!/usr/bin/env bash
set -euo pipefail

# Answer questions about the fuzz output layout, which is one directory per
# target under built/fuzz/out:
#
#   fuzz-run.sh                  the run to analyze, as an absolute path
#   fuzz-run.sh --target PATH    the target name owning a crash or hang file

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/built/fuzz/out"

if [ "${1:-}" = "--target" ]; then
	if [ "$#" -ne 2 ]; then
		echo "usage: $(basename "$0") --target <crash-or-hang-path>" >&2
		exit 2
	fi

	# Resolve the argument so a relative path answers the same as an absolute one.
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
