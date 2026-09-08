#!/usr/bin/env bash
set -euo pipefail

# Analyze a specific fuzz crash or hang by replaying it through a fuzz binary.
# Usage: scripts/fuzz-analyze.sh $FUZZ_RUN/crashes/id:000000...

# Fuzz output is one directory per target. With a single target the run is
# unambiguous; otherwise the caller names it with FUZZ_TARGET.
resolve_fuzz_run() {
	if [ -n "${FUZZ_TARGET:-}" ]; then
		echo "built/fuzz/out/$FUZZ_TARGET/default"
		return 0
	fi
	local runs
	mapfile -t runs < <(find built/fuzz/out -mindepth 2 -maxdepth 2 -type d -name default 2>/dev/null | sort)
	if [ "${#runs[@]}" -eq 1 ]; then
		echo "${runs[0]}"
		return 0
	fi
	if [ "${#runs[@]}" -eq 0 ]; then
		echo "built/fuzz/out/none/default"
		return 0
	fi
	echo "Error: several fuzz runs present. Set FUZZ_TARGET to one of:" >&2
	printf '  %s\n' "${runs[@]}" >&2
	return 1
}

FUZZ_RUN=$(resolve_fuzz_run)

FILE="${1:-}"

if [ -z "$FILE" ]; then
	echo "Error: Please specify a file to analyze" >&2
	echo "Usage: make analyze-fuzz file=$FUZZ_RUN/crashes/id:000000..." >&2
	echo ""
	echo "Available crashes:"
	ls -1 $FUZZ_RUN/crashes/ 2>/dev/null | grep -v README || echo "  (none)"
	echo ""
	echo "Available hangs:"
	ls -1 $FUZZ_RUN/hangs/ 2>/dev/null | grep -v README || echo "  (none)"
	exit 1
fi

echo "Analyzing: $FILE"
echo ""

FUZZ_TARGET=$(ls target/debug/deps/fuzzing-* 2>/dev/null | grep -v '\.d$' | head -1)
if [ -z "$FUZZ_TARGET" ]; then
	echo "Error: Fuzz target not built. Run 'make fuzz-build' first." >&2
	exit 1
fi

echo "Running with input from $FILE..."
echo ""
"$FUZZ_TARGET" < "$FILE" || echo "Exit code: $?"
