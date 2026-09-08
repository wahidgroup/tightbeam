#!/usr/bin/env bash
set -euo pipefail

# Analyze a specific fuzz crash or hang by replaying it through a fuzz binary.
# Usage: scripts/fuzz-analyze.sh $FUZZ_RUN/crashes/id:000000...

# The run directory is resolved by scripts/fuzz-run.sh, which anchors to the
# repository so this works from any working directory.
FUZZ_RUN=$("$(dirname "$0")/fuzz-run.sh")

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
