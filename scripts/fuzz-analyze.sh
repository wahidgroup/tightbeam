#!/usr/bin/env bash
set -euo pipefail

# Analyze a specific fuzz crash or hang by replaying it through a fuzz binary.
# Usage: scripts/fuzz-analyze.sh built/fuzz/out/default/crashes/id:000000...

FILE="${1:-}"

if [ -z "$FILE" ]; then
	echo "Error: Please specify a file to analyze" >&2
	echo "Usage: make analyze-fuzz file=built/fuzz/out/default/crashes/id:000000..." >&2
	echo ""
	echo "Available crashes:"
	ls -1 built/fuzz/out/default/crashes/ 2>/dev/null | grep -v README || echo "  (none)"
	echo ""
	echo "Available hangs:"
	ls -1 built/fuzz/out/default/hangs/ 2>/dev/null | grep -v README || echo "  (none)"
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
