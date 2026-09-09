#!/usr/bin/env bash
set -euo pipefail

# Replay one fuzz crash or hang through the target that produced it.
# Usage: scripts/fuzz-analyze.sh built/fuzz/out/<target>/default/crashes/id:000000...

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FUZZ_RUN_SH="$ROOT/scripts/fuzz-run.sh"

FILE="${1:-}"

# The run is searched for only when the caller named no file. A caller holding
# a crash path has already answered the question, and after `make fuzz-test`
# every target has a run, so searching first would refuse every invocation.
if [ -z "$FILE" ]; then
	FUZZ_RUN=$("$FUZZ_RUN_SH")

	echo "Error: Please specify a file to analyze" >&2
	echo "Usage: make analyze-fuzz file=$FUZZ_RUN/crashes/id:000000..." >&2
	echo ""
	echo "Available crashes:"
	find "$FUZZ_RUN/crashes" -type f ! -name 'README*' 2>/dev/null | sort || echo "  (none)"
	echo ""
	echo "Available hangs:"
	find "$FUZZ_RUN/hangs" -type f ! -name 'README*' 2>/dev/null | sort || echo "  (none)"
	exit 1
fi

if [ ! -f "$FILE" ]; then
	echo "Error: $FILE is not a file." >&2
	exit 1
fi

# The path names its own target, so the input is replayed through the binary
# that found it rather than through whichever binary a glob happened to match.
TARGET="$("$FUZZ_RUN_SH" --target "$FILE")"
BINARY="$ROOT/target/debug/$TARGET"

if [ ! -x "$BINARY" ]; then
	echo "Error: $TARGET is not built at $BINARY. Run 'make fuzz-build' first." >&2
	exit 1
fi

echo "Analyzing: $FILE"
echo "Target:    $TARGET"
echo ""

"$BINARY" < "$FILE" || echo "Exit code: $?"
