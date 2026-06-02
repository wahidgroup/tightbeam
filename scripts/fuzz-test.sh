#!/usr/bin/env bash
set -euo pipefail

# Run AFL fuzz testing for a short time (60 seconds for CI/smoke testing).
# Assumes fuzz targets are already built (see scripts/fuzz-build.sh).
#
# Flags:
#   --skip-missing-crashes  Set AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
#   --skip-cpu-freq         Set AFL_SKIP_CPUFREQ=1

SKIP_MISSING_CRASHES=false
SKIP_CPU_FREQ=false

for arg in "$@"; do
	case "$arg" in
		--skip-missing-crashes) SKIP_MISSING_CRASHES=true ;;
		--skip-cpu-freq)        SKIP_CPU_FREQ=true ;;
		*) echo "Unknown argument: $arg" >&2; exit 1 ;;
	esac
done

echo "Cleaning previous fuzz output..."
rm -rf built/fuzz/out

echo "Running AFL fuzz testing for 60 seconds..."
mkdir -p built/fuzz/in built/fuzz/out
echo "seed" > built/fuzz/in/seed.txt
echo ""

echo "Locating fuzz target binary..."
FUZZ_TARGET=$(ls target/debug/fuzz_* 2>/dev/null | grep -v '\.d$' | head -1)
if [ -z "$FUZZ_TARGET" ]; then
	echo "Error: Could not find any fuzz binary in target/debug/" >&2
	echo "Run 'make fuzz-build' first" >&2
	exit 1
fi
echo "Found: $FUZZ_TARGET"
echo ""

AFL_ENV=""
if [ "$SKIP_MISSING_CRASHES" = true ]; then
	AFL_ENV="$AFL_ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1"
	echo "Note: Skipping crash reporting config check"
fi
if [ "$SKIP_CPU_FREQ" = true ]; then
	AFL_ENV="$AFL_ENV AFL_SKIP_CPUFREQ=1"
	echo "Note: Skipping CPU frequency scaling check"
fi

echo "Starting fuzzer (60 second timeout)..."
echo ""
eval "$AFL_ENV timeout 60 cargo afl fuzz -i built/fuzz/in -o built/fuzz/out \"$FUZZ_TARGET\" > /dev/null 2>&1" || true
echo ""
echo "Fuzz testing completed!"

if [ -d "built/fuzz/out/default" ]; then
	echo "Results saved to built/fuzz/out/"
	CRASHES=$(ls -1 built/fuzz/out/default/crashes/ 2>/dev/null | grep -v README | wc -l)
	HANGS=$(ls -1 built/fuzz/out/default/hangs/ 2>/dev/null | grep -v README | wc -l)
	QUEUE=$(ls -1 built/fuzz/out/default/queue/ 2>/dev/null | grep -v '^\.synced$' | wc -l)
	echo "  Test cases generated: $QUEUE"
	echo "  Crashes found: $CRASHES"
	echo "  Hangs found: $HANGS"
	echo ""
	if [ -f "built/fuzz/out/default/fuzzer_stats" ]; then
		echo "Fuzzing Statistics:"
		EXECS=$(grep "^execs_done" built/fuzz/out/default/fuzzer_stats | awk '{print $3}')
		EXECS_SEC=$(grep "^execs_per_sec" built/fuzz/out/default/fuzzer_stats | awk '{print $3}')
		STABILITY=$(grep "^stability" built/fuzz/out/default/fuzzer_stats | awk '{print $3}')
		BITMAP=$(grep "^bitmap_cvg" built/fuzz/out/default/fuzzer_stats | awk '{print $3}')
		EDGES=$(grep "^edges_found" built/fuzz/out/default/fuzzer_stats | awk '{print $3}')
		TOTAL_EDGES=$(grep "^total_edges" built/fuzz/out/default/fuzzer_stats | awk '{print $3}')
		CYCLES=$(grep "^cycles_done" built/fuzz/out/default/fuzzer_stats | awk '{print $3}')
		echo "  Executions: $EXECS ($EXECS_SEC/sec)"
		echo "  Stability: $STABILITY"
		echo "  Coverage: $BITMAP ($EDGES/$TOTAL_EDGES edges)"
		echo "  Cycles: $CYCLES"
	fi
	echo ""
	if [ "$CRASHES" -gt 0 ]; then
		echo "[!] Crashes detected! Review them at:"
		echo "    built/fuzz/out/default/crashes/"
		echo ""
	fi
	if [ "$HANGS" -gt 0 ]; then
		echo "[!] Hangs detected! Review them at:"
		echo "    built/fuzz/out/default/hangs/"
		echo ""
	fi
else
	echo "No output generated - fuzzer may have exited early"
fi

echo "To run longer fuzzing sessions manually:"
echo "  cargo afl fuzz -i built/fuzz/in -o built/fuzz/out $FUZZ_TARGET"
echo ""
echo "For production fuzzing, configure system properly with: cargo afl system-config"
echo ""
