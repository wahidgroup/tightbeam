#!/usr/bin/env bash
set -euo pipefail

# Run AFL fuzz testing over every built target for a short time (CI smoke).
# Assumes fuzz targets are already built (see scripts/fuzz-build.sh).
#
# Exits non-zero when any target produces a crash or a hang, so this script
# is a gate rather than a report.
#
# Flags:
#   --skip-missing-crashes  Set AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
#   --skip-cpu-freq         Set AFL_SKIP_CPUFREQ=1
#   --seconds N             Fuzz each target for N seconds (default 60)

SKIP_MISSING_CRASHES=false
SKIP_CPU_FREQ=false
SECONDS_PER_TARGET=60

while [ $# -gt 0 ]; do
	case "$1" in
		--skip-missing-crashes) SKIP_MISSING_CRASHES=true ;;
		--skip-cpu-freq)        SKIP_CPU_FREQ=true ;;
		--seconds)              shift; SECONDS_PER_TARGET="$1" ;;
		*) echo "Unknown argument: $1" >&2; exit 1 ;;
	esac
	shift
done

echo "Cleaning previous fuzz output..."
rm -rf built/fuzz/out

mapfile -t FUZZ_TARGETS < <(find target/debug -maxdepth 1 -type f -name 'fuzz_*' ! -name '*.d' | sort)
if [ "${#FUZZ_TARGETS[@]}" -eq 0 ]; then
	echo "Error: Could not find any fuzz binary in target/debug/" >&2
	echo "Run 'make fuzz-build' first" >&2
	exit 1
fi

AFL_ENV=""
if [ "$SKIP_MISSING_CRASHES" = true ]; then
	AFL_ENV="$AFL_ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1"
	echo "Note: Skipping crash reporting config check"
fi
if [ "$SKIP_CPU_FREQ" = true ]; then
	AFL_ENV="$AFL_ENV AFL_SKIP_CPUFREQ=1"
	echo "Note: Skipping CPU frequency scaling check"
fi

echo "Fuzzing ${#FUZZ_TARGETS[@]} target(s) for ${SECONDS_PER_TARGET}s each"
echo ""

# A directory AFL never created counts as zero. Letting `find` fail here
# would trip `pipefail` and report a failure with no crash behind it.
count_files() {
	if [ -d "$1" ]; then
		find "$1" -type f ! -name README.txt | wc -l
	else
		echo 0
	fi
}

TOTAL_CRASHES=0
TOTAL_HANGS=0
FAILED_TARGETS=()

for FUZZ_TARGET in "${FUZZ_TARGETS[@]}"; do
	NAME=$(basename "$FUZZ_TARGET")
	# A target with a curated corpus starts from it. The generic seed is the
	# fallback, because AFL refuses to start with an empty input directory.
	CORPUS="tightbeam/fuzz/${NAME#fuzz_}/seeds"
	IN_DIR="built/fuzz/in/$NAME"
	mkdir -p "$IN_DIR"
	if [ -d "$CORPUS" ] && [ -n "$(find "$CORPUS" -type f -print -quit)" ]; then
		find "$CORPUS" -type f -exec cp {} "$IN_DIR/" \;
		echo "[$NAME] corpus: $CORPUS"
	else
		echo "seed" > "$IN_DIR/seed.txt"
		echo "[$NAME] corpus: none, using a generic seed"
	fi

	OUT_DIR="built/fuzz/out/$NAME"
	mkdir -p "$OUT_DIR"
	eval "$AFL_ENV timeout $SECONDS_PER_TARGET cargo afl fuzz -i \"$IN_DIR\" -o \"$OUT_DIR\" \"$FUZZ_TARGET\" > /dev/null 2>&1" || true

	RESULTS="$OUT_DIR/default"
	if [ ! -d "$RESULTS" ]; then
		echo "[$NAME] no output generated, the fuzzer may have exited early"
		echo ""
		continue
	fi

	CRASHES=$(count_files "$RESULTS/crashes")
	HANGS=$(count_files "$RESULTS/hangs")
	QUEUE=$(count_files "$RESULTS/queue")
	echo "[$NAME] cases: $QUEUE  crashes: $CRASHES  hangs: $HANGS"

	if [ -f "$RESULTS/fuzzer_stats" ]; then
		EXECS=$(awk '/^execs_done/ {print $3}' "$RESULTS/fuzzer_stats")
		BITMAP=$(awk '/^bitmap_cvg/ {print $3}' "$RESULTS/fuzzer_stats")
		STABILITY=$(awk '/^stability/ {print $3}' "$RESULTS/fuzzer_stats")
		echo "[$NAME] execs: $EXECS  coverage: $BITMAP  stability: $STABILITY"
	fi

	TOTAL_CRASHES=$((TOTAL_CRASHES + CRASHES))
	TOTAL_HANGS=$((TOTAL_HANGS + HANGS))
	if [ "$CRASHES" -gt 0 ] || [ "$HANGS" -gt 0 ]; then
		FAILED_TARGETS+=("$NAME")
	fi
	echo ""
done

if [ "$TOTAL_CRASHES" -gt 0 ] || [ "$TOTAL_HANGS" -gt 0 ]; then
	echo "FAILED: $TOTAL_CRASHES crash(es) and $TOTAL_HANGS hang(s)" >&2
	for NAME in "${FAILED_TARGETS[@]}"; do
		echo "  $NAME: built/fuzz/out/$NAME/default/" >&2
	done
	exit 1
fi

echo "All ${#FUZZ_TARGETS[@]} target(s) finished with no crashes and no hangs."
