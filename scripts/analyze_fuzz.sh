#!/bin/bash
# Generic Fuzz Quality Analysis Tool
#
# The script runs AFL on one fuzz test, with the AFL UI shown by default, and
# reports the performance, coverage, test cases, crashes, and hangs of the run.
#
# It works in the project root above its own scripts/ directory, and it finds
# the fuzz test and its seeds in the source trees of detect_fuzz_base.
#
# References:
#   GNU CLI Guidelines: https://www.gnu.org/prep/standards/html_node/Command_002dLine-Interfaces.html
#   POSIX Utility Syntax: https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html

set -euo pipefail


SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# The script sits in scripts/, so the project root is one level up.
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# The name and version that the usage and --version text print.
PROJECT="analyze_fuzz"
VERSION="1.0.0"

# The defaults, which the arguments below override.
DURATION=60
SHOW_UI=true
SKIP_CRASH_CHECK=true
SKIP_CPU_FREQ=true
KEEP_OUTPUT=false
CUSTOM_FUZZ_BASE=""
TEST_NAME=""
SEED_DIR=""
VERIFY_CODE=false
VERIFY_PATTERNS=()

# Print the first source tree that holds the test, in the order tightbeam/fuzz,
# tests/fuzz, tightbeam/tests/fuzz, fuzz, and tests. When none holds it, print
# tightbeam/fuzz, or tests/fuzz when only that tree exists.
detect_fuzz_base() {
    local test_name="$1"
    # The search reads source trees alone. Rustdoc and build artifacts under
    # target/ also match *fuzz*, so a match there would steal the seed paths.
    for base in "tightbeam/fuzz" "tests/fuzz" "tightbeam/tests/fuzz" "fuzz" "tests"; do
        if [ -d "$base/$test_name" ] || [ -f "$base/${test_name}.rs" ]; then
            echo "$base"
            return 0
        fi
    done
    if [ -d "tightbeam/fuzz" ]; then
        echo "tightbeam/fuzz"
        return 0
    fi
    if [ -d "tests/fuzz" ]; then
        echo "tests/fuzz"
        return 0
    fi
    echo "tightbeam/fuzz"
}

usage() {
    cat << EOF
USAGE:
    $PROJECT <TEST_NAME> [OPTIONS] [DURATION] [-- AFL_ARGS...]

DESCRIPTION:
    Runs AFL fuzzing on the specified fuzz test with UI display and generates
    a comprehensive analysis report. Works from any Rust project root.

ARGUMENTS:
    TEST_NAME            Name of the fuzz test (e.g., chess, simple_workflow)
    DURATION             Duration in seconds (default: 60)
    AFL_ARGS             Additional arguments passed to AFL (after --)

OPTIONS:
    -h, --help                Show this help message and exit
    -V, --version             Show version information and exit
    -n, --no-ui               Run without showing AFL UI (output redirected)
    -c, --skip-checks         Skip AFL system configuration checks (sets both flags)
    -C, --skip-crash-check    Skip crash reporting config check
    -F, --skip-cpu-freq       Skip CPU frequency scaling check
    -k, --keep-output         Don't clean previous fuzz output
    -s, --seeds DIR           Custom seed directory (auto-detected if not specified)
    -v, --verify              Enable code verification (requires verify-pattern option)
    -p, --pattern PAT         Add a code verification pattern (format: "feature:pattern")
                              Can be specified multiple times. Requires --verify.

EXAMPLES:
    $PROJECT chess 60                    Run chess fuzz test for 60 seconds
    $PROJECT chess 300 -n                Run chess fuzz test for 5 minutes without UI
    $PROJECT simple_workflow 120         Run simple_workflow test for 2 minutes
    $PROJECT chess 60 -s custom/seeds    Use custom seed directory
    $PROJECT chess 60 --verify -p "Game restart:game_restarted" -p "Loop:loop {"
    $PROJECT chess 60 -- -- -m none      Pass AFL arguments (e.g., memory limit)

EXIT STATUS:
    0    Success
    >0   Error occurred

REFERENCES:
    GNU CLI Guidelines: https://www.gnu.org/prep/standards/html_node/Command_002dLine-Interfaces.html
    POSIX Utility Syntax: https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html
EOF
}

version() {
    cat << EOF
$PROJECT $VERSION
Generic Fuzz Quality Analysis Tool

Works with any Rust project using cargo-afl.
EOF
}

# GNU getopt parses the options in the form the guidelines above describe.
if ! OPTS=$(getopt -o hVncCFkP:s:vp: --long help,version,no-ui,skip-checks,skip-crash-check,skip-cpu-freq,keep-output,path:,seeds:,verify,pattern: -n "$PROJECT" -- "$@"); then
    echo "Error: Failed to parse options" >&2
    usage >&2
    exit 1
fi

eval set -- "$OPTS"

while true; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        -V|--version)
            version
            exit 0
            ;;
        -n|--no-ui)
            SHOW_UI=false
            shift
            ;;
        -c|--skip-checks)
            SKIP_CRASH_CHECK=true
            SKIP_CPU_FREQ=true
            shift
            ;;
        -C|--skip-crash-check)
            SKIP_CRASH_CHECK=true
            shift
            ;;
        -F|--skip-cpu-freq)
            SKIP_CPU_FREQ=true
            shift
            ;;
        -k|--keep-output)
            KEEP_OUTPUT=true
            shift
            ;;
        -P|--path)
            CUSTOM_FUZZ_BASE="$2"
            shift 2
            ;;
        -s|--seeds)
            SEED_DIR="$2"
            shift 2
            ;;
        -v|--verify)
            VERIFY_CODE=true
            shift
            ;;
        -p|--pattern)
            VERIFY_PATTERNS+=("$2")
            shift 2
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "Error: Internal error parsing options" >&2
            exit 1
            ;;
    esac
done

# TEST_NAME is the one required argument.
if [ $# -eq 0 ]; then
    echo "Error: TEST_NAME is required" >&2
    usage >&2
    exit 1
fi

TEST_NAME="$1"
shift

# The test name is the target, so it names this run. scripts/fuzz-run.sh holds
# the output layout in one place and gives each target its own directory, so a
# run here neither collides with `make fuzz-test` nor deletes its results.
FUZZ_RUN="$(FUZZ_TARGET="fuzz_${TEST_NAME}" "$SCRIPT_DIR/fuzz-run.sh")"
FUZZ_OUT="$(dirname "$FUZZ_RUN")"
FUZZ_IN="$PROJECT_ROOT/built/fuzz/in/fuzz_${TEST_NAME}"

# DURATION, in seconds, is optional.
if [ $# -gt 0 ] && [[ "$1" =~ ^[0-9]+$ ]]; then
    DURATION="$1"
    shift
fi

# Every argument after TEST_NAME and DURATION goes to AFL, past an optional --.
AFL_ARGS_ARRAY=()
AFL_ARGS=""
if [ $# -gt 0 ]; then
    if [ "$1" = "--" ]; then
        shift
    fi
    if [ $# -gt 0 ]; then
        AFL_ARGS_ARRAY=("$@")
        AFL_ARGS="${AFL_ARGS_ARRAY[*]}"
    fi
    set --
fi

if ! [[ "$DURATION" =~ ^[0-9]+$ ]] || [ "$DURATION" -le 0 ]; then
    echo "Error: Duration must be a positive integer (seconds)" >&2
    exit 1
fi

# The colony and chess targets run Tokio. Unless the caller passes -m or -t,
# they get no memory limit and a hang timeout of 5000 ms that covers a
# multi-gateway boot. They always run without the forkserver, because ephemeral
# ports and multi-task I/O break its dry run even when the fuzz closure builds
# the runtime.
DISABLE_FORKSRV=false
has_mem_limit=false
has_timeout=false
for arg in "${AFL_ARGS_ARRAY[@]+"${AFL_ARGS_ARRAY[@]}"}"; do
	if [ "$arg" = "-m" ]; then
		has_mem_limit=true
	fi
	if [ "$arg" = "-t" ]; then
		has_timeout=true
	fi
done
case "$TEST_NAME" in
	colony|chess)
		if [ "$has_mem_limit" = false ]; then
			AFL_ARGS_ARRAY=("-m" "none" "${AFL_ARGS_ARRAY[@]+"${AFL_ARGS_ARRAY[@]}"}")
		fi
		if [ "$has_timeout" = false ]; then
			AFL_ARGS_ARRAY=("-t" "5000" "${AFL_ARGS_ARRAY[@]+"${AFL_ARGS_ARRAY[@]}"}")
		fi
		AFL_ARGS="${AFL_ARGS_ARRAY[*]}"
		DISABLE_FORKSRV=true
		;;
esac

# --verify needs at least one --pattern.
if [ "$VERIFY_CODE" = true ] && [ ${#VERIFY_PATTERNS[@]} -eq 0 ]; then
    echo "Error: --verify requires at least one --pattern" >&2
    exit 1
fi

# --path names the fuzz base, and detect_fuzz_base finds one otherwise.
if [ -n "$CUSTOM_FUZZ_BASE" ]; then
	if [ ! -d "$CUSTOM_FUZZ_BASE" ]; then
		echo "Error: Provided path does not exist: $CUSTOM_FUZZ_BASE" >&2
		exit 1
	fi
	FUZZ_BASE="$CUSTOM_FUZZ_BASE"
else
	FUZZ_BASE=$(detect_fuzz_base "$TEST_NAME")
fi

# Without --seeds, the seeds sit in <fuzz base>/<test>/seeds.
if [ -z "$SEED_DIR" ]; then
    SEED_DIR="$FUZZ_BASE/${TEST_NAME}/seeds"
fi

# --verify reads the test source, <test>/mod.rs or else <test>.rs.
TEST_FILE="$FUZZ_BASE/${TEST_NAME}/mod.rs"
if [ ! -f "$TEST_FILE" ]; then
    TEST_FILE="$FUZZ_BASE/${TEST_NAME}.rs"
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Fuzz Quality Analysis Tool - $TEST_NAME"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Phase 1 checks the tools, builds the target, and prepares the seeds.

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Phase 1: Preparation"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "[*] Configuration:"
echo "    Project root: $PROJECT_ROOT"
echo "    Test: $TEST_NAME"
echo "    Fuzz base: $FUZZ_BASE"
echo "    Duration: ${DURATION} seconds ($(($DURATION / 60)) minutes)"
echo "    Show UI: $SHOW_UI"
echo "    Skip crash check: $SKIP_CRASH_CHECK"
echo "    Skip CPU freq check: $SKIP_CPU_FREQ"
echo "    Keep output: $KEEP_OUTPUT"
if [ -n "$SEED_DIR" ]; then
    echo "    Seed directory: $SEED_DIR"
fi
if [ -n "$AFL_ARGS" ]; then
    echo "    AFL arguments: $AFL_ARGS"
fi
echo ""

echo "[*] Checking prerequisites..."
if ! command -v cargo-afl &> /dev/null; then
    echo "[!] ERROR: cargo-afl not found. Run: make setup" >&2
    exit 1
fi
echo "[+] cargo-afl found"

if ! command -v cargo &> /dev/null; then
    echo "[!] ERROR: cargo not found" >&2
    exit 1
fi
echo "[+] cargo found"

if ! command -v getopt &> /dev/null; then
    echo "[!] ERROR: getopt not found (required for POSIX/GNU argument parsing)" >&2
    exit 1
fi
echo "[+] getopt found"
echo ""

# The build tries `make fuzz-build`, then `cargo afl build` on the binary of
# the target, then on the `fuzzing` test.
echo "[*] Building fuzz target..."
BUILD_OK=false
TARGET_HINT="fuzz_${TEST_NAME}"
if command -v make &> /dev/null && make -n fuzz-build &> /dev/null 2>&1; then
	FUZZ_BUILD_LOG="$(mktemp)"
	if make fuzz-build >"$FUZZ_BUILD_LOG" 2>&1; then
		BUILD_OK=true
	else
		echo "    [!] make fuzz-build failed, falling back to direct cargo-afl build..."
		echo "    --- make fuzz-build (last 20 lines) ---"
		tail -n 20 "$FUZZ_BUILD_LOG" | sed 's/^/    /'
		echo "    --------------------------------------"
	fi
	rm -f "$FUZZ_BUILD_LOG"
fi
if [ "$BUILD_OK" = false ]; then
	FEATURES="std,testing-fuzz"
	case "$TEST_NAME" in
		chess) FEATURES="std,testing-fuzz,testing-fdr,testing-csp" ;;
		colony) FEATURES="full,testing-fuzz,testing-fuzz-ijon,testing-csp" ;;
	esac
	for CANDIDATE_BIN in "fuzz_${TEST_NAME}" "${TEST_NAME}"; do
		if RUSTFLAGS="--cfg fuzzing" cargo afl build --bin "$CANDIDATE_BIN" --features "$FEATURES" > /dev/null 2>&1; then
			BUILD_OK=true
			TARGET_HINT="$CANDIDATE_BIN"
			break
		fi
	done
fi
if [ "$BUILD_OK" = false ]; then
	if RUSTFLAGS="--cfg fuzzing" cargo afl build --test fuzzing > /dev/null 2>&1; then
		BUILD_OK=true
		TARGET_HINT=""
	else
		echo "[!] ERROR: Failed to build fuzz target" >&2
		exit 1
	fi
fi
echo "[+] Fuzz target built successfully"
echo ""

# The binary is the first executable match of these patterns, in order, in the
# directory that scripts/fuzz-run.sh names.
FUZZ_TARGET=""
BIN_DIR="$("$SCRIPT_DIR/fuzz-run.sh" --bin-dir)"
SEARCH_PATTERNS=()
if [ -n "$TARGET_HINT" ]; then
	SEARCH_PATTERNS+=("$BIN_DIR/${TARGET_HINT}")
	SEARCH_PATTERNS+=("$BIN_DIR/${TARGET_HINT}-*")
	SEARCH_PATTERNS+=("$BIN_DIR/deps/${TARGET_HINT}-*")
fi
SEARCH_PATTERNS+=("$BIN_DIR/fuzz_${TEST_NAME}")
SEARCH_PATTERNS+=("$BIN_DIR/${TEST_NAME}")
SEARCH_PATTERNS+=("$BIN_DIR/deps/fuzzing-*")
SEARCH_PATTERNS+=("$BIN_DIR/deps/*fuzz*")
SEARCH_PATTERNS+=("$BIN_DIR/fuzz_*")
SEARCH_PATTERNS+=("$BIN_DIR/*fuzz*")

for pattern in "${SEARCH_PATTERNS[@]}"; do
	while IFS= read -r candidate; do
		if [ -n "$candidate" ] && [ -f "$candidate" ] && [ -x "$candidate" ]; then
			FUZZ_TARGET="$candidate"
			break 2
		fi
	done < <(compgen -G "$pattern" 2>/dev/null || true)
done

if [ -z "$FUZZ_TARGET" ] || [ ! -f "$FUZZ_TARGET" ]; then
    echo "[!] ERROR: Could not find fuzzing binary" >&2
    echo "    Searched in: $BIN_DIR/deps/, $BIN_DIR/" >&2
    echo "    Run 'make fuzz-build' first" >&2
    exit 1
fi
echo "[+] Found fuzz target: $(basename "$FUZZ_TARGET")"
echo ""

# A native afl-fuzz runs the binary as built, and `cargo afl fuzz` may rebuild.
if AFL_FUZZ_BIN=$(command -v afl-fuzz 2>/dev/null); then
	echo "[+] Using afl-fuzz binary: $AFL_FUZZ_BIN"
	USE_CARGO_AFL=false
else
	echo "[!] afl-fuzz not found in PATH, falling back to cargo afl fuzz (may rebuild)"
	USE_CARGO_AFL=true
fi
echo ""

# A run without --keep-output starts from an empty output directory.
echo "[*] Preparing seed inputs..."
mkdir -p "$FUZZ_IN"
if [ "$KEEP_OUTPUT" = false ]; then
    rm -rf "$FUZZ_OUT"
fi
mkdir -p "$FUZZ_OUT"

# The seeds come from the version-controlled seed directory. AFL refuses an
# empty input directory, so a minimal seed stands in when that holds none.
if [ -d "$SEED_DIR" ]; then
    # A seed file ends in .txt, .bin, or .dat.
    find "$SEED_DIR" -type f \( -name "*.txt" -o -name "*.bin" -o -name "*.dat" \) -exec cp {} "$FUZZ_IN/" \;
    SEED_COUNT=$(find "$FUZZ_IN" -type f | wc -l)
    if [ "$SEED_COUNT" -gt 0 ]; then
        echo "[+] Copied $SEED_COUNT seed files from $SEED_DIR"
    else
        echo "[!] WARNING: No seed files found in $SEED_DIR"
        echo "    Creating minimal seed file..."
        echo "seed" > "$FUZZ_IN/seed.txt"
        SEED_COUNT=1
    fi
else
    echo "[!] WARNING: Seed directory not found: $SEED_DIR"
    echo "    Creating minimal seed file..."
    echo "seed" > "$FUZZ_IN/seed.txt"
    SEED_COUNT=1
fi
echo "[+] Prepared $SEED_COUNT seed files for fuzzing"
echo ""

# Phase 2 runs with --verify and checks the test source for each --pattern.

if [ "$VERIFY_CODE" = true ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Phase 2: Code Verification"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    if [ ! -f "$TEST_FILE" ]; then
        echo "[!] WARNING: Test file not found: $TEST_FILE"
        echo "    Skipping code verification"
        VERIFY_CODE=false
    else
        VERIFICATION_PASSED=true

        check_code_feature() {
            local feature=$1
            local pattern=$2
            if grep -q "$pattern" "$TEST_FILE" 2>/dev/null; then
                echo "    [+] $feature"
                return 0
            else
                echo "    [-] $feature (NOT FOUND)"
                VERIFICATION_PASSED=false
                return 1
            fi
        }

        echo "Checking $TEST_NAME fuzz test implementation..."
        for pattern_entry in "${VERIFY_PATTERNS[@]}"; do
            # Each entry reads feature:pattern.
            feature="${pattern_entry%%:*}"
            pattern="${pattern_entry#*:}"
            if [ "$feature" = "$pattern_entry" ]; then
                # An entry with no colon is a pattern alone.
                feature="Pattern"
                pattern="$pattern_entry"
            fi
            check_code_feature "$feature" "$pattern"
        done
        echo ""

        if [ "$VERIFICATION_PASSED" = false ]; then
            echo "[!] WARNING: Some expected code features not found"
            echo "    Analysis will continue, but results may be incomplete"
            echo ""
        fi
    fi
fi

# Phase 3 runs AFL for DURATION seconds.

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Phase 3: Fuzzing Execution (${DURATION} seconds)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

AFL_ENV_VARS=()
if [ "$SKIP_CRASH_CHECK" = true ]; then
    AFL_ENV_VARS+=("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1")
fi
if [ "$SKIP_CPU_FREQ" = true ]; then
    AFL_ENV_VARS+=("AFL_SKIP_CPUFREQ=1")
fi
if [ "$DISABLE_FORKSRV" = true ]; then
    AFL_ENV_VARS+=("AFL_NO_FORKSRV=1")
fi

if [ ${#AFL_ENV_VARS[@]} -gt 0 ]; then
    echo "[*] Note: AFL environment overrides"
    if [ "$SKIP_CRASH_CHECK" = true ]; then
        echo "    - Crash reporting check disabled"
    fi
    if [ "$SKIP_CPU_FREQ" = true ]; then
        echo "    - CPU frequency scaling check disabled"
    fi
    if [ "$DISABLE_FORKSRV" = true ]; then
        echo "    - Forkserver disabled (Tokio target)"
    fi
fi

echo "[*] Starting AFL fuzzer..."
echo "    Target: $(basename "$FUZZ_TARGET")"
echo "    Input: $FUZZ_IN/"
echo "    Output: $FUZZ_OUT/"
if [ -n "$AFL_ARGS" ]; then
    echo "    Extra AFL args: $AFL_ARGS"
fi
echo ""

run_afl_command() {
    local hide_output="$1"
    local cmd=(timeout "$DURATION")
    if [ "$USE_CARGO_AFL" = false ]; then
        cmd+=("$AFL_FUZZ_BIN")
    else
        cmd+=("cargo" "afl" "fuzz")
    fi
    cmd+=("-i" "$FUZZ_IN" "-o" "$FUZZ_OUT")
    if [ ${#AFL_ARGS_ARRAY[@]} -gt 0 ]; then
        cmd+=("${AFL_ARGS_ARRAY[@]}")
    fi
    cmd+=(-- "$FUZZ_TARGET")

    if [ ${#AFL_ENV_VARS[@]} -gt 0 ]; then
        cmd=(env "${AFL_ENV_VARS[@]}" "${cmd[@]}")
    fi

    if [ "$hide_output" = "true" ]; then
        "${cmd[@]}" > /dev/null 2>&1
    else
        "${cmd[@]}"
    fi
}

# timeout exits with 124 when DURATION ends the run.
if [ "$SHOW_UI" = true ]; then
    echo "[*] AFL UI will be displayed below..."
    echo "    Press Ctrl+C to stop early (analysis will still be generated)"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    if run_afl_command "false"; then
        TIMEOUT_OCCURRED=false
    else
        EXIT_CODE=$?
        if [ $EXIT_CODE -eq 124 ]; then
            TIMEOUT_OCCURRED=true
        else
            TIMEOUT_OCCURRED=false
            echo "[!] WARNING: Fuzzer exited with code $EXIT_CODE" >&2
        fi
    fi
else
    echo "[*] Running in background (UI hidden)..."
    echo "    Note: Use --no-ui=false to see AFL's real-time TUI display"
    if run_afl_command "true"; then
        TIMEOUT_OCCURRED=false
    else
        EXIT_CODE=$?
        if [ $EXIT_CODE -eq 124 ]; then
            TIMEOUT_OCCURRED=true
        else
            TIMEOUT_OCCURRED=false
        fi
    fi
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ "$TIMEOUT_OCCURRED" = true ]; then
    echo "[+] Fuzzing completed (time limit reached)"
else
    echo "[+] Fuzzing completed"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Phase 4 reads fuzzer_stats and prints the report.

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Phase 4: Analysis Report"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ ! -f "$FUZZ_RUN/fuzzer_stats" ]; then
    echo "[!] ERROR: Fuzzer stats not found. Fuzzing may have failed." >&2
    exit 1
fi

STATS_FILE="$FUZZ_RUN/fuzzer_stats"
EXECS=$(grep "^execs_done" "$STATS_FILE" | awk '{print $3}' || echo "0")
EXECS_PER_SEC=$(grep "^execs_per_sec" "$STATS_FILE" | awk '{print $3}' || echo "0")
CORPUS_COUNT=$(grep "^corpus_count" "$STATS_FILE" | awk '{print $3}' || echo "0")
# AFL may append a % sign to stability.
STABILITY=$(grep "^stability" "$STATS_FILE" | awk '{print $3}' | sed 's/%//' || echo "0")
# The same holds for bitmap_cvg.
COVERAGE=$(grep "^bitmap_cvg" "$STATS_FILE" | awk '{print $3}' | sed 's/%//' || echo "0")
EDGES_FOUND=$(grep "^edges_found" "$STATS_FILE" | awk '{print $3}' || echo "0")
TOTAL_EDGES=$(grep "^total_edges" "$STATS_FILE" | awk '{print $3}' || echo "0")
CYCLES=$(grep "^cycles_done" "$STATS_FILE" | awk '{print $3}' || echo "0")
# AFL++ 4.x writes saved_*, and older AFL writes unique_*. saved_* wins.
UNIQUE_CRASHES=$(grep "^saved_crashes" "$STATS_FILE" | awk '{print $3}')
if [ -z "$UNIQUE_CRASHES" ]; then
	UNIQUE_CRASHES=$(grep "^unique_crashes" "$STATS_FILE" | awk '{print $3}' || echo "0")
fi
UNIQUE_CRASHES=${UNIQUE_CRASHES:-0}
UNIQUE_HANGS=$(grep "^saved_hangs" "$STATS_FILE" | awk '{print $3}')
if [ -z "$UNIQUE_HANGS" ]; then
	UNIQUE_HANGS=$(grep "^unique_hangs" "$STATS_FILE" | awk '{print $3}' || echo "0")
fi
UNIQUE_HANGS=${UNIQUE_HANGS:-0}

echo "[*] Performance Metrics"
echo "──────────────────────────────────────────────────────────────────"
printf "    %-30s %'d\n" "Total Executions:" "$EXECS"
printf "    %-30s %.2f/sec\n" "Execution Rate:" "$EXECS_PER_SEC"
printf "    %-30s %d\n" "Cycles Completed:" "$CYCLES"
printf "    %-30s %.2f%s\n" "Stability:" "$STABILITY" "%"

# The run time prints only when fuzzer_stats holds both timestamps.
START_TIME=$(grep "^start_time" "$STATS_FILE" | awk '{print $3}' 2>/dev/null || echo "")
LAST_UPDATE=$(grep "^last_update" "$STATS_FILE" | awk '{print $3}' 2>/dev/null || echo "")
if [ -n "$START_TIME" ] && [ -n "$LAST_UPDATE" ]; then
    RUNTIME_SEC=$((LAST_UPDATE - START_TIME))
    RUNTIME_MIN=$((RUNTIME_SEC / 60))
    RUNTIME_HOUR=$((RUNTIME_MIN / 60))
    RUNTIME_DAY=$((RUNTIME_HOUR / 24))
    printf "    %-30s %d days, %d hrs, %d min, %d sec\n" "Run Time:" "$RUNTIME_DAY" "$((RUNTIME_HOUR % 24))" "$((RUNTIME_MIN % 60))" "$((RUNTIME_SEC % 60))"
fi
echo ""

echo "[*] Coverage Analysis"
echo "──────────────────────────────────────────────────────────────────"
printf "    %-30s %.2f%s\n" "Bitmap Coverage:" "$COVERAGE" "%"
if [ -n "$TOTAL_EDGES" ] && [ "$TOTAL_EDGES" != "0" ]; then
    EDGE_PERCENT=$(echo "scale=2; $EDGES_FOUND * 100 / $TOTAL_EDGES" | bc 2>/dev/null || echo "0")
    printf "    %-30s %d / %d (%.2f%s)\n" "Edges Found:" "$EDGES_FOUND" "$TOTAL_EDGES" "$EDGE_PERCENT" "%"
else
    printf "    %-30s %d\n" "Edges Found:" "$EDGES_FOUND"
fi
echo ""

echo "[*] Test Case Analysis"
echo "──────────────────────────────────────────────────────────────────"
printf "    %-30s %d\n" "Unique Test Cases:" "$CORPUS_COUNT"

if [ -d "$FUZZ_RUN/queue" ]; then
    QUEUE_COUNT=$(ls $FUZZ_RUN/queue/id:* 2>/dev/null | wc -l)
    printf "    %-30s %d\n" "Queue Size:" "$QUEUE_COUNT"

    if [ "$QUEUE_COUNT" -gt 0 ]; then
        LARGEST=$(ls -S $FUZZ_RUN/queue/id:* 2>/dev/null | head -1)
        if [ -n "$LARGEST" ] && [ -f "$LARGEST" ]; then
            LARGEST_SIZE=$(wc -c < "$LARGEST")
            printf "    %-30s %d bytes\n" "Largest Test Case:" "$LARGEST_SIZE"

            SMALLEST=$(ls -Sr $FUZZ_RUN/queue/id:* 2>/dev/null | head -1)
            if [ -n "$SMALLEST" ] && [ -f "$SMALLEST" ]; then
                SMALLEST_SIZE=$(wc -c < "$SMALLEST")
                printf "    %-30s %d bytes\n" "Smallest Test Case:" "$SMALLEST_SIZE"
            fi
        fi
    fi
else
    echo "    [!] No queue directory found"
fi
echo ""

echo "[*] Safety Analysis"
echo "──────────────────────────────────────────────────────────────────"
printf "    %-30s %d\n" "Unique Crashes:" "$UNIQUE_CRASHES"
printf "    %-30s %d\n" "Unique Hangs:" "$UNIQUE_HANGS"

if [ "$UNIQUE_CRASHES" -gt 0 ]; then
    echo ""
    echo "    [!] Crashes detected! Review them at:"
    echo "        $FUZZ_RUN/crashes/"
fi

if [ "$UNIQUE_HANGS" -gt 0 ]; then
    echo ""
    echo "    [!] Hangs detected! Review them at:"
    echo "        $FUZZ_RUN/hangs/"
fi
echo ""

echo "[*] Recommendations"
echo "──────────────────────────────────────────────────────────────────"

if [ "$EDGES_FOUND" -lt 10 ]; then
    echo "    - Low edge count suggests limited path exploration"
    echo "    - Consider running longer or with different seed inputs"
fi

if [ "$(echo "$STABILITY < 95.0" | bc 2>/dev/null || echo "0")" = "1" ]; then
    echo "    - Low stability (${STABILITY}%) may indicate flaky test behavior"
    echo "    - Review test for non-deterministic elements"
fi

if [ "$UNIQUE_CRASHES" -eq 0 ] && [ "$UNIQUE_HANGS" -eq 0 ]; then
    echo "    [+] No crashes or hangs detected - good stability"
fi
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[*] Summary"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "    Test:             $TEST_NAME"
echo "    Duration:         ${DURATION}s ($(($DURATION / 60))m)"
echo "    Executions:       $EXECS"
echo "    Rate:             $EXECS_PER_SEC/sec"
echo "    Coverage:         ${COVERAGE}%"
echo "    Test Cases:       $CORPUS_COUNT"
echo "    Crashes:          $UNIQUE_CRASHES"
echo "    Hangs:            $UNIQUE_HANGS"
echo ""
echo "    Full stats:       $FUZZ_RUN/fuzzer_stats"
echo "    Test cases:       $FUZZ_RUN/queue/"
if [ "$UNIQUE_CRASHES" -gt 0 ]; then
    echo "    Crashes:          $FUZZ_RUN/crashes/"
fi
if [ "$UNIQUE_HANGS" -gt 0 ]; then
    echo "    Hangs:           $FUZZ_RUN/hangs/"
fi
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[+] Analysis Complete"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
