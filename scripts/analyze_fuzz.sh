#!/bin/bash
# Generic Fuzz Quality Analysis Tool
#
# Runs AFL fuzzing on any fuzz test with UI display and generates
# a comprehensive analysis report.
#
# This script can be used from any Rust project root that uses cargo-afl.
# It automatically detects the project structure and fuzz test locations.
#
# References:
#   GNU CLI Guidelines: https://www.gnu.org/prep/standards/html_node/Command_002dLine-Interfaces.html
#   POSIX Utility Syntax: https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Script is in scripts/ directory, project root is one level up
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Project metadata
PROJECT="analyze_fuzz"
VERSION="1.0.0"

# Default values
DURATION=60
SHOW_UI=true
SKIP_CRASH_CHECK=true
SKIP_CPU_FREQ=true
KEEP_OUTPUT=false
TEST_NAME=""
SEED_DIR=""
VERIFY_CODE=false
VERIFY_PATTERNS=()

# Auto-detect fuzz test locations
# Try common locations: tests/fuzz/, <crate>/tests/fuzz/, fuzz/
detect_fuzz_base() {
    local test_name="$1"
    # Try different common locations
    for base in "tests/fuzz" "tightbeam/tests/fuzz" "fuzz" "tests"; do
        if [ -d "$base/$test_name" ] || [ -f "$base/${test_name}.rs" ]; then
            echo "$base"
            return 0
        fi
    done
    # Default to tests/fuzz if it exists
    if [ -d "tests/fuzz" ]; then
        echo "tests/fuzz"
        return 0
    fi
    # Fallback to first directory containing "fuzz"
    local found=$(find . -maxdepth 3 -type d -name "*fuzz*" 2>/dev/null | head -1)
    if [ -n "$found" ]; then
        echo "$found" | sed 's|^\./||'
        return 0
    fi
    echo "tests/fuzz"  # Default fallback
}

# Print usage information
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

# Print version information
version() {
    cat << EOF
$PROJECT $VERSION
Generic Fuzz Quality Analysis Tool

Works with any Rust project using cargo-afl.
EOF
}

# Parse arguments using getopt (GNU/POSIX compliant)
if ! OPTS=$(getopt -o hVncCFks:vp: --long help,version,no-ui,skip-checks,skip-crash-check,skip-cpu-freq,keep-output,seeds:,verify,pattern: -n "$PROJECT" -- "$@"); then
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

# Handle TEST_NAME argument (required)
if [ $# -eq 0 ]; then
    echo "Error: TEST_NAME is required" >&2
    usage >&2
    exit 1
fi

TEST_NAME="$1"
shift

# Handle DURATION argument (optional)
if [ $# -gt 0 ] && [[ "$1" =~ ^[0-9]+$ ]]; then
    DURATION="$1"
    shift
fi

# Handle AFL_ARGS (everything after --)
AFL_ARGS=""
if [ $# -gt 0 ] && [ "$1" = "--" ]; then
    shift
    AFL_ARGS="$*"
fi

# Validate duration
if ! [[ "$DURATION" =~ ^[0-9]+$ ]] || [ "$DURATION" -le 0 ]; then
    echo "Error: Duration must be a positive integer (seconds)" >&2
    exit 1
fi

# Validate verify patterns if verify is enabled
if [ "$VERIFY_CODE" = true ] && [ ${#VERIFY_PATTERNS[@]} -eq 0 ]; then
    echo "Error: --verify requires at least one --pattern" >&2
    exit 1
fi

# Auto-detect fuzz base directory
FUZZ_BASE=$(detect_fuzz_base "$TEST_NAME")

# Set default seed directory if not provided
if [ -z "$SEED_DIR" ]; then
    SEED_DIR="$FUZZ_BASE/${TEST_NAME}/seeds"
fi

# Determine test file path for code verification
TEST_FILE="$FUZZ_BASE/${TEST_NAME}/mod.rs"
if [ ! -f "$TEST_FILE" ]; then
    # Try .rs file instead
    TEST_FILE="$FUZZ_BASE/${TEST_NAME}.rs"
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Fuzz Quality Analysis Tool - $TEST_NAME"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ============================================================================
# Phase 1: Preparation
# ============================================================================

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

# Check prerequisites
echo "[*] Checking prerequisites..."
if ! command -v cargo-afl &> /dev/null; then
    echo "[!] ERROR: cargo-afl not found. Install with: cargo install cargo-afl" >&2
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

# Build fuzz target
echo "[*] Building fuzz target..."
# Try make build-fuzz first, fallback to cargo afl build
if command -v make &> /dev/null && make -n build-fuzz &> /dev/null 2>&1; then
    if ! make build-fuzz > /dev/null 2>&1; then
        echo "[!] ERROR: Failed to build fuzz target with make" >&2
        exit 1
    fi
else
    # Fallback: try cargo afl build directly
    echo "    Note: make build-fuzz not available, trying cargo afl build..."
    if ! RUSTFLAGS="--cfg fuzzing" cargo afl build --test fuzzing 2>&1 | grep -v "^    " | grep -v "^Compiling" | grep -v "^Finished" | grep -v "^$" || true; then
        echo "[!] ERROR: Failed to build fuzz target" >&2
        exit 1
    fi
fi
echo "[+] Fuzz target built successfully"
echo ""

# Locate fuzz target binary
# Try common binary locations and patterns
FUZZ_TARGET=""
for pattern in "target/debug/deps/fuzzing-*" "target/debug/deps/*fuzz*" "target/debug/fuzz_*" "target/debug/*fuzz*"; do
    FUZZ_TARGET=$(ls $pattern 2>/dev/null | grep -v '\.d$' | grep -v '\.rlib$' | head -1)
    if [ -n "$FUZZ_TARGET" ] && [ -f "$FUZZ_TARGET" ] && [ -x "$FUZZ_TARGET" ]; then
        break
    fi
done

if [ -z "$FUZZ_TARGET" ] || [ ! -f "$FUZZ_TARGET" ]; then
    echo "[!] ERROR: Could not find fuzzing binary" >&2
    echo "    Searched in: target/debug/deps/, target/debug/" >&2
    echo "    Try building with: cargo afl build --test fuzzing" >&2
    exit 1
fi
echo "[+] Found fuzz target: $(basename "$FUZZ_TARGET")"
echo ""

# Prepare seed inputs
echo "[*] Preparing seed inputs..."
mkdir -p built/fuzz/in
if [ "$KEEP_OUTPUT" = false ]; then
    rm -rf built/fuzz/out
fi
mkdir -p built/fuzz/out

# Copy seeds from version-controlled directory to AFL input directory
if [ -d "$SEED_DIR" ]; then
    # Copy all seed files from seed directory
    find "$SEED_DIR" -type f \( -name "*.txt" -o -name "*.bin" -o -name "*.dat" \) -exec cp {} built/fuzz/in/ \;
    SEED_COUNT=$(ls built/fuzz/in/*.* 2>/dev/null | wc -l)
    if [ "$SEED_COUNT" -gt 0 ]; then
        echo "[+] Copied $SEED_COUNT seed files from $SEED_DIR"
    else
        echo "[!] WARNING: No seed files found in $SEED_DIR"
        echo "    Creating minimal seed file..."
        echo "seed" > built/fuzz/in/seed.txt
        SEED_COUNT=1
    fi
else
    echo "[!] WARNING: Seed directory not found: $SEED_DIR"
    echo "    Creating minimal seed file..."
    echo "seed" > built/fuzz/in/seed.txt
    SEED_COUNT=1
fi
echo "[+] Prepared $SEED_COUNT seed files for fuzzing"
echo ""

# ============================================================================
# Phase 2: Code Verification (optional)
# ============================================================================

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
            # Split pattern entry (format: "feature:pattern")
            feature="${pattern_entry%%:*}"
            pattern="${pattern_entry#*:}"
            if [ "$feature" = "$pattern_entry" ]; then
                # No colon found, use entire string as pattern
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

# ============================================================================
# Phase 3: Fuzzing Execution
# ============================================================================

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Phase 3: Fuzzing Execution (${DURATION} seconds)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Set up AFL environment
AFL_ENV=""
if [ "$SKIP_CRASH_CHECK" = true ]; then
    AFL_ENV="${AFL_ENV}AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 "
fi
if [ "$SKIP_CPU_FREQ" = true ]; then
    AFL_ENV="${AFL_ENV}AFL_SKIP_CPUFREQ=1 "
fi

if [ -n "$AFL_ENV" ]; then
    echo "[*] Note: Skipping AFL system configuration checks"
    if [ "$SKIP_CRASH_CHECK" = true ]; then
        echo "    - Crash reporting check disabled"
    fi
    if [ "$SKIP_CPU_FREQ" = true ]; then
        echo "    - CPU frequency scaling check disabled"
    fi
fi

echo "[*] Starting AFL fuzzer..."
echo "    Target: $(basename "$FUZZ_TARGET")"
echo "    Input: built/fuzz/in/"
echo "    Output: built/fuzz/out/"
if [ -n "$AFL_ARGS" ]; then
    echo "    Extra AFL args: $AFL_ARGS"
fi
echo ""

# Run fuzzer
if [ "$SHOW_UI" = true ]; then
    echo "[*] AFL UI will be displayed below..."
    echo "    Press Ctrl+C to stop early (analysis will still be generated)"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    # Run with UI visible (AFL's TUI will be displayed)
    # The UI shows real-time stats: cycles, corpus count, coverage, exec speed, etc.
    # Use timeout with SIGTERM (default) - AFL will handle it gracefully
    # Exit code 124 means timeout occurred (expected), other codes are errors
    if eval "$AFL_ENV timeout $DURATION cargo afl fuzz -i built/fuzz/in -o built/fuzz/out $AFL_ARGS \"$FUZZ_TARGET\""; then
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
    if eval "$AFL_ENV timeout $DURATION cargo afl fuzz -i built/fuzz/in -o built/fuzz/out $AFL_ARGS \"$FUZZ_TARGET\" > /dev/null 2>&1"; then
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

# ============================================================================
# Phase 4: Analysis Report
# ============================================================================

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Phase 4: Analysis Report"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ ! -f "built/fuzz/out/default/fuzzer_stats" ]; then
    echo "[!] ERROR: Fuzzer stats not found. Fuzzing may have failed." >&2
    exit 1
fi

# Extract statistics
STATS_FILE="built/fuzz/out/default/fuzzer_stats"
EXECS=$(grep "^execs_done" "$STATS_FILE" | awk '{print $3}' || echo "0")
EXECS_PER_SEC=$(grep "^execs_per_sec" "$STATS_FILE" | awk '{print $3}' || echo "0")
CORPUS_COUNT=$(grep "^corpus_count" "$STATS_FILE" | awk '{print $3}' || echo "0")
# Strip % from stability if present (AFL sometimes includes it)
STABILITY=$(grep "^stability" "$STATS_FILE" | awk '{print $3}' | sed 's/%//' || echo "0")
# Strip % from coverage if present
COVERAGE=$(grep "^bitmap_cvg" "$STATS_FILE" | awk '{print $3}' | sed 's/%//' || echo "0")
EDGES_FOUND=$(grep "^edges_found" "$STATS_FILE" | awk '{print $3}' || echo "0")
TOTAL_EDGES=$(grep "^total_edges" "$STATS_FILE" | awk '{print $3}' || echo "0")
CYCLES=$(grep "^cycles_done" "$STATS_FILE" | awk '{print $3}' || echo "0")
UNIQUE_CRASHES=$(grep "^unique_crashes" "$STATS_FILE" | awk '{print $3}' || echo "0")
UNIQUE_HANGS=$(grep "^unique_hangs" "$STATS_FILE" | awk '{print $3}' || echo "0")

# Performance Metrics
echo "[*] Performance Metrics"
echo "──────────────────────────────────────────────────────────────────"
printf "    %-30s %'d\n" "Total Executions:" "$EXECS"
printf "    %-30s %.2f/sec\n" "Execution Rate:" "$EXECS_PER_SEC"
printf "    %-30s %d\n" "Cycles Completed:" "$CYCLES"
printf "    %-30s %.2f%s\n" "Stability:" "$STABILITY" "%"

# Calculate runtime from stats if available
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

# Coverage Analysis
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

# Test Case Analysis
echo "[*] Test Case Analysis"
echo "──────────────────────────────────────────────────────────────────"
printf "    %-30s %d\n" "Unique Test Cases:" "$CORPUS_COUNT"

if [ -d "built/fuzz/out/default/queue" ]; then
    QUEUE_COUNT=$(ls built/fuzz/out/default/queue/id:* 2>/dev/null | wc -l)
    printf "    %-30s %d\n" "Queue Size:" "$QUEUE_COUNT"

    # Size distribution
    if [ "$QUEUE_COUNT" -gt 0 ]; then
        LARGEST=$(ls -S built/fuzz/out/default/queue/id:* 2>/dev/null | head -1)
        if [ -n "$LARGEST" ] && [ -f "$LARGEST" ]; then
            LARGEST_SIZE=$(wc -c < "$LARGEST")
            printf "    %-30s %d bytes\n" "Largest Test Case:" "$LARGEST_SIZE"

            SMALLEST=$(ls -Sr built/fuzz/out/default/queue/id:* 2>/dev/null | head -1)
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

# Safety Analysis
echo "[*] Safety Analysis"
echo "──────────────────────────────────────────────────────────────────"
printf "    %-30s %d\n" "Unique Crashes:" "$UNIQUE_CRASHES"
printf "    %-30s %d\n" "Unique Hangs:" "$UNIQUE_HANGS"

if [ "$UNIQUE_CRASHES" -gt 0 ]; then
    echo ""
    echo "    [!] Crashes detected! Review them at:"
    echo "        built/fuzz/out/default/crashes/"
fi

if [ "$UNIQUE_HANGS" -gt 0 ]; then
    echo ""
    echo "    [!] Hangs detected! Review them at:"
    echo "        built/fuzz/out/default/hangs/"
fi
echo ""

# Recommendations
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

# Summary
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
echo "    Full stats:       built/fuzz/out/default/fuzzer_stats"
echo "    Test cases:       built/fuzz/out/default/queue/"
if [ "$UNIQUE_CRASHES" -gt 0 ]; then
    echo "    Crashes:          built/fuzz/out/default/crashes/"
fi
if [ "$UNIQUE_HANGS" -gt 0 ]; then
    echo "    Hangs:           built/fuzz/out/default/hangs/"
fi
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[+] Analysis Complete"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

