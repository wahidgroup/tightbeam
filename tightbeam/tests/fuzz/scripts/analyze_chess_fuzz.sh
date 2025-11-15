#!/bin/bash
# Chess Engine Fuzz Quality Analysis Tool
#
# Runs AFL fuzzing on the chess engine with UI display and generates
# a comprehensive analysis report.
#
# References:
#   GNU CLI Guidelines: https://www.gnu.org/prep/standards/html_node/Command_002dLine-Interfaces.html
#   POSIX Utility Syntax: https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Navigate to project root (4 levels up from tests/fuzz/scripts/)
# scripts/ -> fuzz/ -> tests/ -> tightbeam/ -> project root
cd "$SCRIPT_DIR/../../../.."

# Project metadata
PROJECT="analyze_chess_fuzz"
VERSION="1.0.0"

# Default values
DURATION=60
SHOW_UI=true
SKIP_CRASH_CHECK=true
SKIP_CPU_FREQ=true
KEEP_OUTPUT=false

# Print usage information
usage() {
    cat << EOF
USAGE:
    $PROJECT [OPTIONS] [DURATION]

DESCRIPTION:
    Runs AFL fuzzing on the chess engine with UI display and generates
    a comprehensive analysis report.

ARGUMENTS:
    DURATION              Duration in seconds (default: 60)

OPTIONS:
    -h, --help            Show this help message and exit
    -V, --version         Show version information and exit
    -n, --no-ui           Run without showing AFL UI (output redirected)
    -c, --skip-checks     Skip AFL system configuration checks (sets both flags)
    -C, --skip-crash-check    Skip crash reporting config check
    -F, --skip-cpu-freq       Skip CPU frequency scaling check
    -k, --keep-output     Don't clean previous fuzz output

EXAMPLES:
    $PROJECT 60                    Run for 60 seconds (skips checks by default)
    $PROJECT 300 -n                Run for 5 minutes without UI
    $PROJECT 120 -c                Explicitly skip checks (redundant, default)
    $PROJECT 60 -C                 Only skip crash check
    $PROJECT 60 -F                 Only skip CPU freq check

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
Chess Engine Fuzz Quality Analysis Tool

Part of the tightbeam project.
EOF
}

# Parse arguments using getopt (GNU/POSIX compliant)
if ! OPTS=$(getopt -o hVncCFk --long help,version,no-ui,skip-checks,skip-crash-check,skip-cpu-freq,keep-output -n "$PROJECT" -- "$@"); then
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

# Handle DURATION argument
if [ $# -gt 0 ]; then
    DURATION="$1"
    shift
fi

if [ $# -gt 0 ]; then
    echo "Error: Unexpected argument: $1" >&2
    usage >&2
    exit 1
fi

# Validate duration
if ! [[ "$DURATION" =~ ^[0-9]+$ ]] || [ "$DURATION" -le 0 ]; then
    echo "Error: Duration must be a positive integer (seconds)" >&2
    exit 1
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     Chess Engine Fuzz Quality Analysis Tool                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ============================================================================
# Phase 1: Preparation
# ============================================================================

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Phase 1: Preparation"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "📋 Configuration:"
echo "   Duration: ${DURATION} seconds ($(($DURATION / 60)) minutes)"
echo "   Show UI: $SHOW_UI"
echo "   Skip crash check: $SKIP_CRASH_CHECK"
echo "   Skip CPU freq check: $SKIP_CPU_FREQ"
echo "   Keep output: $KEEP_OUTPUT"
echo ""

# Check prerequisites
echo "🔍 Checking prerequisites..."
if ! command -v cargo-afl &> /dev/null; then
    echo "❌ Error: cargo-afl not found. Install with: cargo install cargo-afl" >&2
    exit 1
fi
echo "   ✓ cargo-afl found"

if ! command -v cargo &> /dev/null; then
    echo "❌ Error: cargo not found" >&2
    exit 1
fi
echo "   ✓ cargo found"

if ! command -v getopt &> /dev/null; then
    echo "❌ Error: getopt not found (required for POSIX/GNU argument parsing)" >&2
    exit 1
fi
echo "   ✓ getopt found"
echo ""

# Build fuzz target
echo "🔨 Building fuzz target..."
if ! make build-fuzz > /dev/null 2>&1; then
    echo "❌ Error: Failed to build fuzz target" >&2
    exit 1
fi
echo "   ✓ Fuzz target built successfully"
echo ""

# Locate fuzz target binary
FUZZ_TARGET=$(ls target/debug/deps/fuzzing-* 2>/dev/null | grep -v '\.d$' | head -1)
if [ -z "$FUZZ_TARGET" ]; then
    echo "❌ Error: Could not find fuzzing binary" >&2
    exit 1
fi
echo "   ✓ Found fuzz target: $(basename "$FUZZ_TARGET")"
echo ""

# Prepare seed inputs
echo "🌱 Preparing seed inputs..."
mkdir -p built/fuzz/in
if [ "$KEEP_OUTPUT" = false ]; then
    rm -rf built/fuzz/out
fi
mkdir -p built/fuzz/out

# Copy seeds from version-controlled directory to AFL input directory
SEED_SOURCE_DIR="tightbeam/tests/fuzz/chess/seeds"
if [ -d "$SEED_SOURCE_DIR" ]; then
    # Copy all seed files from chess/seeds/ subdirectories
    find "$SEED_SOURCE_DIR" -name "*.txt" -type f -exec cp {} built/fuzz/in/ \;
    SEED_COUNT=$(ls built/fuzz/in/*.txt 2>/dev/null | wc -l)
    if [ "$SEED_COUNT" -gt 0 ]; then
        echo "   ✓ Copied $SEED_COUNT seed files from $SEED_SOURCE_DIR"
    else
        echo "   ⚠️  No seed files found in $SEED_SOURCE_DIR"
        echo "   Creating minimal seed file..."
        echo "seed" > built/fuzz/in/seed.txt
        SEED_COUNT=1
    fi
else
    echo "   ⚠️  Seed directory not found: $SEED_SOURCE_DIR"
    echo "   Creating minimal seed file..."
    echo "seed" > built/fuzz/in/seed.txt
    SEED_COUNT=1
fi
echo "   ✓ Prepared $SEED_COUNT seed files for fuzzing"
echo ""

# ============================================================================
# Phase 2: Code Verification
# ============================================================================

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Phase 2: Code Verification"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

CHESS_TEST_FILE="tightbeam/tests/fuzz/chess/mod.rs"
VERIFICATION_PASSED=true

check_code_feature() {
    local feature=$1
    local pattern=$2
    if grep -q "$pattern" "$CHESS_TEST_FILE" 2>/dev/null; then
        echo "   ✓ $feature"
        return 0
    else
        echo "   ✗ $feature (NOT FOUND)"
        VERIFICATION_PASSED=false
        return 1
    fi
}

echo "Checking chess engine fuzz test implementation..."
check_code_feature "Game restart event" "game_restarted"
check_code_feature "Game state reset" "client_game_state = ChessGameState::new()"
check_code_feature "Order reset logic" "order = 1"
check_code_feature "Continuous loop" "loop {"
check_code_feature "Move validation tracking" "move_validated"
check_code_feature "Server move tracking" "server_move"
check_code_feature "Game end detection" "game_ended"
echo ""

if [ "$VERIFICATION_PASSED" = false ]; then
    echo "⚠ Warning: Some expected code features not found"
    echo "   Analysis will continue, but results may be incomplete"
    echo ""
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
    echo "   Note: Skipping AFL system configuration checks"
    if [ "$SKIP_CRASH_CHECK" = true ]; then
        echo "         - Crash reporting check disabled"
    fi
    if [ "$SKIP_CPU_FREQ" = true ]; then
        echo "         - CPU frequency scaling check disabled"
    fi
fi

echo "🚀 Starting AFL fuzzer..."
echo "   Target: $(basename "$FUZZ_TARGET")"
echo "   Input: built/fuzz/in/"
echo "   Output: built/fuzz/out/"
echo ""

# Run fuzzer
if [ "$SHOW_UI" = true ]; then
    echo "   AFL UI will be displayed below..."
    echo "   Press Ctrl+C to stop early (analysis will still be generated)"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    # Run with UI visible (AFL's TUI will be displayed)
    # The UI shows real-time stats: cycles, corpus count, coverage, exec speed, etc.
    # Use timeout with SIGTERM (default) - AFL will handle it gracefully
    # Exit code 124 means timeout occurred (expected), other codes are errors
    if eval "$AFL_ENV timeout $DURATION cargo afl fuzz -i built/fuzz/in -o built/fuzz/out \"$FUZZ_TARGET\""; then
        TIMEOUT_OCCURRED=false
    else
        EXIT_CODE=$?
        if [ $EXIT_CODE -eq 124 ]; then
            TIMEOUT_OCCURRED=true
        else
            TIMEOUT_OCCURRED=false
            echo "   ⚠ Warning: Fuzzer exited with code $EXIT_CODE" >&2
        fi
    fi
else
    echo "   Running in background (UI hidden)..."
    echo "   Note: Use --no-ui=false to see AFL's real-time TUI display"
    if eval "$AFL_ENV timeout $DURATION cargo afl fuzz -i built/fuzz/in -o built/fuzz/out \"$FUZZ_TARGET\" > /dev/null 2>&1"; then
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
    echo "   Fuzzing completed (time limit reached)"
else
    echo "   Fuzzing completed"
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
    echo "❌ Error: Fuzzer stats not found. Fuzzing may have failed." >&2
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
echo "📊 Performance Metrics"
echo "──────────────────────────────────────────────────────────────────"
printf "   %-30s %'d\n" "Total Executions:" "$EXECS"
printf "   %-30s %.2f/sec\n" "Execution Rate:" "$EXECS_PER_SEC"
printf "   %-30s %d\n" "Cycles Completed:" "$CYCLES"
printf "   %-30s %.2f%s\n" "Stability:" "$STABILITY" "%"

# Calculate runtime from stats if available
START_TIME=$(grep "^start_time" "$STATS_FILE" | awk '{print $3}' 2>/dev/null || echo "")
LAST_UPDATE=$(grep "^last_update" "$STATS_FILE" | awk '{print $3}' 2>/dev/null || echo "")
if [ -n "$START_TIME" ] && [ -n "$LAST_UPDATE" ]; then
    RUNTIME_SEC=$((LAST_UPDATE - START_TIME))
    RUNTIME_MIN=$((RUNTIME_SEC / 60))
    RUNTIME_HOUR=$((RUNTIME_MIN / 60))
    RUNTIME_DAY=$((RUNTIME_HOUR / 24))
    printf "   %-30s %d days, %d hrs, %d min, %d sec\n" "Run Time:" "$RUNTIME_DAY" "$((RUNTIME_HOUR % 24))" "$((RUNTIME_MIN % 60))" "$((RUNTIME_SEC % 60))"
fi
echo ""

# Coverage Analysis
echo "📈 Coverage Analysis"
echo "──────────────────────────────────────────────────────────────────"
printf "   %-30s %.2f%s\n" "Bitmap Coverage:" "$COVERAGE" "%"
if [ -n "$TOTAL_EDGES" ] && [ "$TOTAL_EDGES" != "0" ]; then
    EDGE_PERCENT=$(echo "scale=2; $EDGES_FOUND * 100 / $TOTAL_EDGES" | bc 2>/dev/null || echo "0")
    printf "   %-30s %d / %d (%.2f%s)\n" "Edges Found:" "$EDGES_FOUND" "$TOTAL_EDGES" "$EDGE_PERCENT" "%"
else
    printf "   %-30s %d\n" "Edges Found:" "$EDGES_FOUND"
fi
echo ""

# Test Case Analysis
echo "🧪 Test Case Analysis"
echo "──────────────────────────────────────────────────────────────────"
printf "   %-30s %d\n" "Unique Test Cases:" "$CORPUS_COUNT"

if [ -d "built/fuzz/out/default/queue" ]; then
    QUEUE_COUNT=$(ls built/fuzz/out/default/queue/id:* 2>/dev/null | wc -l)
    printf "   %-30s %d\n" "Queue Size:" "$QUEUE_COUNT"

    # Size distribution
    if [ "$QUEUE_COUNT" -gt 0 ]; then
        LARGEST=$(ls -S built/fuzz/out/default/queue/id:* 2>/dev/null | head -1)
        if [ -n "$LARGEST" ] && [ -f "$LARGEST" ]; then
            LARGEST_SIZE=$(wc -c < "$LARGEST")
            printf "   %-30s %d bytes (~%d moves)\n" "Largest Test Case:" "$LARGEST_SIZE" "$((LARGEST_SIZE / 4))"

            SMALLEST=$(ls -Sr built/fuzz/out/default/queue/id:* 2>/dev/null | head -1)
            if [ -n "$SMALLEST" ] && [ -f "$SMALLEST" ]; then
                SMALLEST_SIZE=$(wc -c < "$SMALLEST")
                printf "   %-30s %d bytes (~%d moves)\n" "Smallest Test Case:" "$SMALLEST_SIZE" "$((SMALLEST_SIZE / 4))"
            fi
        fi
    fi
else
    echo "   ⚠ No queue directory found"
fi
echo ""

# Safety Analysis
echo "🛡️  Safety Analysis"
echo "──────────────────────────────────────────────────────────────────"
printf "   %-30s %d\n" "Unique Crashes:" "$UNIQUE_CRASHES"
printf "   %-30s %d\n" "Unique Hangs:" "$UNIQUE_HANGS"

if [ "$UNIQUE_CRASHES" -gt 0 ]; then
    echo ""
    echo "   ⚠️  Crashes detected! Review them at:"
    echo "      built/fuzz/out/default/crashes/"
fi

if [ "$UNIQUE_HANGS" -gt 0 ]; then
    echo ""
    echo "   ⚠️  Hangs detected! Review them at:"
    echo "      built/fuzz/out/default/hangs/"
fi
echo ""

# Game Restart Analysis
echo "🔄 Game Restart Analysis"
echo "──────────────────────────────────────────────────────────────────"

# Check if game restart code paths are being hit
# This is inferred from coverage - if coverage increases over time, game restart paths may be explored
if [ -n "$COVERAGE" ] && [ "$(echo "$COVERAGE > 36.36" | bc 2>/dev/null || echo "0")" = "1" ]; then
    echo "   ✓ Coverage above baseline (36.36%)"
    echo "     This suggests game restart paths may be explored"
else
    echo "   ⚠ Coverage at baseline (36.36%)"
    echo "     Game restart paths (checkmate/stalemate) not yet triggered"
    echo "     This is normal - random moves rarely end games quickly"
fi

# Check test case sizes for potential multiple games
if [ -n "$LARGEST_SIZE" ] && [ "$LARGEST_SIZE" -ge 80 ]; then
    echo "   ✓ Large test cases found (80+ bytes)"
    echo "     These allow multiple games per execution"
else
    echo "   ⚠ Test cases are small (< 80 bytes)"
    echo "     May only allow single game per execution"
fi
echo ""

# Recommendations
echo "💡 Recommendations"
echo "──────────────────────────────────────────────────────────────────"

if [ "$(echo "$COVERAGE <= 36.36" | bc 2>/dev/null || echo "1")" = "1" ]; then
    echo "   • Run longer (10-30 minutes) to find game-ending sequences"
    echo "   • Game restart logic is implemented but needs game endings to trigger"
fi

if [ "$EDGES_FOUND" -lt 10 ]; then
    echo "   • Low edge count suggests limited path exploration"
    echo "   • Consider running longer or with different seed inputs"
fi

if [ "$(echo "$STABILITY < 95.0" | bc 2>/dev/null || echo "0")" = "1" ]; then
    echo "   • Low stability (${STABILITY}%) may indicate flaky test behavior"
    echo "   • Review test for non-deterministic elements"
fi

if [ "$UNIQUE_CRASHES" -eq 0 ] && [ "$UNIQUE_HANGS" -eq 0 ]; then
    echo "   ✓ No crashes or hangs detected - good stability"
fi
echo ""

# Summary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Summary"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "   Duration:        ${DURATION}s ($(($DURATION / 60))m)"
echo "   Executions:      $EXECS"
echo "   Rate:            $EXECS_PER_SEC/sec"
echo "   Coverage:        ${COVERAGE}%"
echo "   Test Cases:      $CORPUS_COUNT"
echo "   Crashes:         $UNIQUE_CRASHES"
echo "   Hangs:           $UNIQUE_HANGS"
echo ""
echo "   Full stats:      built/fuzz/out/default/fuzzer_stats"
echo "   Test cases:      built/fuzz/out/default/queue/"
if [ "$UNIQUE_CRASHES" -gt 0 ]; then
    echo "   Crashes:         built/fuzz/out/default/crashes/"
fi
if [ "$UNIQUE_HANGS" -gt 0 ]; then
    echo "   Hangs:          built/fuzz/out/default/hangs/"
fi
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    Analysis Complete                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
