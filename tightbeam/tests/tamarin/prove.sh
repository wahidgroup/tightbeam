#!/usr/bin/env bash
set -euo pipefail

# Runs Tamarin on the protocol models, in a container with no network and a
# read-only model folder.
#
#   prove.sh all                       runs every sound proof and every control
#   prove.sh trace <model> [flags]     prints the full output, with any attack
#   prove.sh <model.spthy> [flags]     proves one model, and prints its summary
#
# Tamarin exits 0 on a falsified lemma, so `all` reads each summary. A sound
# model must verify every lemma, and each control must give its attack.
#
# LIMIT_SECONDS bounds one run of Tamarin, 600 by default.

HERE="$(cd "$(dirname "$0")" && pwd)"
IMAGE=tightbeam-tamarin:1.12.0
LIMIT_SECONDS="${LIMIT_SECONDS:-600}"
FAILED=0

if ! docker image inspect "$IMAGE" > /dev/null 2>&1; then
	docker build -t "$IMAGE" "$HERE"
fi

# The derivation check has a time limit of its own, which load can trip.
prove() {
	case " $* " in
		*' --prove='*) ;;
		*) set -- --prove "$@" ;;
	esac

	docker run --rm --network none --memory=8g --cpus=4 -e LC_ALL=C.UTF-8 -v "$HERE:/work:ro" -w /work "$IMAGE" \
		timeout "$LIMIT_SECONDS" tamarin-prover --quit-on-warning --derivcheck-timeout=0 "$@" 2>&1
}

summary() {
	sed -n '/summary of summaries:/,$p'
}

# Proves every lemma of a model, and holds the summary to `verified` alone.
sound() {
	local model="$1"
	local started=$SECONDS

	local output
	local status=0
	output="$(prove "$model")" || status=$?

	local report
	report="$(printf '%s\n' "$output" | summary)"

	local verdict=FAILED
	if [ "$status" -eq 0 ] && grep -q ': verified' <<< "$report" && ! grep -qE 'falsified|analysis incomplete' <<< "$report"; then
		verdict=ok
	fi

	[ "$verdict" = ok ] || FAILED=$((FAILED + 1))
	printf '%-7s %5ss  sound %s, %s lemmas\n' "$verdict" "$((SECONDS - started))" "$model" "$(grep -c ': verified' <<< "$report")"
}

# Runs one control, and holds its lemma to the result that shows the attack.
# Every other lemma of the run reads `analysis incomplete`, so the check reads
# the line of this lemma alone.
control() {
	local model="$1"
	local lemma="$2"
	local result="$3"
	shift 3
	local started=$SECONDS

	local output
	local status=0
	output="$(prove "$model" "--prove=$lemma" "$@")" || status=$?

	local line
	line="$(printf '%s\n' "$output" | summary | grep -E "^ *$lemma \(" || true)"

	local verdict=FAILED
	if [ "$status" -eq 0 ] && grep -q ": $result" <<< "$line"; then
		verdict=ok
	fi

	[ "$verdict" = ok ] || FAILED=$((FAILED + 1))
	printf '%-7s %5ss  %s %s: %s\n' "$verdict" "$((SECONDS - started))" "$model" "$*" "${line:-no result}"
}

if [ "${1:-}" = all ]; then
	ATTACK='falsified - found trace'

	sound hpke.spthy
	sound cms.spthy
	sound rekey.spthy

	control hpke.spthy client_authenticates_server "$ATTACK" --defines=UNBOUND_SIGNATURE
	control hpke.spthy forward_secrecy_client "$ATTACK" --defines=STATIC_SERVER_KEY
	control hpke.spthy server_authenticates_client "$ATTACK" --defines=UNBOUND_FINISHED
	control hpke.spthy client_agrees_on_negotiation "$ATTACK" --defines=UNBOUND_OFFER

	control cms.spthy attack_on_server_authentication verified --defines=UNBOUND_SIGNATURE --defines=FOCUS --defines=ACCEPT_ONLY
	control cms.spthy attack_on_client_authentication verified --defines=UNBOUND_FINISHED --defines=FOCUS
	control cms.spthy attack_on_forward_secrecy verified --defines=NO_EE --defines=FOCUS
	control cms.spthy client_key_needs_both_secrets "$ATTACK" --defines=NO_BASE
	control cms.spthy client_agrees_on_negotiation "$ATTACK" --defines=UNBOUND_OFFER

	control rekey.spthy next_epoch_secret_at_client "$ATTACK" --defines=NO_FRESH_EXCHANGE
	control rekey.spthy next_epoch_secret_at_client "$ATTACK" --defines=UNPINNED_SHARE
	control rekey.spthy server_agrees_with_client "$ATTACK" --defines=NO_ROLE_TAG

	echo "$FAILED failed, total ${SECONDS}s"
	[ "$FAILED" -eq 0 ]
	exit
fi

if [ "${1:-}" = trace ]; then
	shift
	prove "$@"
	exit
fi

OUTPUT="$(prove "$@")" || STATUS=$?
if ! printf '%s\n' "$OUTPUT" | grep -q 'summary of summaries:'; then
	echo "no summary, exit code ${STATUS:-0}" >&2
	printf '%s\n' "$OUTPUT" | tail -n 30 >&2
	exit 1
fi

printf '%s\n' "$OUTPUT" | summary
