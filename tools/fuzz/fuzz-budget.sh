#!/usr/bin/env bash
# fuzz-budget.sh — run FuzzCorrectness until a wall-clock time budget is
# exhausted or a target number of distinct crashers has been found,
# whichever comes first.
#
# go test -fuzz stops at the very first failure by design
# and re-fails immediately replaying it on every later invocation, since a
# crasher gets written under testdata/fuzz/FuzzCorrectness/ and is always
# replayed as seed corpus. This script loops around that: each time a run
# fails, it relocates the newly-written crasher out of that directory (so
# the next invocation doesn't just immediately re-fail replaying it) and
# resumes fuzzing with whatever time budget remains.
#
# Usage:
#   ./fuzz-budget.sh [TIME] [MAX_ERRORS]
#   TIME        total wall-clock budget as a sequence of <number><unit>
#               chunks (h/m/s), e.g. 10m, 1h30m, 45s. Default: 10m.
#   MAX_ERRORS  stop after this many distinct crashers. Default: 5.
#
# Found crashers are moved to found/<run-timestamp>/<found-time>-<hash>,
# in the same "go test fuzz v1" encoding go test itself writes. To
# reproduce and debug one, copy it back:
#   cp found/.../HHMMSS-<hash> testdata/fuzz/FuzzCorrectness/<hash>
#   go test -run=FuzzCorrectness .
# Once understood, shrink it and add the minimal repro to
# tools/re2test/custom-tests.txt as a permanent regression test — don't rely
# on the testdata/fuzz entry alone for that.

set -euo pipefail
cd "$(dirname "$0")"

TIME="${1:-10m}"
MAX_ERRORS="${2:-5}"
CORPUS_DIR="testdata/fuzz/FuzzCorrectness"
FOUND_DIR="found/$(date +%Y%m%d-%H%M%S)"

if ! [[ "$MAX_ERRORS" =~ ^[0-9]+$ ]] || [[ "$MAX_ERRORS" -eq 0 ]]; then
	echo "MAX_ERRORS must be a positive integer, got: $MAX_ERRORS" >&2
	exit 2
fi

# parse_duration converts a Go-style duration string (h/m/s components,
# e.g. "1h30m", "10m", "45s") to whole seconds. No fractional units, and
# no support for go test's count-based "-fuzztime=1000x" form.
parse_duration() {
	local dur="$1" total=0 num unit
	while [[ "$dur" =~ ^([0-9]+)(h|m|s)(.*)$ ]]; do
		num="${BASH_REMATCH[1]}"
		unit="${BASH_REMATCH[2]}"
		dur="${BASH_REMATCH[3]}"
		case "$unit" in
		h) total=$((total + num * 3600)) ;;
		m) total=$((total + num * 60)) ;;
		s) total=$((total + num)) ;;
		esac
	done
	if [[ -n "$dur" || "$total" -eq 0 ]]; then
		echo "could not parse duration: $1 (expected e.g. 10m, 1h30m, 45s)" >&2
		exit 2
	fi
	echo "$total"
}

mkdir -p "$CORPUS_DIR"

budget_secs=$(parse_duration "$TIME")
deadline=$(($(date +%s) + budget_secs))
found=0

while :; do
	now=$(date +%s)
	remaining=$((deadline - now))
	if ((remaining <= 0)); then
		echo "time budget exhausted (${TIME}), ${found} crasher(s) found"
		break
	fi
	if ((found >= MAX_ERRORS)); then
		echo "error limit reached (${MAX_ERRORS}), stopping with ${remaining}s left on the clock"
		break
	fi

	before=$(ls "$CORPUS_DIR" 2>/dev/null | sort)
	echo "== fuzzing for up to ${remaining}s (found ${found}/${MAX_ERRORS} so far) =="
	log=$(mktemp)
	if go test -fuzz=FuzzCorrectness -fuzztime="${remaining}s" . >"$log" 2>&1; then
		rm -f "$log"
		echo "fuzztime elapsed with no new failure"
		continue
	fi
	grep -v '^fuzz: elapsed:' "$log" >&2 || true
	rm -f "$log"

	after=$(ls "$CORPUS_DIR" 2>/dev/null | sort)
	new_files=$(comm -13 <(echo "$before") <(echo "$after"))
	if [[ -z "$new_files" ]]; then
		echo "go test failed but no new file appeared under $CORPUS_DIR — a" \
			"pre-existing seed corpus entry is failing (a real regression, not" \
			"a new fuzz-discovered bug); stopping instead of looping forever." >&2
		exit 1
	fi

	mkdir -p "$FOUND_DIR"
	while IFS= read -r f; do
		[[ -z "$f" ]] && continue
		found=$((found + 1))
		dest="$FOUND_DIR/$(date +%H%M%S)-$f"
		mv "$CORPUS_DIR/$f" "$dest"
		echo "crasher #${found} -> ${dest}"
	done <<<"$new_files"
done

if ((found > 0)); then
	echo "done: ${found} crasher(s) saved under ${FOUND_DIR}"
else
	echo "done: no crashers found"
fi
