#!/usr/bin/env bash
# fuzz-budget.sh — run one fuzz target until a wall-clock time budget is
# exhausted or a target number of distinct crashers has been found,
# whichever comes first.
#
# go test -fuzz stops at the very first failure by design
# and re-fails immediately replaying it on every later invocation, since a
# crasher gets written under testdata/fuzz/<TARGET>/ and is always
# replayed as seed corpus. This script loops around that: each time a run
# fails, it relocates the newly-written crasher out of that directory (so
# the next invocation doesn't just immediately re-fail replaying it) and
# resumes fuzzing with whatever time budget remains.
#
# Usage:
#   ./fuzz-budget.sh [TIME] [MAX_ERRORS] [TARGET]
#   TIME        total wall-clock budget as a sequence of <number><unit>
#               chunks (h/m/s), e.g. 10m, 1h30m, 45s. Default: 10m.
#   MAX_ERRORS  stop after this many distinct crashers. Default: 5.
#   TARGET      the fuzz function to run, e.g. FuzzSet, FuzzSetCaps or
#               FuzzFindBatch for sets. Default: FuzzCorrectness.
#
# Found crashers are moved to found/<TARGET>/<run-timestamp>/<found-time>-<hash>
# — per target, mirroring testdata/fuzz/<TARGET>/, because the file itself does
# not record which target produced it — in the same "go test fuzz v1" encoding
# go test itself writes. To reproduce and debug one, copy it back under the
# same target:
#   cp found/<TARGET>/.../HHMMSS-<hash> testdata/fuzz/<TARGET>/<hash>
#   go test -run=<TARGET> .
# Once understood, shrink it and add the minimal repro to
# tools/re2test/custom-tests.txt (custom-sets.txt for a set target) as a
# permanent regression test — don't rely on the testdata/fuzz entry alone for
# that.
#
# TRIAGE: not every crasher is a defect. Go's fuzzer kills any single call
# that runs longer than 10 seconds and files the input exactly as it files a
# wrong answer, so a slow COMPILE arrives looking like an engine bug.
#
# Sort them by TIMING before looking for a wrong answer:
#
#   cp found/<TARGET>/.../HHMMSS-<hash> testdata/fuzz/<TARGET>/<hash>
#   /usr/bin/time go test -run='^<TARGET>$/<hash>$' .
#
# A file that PASSES on that solo replay and reports no mismatch is a TIMING
# ARTEFACT, not a defect. Two kinds turn up, and neither is an engine fault:
#
#   * A slow compile. The harness's maxNFAInsts cap does not bound this —
#     cost is not predicted by instruction count (17 instructions have taken
#     1.7s, 802 have taken 42s). The build the fuzzer uses is instrumented for
#     coverage, which costs at least another 2x on top of a solo run, so a
#     case needs to be near 2-3 seconds solo to stay under the limit, not
#     merely under 10.
#
#   * A file Go's MINIMISER wrote. When the worker shrinking a crasher dies,
#     Go writes out whatever candidate that worker was holding, with the
#     message "hung or terminated unexpectedly while minimizing". These
#     replay in milliseconds and need not even be the shape they look like
#     (`.{7000` parses as `.` followed by the literal text `{7000`).
#
# This is accepted behaviour, not an open bug: making the compiler faster was
# tried, measured, and does not close it, because the mutator simply scales the
# pattern until it crosses whatever bar exists. plans/FUZZER_BUGS.md bug 83
# carries the measurements and the one approach that would actually end it.

set -euo pipefail
cd "$(dirname "$0")"

TIME="${1:-10m}"
MAX_ERRORS="${2:-5}"
TARGET="${3:-FuzzCorrectness}"
CORPUS_DIR="testdata/fuzz/${TARGET}"
FOUND_DIR="found/${TARGET}/$(date +%Y%m%d-%H%M%S)"

if ! [[ "$MAX_ERRORS" =~ ^[0-9]+$ ]] || [[ "$MAX_ERRORS" -eq 0 ]]; then
	echo "MAX_ERRORS must be a positive integer, got: $MAX_ERRORS" >&2
	exit 2
fi

# -fuzz takes a regular expression and refuses to run when it matches more
# than one fuzz function, and FuzzSet is a prefix of FuzzSetCaps — so the name
# is checked against the package's own list and anchored below.
#
# The list is captured BEFORE it is searched. Piping `go test -list` straight
# into `grep -q` fails under pipefail: grep exits at the first hit, go test
# dies writing the rest of the list, and a valid name is reported as unknown.
fuzz_targets=$(go test -list '^Fuzz' . | grep '^Fuzz')
if ! [[ "$TARGET" =~ ^Fuzz[A-Za-z0-9_]+$ ]] || ! grep -qx "$TARGET" <<<"$fuzz_targets"; then
	echo "TARGET must name a fuzz function in this package, got: $TARGET" >&2
	echo "available: $(tr '\n' ' ' <<<"$fuzz_targets")" >&2
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
	echo "== fuzzing ${TARGET} for up to ${remaining}s (found ${found}/${MAX_ERRORS} so far) =="
	log=$(mktemp)
	if go test -fuzz="^${TARGET}\$" -fuzztime="${remaining}s" . >"$log" 2>&1; then
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
