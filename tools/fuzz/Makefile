.PHONY: seed seed-all fuzz fuzz-long clean \
        seed-match seed-groups seed-engines seed-bodies seed-set \
        seed-caps seed-batch seed-iteration \
        fuzz-match fuzz-groups fuzz-engines fuzz-bodies fuzz-set

# ---------------------------------------------------------------------------
# Layer 1: the original no-capture DFA/CompiledDFA find body.

# Run just the seed corpus (tools/re2test/custom-tests.txt pairs plus any
# checked-in failing/interesting cases under testdata/fuzz/) as a regular
# test — fast, deterministic, safe for routine use.
seed:
	go test -run=FuzzCorrectness -v .

# Short interactive fuzz run.
fuzz:
	go test -fuzz=FuzzCorrectness -fuzztime=1m .

# Overnight run.
fuzz-long:
	go test -fuzz=FuzzCorrectness -fuzztime=8h .

# ---------------------------------------------------------------------------
# Layer 2: the paths Layer 1 never reaches.
#
# Only ONE -fuzz target can run per `go test` invocation, hence one goal each.
# The seed-* goals have no such restriction and are what CI should run.

# Replay every Layer-2 target's seed corpus.
seed-all: seed seed-match seed-groups seed-engines seed-bodies seed-set seed-caps seed-batch seed-iteration

seed-match:                     ## anchored match (full-consumption oracle)
	go test -run=FuzzMatch .
seed-groups:                    ## captures, selector's engine choice
	go test -run='FuzzGroups$$' .
seed-engines:                   ## captures, TDFA vs Backtracking cross-check
	go test -run=FuzzGroupsBothEngines .
seed-bodies:                    ## captures, Backtracking fast body vs its fallback
	go test -run=FuzzGroupsBothBodies .
seed-set:                       ## set find (overlapping)
	go test -run='FuzzSet$$' .
seed-caps:                      ## every set capability, at every `from`
	go test -run='FuzzSetCaps$$' .
seed-batch:                     ## set find through the batch entry, capacity 1
	go test -run='FuzzFindBatch$$' .
seed-iteration:                 ## find iterated from successive offsets
	go test -run='FuzzFindIteration$$' .

# Each fuzz-* goal pairs -fuzz with a matching -run. Without the -run filter,
# `go test -fuzz=X` still replays EVERY other target's seed corpus first, so one
# open bug anywhere (e.g. one in FuzzGroups) aborts the run before the
# requested target ever starts fuzzing.
fuzz-match:
	go test -run=FuzzMatch -fuzz=FuzzMatch -fuzztime=10m .
fuzz-groups:
	go test -run='FuzzGroups$$' -fuzz='FuzzGroups$$' -fuzztime=10m .
fuzz-engines:
	go test -run=FuzzGroupsBothEngines -fuzz=FuzzGroupsBothEngines -fuzztime=10m .
fuzz-bodies:
	go test -run=FuzzGroupsBothBodies -fuzz=FuzzGroupsBothBodies -fuzztime=10m .
fuzz-set:
	go test -run='FuzzSet$$' -fuzz='FuzzSet$$' -fuzztime=10m .

clean:
	rm -rf testdata/fuzz
