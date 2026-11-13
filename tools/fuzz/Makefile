.PHONY: seed seed-all fuzz fuzz-long clean \
        seed-match seed-groups seed-engines seed-bodies seed-set \
        seed-caps seed-batch seed-iteration \
        fuzz-match fuzz-groups fuzz-engines fuzz-bodies fuzz-set \
        seed-unicode fuzz-unicode fuzz-unicode-groups fuzz-unicode-set \
        seed-long seed-set-routes fuzz-long-input fuzz-set-routes

# FRESH=1 starts a fuzzing goal from its target's seeds only, not from the
# inputs earlier runs saved: go test re-runs every saved input before it fuzzes
# anything new, and that grows with each run (FuzzSetCaps under -unicode: 4,096
# inputs, 4.5 minutes). The run gets an empty cache directory of its own,
# deleted when it ends; the saved inputs are left as they are. go test passes
# its own -test.fuzzcachedir first, and the last one wins:
#   make fuzz-set-routes FRESH=1
FRESH ?=
ifeq ($(FRESH),1)
fresh = d=$$(mktemp -d) && trap 'rm -rf "$${d:?}"' EXIT &&
FRESH_ARG = -test.fuzzcachedir=$$d
FRESH_ARGS = -args $(FRESH_ARG)
else ifneq ($(FRESH),)
$(error FRESH must be 1 or unset, got: $(FRESH))
endif

# ---------------------------------------------------------------------------
# Layer 1: the original no-capture DFA/CompiledDFA find body.

# Run just the seed corpus (tools/re2test/custom-tests.txt pairs plus any
# checked-in failing/interesting cases under testdata/fuzz/) as a regular
# test — fast, deterministic, safe for routine use.
seed:
	go test -run=FuzzCorrectness -v .

# Short interactive fuzz run.
fuzz:
	$(fresh) go test -fuzz=FuzzCorrectness -fuzztime=1m . $(FRESH_ARGS)

# Overnight run.
fuzz-long:
	$(fresh) go test -fuzz=FuzzCorrectness -fuzztime=8h . $(FRESH_ARGS)

# ---------------------------------------------------------------------------
# Layer 2: the paths Layer 1 never reaches.
#
# Only ONE -fuzz target can run per `go test` invocation, hence one goal each.
# The seed-* goals have no such restriction and are what CI should run.

# Replay every Layer-2 target's seed corpus.
seed-all: seed seed-match seed-groups seed-engines seed-bodies seed-set seed-caps seed-batch seed-iteration \
          seed-long seed-set-routes

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
seed-long:                      ## built patterns + long witness inputs, byte and Unicode mode
	go test -run='FuzzLongInput$$' .
seed-set-routes:                ## built sets + long inputs, every route of find agreeing with Go
	go test -run='FuzzSetRoutes$$' .

# Each fuzz-* goal pairs -fuzz with a matching -run. Without the -run filter,
# `go test -fuzz=X` still replays EVERY other target's seed corpus first, so one
# open bug anywhere (e.g. one in FuzzGroups) aborts the run before the
# requested target ever starts fuzzing.
fuzz-match:
	$(fresh) go test -run=FuzzMatch -fuzz=FuzzMatch -fuzztime=10m . $(FRESH_ARGS)
fuzz-groups:
	$(fresh) go test -run='FuzzGroups$$' -fuzz='FuzzGroups$$' -fuzztime=10m . $(FRESH_ARGS)
fuzz-engines:
	$(fresh) go test -run=FuzzGroupsBothEngines -fuzz=FuzzGroupsBothEngines -fuzztime=10m . $(FRESH_ARGS)
fuzz-bodies:
	$(fresh) go test -run=FuzzGroupsBothBodies -fuzz=FuzzGroupsBothBodies -fuzztime=10m . $(FRESH_ARGS)
fuzz-set:
	$(fresh) go test -run='FuzzSet$$' -fuzz='FuzzSet$$' -fuzztime=10m . $(FRESH_ARGS)

# The generator-driven targets: the fuzz engine supplies only a seed (and the
# mode), the target BUILDS the pattern or set and its long inputs. One worker
# (-parallel=1), so a run stays inside one process's memory — plus its compile
# process, which runs the budgeted compiles (compilechild.go); FUZZTIME sets
# the length, 5 minutes unless given: `make fuzz-long-input FUZZTIME=8h`.
FUZZTIME ?= 5m
fuzz-long-input:
	$(fresh) go test -run='FuzzLongInput$$' -fuzz='FuzzLongInput$$' -fuzztime=$(FUZZTIME) -parallel=1 . $(FRESH_ARGS)
fuzz-set-routes:
	$(fresh) go test -run='FuzzSetRoutes$$' -fuzz='FuzzSetRoutes$$' -fuzztime=$(FUZZTIME) -parallel=1 . $(FRESH_ARGS)

# ---------------------------------------------------------------------------
# Unicode mode: the same targets with every pattern compiled in Unicode mode
# (-unicode), seeded also with the Unicode start-position shapes over
# multi-byte and invalid input (unicodeSeeds; pairs of them for the set
# targets, unicodeSetSeeds). Go is the oracle except on
# input that is not valid UTF-8 for a pattern that can match U+FFFD, which
# Unicode mode, by design, does not (unicodeModeOutOfScope).

# Replay the seed corpora of every target unicodeSeeds or unicodeSetSeeds
# feeds, in Unicode mode.
seed-unicode:
	go test -run='Fuzz(Correctness|Match|Groups|GroupsBothBodies|GroupsBothEngines|FindIteration|Set|SetCaps|FindBatch)$$' . -args -unicode

fuzz-unicode:
	$(fresh) go test -run=FuzzCorrectness -fuzz=FuzzCorrectness -fuzztime=10m . -args -unicode $(FRESH_ARG)
fuzz-unicode-groups:
	$(fresh) go test -run='FuzzGroups$$' -fuzz='FuzzGroups$$' -fuzztime=10m . -args -unicode $(FRESH_ARG)
fuzz-unicode-set:
	$(fresh) go test -run='FuzzSetCaps$$' -fuzz='FuzzSetCaps$$' -fuzztime=10m . -args -unicode $(FRESH_ARG)

clean:
	rm -rf testdata/fuzz
