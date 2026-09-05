# tools/setperf — cross-engine comparison against regex-automata.
#
# The Rust harness is shared with tools/perftest: one crate, one toolchain,
# one build artefact. Build it there first (or via the `harnesses` target).

.PHONY: run fuel fuel-lm fuel-lnm fuel-frontends fuel-cross size verify harnesses baseline check clean

run: harnesses
	go run .

fuel:
	go run . -fuel

# The same board under a set-level hint. NOT baselined and NOT part of
# `check`: every committed baseline was captured neutral, and these rows are
# keyed with the hint (`|prefer-match`) precisely so a hinted run can never be
# compared against one — see setHintsKeySuffix. Read them against a neutral
# `make fuel` from the same tree, never against baseline_fuel.txt.
fuel-lm:
	go run . -fuel -hints=prefer-match

fuel-lnm:
	go run . -fuel -hints=prefer-no-match

# Every literal frontend forced over every family, which is how the crossover
# constants in chooseLiteralFrontend get interrogated rather than assumed
# (TODO task 71 closed that question for the keywords families on a dense
# corpus; this is the command that re-asks it for a new shape).
fuel-frontends:
	@for fe in packed-pair teddy ac scalar; do \
		echo "=== frontend: $$fe ==="; \
		go run . -fuel -force-frontend=$$fe 2>/dev/null; \
	done

# Cross-engine fuel: ours vs regex-automata's, both metered by wasmtime over
# one whole-input operation. Deterministic and machine-independent, so it is
# the number to quote in a plan — unlike the full matrix's wall-clock, which is
# placement noise here. Needs the Rust harness.
fuel-cross: harnesses
	go run . -fuel-cross

size:
	go run . -size

verify: harnesses
	go run . -verify

harnesses:
	$(MAKE) -C ../perftest harnesses

# Capture the deterministic baselines. Fuel and module size are exact, so
# these are compared for EQUALITY, not within a tolerance — a change is a
# change and must be attributed. Wall-clock is deliberately not baselined:
# it is instruction-placement noise on this machine, so a committed number
# would only ever produce
# false alarms.
#
# Written through a TEMPORARY file and moved into place only on success. The
# shell truncates a `>` redirect BEFORE the command runs, so a run that failed
# part-way left a half-written baseline — and these files are gitignored, so
# there is nothing to restore them from.
#
# stderr is NOT discarded: the fuel path routes "row exceeded the budget" notes
# and every HARNESS ERROR there precisely so this target shows them, and
# `2>/dev/null` hid exactly the messages written for it.
baseline:
	go run . -fuel > baseline_fuel.txt.tmp && mv baseline_fuel.txt.tmp baseline_fuel.txt
	go run . -size > baseline_size.txt.tmp && mv baseline_size.txt.tmp baseline_size.txt
	@echo "setperf baselines captured."

check:
	@echo "Checking setperf fuel baseline (exact)..."
	@go run . -compare-fuel baseline_fuel.txt || \
		(echo "SETPERF REGRESSION: fuel — run 'make baseline' if intentional" && exit 1)
	@echo "Checking setperf module-size baseline (exact)..."
	@go run . -compare-size baseline_size.txt || \
		(echo "SETPERF REGRESSION: module size — run 'make baseline' if intentional" && exit 1)
	@echo "All setperf baseline checks passed."

clean:
	rm -f setperf baseline_fuel.txt.tmp baseline_size.txt.tmp
