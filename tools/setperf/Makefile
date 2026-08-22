# tools/setperf — cross-engine comparison against regex-automata (plans/SETS.md §9.9).
#
# The Rust harness is shared with tools/perftest: one crate, one toolchain,
# one build artefact. Build it there first (or via the `harnesses` target).

.PHONY: run fuel size verify harnesses baseline check clean

run: harnesses
	go run .

fuel:
	go run . -fuel

size:
	go run . -size

verify: harnesses
	go run . -verify

harnesses:
	$(MAKE) -C ../perftest harnesses

# Capture the deterministic baselines. Fuel and module size are exact, so
# these are compared for EQUALITY, not within a tolerance — a change is a
# change and must be attributed. Wall-clock is deliberately not baselined:
# it is placement noise on this machine (see plans/TODO.md's
# placement-roulette entry), so a committed number would only ever produce
# false alarms.
baseline:
	go run . -fuel 2>/dev/null > baseline_fuel.txt
	go run . -size 2>/dev/null > baseline_size.txt
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
	rm -f setperf
