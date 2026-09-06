.PHONY: run time sets baseline check clean

# The sweep: fuel and module size for every case. Deterministic, so this is the
# form to compare two trees with, and what `baseline` captures.
run:
	go run . $(ARGS)

# Adds p50 wall-clock. Read the README before believing any of it below ~1 KB:
# every cell carries a ~2.4µs host-call floor.
time:
	go run . -time $(ARGS)

# The set cases alone.
sets:
	go run . -sets $(ARGS)

# Capture the current fuel/size sweep. Fuel is deterministic, so this file is a
# real regression signal rather than a timing snapshot.
baseline:
	go run . > baseline_len.txt 2>&1
	@echo "Baseline captured to baseline_len.txt"

# Compare the current tree against the captured baseline. Any difference is a
# real change in emitted code — there is no tolerance to set, because fuel does
# not drift.
check:
	@go run . > /tmp/lentest_now.txt 2>&1
	@diff baseline_len.txt /tmp/lentest_now.txt && echo "lentest: no change vs baseline" || \
		(echo "lentest: CHANGED vs baseline — expected if you wired a mechanism to InputLength; run 'make baseline' if intentional" && exit 1)

clean:
	rm -f /tmp/lentest_now.txt
