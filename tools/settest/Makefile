.PHONY: run example-lnm example-shufti example-adaptive examples clean

# Run against an arbitrary config / set / capability / input file, e.g.:
#   make run ARGS="-config myset.yaml -cap find -inputs myinputs.txt"
#   make run ARGS="-config myset.yaml -set secrets -cap scan_any -inputs in.txt -detailed"
#
# -config takes the SAME YAML `regexped compile` reads, so the set under test is
# the set you would ship. Only the set-level `hints:` is varied.
run:
	go run . $(ARGS)

# Clear prefer-no-match win, with no literal frontend involved. Eight class-chain
# patterns all starting with [a-z], so the union automaton's entry state
# self-loops on the other 230 bytes; prefer-no-match turns on emitUnionSkip,
# which strides 16 bytes at a time through such a run. The non-matching inputs
# are sparse in [a-z] (the win case, ~-75% fuel); the matching ones are prose
# (the harm case, and it does cost fuel there) — which together are the whole
# reason this is a hint and not the default.
example-lnm:
	go run . -config examples/classchain.yaml -inputs examples/classchain_inputs.txt -iters 200 $(ARGS)

# Clear prefer-no-match win in a literal set: 21 patterns with distinct [A-U]
# first bytes. -force-frontend scalar is REQUIRED for the A/B to exist at all —
# Shufti is reachable only out of the scalar branch, and left to itself the
# chooser sends these 21 short literals to Teddy, where all three modes emit
# identical bytes and the run measures nothing.
example-shufti:
	go run . -config examples/shufti.yaml -inputs examples/shufti_inputs.txt -force-frontend scalar -iters 200 $(ARGS)

# The `shuftiAdaptive` A/B (task 74). Not a hint comparison — both arms use
# prefer-no-match, and what differs is the runtime density switch that the
# forced-Shufti frontend carries. Nothing reachable from YAML compiles both
# arms (the verdict `prefer-no-match && !rare` is deterministic per set), which
# is why -adaptive exists and why likelytest's `set-shufti-dense-harm` cannot
# be this comparison however it is read.
#
# Read the prefer-no-match FUEL rows of the two runs against each other.
# 2026-09-01, dense input: on 387,906 / 532,866 against off 463,035 / 642,794 —
# the switch is worth 16-17%. On sparse input (example-shufti with -adaptive)
# it costs 3-9% instead, which is the trade it exists to make.
example-adaptive:
	@echo "===== adaptive ON  (the compiler's own verdict for this set) ====="
	go run . -config examples/dense_harm.yaml -inputs examples/dense_harm_inputs.txt -force-frontend scalar -adaptive on -iters 300 $(ARGS)
	@echo "===== adaptive OFF ====="
	go run . -config examples/dense_harm.yaml -inputs examples/dense_harm_inputs.txt -force-frontend scalar -adaptive off -iters 300 $(ARGS)

examples: example-lnm example-shufti example-adaptive

clean:
	rm -f settest
