.PHONY: run example-lm example-lnm example-combined examples clean

# Run against an arbitrary pattern/mode/input file, e.g.:
#   make run ARGS="-pattern '[a-z]+' -mode find -inputs myinputs.txt -detailed"
run:
	go run . $(ARGS)

# Clear LikelyMatch win on the matching-inputs table (LM-1: relaxes the
# lit-chain SIMD-verify gate from N>=24 to N>=1; see plans/LM_TODO.md
# LM-1, and tools/likelytest's "dense-akia" case). AKIA[A-Z0-9]{16} has
# count N=16, below the neutral/LikelyNoMatch gate of 24 but above
# LikelyMatch's gate of 1 — under neutral this pattern falls back to a
# plain scalar DFA scan/verify; under LikelyMatch it takes the SIMD
# counted-chain verify path instead. The old example here
# (https://cdn\.io/[0-9a-f]{64}, N=64) was already >=24 under neutral,
# so LikelyMatch never changed its codegen and the win was always 0% —
# it predates LM-1 lowering the gate and was never revisited.
example-lm:
	go run . -pattern 'AKIA[A-Z0-9]{16}' -mode find -inputs examples/lm_akia_inputs.txt $(ARGS)

# Clear LikelyNoMatch win on the non-matching-inputs table (no literal
# anchor, wide first-byte class; see plans/TODO.md LNM Action 5).
example-lnm:
	go run . -pattern '[a-zA-Z]{8,}' -mode find -inputs examples/lnm_inputs.txt $(ARGS)

# Both wins in one pattern, by fuel: LikelyMatch gains on the matching bucket,
# LikelyNoMatch gains on the non-matching bucket, each mode flat in the
# other's bucket. Bare (no literal anchor) `[A-Z]{8,}` hits two independent
# LikelyMode-gated detectors in engine_dfa.go that share the same DFA find
# layout but are gated in opposite directions:
#   - detectShuftiSelfLoop's bare-pattern bail (len(l.prefix)==0) is lifted
#     only when l.lmBareShufti (LikelyMatch + minLen>=8, see
#     lmBareShuftiEligible) — SIMD self-loop bulk-skip through a long run of
#     matching bytes, big win on dense matching input, no effect on
#     non-matching input (self-loop is never entered).
#   - LikelyNoMatch's dominant-state SIMD bulk-skip (Opt 1) speeds up
#     scanning through bytes outside the first-byte class, big win on
#     non-matching input, no effect once inside a real match run.
# The old example here (`[0-9]{8}ghp_[A-Za-z0-9]{200}`) relied on Gap E
# (analyseLitChainPrefixed), which is not LikelyMode-gated at all — it always
# emits identical code regardless of mode, so the win was always 0%/0%.
example-combined:
	go run . -pattern '[A-Z]{8,}' -mode find -inputs examples/lm_lnm_combined_inputs.txt $(ARGS)

examples: example-lm example-lnm example-combined

clean:
	rm -f pattest
