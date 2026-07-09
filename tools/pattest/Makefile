.PHONY: run example-lm example-lnm example-combined examples clean

# Run against an arbitrary pattern/mode/input file, e.g.:
#   make run ARGS="-pattern '[a-z]+' -mode find -inputs myinputs.txt -detailed"
run:
	go run . $(ARGS)

# Clear LikelyMatch win on the matching-inputs table (literal-anchored
# counted-chain suffix; see plans/TODO.md task 5 / LIKELY.md Opt 2). A
# content-addressed URL (SHA-256 hex digest as the last path segment, no
# trailing literal) — realistic shape for CDN/blob-storage/image-digest
# URLs. Buffers are short (~100 bytes of filler before the URL/absent)
# deliberately: at large buffer sizes the fixed literal-scan cost (shared
# by every mode) dilutes Opt 2's relative fuel win down to ~1-2%, since
# Opt 2 only accelerates the class-verify step, not the literal search.
example-lm:
	go run . -pattern 'https://cdn\.io/[0-9a-f]{64}' -mode find -inputs examples/lm_url_inputs.txt $(ARGS)

# Clear LikelyNoMatch win on the non-matching-inputs table (no literal
# anchor, wide first-byte class; see plans/TODO.md LNM Action 5).
example-lnm:
	go run . -pattern '[a-zA-Z]{8,}' -mode find -inputs examples/lnm_inputs.txt $(ARGS)

# Both wins in one pattern, by fuel: LikelyMatch gains on match, LikelyNoMatch
# gains on no-match, each mode flat-or-worse in the other's bucket. NOT
# realistic (a 200-char suffix is not a real secret format) — the 200-count
# is deliberately oversized so Gap E's unconditional (non-short-circuiting)
# suffix verify becomes expensive enough on rejected candidates to flip from
# "harmless side benefit" (as it is at a realistic count like 36) to a
# measurable regression on the no-match bucket, isolating each mode's win to
# its own bucket. See conversation notes / plans/TODO.md tasks 5, 22.
example-combined:
	go run . -pattern '[0-9]{8}ghp_[A-Za-z0-9]{200}' -mode find -inputs examples/lm_lnm_combined_inputs.txt $(ARGS)

examples: example-lm example-lnm example-combined

clean:
	rm -f pattest
