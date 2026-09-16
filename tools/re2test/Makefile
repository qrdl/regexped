.PHONY: test exhaustive custom adjusted sets sets-likely sets-exhaustive set-batch likelymatch likelynomatch force-backtrack-likelynomatch matchonly findonly groupsonly clean

TESTDATA     := re2-exhaustive.txt
TESTDATA_BZ2 := $(shell go env GOROOT)/src/regexp/testdata/re2-exhaustive.txt.bz2
CUSTOM       := custom-tests.txt
CUSTOM_SETS  := custom-sets.txt
ADJUSTED     := re2-adjusted.txt

# RE2TEST_FLAGS is appended to every re2test invocation below, so one flag can
# be applied to the whole suite — e.g. `make test RE2TEST_FLAGS=--bt-fallback-always`
# runs every target with every Backtracking program answered by its memoised
# fallback body alone. From the repository root, `make re2test RE2TEST_FLAGS=...`
# reaches here through MAKEFLAGS. Empty by default: no invocation changes.
RE2TEST_FLAGS ?=

$(TESTDATA): $(TESTDATA_BZ2)
	bzip2 -dk -c $< > $@

# --all-matches closes the corpus's OTHER blind spot. re2-exhaustive.txt carries
# four columns, so col4 (every match) is absent and only the FIRST match of each
# row is ever checked. A pattern whose first match is right and whose later ones
# are wrong passed — which is half of why `\b` could skip every boundary after a
# word character, since its first match is at position 0 and was always found.
# The flag synthesises col4 from a Go oracle for rows that lack one: 4.9M rows,
# and it costs about 40% more wall time than the bare run.
exhaustive: $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --all-matches $(TESTDATA)

custom:
	# Expectation file vs Go, no WASM involved. Was commented out while its
	# col0 oracle was wrong (it used a leftmost-first find plus a span check
	# instead of matching the export's actual contract, and reported 167 false
	# disagreements). Fixed and clean now, so it runs again: it is
	# the only thing that keeps the file honest, since every other check
	# compares WASM against the file rather than against Go.
	go run . $(RE2TEST_FLAGS) --validate-go --validate-groups $(CUSTOM)
	go run . $(RE2TEST_FLAGS) --validate-groups $(CUSTOM)

$(ADJUSTED): $(TESTDATA)
	go run ./make_adjusted $(TESTDATA) $(ADJUSTED)

adjusted: $(ADJUSTED)
	go run . $(RE2TEST_FLAGS) --validate-groups $(ADJUSTED)

force-backtrack: $(ADJUSTED)
	go run . $(RE2TEST_FLAGS) --force-backtrack $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --force-backtrack --validate-groups $(ADJUSTED)
	go run . $(RE2TEST_FLAGS) --force-backtrack --validate-groups $(CUSTOM)

# Corpus inputs carrying a byte above 0x7F, which every other target SKIPS.
#
# The skip exists because the expectation columns are RE2's and RE2 decodes
# UTF-8, while this is a byte engine: for `.` and a negated class the two
# legitimately disagree, so the columns would report correct behaviour as
# failure. This target judges those rows against a Go oracle run on an ASCII
# TWIN of the input instead — see highbytes.go for why that is sound.
#
# It found `\b` missing every word boundary whose preceding byte was a word
# character (337 rows, one root cause, not actually high-byte specific — pure
# ASCII "a b" failed the same way). Fixed 2026-09-09, and this target has been
# part of `test` since.
#
# Worth knowing what this covers: without it the whole corpus is blind to high
# bytes, which is how a Backtracking engine that dropped every byte >= 0x80
# from a rune range stayed green across ~9.5M cases.
high-bytes: $(ADJUSTED)
	go run . $(RE2TEST_FLAGS) --high-bytes $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --high-bytes --validate-groups $(ADJUSTED)
	# --high-bytes-check-corpus only here: custom-tests.txt's columns are
	# written for a BYTE engine, so they can be compared with the twin. The
	# RE2-derived corpora above carry UTF-8 answers that legitimately differ.
	go run . $(RE2TEST_FLAGS) --high-bytes --high-bytes-check-corpus --validate-groups $(CUSTOM)

# Run every test under LikelyMode=LikelyMatch. Patterns matching the lit-chain
# shape (literal + counted class) take the lit-chain emission path; others fall
# through to the standard DFA. Confirms LikelyMatch correctness across the
# full corpus.
likelymatch: $(ADJUSTED)
	go run . $(RE2TEST_FLAGS) --likelymatch $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --likelymatch --validate-groups $(ADJUSTED)
	go run . $(RE2TEST_FLAGS) --likelymatch --validate-groups $(CUSTOM)

# Run every test under LikelyMode=LikelyNoMatch. Patterns with a dominant
# self-loop (≥240/256 byte classes back to itself, ≤4 exit bytes,
# mid-accepting) take the dominant-self-loop SIMD bulk-skip path; others fall through to
# the standard DFA. Confirms LikelyNoMatch correctness across the full corpus.
likelynomatch: $(ADJUSTED)
	go run . $(RE2TEST_FLAGS) --likelynomatch $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --likelynomatch --validate-groups $(ADJUSTED)
	go run . $(RE2TEST_FLAGS) --likelynomatch --validate-groups $(CUSTOM)

# Run every test with the DFA forced to overflow (--force-backtrack, so
# find/match always fall back to Backtracking) AND under
# LikelyMode=LikelyNoMatch. This is the combination that exercises BT's own
# impossible-byte prefix-scan path (compile/engine_backtrack.go buildBTFindBody)
# across the full corpus: --force-backtrack alone never sets LikelyNoMatch,
# and --likelynomatch alone rarely forces BT (only for patterns whose DFA
# already overflows MaxDFAStates), so neither flag on its own reaches this
# code path at any real scale. Regression test for the bug where
# buildBTFindBody's v128-local allocation silently emitted invalid WASM for
# first-byte sets of 17..64 bytes routed through the Shufti path).
force-backtrack-likelynomatch: $(ADJUSTED)
	go run . $(RE2TEST_FLAGS) --force-backtrack --likelynomatch $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --force-backtrack --likelynomatch --validate-groups $(ADJUSTED)
	go run . $(RE2TEST_FLAGS) --force-backtrack --likelynomatch --validate-groups $(CUSTOM)

# Run every test with match_func compiled alone (no find_func) for
# non-capturing patterns. Reaches the needMatch && !needFind call site
# (compile.go:921, buildLenAltMatchBody) that the default combined
# match+find dispatch never exercises. Regression test for
# the lit-chain-alt anchored-match bugs.
matchonly: $(ADJUSTED)
	go run . $(RE2TEST_FLAGS) --match-only $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --match-only --validate-groups $(ADJUSTED)
	go run . $(RE2TEST_FLAGS) --match-only --validate-groups $(CUSTOM)

# Run every test with find_func compiled alone (no match_func) for
# non-capturing patterns. Mirror of matchonly: reaches the
# `needFind && !needMatch` call sites in compile.go — the alt-prefixed
# find body, the alt-range find body, and the strict/lenient alt find
# bodies — which the default combined match+find dispatch never reaches at
# all. Regression test for the lit-chain alternation find bodies.
findonly: $(ADJUSTED)
	go run . $(RE2TEST_FLAGS) --find-only $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --find-only --validate-groups $(ADJUSTED)
	go run . $(RE2TEST_FLAGS) --find-only --validate-groups $(CUSTOM)

# Run every test with only groups_func compiled (no match_func/find_func)
# for capturing patterns. Surfaces lit-chain capture path bugs that depend
# on the narrow needGroups-only gate (compile.go), which the default
# combined match+find+groups dispatch never exercises in isolation.
groupsonly: $(ADJUSTED)
	go run . $(RE2TEST_FLAGS) --groups-only $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --groups-only --validate-groups $(ADJUSTED)
	go run . $(RE2TEST_FLAGS) --groups-only --validate-groups $(CUSTOM)

test: exhaustive custom adjusted high-bytes force-backtrack likelymatch likelynomatch force-backtrack-likelynomatch matchonly findonly groupsonly sets sets-likely

# ---------------------------------------------------------------------------
# Set-capability coverage.
#
# Two scales, and the difference between them is only --sample:
#
#   sets             the standing gate, part of `make test`. Every one of the
#                    eight capabilities, both `find` modes, both find_batch
#                    capacities and every capability profile — over a SAMPLE of
#                    the corpus, in a few minutes.
#   sets-exhaustive  the same coverage over the WHOLE corpus, plus the
#                    whole-block configuration `--sets` used originally. Hours.
#                    Run it before a release or after touching a set emitter.
#
# Why the corpus is chunked: it has 27 blocks of 132..7020 patterns, so one set
# per block never crosses the thresholds the compiler specialises on from below
# (packed-pair <=16, Teddy <=64, AC >16, wide `_all` >64). --set-chunk fixes the
# set size; --set-shuffle makes a set hold unrelated patterns instead of
# variations of one generator family, which is the pattern INTERACTION the corpus
# says the corpus cannot otherwise produce. --set-subset makes the set select a
# NAMED SUBSET, the only configuration in which PATTERN_COUNT and ID_SPACE
# differ — and confusing those two is a memory-safety bug, not a wrong answer
# — the id-space hazard, which `patterns: all` can never expose.
SET_PROFILES := all-profiles

sets: $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=8  --sample=200 --set-profiles=$(SET_PROFILES) $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=16 --sample=150 --set-shuffle --set-profiles=$(SET_PROFILES) $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=70 --sample=60  --set-shuffle --set-profiles=$(SET_PROFILES) $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=16 --sample=150 --set-shuffle --set-subset --set-profiles=$(SET_PROFILES) $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=70 --sample=60  --set-shuffle --set-subset --set-profiles=$(SET_PROFILES) $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=0  --set-profiles=$(SET_PROFILES) $(CUSTOM_SETS)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=4  --set-profiles=$(SET_PROFILES) $(CUSTOM_SETS)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=0  --set-subset --set-profiles=$(SET_PROFILES) $(CUSTOM_SETS)
	# --set-bt forces set members onto the Backtracking fallback engine
	# which is the only way to reach a BT-backed bucket at corpus scale. It was
	# wired into no target at all, so that path had no standing gate.
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=8 --sample=250 --set-bt=1 --set-profiles=$(SET_PROFILES) $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=0 --set-bt=1 --set-profiles=$(SET_PROFILES) $(CUSTOM_SETS)

# The set capabilities under a non-neutral set-level hint.
#
# `sets` above runs entirely NEUTRAL, so every hint-gated set emitter had no
# correctness gate at all: the Shufti self-loop channels in the bucket
# suffix bodies, the counted-chain packer split, and the forced-Shufti frontend are all
# invisible to it. --likelymatch / --likelynomatch reach the set path as
# set-level `hints:` (see main.go's setHints resolution), so these runs compile
# genuinely different bodies from the ones `sets` checks.
#
# Deliberately fewer configurations than `sets`: the hint changes the BODY, not
# which capability or which oracle, so the chunk/subset/profile axes are
# already covered above. What is new here is the emission, and one chunk size
# per hint reaches it across the whole corpus.
sets-likely: $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=8  --sample=200 --likelymatch   --set-profiles=$(SET_PROFILES) $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=16 --sample=150 --set-shuffle --likelymatch   --set-profiles=$(SET_PROFILES) $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=8  --sample=200 --likelynomatch --set-profiles=$(SET_PROFILES) $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=16 --sample=150 --set-shuffle --likelynomatch --set-profiles=$(SET_PROFILES) $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=0  --likelymatch   --set-profiles=$(SET_PROFILES) $(CUSTOM_SETS)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=0  --likelynomatch --set-profiles=$(SET_PROFILES) $(CUSTOM_SETS)

sets-exhaustive: $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=8  --set-profiles=all $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=32 --set-shuffle --set-profiles=all $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=70 --set-shuffle --set-profiles=all $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=32 --set-shuffle --set-subset --set-profiles=all $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=8  --sample=10 --set-profiles=$(SET_PROFILES) $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=16 --sample=10 --set-shuffle --set-subset --set-profiles=$(SET_PROFILES) $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=0  --set-profiles=$(SET_PROFILES) $(CUSTOM_SETS)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=4  --set-profiles=$(SET_PROFILES) $(CUSTOM_SETS)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=0  --set-subset --set-profiles=$(SET_PROFILES) $(CUSTOM_SETS)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=8  --set-bt=1 --set-profiles=$(SET_PROFILES) $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=0  --set-bt=1 --set-profiles=$(SET_PROFILES) $(CUSTOM_SETS)
	$(MAKE) set-batch

# The original shape: ONE set per corpus block, `find` and `find_batch` only,
# against the same col4 oracle. This run must keep passing unchanged, and it
# is the only configuration that compiles sets of
# several thousand patterns. --set-batch drives find_batch at a buffer capacity
# of ONE so every multi-match position splits.
set-batch: $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=0 --set-profiles=find $(TESTDATA)
	go run . $(RE2TEST_FLAGS) --sets --set-chunk=0 --set-batch --set-profiles=batch $(TESTDATA)

clean:
	rm -f $(TESTDATA) $(ADJUSTED)
