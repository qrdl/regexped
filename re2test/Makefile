.PHONY: test exhaustive custom adjusted sets likelymatch likelynomatch clean

TESTDATA     := re2-exhaustive.txt
TESTDATA_BZ2 := $(shell go env GOROOT)/src/regexp/testdata/re2-exhaustive.txt.bz2
CUSTOM       := custom-tests.txt
CUSTOM_SETS  := custom-sets.txt
ADJUSTED     := re2-adjusted.txt

$(TESTDATA): $(TESTDATA_BZ2)
	bzip2 -dk -c $< > $@

exhaustive: $(TESTDATA)
	go run . $(TESTDATA)

custom:
	#go run . --validate-go --validate-groups $(CUSTOM)
	go run . --validate-groups $(CUSTOM)

$(ADJUSTED): $(TESTDATA)
	go run ./make_adjusted $(TESTDATA) $(ADJUSTED)

adjusted: $(ADJUSTED)
	go run . --validate-groups $(ADJUSTED)

force-backtrack: $(ADJUSTED)
	go run . --force-backtrack $(TESTDATA)
	go run . --force-backtrack --validate-groups $(ADJUSTED)
	go run . --force-backtrack --validate-groups $(CUSTOM)

# Run every test under LikelyMode=LikelyMatch. Patterns matching the lit-chain
# shape (literal + counted class) take the Opt 2 emission path; others fall
# through to the standard DFA. Confirms LikelyMatch correctness across the
# full corpus.
likelymatch: $(ADJUSTED)
	go run . --likelymatch $(TESTDATA)
	go run . --likelymatch --validate-groups $(ADJUSTED)
	go run . --likelymatch --validate-groups $(CUSTOM)

# Run every test under LikelyMode=LikelyNoMatch. Patterns with a dominant
# self-loop (≥240/256 byte classes back to itself, ≤4 exit bytes,
# mid-accepting) take the Opt 1 SIMD bulk-skip path; others fall through to
# the standard DFA. Confirms LikelyNoMatch correctness across the full corpus.
likelynomatch: $(ADJUSTED)
	go run . --likelynomatch $(TESTDATA)
	go run . --likelynomatch --validate-groups $(ADJUSTED)
	go run . --likelynomatch --validate-groups $(CUSTOM)

test: exhaustive custom adjusted force-backtrack likelymatch likelynomatch sets

sets: $(TESTDATA)
	go run . --sets $(TESTDATA)
	go run . --sets $(CUSTOM_SETS)

clean:
	rm -f $(TESTDATA) $(ADJUSTED)
