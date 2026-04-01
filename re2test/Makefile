.PHONY: test exhaustive custom adjusted clean

TESTDATA     := re2-exhaustive.txt
TESTDATA_BZ2 := $(shell go env GOROOT)/src/regexp/testdata/re2-exhaustive.txt.bz2
CUSTOM       := custom-tests.txt
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

test: exhaustive custom adjusted force-backtrack

clean:
	rm -f $(TESTDATA) $(ADJUSTED)
