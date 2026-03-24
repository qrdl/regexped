.PHONY: test exhaustive custom clean

TESTDATA     := re2-exhaustive.txt
TESTDATA_BZ2 := $(shell go env GOROOT)/src/regexp/testdata/re2-exhaustive.txt.bz2
CUSTOM       := custom-tests.txt

$(TESTDATA): $(TESTDATA_BZ2)
	bzip2 -dk -c $< > $@

exhaustive: $(TESTDATA)
	go run . $(TESTDATA)

custom:
	go run . --validate-go --validate-groups $(CUSTOM)
	go run . --validate-groups $(CUSTOM)

test: exhaustive custom

clean:
	rm -f $(TESTDATA)
