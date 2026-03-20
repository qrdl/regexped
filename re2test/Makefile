.PHONY: test clean

TESTDATA := re2-exhaustive.txt
TESTDATA_BZ2 := $(shell go env GOROOT)/src/regexp/testdata/re2-exhaustive.txt.bz2

$(TESTDATA): $(TESTDATA_BZ2)
	bzip2 -dk -c $< > $@

test: $(TESTDATA)
	go run . $(TESTDATA)

clean:
	rm -f $(TESTDATA)
