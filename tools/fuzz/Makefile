.PHONY: seed fuzz fuzz-long clean

# Run just the seed corpus (tools/re2test/custom-tests.txt pairs plus any
# checked-in failing/interesting cases under testdata/fuzz/) as a regular
# test — fast, deterministic, safe for routine use.
seed:
	go test -run=FuzzCorrectness -v .

# Short interactive fuzz run.
fuzz:
	go test -fuzz=FuzzCorrectness -fuzztime=1m .

# Overnight run (see plans/FUZZER.md "Practical concerns").
fuzz-long:
	go test -fuzz=FuzzCorrectness -fuzztime=8h .

clean:
	rm -rf testdata/fuzz
