package fuzz

import (
	"bufio"
	"os"
	"strconv"
)

// seedCase is one (pattern, input) pair extracted from the re2test custom
// corpus, used to seed the byte-level fuzzer.
type seedCase struct {
	pattern string
	input   string
}

// seedCorpus parses tools/re2test/custom-tests.txt and returns every
// (pattern, input) pairing it contains, cross-producting each "regexps"
// block's patterns with the preceding "strings" block's inputs — the same
// pairing tools/re2test/main.go tests against the expected-result columns.
// Those columns aren't needed here: FuzzCorrectness recomputes its own
// expectation via the Go stdlib oracle, so this only needs the pairs.
//
// Any parse hiccup just yields fewer seeds, not a failure — Go's fuzzer
// runs fine (just less directed) with an empty seed corpus.
func seedCorpus(path string) []seedCase {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var (
		cases       []seedCase
		testStrings []string
		inStrings   bool
	)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		switch {
		case line[0] == '#':
			continue
		case 'A' <= line[0] && line[0] <= 'Z':
			continue
		case line == "strings":
			testStrings = testStrings[:0]
			inStrings = true
		case line == "regexps":
			inStrings = false
		case line[0] == '"':
			q, err := strconv.Unquote(line)
			if err != nil {
				continue
			}
			if inStrings {
				testStrings = append(testStrings, q)
				continue
			}
			// A pattern line (regexps block): pair it with every input from
			// the preceding strings block.
			for _, s := range testStrings {
				cases = append(cases, seedCase{pattern: q, input: s})
			}
		default:
			// Result line (e.g. "0-1;0-1;-;-") — not needed for seeding.
		}
	}
	_ = scanner.Err() // a read error just yields fewer seeds, not a failure — see doc comment
	return cases
}
