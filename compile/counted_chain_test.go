package compile

import (
	"fmt"
	"regexp/syntax"
	"testing"
)

func chainTable(t *testing.T, pat string) *dfaTable {
	t.Helper()
	re, err := syntax.Parse(pat, syntax.Perl)
	if err != nil {
		t.Fatalf("pattern=%q parse: %v", pat, err)
	}
	table, _, err := mergeSuffixDFA([]*syntax.Regexp{re}, CompileSetOptions{})
	if err != nil {
		t.Fatalf("pattern=%q mergeSuffixDFA: %v", pat, err)
	}
	return table
}

func TestIsCountedClassChain_Accepts(t *testing.T) {
	cases := []struct {
		pat     string
		wantN   int
		classSz int
	}{
		{`[A-Z0-9]{16}`, 16, 36},
		{`[A-Za-z0-9]{36}`, 36, 62},
		{`[0-9]{4}`, 4, 10},
		{`[a-f]{24}`, 24, 6},
	}
	for _, c := range cases {
		table := chainTable(t, c.pat)
		class, n, ok := isCountedClassChain(table)
		if !ok {
			t.Errorf("pattern=%q: expected chain detected, got ok=false", c.pat)
			continue
		}
		if n != c.wantN {
			t.Errorf("pattern=%q: n=%d, want %d", c.pat, n, c.wantN)
		}
		if len(class) != c.classSz {
			t.Errorf("pattern=%q: classSz=%d, want %d", c.pat, len(class), c.classSz)
		}
	}
}

func TestIsCountedClassChain_Rejects(t *testing.T) {
	cases := []string{
		`[A-Z0-9]{16,20}`,   // range, not exact — intermediate states also accept
		`[A-Z0-9]{16,}`,     // open-ended
		`[A-Z0-9]+`,         // unbounded self-loop (cycle)
		`[A-Z]{8}[0-9]{8}`,  // class changes partway — not uniform C
		`(?:AB|CD)[A-Z]{16}`, // branching before the chain
		`[A-Z0-9]{16}\b`,    // word boundary
	}
	for _, pat := range cases {
		table := chainTable(t, pat)
		_, _, ok := isCountedClassChain(table)
		if ok {
			t.Errorf("pattern=%q: expected rejection, got ok=true", pat)
		}
	}
}

func TestIsCountedClassChain_RealPatterns(t *testing.T) {
	for _, pat := range []string{`AKIA[A-Z0-9]{16}`, `ghp_[A-Za-z0-9]{36}`} {
		re, err := syntax.Parse(pat, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		// Mirror analyzePattern's literal/suffix split for a rough check:
		// simplest way is to just check the FULL DFA fails (has the literal
		// prefix baked in) but the SUFFIX (class only) succeeds — already
		// covered by TestIsCountedClassChain_Accepts. Here just sanity check
		// the full pattern's own DFA does NOT spuriously look like a chain
		// (it has more states due to the literal prefix).
		prog, err := syntax.Compile(re.Simplify())
		if err != nil {
			t.Fatal(err)
		}
		d := newDFA(prog, false, true)
		full := dfaTableFrom(d)
		_, n, ok := isCountedClassChain(full)
		if ok {
			t.Errorf("pattern=%q: full DFA (with literal prefix) unexpectedly detected as a chain, n=%d", pat, n)
		}
	}
}

func TestCountedChainEmission(t *testing.T) {
	// End-to-end: does genSuffixWASM actually take the fast path (small,
	// table-free body) for the target patterns vs. a plain repeated class
	// with no literal (used as a suffix, single pattern)?
	table := chainTable(t, `[A-Z0-9]{16}`)
	body, dataBytes, dataSegCount, _ := genSuffixWASM(table, 0, 0, []int{5}, []int{0})
	fmt.Printf("counted-chain suffix: bodyLen=%d dataBytesLen=%d dataSegCount=%d\n", len(body), len(dataBytes), dataSegCount)
	if dataSegCount != 0 {
		t.Errorf("expected 0 data segments (pure SIMD, no table), got %d", dataSegCount)
	}
}
