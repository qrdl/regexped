package compile

import (
	"fmt"
	"regexp/syntax"
	"testing"

	"github.com/qrdl/regexped/config"
)

// A CROSS-PRODUCT of pattern fragments, compiled for every capability.
//
// The hand-picked matrices next door name the path each case selects, which
// makes them readable and makes a stale case obvious. It also makes them blind
// to arms nobody thought to aim at — and several such arms turn on properties
// that are not visible in the pattern text at all. The clearest example: the
// find body picks its post-prefix resume state by comparing the states reached
// from midStart and from midStartWord, so `\bERROR[a-z]*` selects a different
// arm from `\bERROR:[a-z]*`, purely because a colon is not a word character.
// Three hand-written attempts missed that; enumerating found it immediately.
//
// So this compiles the product of {leading assertion} x {literal} x {tail} x
// {trailing assertion}, which is a few thousand patterns in a couple of
// seconds, and asserts the compiler either produces a well-formed module or
// declines cleanly. It is a SMOKE test over breadth — the corpus runners in
// tools/ check the answers — and its value is that it reaches shapes nobody
// selected on purpose.

func crossProductPatterns() []string {
	leading := []string{"", `\b`, `\B`, `(?m:^)`, `(?m:^)\b`, `\b(?m:^)`, `\A`}
	literals := []string{"ERROR", "AB", "Q", "abc_", "KEY:", "x"}
	tails := []string{"", "[a-z]*", "[0-9]+", ".*", "[a-z]{3}", `[^\n]*`, "[a-z]{2,6}", "x?"}
	trailing := []string{"", `\b`, `\B`, `(?m:$)`, `\z`}

	var out []string
	for _, lead := range leading {
		for _, lit := range literals {
			for _, tail := range tails {
				for _, trail := range trailing {
					out = append(out, lead+lit+tail+trail)
				}
			}
		}
	}
	return out
}

// TestPatternCrossProductCompiles compiles each pattern for match and for
// find.
//
// A pattern the compiler DECLINES is fine — a documented ceiling, or a shape
// no engine serves — and is skipped rather than failed, because this list is
// generated rather than curated and its job is reach, not a claim that every
// product of these fragments is supported. What is NOT fine is a module that
// comes back malformed.
func TestPatternCrossProductCompiles(t *testing.T) {
	pats := crossProductPatterns()
	if len(pats) < 1000 {
		t.Fatalf("cross-product collapsed to %d patterns; the fragment lists have drifted", len(pats))
	}
	compiled := 0
	for _, pat := range pats {
		if _, err := syntax.Parse(pat, syntax.Perl); err != nil {
			continue
		}
		for _, kind := range []string{"match", "find"} {
			e := config.RegexEntry{Name: "p", Pattern: pat}
			if kind == "match" {
				e.MatchFunc = "p_match"
			} else {
				e.FindFunc = "p_find"
			}
			wasm, _, err := Compile([]config.RegexEntry{e}, 65536, true)
			if err != nil {
				continue // a declined shape, not a failure
			}
			compiled++
			if len(wasm) < 8 || string(wasm[:4]) != "\x00asm" {
				t.Fatalf("%s/%s: malformed module (%d bytes)", pat, kind, len(wasm))
			}
		}
	}
	// Guard against the whole sweep silently becoming a no-op — if the
	// compiler started declining everything, every case above would `continue`
	// and the test would pass having checked nothing.
	if compiled < len(pats) {
		t.Fatalf("only %d of %d patterns compiled; the sweep is mostly skipping", compiled, len(pats))
	}
}

// captureCrossProduct is the same idea for the CAPTURE engines, where the
// interesting axis is which engine the selector picks: TDFA when the pattern
// is unambiguous and small enough, Backtracking otherwise. Both are reached by
// varying the properties the gates test — non-greedy quantifiers, word
// boundaries, line anchors, inverted classes, nesting.
func captureCrossProduct() []string {
	bodies := []string{
		`(a+)(b+)`, `(a+?)(b+)`, `(\w+)`, `([^,]+),`, `(a|b)*c`, `((a)(b))`,
		`(?P<x>[0-9]{2})-(?P<y>[0-9]{2})`, `(a)(b)(c)(d)(e)`, `(.*?)END`,
		`\b(\w+)\b`, `(?m:^)(\w+)(?m:$)`, `(a{2,4})b`, `((?:ab)+)c`,
	}
	wrappers := []string{"%s", `x%s`, `%sy`, `(?:%s)+`, `(?:%s)?`}
	var out []string
	for _, b := range bodies {
		for _, w := range wrappers {
			out = append(out, fmt.Sprintf(w, b))
		}
	}
	return out
}

// TestCaptureCrossProductCompiles drives the capture path — TDFA and
// Backtracking — over the same kind of enumeration, and additionally under a
// squeezed TDFA budget, which is the documented way to force a pattern onto
// Backtracking that would otherwise be TDFA-eligible.
func TestCaptureCrossProductCompiles(t *testing.T) {
	budgets := []struct {
		name       string
		states     int
		regs       int
		wantForced bool
	}{
		{"default budget", 0, 0, false},
		// Small enough that no TDFA construction fits: everything with
		// captures lands on Backtracking.
		{"squeezed budget", 4, 1, true},
	}
	for _, b := range budgets {
		t.Run(b.name, func(t *testing.T) {
			compiled := 0
			for _, pat := range captureCrossProduct() {
				parsed, err := syntax.Parse(pat, syntax.Perl)
				if err != nil || parsed.MaxCap() == 0 {
					continue
				}
				wasm, _, err := CompileFile(config.BuildConfig{
					Regexps: []config.RegexEntry{
						{Name: "p", Pattern: pat, GroupsFunc: "p_groups"},
					},
					MaxDFAStates: b.states,
					MaxTDFARegs:  b.regs,
				}, "")
				if err != nil {
					continue // a documented ceiling
				}
				compiled++
				if len(wasm) < 8 || string(wasm[:4]) != "\x00asm" {
					t.Fatalf("%s: malformed module", pat)
				}
			}
			if compiled == 0 {
				t.Fatal("nothing compiled: the sweep checked nothing")
			}
		})
	}
}
