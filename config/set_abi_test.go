package config

import "testing"

// The ABI helpers in this package are the SHARED DEFINITION of numbers the
// compiler and all six stub generators must agree on: how many tuples a `find`
// position can produce, how wide a pattern id can be, how the batch cursor
// splits its 32 low bits, and how much scratch an overlapping drive wants.
//
// Every one of them was at 0% here. They are exercised constantly — by
// `compile`, by `generate`, by every corpus runner — but never from this
// package, so nothing pinned the CONTRACT itself. A helper is exactly the kind
// of code where that matters: the whole reason these live in `config` rather
// than being recomputed on each side is that two spellings would drift, and a
// test in one of the consumers would only pin that consumer's reading.

func setWithNames(names ...string) SetConfig {
	return SetConfig{Name: "s", Patterns: PatternSelector{Names: names}}
}

func cfgWithPatterns(names ...string) BuildConfig {
	entries := make([]RegexEntry, len(names))
	for i, n := range names {
		entries[i] = RegexEntry{Name: n, Pattern: "x"}
	}
	return BuildConfig{Regexps: entries}
}

// TestPatternCountAndIDSpaceSizeDiffer is the id-space hazard stated as a test.
//
// PATTERN_COUNT sizes the tuple buffer — the worst case at ONE position.
// ID_SPACE sizes anything indexed BY a pattern id: the gate array, the `_all`
// bitmap, and the narrow-vs-wide `_all` ABI choice. For `patterns: all` they
// are equal, which is why sizing one from the other survived so long; for a
// NAMED SUBSET they are not, and using the wrong one wrote past the end of a
// caller's array.
func TestPatternCountAndIDSpaceSizeDiffer(t *testing.T) {
	cfg := cfgWithPatterns("a", "b", "c", "d", "e", "f", "g")

	all := SetConfig{Name: "s", Patterns: PatternSelector{All: true}}
	if got := all.PatternCount(cfg); got != 7 {
		t.Errorf("all PatternCount = %d, want 7", got)
	}
	if got := all.IDSpaceSize(cfg); got != 7 {
		t.Errorf("all IDSpaceSize = %d, want 7", got)
	}

	// Two patterns, but the last one is global id 6 — so ids up to 6 are
	// reportable and anything indexed by id needs SEVEN slots, not two.
	sub := setWithNames("a", "g")
	if got := sub.PatternCount(cfg); got != 2 {
		t.Errorf("subset PatternCount = %d, want 2", got)
	}
	if got := sub.IDSpaceSize(cfg); got != 7 {
		t.Errorf("subset IDSpaceSize = %d, want 7 (id 6 is reportable)", got)
	}
}

// TestIDSpaceSizeEdgeCases covers the shapes the lookup has to survive: a name
// that is not in the config at all, duplicate names (first wins), and an empty
// selection.
func TestIDSpaceSizeEdgeCases(t *testing.T) {
	cfg := cfgWithPatterns("a", "b", "a", "c")
	cases := []struct {
		name  string
		names []string
		want  int
	}{
		{"duplicate name resolves to the FIRST occurrence", []string{"a"}, 1},
		{"later distinct name", []string{"c"}, 4},
		{"unknown name contributes no id", []string{"nope"}, 0},
		{"known and unknown mixed", []string{"nope", "b"}, 2},
		{"empty selection", nil, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := setWithNames(c.names...).IDSpaceSize(cfg); got != c.want {
				t.Errorf("IDSpaceSize(%v) = %d, want %d", c.names, got, c.want)
			}
		})
	}
}

// TestSetCursorFieldWidths pins the batch cursor layout.
//
// The returned i64 splits its LOW 32 bits between `k` (the intra-position
// resume index) and `count` (tuples delivered). k must hold [0, patternCount],
// INCLUSIVE — a position where every pattern matches resumes at k ==
// patternCount — and count gets whatever is left. Widths are ABI facts no
// generator exports, so this is the only place they are stated as a test.
func TestSetCursorFieldWidths(t *testing.T) {
	// From ONE, not zero. A set with no patterns is rejected by ValidateSets
	// ("patterns is required"), and the width rule does not define itself
	// there: kBits would be 0, countBits 32, and `uint32(1)<<32` is 0 in Go,
	// so MaxCount comes out as -1. Unreachable, so pinning it would be
	// pinning an accident rather than the contract.
	for _, patterns := range []int{1, 2, 3, 4, 7, 8, 9, 31, 32, 33, 63, 64, 65, 1000} {
		kBits := SetCursorKBits(patterns)
		countBits := SetCursorCountBits(patterns)

		if kBits+countBits != 32 {
			t.Errorf("patterns=%d: kBits %d + countBits %d != 32", patterns, kBits, countBits)
		}
		if kBits < 0 || countBits < 1 {
			t.Errorf("patterns=%d: nonsensical widths k=%d count=%d", patterns, kBits, countBits)
		}
		// k must be representable at its maximum, which is patternCount
		// itself, not patternCount-1.
		if kBits < 32 && patterns >= 1<<uint(kBits) {
			t.Errorf("patterns=%d: kBits=%d cannot hold k up to %d", patterns, kBits, patterns)
		}
		maxCount := SetCursorMaxCount(patterns)
		if want := int32(uint32(1)<<uint(countBits)) - 1; maxCount != want {
			t.Errorf("patterns=%d: MaxCount = %d, want %d", patterns, maxCount, want)
		}
		if maxCount < 1 {
			t.Errorf("patterns=%d: MaxCount %d leaves no room to deliver anything", patterns, maxCount)
		}
	}
}

// TestSetCursorMaxCountIsMonotonic: more patterns can only take bits AWAY from
// the count field, never add them. A non-monotonic step would mean some
// pattern count got a wider count field than a smaller one, which no layout
// rule should produce.
func TestSetCursorMaxCountIsMonotonic(t *testing.T) {
	prev := SetCursorMaxCount(1)
	for patterns := 2; patterns <= 300; patterns++ {
		got := SetCursorMaxCount(patterns)
		if got > prev {
			t.Fatalf("patterns=%d: MaxCount rose from %d to %d", patterns, prev, got)
		}
		prev = got
	}
}

// TestSetOverlapCacheBytes pins the sizing rule the compiler and the JS/TS
// stubs both compute: a 16-byte header plus twelve bytes per tuple, worst case
// one tuple per pattern per START POSITION — of which there are len+1, not len,
// because a match can begin at end of input.
func TestSetOverlapCacheBytes(t *testing.T) {
	if got, want := SetOverlapCacheBytes(0, 1), SetOverlapCacheHeaderBytes+12; got != want {
		t.Errorf("empty input, 1 pattern: %d, want %d (position 0 is still a start)", got, want)
	}
	if got, want := SetOverlapCacheBytes(100, 3), SetOverlapCacheHeaderBytes+101*3*12; got != want {
		t.Errorf("100 bytes, 3 patterns: %d, want %d", got, want)
	}
	// Strictly increasing in both arguments — a cache that did not grow with
	// the input would be handed to a sweep that overruns it.
	if SetOverlapCacheBytes(10, 1) <= SetOverlapCacheBytes(9, 1) {
		t.Error("not increasing in input length")
	}
	if SetOverlapCacheBytes(10, 2) <= SetOverlapCacheBytes(10, 1) {
		t.Error("not increasing in pattern count")
	}
	if SetOverlapCacheHeaderBytes%4 != 0 {
		t.Errorf("header %d is not 4-byte aligned; its slots are i32",
			SetOverlapCacheHeaderBytes)
	}
}

// TestBatchFindHint: batching is requested through `hints:`, not declared as a
// capability, and only alongside `find`.
func TestBatchFindHint(t *testing.T) {
	cases := []struct {
		name string
		set  SetConfig
		want bool
	}{
		{"no hints", SetConfig{Find: "f"}, false},
		{"batch-find", SetConfig{Find: "f", Hints: []string{"batch-find"}}, true},
		{"batch-find among others", SetConfig{Find: "f", Hints: []string{"prefer-match", "batch-find"}}, true},
		{"an unrelated hint", SetConfig{Find: "f", Hints: []string{"prefer-match"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.set.BatchFind(); got != c.want {
				t.Errorf("BatchFind() = %v, want %v", got, c.want)
			}
		})
	}
}

// TestSanitizeSetName: set names reach generated identifiers, so anything that
// is not identifier-safe has to be mapped to something that is, without
// colliding with a leading digit.
func TestSanitizeSetName(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"secrets", "secrets"},
		{"my-set", "my_set"},
		{"my.set", "my_set"},
		{"my set", "my_set"},
		// An empty name still has to yield a legal identifier, since it is
		// interpolated into one in six languages.
		{"", "SET"},
	} {
		if got := SanitizeSetName(c.in); got != c.want {
			t.Errorf("SanitizeSetName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// Whatever the rule for a leading digit is, the result must not START with
	// one: it is interpolated into an identifier position in six languages.
	if got := SanitizeSetName("9lives"); got != "" && got[0] >= '0' && got[0] <= '9' {
		t.Errorf("SanitizeSetName(%q) = %q, which is not a legal identifier start", "9lives", got)
	}
}
