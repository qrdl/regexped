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

// The CHECKPOINTED region's arithmetic, which every stub in six languages
// reproduces and the sweep then validates.
//
// The stride is the whole knob. Below the budget it is the WHOLE SPAN, which is
// one block: one sweep, nothing re-swept, and the behaviour the whole-drive
// cache had. Above it the stride drops to the square-root optimum and the
// region becomes sqrt-sized, at the cost of sweeping each position twice. The
// crossover is therefore a memory policy and not a performance one, and this
// pins where it is.
func TestSetOverlapCheckpointStride(t *testing.T) {
	const cells, pats = 6, 3
	row := SetOverlapBlockRowBytes(pats)

	// SINGLE BLOCK below the budget: the stride IS the span.
	if got, want := SetOverlapCheckpointStride(1000, cells, pats), 1001; got != want {
		t.Errorf("a 1000-byte input strides %d, want %d (m, i.e. one block)", got, want)
	}
	// Find the crossover by construction rather than by a constant: it is
	// where the single-block region passes the budget.
	cross := 0
	for m := 1; ; m++ {
		if SetOverlapCheckpointHeaderBytes+(cells*4+4)+4+m*row > SetOverlapCacheMaxBytes {
			cross = m - 1 // the last m that still fits
			break
		}
	}
	if got := SetOverlapCheckpointStride(cross-1, cells, pats); got != cross {
		t.Errorf("just below the crossover the stride is %d, want %d (still one block)", got, cross)
	}
	if got := SetOverlapCheckpointStride(cross, cells, pats); got >= cross+1 {
		t.Errorf("just above the crossover the stride is still the whole span (%d): "+
			"the region would be over budget", got)
	}
	// The 16 floor: a tiny stride is all cost and no saving, since every block
	// re-sweeps from a checkpoint.
	if got := SetOverlapCheckpointStride(1<<30, 1, 64); got < 16 {
		t.Errorf("stride %d is below the floor of 16", got)
	}
	// And it never exceeds the span, whatever the square root says.
	for _, n := range []int{0, 1, 2, 5} {
		if got := SetOverlapCheckpointStride(n, cells, pats); got > n+1 {
			t.Errorf("input %d strides %d, which is wider than the span of %d", n, got, n+1)
		}
	}
}

// The region and the stride are computed by two functions that must describe
// the SAME layout: the caller sizes the allocation from one and writes the
// other into the header, and the sweep refuses a header that does not fit the
// region it was given.
func TestSetOverlapCheckpointBytesAgreesWithStride(t *testing.T) {
	for _, tc := range []struct{ n, cells, pats int }{
		{0, 6, 3}, {1, 6, 3}, {100, 6, 3}, {4096, 353, 32}, {1 << 20, 353, 32},
	} {
		k := SetOverlapCheckpointStride(tc.n, tc.cells, tc.pats)
		got := SetOverlapCheckpointBytes(tc.n, tc.cells, tc.pats)
		want := SetOverlapCheckpointBytesForStride(tc.n, tc.cells, tc.pats, k)
		if got != want {
			t.Errorf("len=%d: Bytes says %d, BytesForStride at the chosen k=%d says %d",
				tc.n, got, k, want)
		}
		// The layout the sweep computes: header, one column per block, the
		// cumulative counts, and one block buffer.
		m := tc.n + 1
		nb := (m + k - 1) / k
		exact := SetOverlapCheckpointHeaderBytes + nb*tc.cells*4 + (nb+1)*4 +
			k*SetOverlapBlockRowBytes(tc.pats)
		if got != exact {
			t.Errorf("len=%d: %d bytes reserved, %d needed by the layout", tc.n, got, exact)
		}
	}
}

// A stride the caller chose is clamped into range before it sizes anything,
// because a caller may pass one the sweep would refuse.
func TestSetOverlapCheckpointBytesForStrideClamps(t *testing.T) {
	const cells, pats = 6, 3
	base := SetOverlapCheckpointBytesForStride(100, cells, pats, 1)
	if got := SetOverlapCheckpointBytesForStride(100, cells, pats, 0); got != base {
		t.Errorf("k=0 sized %d, want the k=1 size %d", got, base)
	}
	if got := SetOverlapCheckpointBytesForStride(100, cells, pats, -7); got != base {
		t.Errorf("k=-7 sized %d, want the k=1 size %d", got, base)
	}
	whole := SetOverlapCheckpointBytesForStride(100, cells, pats, 101)
	if got := SetOverlapCheckpointBytesForStride(100, cells, pats, 1<<20); got != whole {
		t.Errorf("a stride wider than the span sized %d, want the one-block size %d", got, whole)
	}
}

// The single-block size OVERFLOWS on a large enough input, and overflowing is
// itself a reason to checkpoint rather than a reason to fail.
func TestSingleBlockBytesOverflowDeclinesTheWholeSpan(t *testing.T) {
	if got := singleBlockBytes(1<<62, 6, 3); got != 0 {
		t.Errorf("an m that overflows returned %d, want 0 (the signal to checkpoint)", got)
	}
	// And the stride function survives it: it must pick the sqrt arm rather
	// than compare against a wrapped number.
	if got := SetOverlapCheckpointStride(1<<40, 353, 32); got <= 0 || got > 1<<40 {
		t.Errorf("stride %d for a huge input is not in range", got)
	}
}
