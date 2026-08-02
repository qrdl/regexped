package compile

// Byte-rarity classifier — used by `EmitPrefixScan` to decide whether
// to route a 17..64-byte first-byte set through Shufti SIMD lookup or
// fall back to scalar firstByteFlags (LNM.md Action 3 deferred portion).
//
// Each byte gets a discrete rarity class on a 0–3 scale based on its
// expected frequency in "typical" workload input (prose-leaning corpus
// assumption):
//
//   0  rare       — essentially never in ASCII text (control bytes,
//                   high-bit / Latin-1, NUL, DEL).
//   1  uncommon   — appears occasionally; markup / source-only chars
//                   (`<`, `>`, `[`, `]`, `{`, `}`, `\`, `|`, `~`, `^`,
//                   `` ` ``, `@`, `_`, `$`, `%`).
//   2  mid        — moderate in prose, common in code/config (digits,
//                   common punctuation, UPPERCASE letters — capitals
//                   in prose are sentence-initial only, ~0.5 %/letter).
//   3  common     — heavily present in prose (lowercase letters,
//                   space, tab, comma, period, CR, LF). 5–15 % each.
//
// `firstByteSetRaritySum` sums the per-byte rarity classes across the
// pattern's first-byte set. The sum approximates the expected
// per-chunk candidate-hit rate; the SIMD vs scalar choice keys on it.
//
// Tuning: a higher sum implies more frequent scalar early-exits per
// chunk, so scalar wins. A lower sum implies the scalar must scan most
// bytes per chunk (no early exit), letting Shufti's fixed-cost
// 16-bytes/chunk SIMD pay back. Crossover threshold is set by
// measurement — see LNM.md.

var byteRarity = func() [256]int8 {
	var t [256]int8
	// Default 0 (rare) for unspecified bytes — control / high-bit / NUL.
	t['\t'] = 3
	t['\n'] = 3
	t['\r'] = 3
	t[' '] = 3
	t[','] = 3
	t['.'] = 3
	for c := 'a'; c <= 'z'; c++ {
		t[c] = 3 // lowercase: dominant in prose, ~5-15 % each
	}
	for c := 'A'; c <= 'Z'; c++ {
		t[c] = 2 // uppercase: ~0.5 % each in prose (sentence-initial only)
	}
	for c := '0'; c <= '9'; c++ {
		t[c] = 2
	}
	for _, c := range []byte{'/', '*', '=', '+', '-', '#', '&',
		'(', ')', ':', ';', '?', '!', '\'', '"'} {
		t[c] = 2
	}
	for _, c := range []byte{'<', '>', '[', ']', '{', '}',
		'\\', '|', '~', '^', '`', '@', '_', '$', '%'} {
		t[c] = 1
	}
	return t
}()

// firstByteSetRaritySum returns the sum of byte-rarity classes across
// the first-byte set. Higher = more likely a chunk has at least one
// candidate (scalar wins via early-exit); lower = chunks tend to have
// no candidates (Shufti's fixed 16-byte SIMD wins).
func firstByteSetRaritySum(bytes []byte) int {
	sum := 0
	for _, b := range bytes {
		sum += int(byteRarity[b])
	}
	return sum
}

// shuftiBeatsScalar reports whether Shufti is expected to beat scalar
// firstByteFlags for a first-byte set in the 17..64-byte band.
//
// Rationale: scalar's per-chunk cost depends on average exit position
// (= 1 / per-byte hit probability); Shufti's per-chunk cost is fixed
// (~25-70 SIMD ops depending on half count). Below a sum threshold,
// scalar can't exit early enough to win; above, scalar dominates.
//
// Threshold = 40 chosen by initial measurement (see perftest). Will
// be tuned as more workloads are observed.
//
// Examples (prose-calibrated):
//
//	[A-Z]        (26 chars): sum = 26*2 = 52 → scalar  (mixed)
//	[a-zA-Z]     (52 chars): sum = 26*3+26*2 = 130 → scalar (dense)
//	[\x00-\x1f]  (32 chars): sum = 0 → Shufti        (rare)
//	[<>{}\[\]|`] (8 chars):  sum = 8*1 = 8 → Shufti  (uncommon)
//
// The 9..16-byte band uses Shufti unconditionally (shipped portion
// of LNM Action 3); this helper only governs the 17..64 band.
func shuftiBeatsScalar(firstByteSet []byte) bool {
	const threshold = 40
	return firstByteSetRaritySum(firstByteSet) < threshold
}
