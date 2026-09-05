package compile

// Byte-rarity classifier — used by `EmitPrefixScan` to decide whether
// to route a 17..64-byte first-byte set through Shufti SIMD lookup or
// fall back to scalar firstByteFlags.
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
// measurement.

// SIBLING TABLE: byte_rank.go's byteRank is the other hand-maintained
// background byte-frequency model in this package. They answer different
// questions — this one grades a byte 0..3 for the Shufti density gate, that
// one ranks bytes 0..255 to pick the packed-pair probe COLUMNS — and they are
// tuned independently, so they are not duplicates to merge. Merging them (or
// deriving one from the other) is a performance experiment and needs fuel
// measurement, not a refactor.
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
	// Uppercase and digits were graded 2 — two thirds of lowercase's 3 —
	// while this file's own comment puts them at ~0.5% of prose against
	// lowercase's 5-15%. An additive model with those weights cannot tell
	// "26 bytes that are individually rare" from "17 bytes that are
	// individually dominant": `[A-Z]` summed to 52 and `[a-q]` to 51, and
	// measured on prose, forcing Shufti on the first is worth -79% while on
	// the second it costs +5.9%. Grading both at 1 separates them — `[A-Z]`
	// to 26, `[A-Z0-9]` to 36, `[a-fA-F0-9]` to 34, all under the threshold
	// and all measured wins, while every dense-lowercase set stays above it
	// and stays scalar.
	for c := 'A'; c <= 'Z'; c++ {
		t[c] = 1 // uppercase: ~0.5 % each in prose (sentence-initial only)
	}
	for c := '0'; c <= '9'; c++ {
		t[c] = 1
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
// Threshold = 40 chosen by initial measurement (see perftest). It was
// re-interrogated when the Shufti emission got cheaper (one nibble-table pair
// for every class in practice, not ceil(N/8)): the crossover on prose sits
// between sums of 72 and 78, far above 40, which looked like an argument for
// raising the threshold. It was not — the same measurement found sums 51 and
// 52 landing on OPPOSITE sides, so no threshold can separate the two. The
// per-byte weights were what mis-ranked them; see byteRarity above. With
// those corrected, 40 classifies every measured set correctly or
// conservatively and needs no change.
//
// Examples (prose-calibrated), sums as graded today:
//
//	[A-Z]        (26 chars): sum = 26*1 = 26 → Shufti  (rare in prose)
//	[a-q]        (17 chars): sum = 17*3 = 51 → scalar  (dominant letters)
//	[a-zA-Z]     (52 chars): sum = 26*3+26*1 = 104 → scalar (dense)
//	[\x00-\x1f]  (32 chars): sum = 0 → Shufti        (rare)
//	[<>{}\[\]|`] (8 chars):  sum = 8*1 = 8 → Shufti  (uncommon)
//
// The 9..16-byte band uses Shufti unconditionally (shipped portion
// of LNM Action 3); this helper only governs the 17..64 band.
func shuftiBeatsScalar(firstByteSet []byte) bool {
	const threshold = 40
	return firstByteSetRaritySum(firstByteSet) < threshold
}
