package compile

import (
	"regexp/syntax"
)

// First-byte eligibility mask.
//
// A fallback bucket has no literal to skip with, so the scalar find body
// evaluates it at EVERY position: gate pre-mask, then a suffix-DFA call. The
// call is the expensive half, and on a literal-less set it dominates —
// measured 181 fuel/byte for a set of one fallback pattern, against a ~55
// fuel/position floor when the mask arrives empty.
//
// But a pattern can only match at p if it can CONSUME input[p] as its first
// byte. That is a property of the pattern alone, so it precomputes into a
// 256-entry table of bucket-local pattern bits: startable[b] names every
// pattern of the bucket that can begin a match with byte b. ANDing the
// pre-mask with it clears the patterns that cannot, and when nothing survives
// the suffix call is skipped entirely.
//
// # Why this pays on a set whose patterns are NOT all narrow
//
// greedy-3 (`a+`, `[^\n]*ERROR`, `x?y`) packs into ONE fallback bucket, and
// `[^\n]*ERROR` starts with almost any byte — so the bucket's UNION is
// all-ones and a bucket-granular test could never fire. Per-PATTERN bits are
// what make it work: G9's preflight has already gated `[^\n]*ERROR` out of
// the drive (it matches nowhere), so at a byte that is neither `a` nor `x`/`y`
// the surviving mask is empty even though the table entry is not.
//
// # Soundness
//
// The table must OVER-approximate: a pattern wrongly cleared is a lost match.
// firstByteSet therefore answers "every byte" whenever it cannot prove a
// narrower set — a nullable pattern (which matches without consuming
// anything), `.`-like classes, wide Unicode classes, and anything
// getFirstRuneSet declines to compute. Zero-width assertions are transparent
// to it: `\bfoo` still starts with `f`, because an assertion restricts WHERE
// a byte may be consumed, never WHICH.

// firstByteSet returns the set of bytes that can begin a match of pat as a
// 256-element boolean slice, or nil when every byte must be assumed possible.
//
// Built on getFirstRuneSet, whose contract is already "empty result means
// undetermined" (see its callers in selector.go), so its conservatism is
// inherited rather than restated.
func firstByteSet(pat string) []bool {
	parsed, err := syntax.Parse(pat, syntax.Perl)
	if err != nil {
		return nil
	}
	stripCaptures(parsed)
	prog, err := syntax.Compile(parsed.Simplify())
	if err != nil {
		return nil
	}
	runes := getFirstRuneSet(prog, prog.Start)
	if len(runes) == 0 {
		return nil // undetermined — assume every byte
	}
	out := make([]bool, 256)
	for r := range runes {
		if r < 0 || r > 0x7F {
			// A non-ASCII rune is encoded as several bytes and what leads it
			// is a UTF-8 lead byte, not the rune. Not worth deriving for a
			// byte-oriented engine whose Unicode support is out of scope
			// (CLAUDE.md): give up and let every byte through.
			return nil
		}
		out[r] = true
	}
	return out
}

// buildStartableTable returns bucket bi's 256-entry first-byte table, or nil
// when it cannot clear anything and would therefore be dead weight.
//
// Entry b holds the bucket-local bits of the patterns that can begin at byte
// b. A pattern whose first-byte set is undetermined contributes to EVERY
// entry, which is what makes the table safe on mixed buckets.
func buildStartableTable(bkt *bucket) []uint32 {
	if len(bkt.patterns) == 0 || len(bkt.patterns) > bucketMaskBits {
		return nil
	}
	if bkt.sparse {
		// A G17-sparse bucket reads its answer out of per-state LISTS and
		// ignores every i32 mask on the candidate path (validMask included),
		// so a table indexed into one is dead weight there — and, worse, a
		// reader who wired it up would be applying a bucket-local mask to a
		// body that never consults one. The >32 guard above already excludes
		// today's sparse buckets; this states the rule rather than relying on
		// the count.
		return nil
	}
	tab := make([]uint32, 256)
	narrow := false
	for k, p := range bkt.patterns {
		// No k >= 32 check: the len(bkt.patterns) > 32 guard above already
		// returned, so it was unreachable.
		bit := uint32(1) << uint(k)
		set := firstByteSet(p.fullPattern)
		if set == nil {
			for b := range tab {
				tab[b] |= bit
			}
			continue
		}
		narrow = true
		for b, ok := range set {
			if ok {
				tab[b] |= bit
			}
		}
	}
	if !narrow {
		return nil // every pattern starts anywhere: the AND is a no-op
	}
	return tab
}
