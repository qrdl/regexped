package compile

// Background byte-frequency ranks, used only to pick which byte columns a
// packed-pair prefilter should probe.
//
// PROVENANCE AND WEIGHT. This is a heuristic, not a contract. The ranks
// approximate how often a byte occurs in typical scanned input (text, logs,
// source, protocol traffic): rank 0 is the rarest, 255 the most common. It
// exists because a prefilter's whole value is its false-positive rate, and a
// pair of columns pinned to rare bytes produces far fewer candidate positions
// than a pair pinned to `e` and `t`. It is the same idea as the memchr crate's
// rank table and serves the same purpose.
//
// **Nothing about correctness depends on these numbers.** A pathological
// ranking would choose bad probe columns and make the prefilter slower; it
// could never make it wrong, because every candidate the prefilter produces is
// verified byte-for-byte against the full literal before any bucket runs. That
// is why the table is checked in as a plain heuristic with no derivation
// script: retuning it is a performance experiment, not a correctness change.
//
// The shape encoded here: ASCII letters and digits are common, with `etaoin
// shrdlu` most common of all; whitespace and the frequent punctuation of
// structured text are common; control bytes and high bytes are rare.
var byteRank = func() [256]uint8 {
	var r [256]uint8
	// Default: high bytes and control bytes are rare. Spread them over the
	// low ranks so ties are broken deterministically by byte value.
	for i := 0; i < 256; i++ {
		r[i] = 32
	}
	// Control bytes (except the whitespace ones below) are the rarest things
	// in text-like input.
	for i := 0; i < 32; i++ {
		r[i] = 4
	}
	// High/non-ASCII: rare in ASCII-dominated corpora but not as rare as
	// control bytes, since UTF-8 continuation bytes cluster.
	for i := 128; i < 256; i++ {
		r[i] = 24
	}
	// Uncommon ASCII punctuation.
	for _, c := range []byte("`~^\\|{}@$%&*+<>#") {
		r[c] = 48
	}
	// Common structural punctuation in logs, source and protocol text.
	for _, c := range []byte("()[]!?;:'\"-_/=,.") {
		r[c] = 120
	}
	// Digits.
	for c := byte('0'); c <= '9'; c++ {
		r[c] = 140
	}
	// Uppercase letters: less common than lowercase in running text.
	for c := byte('A'); c <= 'Z'; c++ {
		r[c] = 150
	}
	// Lowercase letters.
	for c := byte('a'); c <= 'z'; c++ {
		r[c] = 200
	}
	// The most common letters and the space, which dominate English-like text.
	for _, c := range []byte("etaoinshrdlu") {
		r[c] = 240
	}
	r[' '] = 255
	// The rarest ASCII letters — these make excellent probe bytes.
	for _, c := range []byte("qxzjkvw") {
		r[c] = 90
	}
	for _, c := range []byte("QXZJKVW") {
		r[c] = 70
	}
	return r
}()

// packedPairPlan describes a two-column byte-equality prefilter: a position p
// is a candidate iff input[p+Off1] is in Bytes1 AND input[p+Off2] is in Bytes2.
//
// Both columns lie inside the probe window (offsets 0..min(4,minLen)-1), so a
// candidate position is always fully covered by every literal in the set. The
// prefilter pins only these two bytes, so each candidate is verified against
// every literal from offset 0 before any bucket runs.
type packedPairPlan struct {
	Off1, Off2 int    // column offsets, Off1 < Off2
	Bytes1     []byte // distinct bytes appearing at Off1, ascending
	Bytes2     []byte // distinct bytes appearing at Off2, ascending
	MinLen     int    // shortest literal in the set — bounds the SIMD guard
}

// splatCount is how many i8x16.splat vectors the emitted body hoists.
func (p *packedPairPlan) splatCount() int { return len(p.Bytes1) + len(p.Bytes2) }

// packedPairByteBudget caps |Bytes1| + |Bytes2|.
//
// Each byte in a column costs one i8x16.eq plus (beyond the first) one v128.or
// per 16-byte chunk, so the per-chunk cost grows linearly with the budget while
// Teddy's nibble tables stay flat. The crossover measured
// Task G1 put packed-pair ahead through 4 and behind Teddy beyond it, which is
// also the point at which two columns stop being selective enough to be worth
// the verification they imply.
const packedPairByteBudget = 4

// packedPairChunks is how many 16-byte blocks the emitted scan loop handles
// per iteration.
//
// Probe work scales linearly with this — two v128 loads and one i8x16.eq per
// probe byte per block — but the per-iteration scaffolding does not: one
// bounds guard, one drain check, one position bump and one loop branch cover
// the whole span. Two blocks is the measured optimum and also the natural
// ceiling for this shape, because two 16-bit bitmasks fill a 32-bit lane mask
// exactly; a third block would need a second mask register and a second
// decode loop, giving back what the widening buys. See §16.4 for the numbers.
const packedPairChunks = 2

// packedPairMaxLiterals caps how many literals a packed pair will serve.
//
// Every candidate position verifies EVERY literal from offset 0 (the pair pins
// only two bytes and cannot say which literal produced the candidate), so the
// verification cost is linear in the literal count. Teddy's lanes localise that
// work and win once there are enough literals to matter.
const packedPairMaxLiterals = 16

// choosePackedPair picks the best two-column prefilter for a set of literals,
// or reports false when none qualifies.
//
// Selection rule: among all column pairs inside the probe window whose combined
// distinct-byte count fits packedPairByteBudget, take the one whose bytes have
// the lowest summed background frequency (byteRank) — the rarest pair produces
// the fewest candidates. Ties break toward the earlier columns, which keeps the
// choice deterministic and keeps the two loads close together.
func choosePackedPair(literals [][]byte) (*packedPairPlan, bool) {
	if len(literals) == 0 || len(literals) > packedPairMaxLiterals {
		return nil, false
	}
	minLen := 1 << 30
	for _, lit := range literals {
		if len(lit) == 0 {
			return nil, false
		}
		if len(lit) < minLen {
			minLen = len(lit)
		}
	}
	// Two distinct columns are required, so a one-byte literal cannot be
	// served: its probe window has a single column.
	window := minLen
	if window > 4 {
		window = 4
	}
	if window < 2 {
		return nil, false
	}

	// Distinct bytes per column, ascending, plus the summed rank of each.
	cols := make([][]byte, window)
	rank := make([]int, window)
	for o := 0; o < window; o++ {
		var seen [256]bool
		for _, lit := range literals {
			seen[lit[o]] = true
		}
		for i := 0; i < 256; i++ {
			if seen[i] {
				cols[o] = append(cols[o], byte(i))
				rank[o] += int(byteRank[i])
			}
		}
	}

	best := (*packedPairPlan)(nil)
	bestRank := 1 << 30
	for o1 := 0; o1 < window; o1++ {
		for o2 := o1 + 1; o2 < window; o2++ {
			if len(cols[o1])+len(cols[o2]) > packedPairByteBudget {
				continue
			}
			// Summing the ranks of every byte in both columns scores a wide
			// column of rare bytes against a narrow column of common ones on
			// the same scale: both make the prefilter less selective.
			r := rank[o1] + rank[o2]
			if r < bestRank {
				bestRank = r
				best = &packedPairPlan{
					Off1: o1, Off2: o2,
					Bytes1: cols[o1], Bytes2: cols[o2],
					MinLen: minLen,
				}
			}
		}
	}
	if best == nil {
		return nil, false
	}
	return best, true
}
