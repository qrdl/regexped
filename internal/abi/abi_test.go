package abi

import (
	"math"
	"testing"
)

// This package is two constants, so these tests pin the INVARIANTS the doc
// comment states rather than the literal values — the values are arbitrary,
// but every property below is load-bearing for a host trying to tell "the
// input does not match" from "the engine gave up".

// TestSentinelsAreDistinguishable covers the reason the package exists. A host
// that cannot separate the two reports BTStackOverflow as "no match", which is
// a false negative that scales with input length and carries no diagnostic.
func TestSentinelsAreDistinguishable(t *testing.T) {
	if NoMatch == BTStackOverflow {
		t.Fatalf("the two sentinels collide at %d; a host cannot tell an unknown answer from a negative one", NoMatch)
	}
	for _, c := range []struct {
		name string
		v    int
	}{{"NoMatch", NoMatch}, {"BTStackOverflow", BTStackOverflow}} {
		if c.v >= 0 {
			t.Errorf("%s = %d: a non-negative sentinel is indistinguishable from a match end position", c.name, c.v)
		}
	}
}

// TestSentinelsSurviveSignExtension covers the i64-returning find exports,
// which emit these as i64.const — so the i32 and i64 spellings must denote the
// same value. A sentinel that changed meaning on widening would be caught by
// nothing else: the stubs read i64, the emitters write the i32 constant.
func TestSentinelsSurviveSignExtension(t *testing.T) {
	if got := int64(int32(NoMatch)); got != int64(NoMatch) {
		t.Errorf("NoMatch sign-extends to %d, want %d", got, NoMatch)
	}
	if got := int64(int32(BTStackOverflow)); got != int64(BTStackOverflow) {
		t.Errorf("BTStackOverflow sign-extends to %d, want %d", got, BTStackOverflow)
	}
}

// TestPackedFindResultNeverCollides covers the doc's central claim: a genuine
// packed (start << 32 | end) always has bit 63 clear, because start is a
// non-negative i32. If that ever stopped holding, a real match at some extreme
// position would be read as an error by every generated stub — a wrong answer
// no corpus run would surface, since the corpus never reaches 2^31 bytes.
func TestPackedFindResultNeverCollides(t *testing.T) {
	starts := []int32{0, 1, 2, math.MaxInt32 - 1, math.MaxInt32}
	ends := []uint32{0, 1, 2, math.MaxInt32, math.MaxUint32 - 1, math.MaxUint32}
	for _, s := range starts {
		for _, e := range ends {
			packed := int64(s)<<32 | int64(e)
			if packed < 0 {
				t.Errorf("packed(start=%d, end=%d) = %d is negative", s, e, packed)
			}
			if packed == int64(NoMatch) || packed == int64(BTStackOverflow) {
				t.Errorf("packed(start=%d, end=%d) = %d collides with a sentinel", s, e, packed)
			}
		}
	}
}
