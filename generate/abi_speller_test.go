package generate

import (
	"strings"
	"testing"
)

// The four per-language ABI SPELLERS, exercised over every parameter the
// descriptor can hand them.
//
// The descriptor in set_stub.go decides WHICH parameters a capability takes
// and in what order; each speller decides only how one is written. That split
// is the whole point of R12 — the generators stopped deciding the ABI — and it
// means a speller is a pure lookup, so the honest test is to hand it every
// value rather than wait for a set shape that happens to produce one.
//
// The gap that hid here: `abiBitmapPtr` is only produced by the WIDE `_all`
// form, so until a >64-id set appeared in some other test, a quarter of every
// speller was unwritten. A missing arm is not a compile error — the switch
// falls through to its panic — so nothing would have said so until a user with
// seventy patterns generated a stub.

func allABIParams() []abiParam {
	return []abiParam{
		abiInputPtr, abiInputLen, abiFrom, abiGatePtr,
		abiBitmapPtr, abiTuplePtr, abiOutCap, abiCursor,
	}
}

func TestABISpellersHandleEveryParam(t *testing.T) {
	spellers := map[string]func(abiParam) string{
		"rust": rustABIParam,
		"go":   goABIParam,
		"c":    cABIParam,
		"as":   asABIParam,
	}
	for lang, spell := range spellers {
		t.Run(lang, func(t *testing.T) {
			seen := map[string]abiParam{}
			for _, p := range allABIParams() {
				got := func() (s string) {
					defer func() {
						if r := recover(); r != nil {
							t.Errorf("%s: param %d panicked: %v", lang, p, r)
						}
					}()
					return spell(p)
				}()
				if strings.TrimSpace(got) == "" {
					t.Errorf("%s: param %d spelled as empty", lang, p)
					continue
				}
				// Two parameters may share a spelling only when they share a
				// slot by design — Go and AssemblyScript write the bitmap and
				// the tuple buffer the same way, because both are just a
				// pointer there. Anything else is two ABI positions that would
				// be indistinguishable in a generated signature.
				if prev, dup := seen[got]; dup {
					sharedSlot := (prev == abiBitmapPtr && p == abiTuplePtr) ||
						(prev == abiTuplePtr && p == abiBitmapPtr)
					if !sharedSlot {
						t.Errorf("%s: params %d and %d both spell as %q", lang, prev, p, got)
					}
				}
				seen[got] = p
			}
		})
	}
}

// TestABISpellersRejectUnknownParam: the switches end in a panic on purpose.
// A new abiParam that a speller has not learned must stop the build loudly
// rather than emit a signature missing an argument, which would fail much
// later as an arity mismatch in someone else's compiler.
func TestABISpellersRejectUnknownParam(t *testing.T) {
	unknown := abiParam(9999)
	for lang, spell := range map[string]func(abiParam) string{
		"rust": rustABIParam,
		"go":   goABIParam,
		"c":    cABIParam,
		"as":   asABIParam,
	} {
		t.Run(lang, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("an unknown abiParam was spelled instead of rejected")
				}
			}()
			spell(unknown)
		})
	}
}

// TestABIRetSpellers covers the return-type half, which is only two values but
// decides whether a capability hands back a bitmask or a count.
func TestABIRetSpellers(t *testing.T) {
	for lang, spell := range map[string]func(abiRet) string{
		"rust": rustABIRet,
		"go":   goABIRet,
		"c":    cABIRet,
		"as":   asABIRet,
	} {
		t.Run(lang, func(t *testing.T) {
			i32, i64 := spell(abiRetI32), spell(abiRetI64)
			if i32 == "" || i64 == "" {
				t.Fatalf("empty return spelling: i32=%q i64=%q", i32, i64)
			}
			if i32 == i64 {
				t.Errorf("i32 and i64 both spell as %q; a 64-bit bitmask would "+
					"be truncated to a count with no diagnostic", i32)
			}
		})
	}
}
