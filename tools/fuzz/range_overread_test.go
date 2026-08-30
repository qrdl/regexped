package fuzz

import (
	"strings"
	"testing"

	"github.com/qrdl/regexped/compile"
	"github.com/qrdl/regexped/config"
)

// Range-overread regression.
//
// emitRangeClassVerify runs the class verify over `countMax` bytes via
// planRangeChunks, which covers [K, K+countMax) rounded up to a 16-byte
// multiple. Every caller only bounds-checks `base + K + countMin <= len`, so
// the trailing chunks read up to `countMax - countMin + 15` bytes past
// `ptr+len`. The values read there never reach the result (match_len is capped
// at `len - base - K` before use), which is exactly why this stayed invisible:
// the only observable symptom is the load itself walking off the end of linear
// memory and trapping.
//
// The test places the input flush against the end of the module's memory, so
// any over-read is a trap rather than a silent read of neighbouring bytes.
// This is not a contrived pointer: the exported match/find functions take an
// arbitrary (ptr, len), and in embedded mode they read the *host's* memory,
// where an input near the last page is ordinary.
//
// Note that the standalone module used here has its DFA tables at page 1, so
// the end of memory is well past them — nothing else is disturbed by writing
// there.
func TestRangeVerifyNoOverreadAtMemoryEnd(t *testing.T) {
	// Each case is a lit-chain range whose countMax − countMin window is wide
	// enough that the chunk plan reaches past the bounds-checked prefix.
	cases := []struct {
		pattern string
		input   string
	}{
		{`A[0-9]{24,60}`, "A" + strings.Repeat("7", 24)},
		{`A[0-9]{24,60}`, "A" + strings.Repeat("7", 40)},
		{`AKIA[A-Z0-9]{16,120}`, "AKIA" + strings.Repeat("Q", 16)},
		{`ghp_[A-Za-z0-9]{36,37}`, "ghp_" + strings.Repeat("z", 36)},
		// Non-greedy: anchored match still runs the full range verify.
		{`A[0-9]{24,60}?`, "A" + strings.Repeat("7", 24)},
		// Wide window: chunks whose clamp distance exceeds 32, where WASM's
		// mod-32 shift count leaves the mask garbage. Harmless (see the
		// emitRangeClassVerify comment) but only if it never traps.
		{`A[0-9]{24,900}`, "A" + strings.Repeat("7", 24)},
	}

	for _, c := range cases {
		entry := config.RegexEntry{Pattern: c.pattern, MatchFunc: "match", FindFunc: "find"}
		wasmBytes, _, err := compile.Compile([]config.RegexEntry{entry}, tableBase, true)
		if err != nil {
			t.Fatalf("pattern=%q compile: %v", c.pattern, err)
		}
		for _, export := range []string{"match", "find"} {
			store, inst, mem, release, err := instantiate(wasmBytes)
			defer release()
			if err != nil {
				t.Fatalf("pattern=%q instantiate: %v", c.pattern, err)
			}
			fn := inst.GetFunc(store, export)
			if fn == nil {
				t.Fatalf("pattern=%q: no %q export", c.pattern, export)
			}
			data := mem.UnsafeData(store)
			ptr := len(data) - len(c.input)
			copy(data[ptr:], c.input)
			args := []any{int32(ptr), int32(len(c.input))}
			if export == "find" {
				args = append(args, int32(0)) // find takes `from`
			}
			if _, err := fn.Call(store, args...); err != nil {
				t.Errorf("pattern=%q %s at ptr=%d (memory size %d): %v",
					c.pattern, export, ptr, len(data), err)
			}
		}
	}
}
