package compile

import (
	"fmt"
	"reflect"
	"regexp/syntax"
	"testing"

	"github.com/qrdl/regexped/config"
)

func newTDFAForPattern(t *testing.T, pattern string) *tdfaTable {
	t.Helper()
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		t.Fatalf("parse %q: %v", pattern, err)
	}
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		t.Fatalf("compile %q: %v", pattern, err)
	}
	tt, ok := newTDFA(prog, 2000)
	if !ok {
		t.Fatalf("newTDFA rejected pattern %q", pattern)
	}
	return tt
}

func TestDetectTDFABulkSkipAccept(t *testing.T) {
	cases := []struct {
		name       string
		pattern    string
		minSelfLen int
	}{
		{"word-class", `(\w+)`, 60},
		{"lower-class", `<([a-z]+)>`, 24},
		// Constructed via newTDFA directly, bypassing selectBestEngine — note
		// this exact pattern is routed to Backtracking in production because
		// the trailing Y overlaps the [a-zA-Z] self-loop class, triggering
		// hasAmbiguousCaptures. This test is only
		// exercising the detector in isolation, not real engine selection.
		{"letter-class", `X([a-zA-Z]+)Y`, 50},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tt := newTDFAForPattern(t, c.pattern)
			info := detectTDFABulkSkip(tt)
			if info == nil {
				t.Fatalf("detectTDFABulkSkip(%q) = nil, want non-nil", c.pattern)
			}
			if len(info.selfLoopBytes) < c.minSelfLen {
				t.Errorf("selfLoopBytes = %d bytes, want >= %d", len(info.selfLoopBytes), c.minSelfLen)
			}
			for _, op := range info.ops {
				if op.src != -1 {
					t.Errorf("op %+v is not set-to-pos (src=%d)", op, op.src)
				}
			}
			gs := int(info.wasmState) - 1
			count := 0
			for bv := 0; bv < 256; bv++ {
				if tt.transitions[gs*256+bv] == gs {
					count++
				}
			}
			if count != len(info.selfLoopBytes) {
				t.Errorf("independent self-loop recount = %d, detector reported %d", count, len(info.selfLoopBytes))
			}
		})
	}
}

// buildTestTDFATable hand-builds a single-state tdfaTable (state 0 only) that
// self-loops on selfLoopBytes, firing ops on every one of them. Bytes not in
// selfLoopBytes are dead transitions. Used to construct detector reject cases
// that are impractical to reach via a real pattern.
func buildTestTDFATable(selfLoopBytes []byte, ops []tdfaTagOp, immediateAccept bool) *tdfaTable {
	trans := make([]int, 256)
	for i := range trans {
		trans[i] = -1
	}
	tagOps := make([][]tdfaTagOp, 256)
	for _, bv := range selfLoopBytes {
		trans[bv] = 0
		tagOps[bv] = ops
	}
	imm := map[int]uint64{}
	if immediateAccept {
		imm[0] = 1
	}
	dt := &dfaTable{
		numStates:             1,
		transitions:           trans,
		immediateAcceptStates: imm,
	}
	return &tdfaTable{dfaTable: dt, tagOps: tagOps}
}

func bytesRange(n int) []byte {
	bs := make([]byte, n)
	for i := range bs {
		bs[i] = byte(i)
	}
	return bs
}

func TestDetectTDFABulkSkipReject(t *testing.T) {
	setOp := []tdfaTagOp{{dst: 0, src: -1}}

	t.Run("non-uniform-ops", func(t *testing.T) {
		trans := make([]int, 256)
		for i := range trans {
			trans[i] = -1
		}
		tagOps := make([][]tdfaTagOp, 256)
		for bv := 0; bv < 10; bv++ {
			trans[bv] = 0
			if bv < 5 {
				tagOps[bv] = []tdfaTagOp{{dst: 0, src: -1}}
			} else {
				tagOps[bv] = []tdfaTagOp{{dst: 1, src: -1}}
			}
		}
		tt := &tdfaTable{dfaTable: &dfaTable{numStates: 1, transitions: trans, immediateAcceptStates: map[int]uint64{}}, tagOps: tagOps}
		if info := detectTDFABulkSkip(tt); info != nil {
			t.Errorf("non-uniform tag ops on self-loop must be rejected, got %+v", info)
		}
	})

	t.Run("copy-op", func(t *testing.T) {
		copyOp := []tdfaTagOp{{dst: 0, src: 1}}
		tt := buildTestTDFATable(bytesRange(20), copyOp, false)
		if info := detectTDFABulkSkip(tt); info != nil {
			t.Errorf("copy-op self-loop must be rejected (out of v1 scope), got %+v", info)
		}
	})

	t.Run("too-few-bytes", func(t *testing.T) {
		tt := buildTestTDFATable(bytesRange(tdfaBulkSkipMinBytes-1), setOp, false)
		if info := detectTDFABulkSkip(tt); info != nil {
			t.Errorf("self-loop below min size must be rejected, got %+v", info)
		}
	})

	t.Run("too-many-bytes", func(t *testing.T) {
		tt := buildTestTDFATable(bytesRange(tdfaBulkSkipMaxBytes+1), setOp, false)
		if info := detectTDFABulkSkip(tt); info != nil {
			t.Errorf("self-loop above max size must be rejected, got %+v", info)
		}
	})

	t.Run("immediate-accept-state", func(t *testing.T) {
		tt := buildTestTDFATable(bytesRange(20), setOp, true)
		if info := detectTDFABulkSkip(tt); info != nil {
			t.Errorf("immediate-accept state must be excluded from candidacy, got %+v", info)
		}
	})

	t.Run("qualifying-boundary-sizes", func(t *testing.T) {
		for _, n := range []int{tdfaBulkSkipMinBytes, tdfaBulkSkipMaxBytes} {
			tt := buildTestTDFATable(bytesRange(n), setOp, false)
			info := detectTDFABulkSkip(tt)
			if info == nil {
				t.Errorf("self-loop of exactly %d bytes should qualify", n)
				continue
			}
			if len(info.selfLoopBytes) != n {
				t.Errorf("n=%d: selfLoopBytes = %d, want %d", n, len(info.selfLoopBytes), n)
			}
		}
	})
}

// decodeControlFlow walks emitted WASM bytecode that uses only the fixed
// instruction set emitTDFABulkSkip/emitShuftiPrefixCheck emit, and returns
// the sequence of control-flow instructions (block/loop/if/else/end/br/
// br_if) encountered, with br/br_if immediates rendered inline. All other
// instructions are decoded just far enough to skip their operands. This
// independently verifies the block/loop/if nesting and branch depths
// without needing a live WASM runtime — the only way to catch a
// depth-arithmetic bug that isn't also a validator error (see Gap F plan,
// risk #1: an off-by-one branch depth is still a *valid* WASM program, just
// one that jumps to the wrong place).
func decodeControlFlow(t *testing.T, b []byte) []string {
	t.Helper()
	var ops []string
	i := 0
	skipLEB := func() {
		for i < len(b) && b[i]&0x80 != 0 {
			i++
		}
		i++
	}
	readDepth := func() byte {
		start := i
		skipLEB()
		if start >= len(b) {
			t.Fatalf("decodeControlFlow: truncated branch immediate at byte %d", start)
		}
		return b[start]
	}
	for i < len(b) {
		op := b[i]
		switch op {
		case 0x02: // block
			i++
			i++ // blocktype
			ops = append(ops, "block")
		case 0x03: // loop
			i++
			i++
			ops = append(ops, "loop")
		case 0x04: // if
			i++
			i++
			ops = append(ops, "if")
		case 0x05: // else
			i++
			ops = append(ops, "else")
		case 0x0B: // end
			i++
			ops = append(ops, "end")
		case 0x0C: // br
			i++
			d := readDepth()
			ops = append(ops, fmt.Sprintf("br %d", d))
		case 0x0D: // br_if
			i++
			d := readDepth()
			ops = append(ops, fmt.Sprintf("br_if %d", d))
		case 0x20, 0x21, 0x22, 0x41: // local.get/set/tee, i32.const
			i++
			skipLEB()
		case 0x45, 0x46, 0x47, 0x4B, 0x6A, 0x68, 0x73: // eqz, eq, ne, gt_u, add, ctz, xor
			i++
		case 0xFD: // SIMD prefix
			i++
			sub := b[i]
			i++
			switch sub {
			case 0x00: // v128.load: align, offset
				skipLEB()
				skipLEB()
			case 0x0C: // v128.const: 16 raw bytes
				i += 16
			case 0x0E, 0x0F, 0x23, 0x24, 0x4E, 0x50, 0x64, 0x6D:
				// swizzle, splat, eq, ne, and, or, bitmask, shr_u — no
				// immediates. eq joined the list when the bulk skip switched to
				// the STOP polarity (emitShuftiStopMask): it compares the merged
				// lanes against zero instead of taking a member mask and
				// inverting it with an i32 xor.
			default:
				t.Fatalf("decodeControlFlow: unhandled SIMD subopcode 0x%02x at byte %d", sub, i-2)
			}
		default:
			t.Fatalf("decodeControlFlow: unhandled opcode 0x%02x at byte %d", op, i)
		}
	}
	return ops
}

func TestEmitTDFABulkSkipShape(t *testing.T) {
	info := &tdfaBulkSkipInfo{
		wasmState:     5,
		selfLoopBytes: bytesRange(20),
		ops:           []tdfaTagOp{{dst: 0, src: -1}},
	}
	const (
		localPos       = 3
		localChunk     = 10
		localMask      = 11
		localSkipStart = 12
		localCapBase   = 7
	)
	b := emitTDFABulkSkip(nil, info, localPos, localChunk, localMask, localSkipStart, localCapBase, nil)

	got := decodeControlFlow(t, b)
	want := []string{
		"block",   // $skip_done
		"loop",    // $chunks
		"br_if 1", // insufficient bytes -> $skip_done
		"if",      // mask == 0
		"br 1",    // continue $chunks
		"else",
		"br 2", // break $skip_done
		"end",  // end if
		"end",  // end loop $chunks
		"end",  // end block $skip_done
		"if",   // pos != skipStart
		"br 2", // loop back to $main
		"end",  // end if
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("control-flow shape mismatch:\ngot:  %v\nwant: %v", got, want)
	}
}

func TestEmitTDFABulkSkipShapeNoTagOps(t *testing.T) {
	// A self-loop with zero tag ops (state that fires no capture writes at
	// all) must still bulk-skip correctly — the "if pos != skipStart" body
	// is simply empty apart from the loop-back branch.
	info := &tdfaBulkSkipInfo{
		wasmState:     5,
		selfLoopBytes: bytesRange(10),
		ops:           nil,
	}
	b := emitTDFABulkSkip(nil, info, 3, 10, 11, 12, 7, nil)
	got := decodeControlFlow(t, b)
	want := []string{
		"block", "loop", "br_if 1",
		"if", "br 1", "else", "br 2", "end",
		"end", "end",
		"if", "br 2", "end",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("control-flow shape mismatch:\ngot:  %v\nwant: %v", got, want)
	}
}

// TestTDFABulkSkipMidAcceptModuleValid compiles whole modules for the
// bulk-skip shapes end to end, so the mid-accept tail is type-checked by
// mustCompileEntries' validator rather than only by the
// control-flow shape decoder above.
//
// The tail is emitted INSIDE emitTDFABulkSkip's "if pos != skipStart" body and
// is followed by `br 2` out to loop $main, so it has to be perfectly balanced:
// emitTDFAWriteCaptures opens a block per TDFA state, and one missing `end`
// would retarget that branch at the wrong label. Nothing in the unit tests
// above would notice — the shape decoder is handed a nil tail.
//
// Behavioural coverage (right capture values, not just a well-formed module)
// lives in tools/fuzz's TestTDFABulkSkipMidAccept, which needs wasmtime.
func TestTDFABulkSkipMidAcceptModuleValid(t *testing.T) {
	// Each pattern's dominant state self-loops on a class of 8..64 bytes AND
	// is mid-accepting, which is exactly the combination that emits the tail.
	for _, pattern := range []string{
		`^([a-z]+)`,
		`^([0-9]+)`,
		`^([a-zA-Z]+)`,
		`^(\w+)`,
		`^([a-z]+)([0-9]*)`,
	} {
		t.Run(pattern, func(t *testing.T) {
			tt := newTDFAForPattern(t, pattern)
			if detectTDFABulkSkip(tt) == nil {
				t.Fatalf("pattern %q no longer has a bulk-skip state — this test would compile nothing relevant", pattern)
			}
			mustCompileEntries(t, []config.RegexEntry{{Pattern: pattern, GroupsFunc: "g"}})
		})
	}
}
