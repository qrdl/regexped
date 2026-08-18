package compile

import (
	"reflect"
	"regexp/syntax"
	"testing"
)

// relocateProg returns a copy of prog whose instructions all live at PCs >= off,
// by prepending off unreachable InstFail padding instructions and shifting every
// PC-valued field. The relocated program is behaviourally identical to the
// original: only the numeric values of its PCs change.
//
// Arg is a PC only for InstAlt/InstAltMatch. For InstCapture it is a capture
// slot index and for InstEmptyWidth it is an EmptyOp bitmask, so it must not be
// shifted for those.
func relocateProg(prog *syntax.Prog, off uint32) *syntax.Prog {
	out := &syntax.Prog{
		Inst:   make([]syntax.Inst, off, off+uint32(len(prog.Inst))),
		Start:  prog.Start + int(off),
		NumCap: prog.NumCap,
	}
	for i := range out.Inst {
		out.Inst[i] = syntax.Inst{Op: syntax.InstFail}
	}
	for _, in := range prog.Inst {
		cp := in
		if len(in.Rune) > 0 {
			cp.Rune = append([]rune(nil), in.Rune...)
		}
		switch in.Op {
		case syntax.InstFail, syntax.InstMatch:
			// Out is unused.
		default:
			cp.Out = in.Out + off
		}
		if in.Op == syntax.InstAlt || in.Op == syntax.InstAltMatch {
			cp.Arg = in.Arg + off
		}
		out.Inst = append(out.Inst, cp)
	}
	return out
}

// TestDFA_HighPCsDoNotCollide pins the fixed-width NFA-PC key encoding in
// setToKey. The previous encoding used strings.Builder.WriteRune, which maps
// every PC in the UTF-16 surrogate window 0xD800-0xDFFF (2048 distinct values)
// — and PC 0xFFFD — onto utf8.RuneError's three bytes. Distinct NFA state sets
// then produced equal map keys, were merged into one DFA state, and the emitted
// table was silently wrong: no error, no fallback to another engine.
//
// Relocating a program to high PCs cannot change its language, so its DFA must
// be identical instruction-for-instruction. Under the old encoding the
// relocated DFA collapses to fewer states.
func TestDFA_HighPCsDoNotCollide(t *testing.T) {
	pats := []string{
		"ab",
		"a[bc]d|ae",
		"[0-9]+x",
		"a*b",
	}
	// 0xD800 puts every reachable PC inside the surrogate window; 0xFFFB places
	// PC 0xFFFD (RuneError itself) among the reachable ones.
	offsets := []uint32{0xD800, 0xFFFB}

	for _, pat := range pats {
		re, err := syntax.Parse(pat, syntax.Perl)
		if err != nil {
			t.Fatalf("parse %q: %v", pat, err)
		}
		prog, err := syntax.Compile(re.Simplify())
		if err != nil {
			t.Fatalf("compile %q: %v", pat, err)
		}
		base, ok := newDFA(prog, false, false, 1024)
		if !ok {
			t.Fatalf("%q: baseline DFA construction failed", pat)
		}

		for _, off := range offsets {
			moved, ok := newDFA(relocateProg(prog, off), false, false, 1024)
			if !ok {
				t.Fatalf("%q @ off=%#x: relocated DFA construction failed", pat, off)
			}
			if moved.numStates != base.numStates {
				t.Errorf("%q @ off=%#x: numStates = %d, want %d (distinct NFA state sets were merged)",
					pat, off, moved.numStates, base.numStates)
				continue
			}
			if !reflect.DeepEqual(moved.transitions, base.transitions) {
				t.Errorf("%q @ off=%#x: transition table differs from the same program at low PCs", pat, off)
			}
			if !reflect.DeepEqual(moved.accepting, base.accepting) {
				t.Errorf("%q @ off=%#x: accept map differs from the same program at low PCs", pat, off)
			}
		}
	}
}
