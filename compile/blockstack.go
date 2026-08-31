package compile

import "fmt"

// ── WASM branch depths ─────────────────────────────────
//
// A `br` in WASM names its target by COUNTING enclosing block/loop/if levels
// outward, so every branch depth in a hand-written emitter is an integer
// literal that has to stay correct as the surrounding structure changes.
//
// The failure mode is the expensive kind. A wrong depth does not fail
// validation: `br 2` where `br 3` was meant is a well-typed module that
// branches to the wrong enclosing block, so it silently skips input or
// re-scans it. Nothing but a full corpus run catches it.
//
// The set emitters carry 118 such literals; the two first-byte skip loops
// alone carry 21, and one of them keeps a small table of depth CORRECTIONS
// because its adaptive counter adds a block level on some paths and not
// others (`br 4` there, `br 3` here).
//
// blockStack replaces the counting with naming. Push a label when a
// block/loop/if opens, Pop when it ends, and Depth("skip_done") computes what
// the literal would have been. A label that is not open is a panic at compile
// time rather than a module that branches somewhere plausible.
//
// It does NOT emit anything. The emitters keep their own structure and their
// own opcode bytes; this only answers "how many levels out is that?", which is
// the single question they were getting wrong by hand.
type blockStack struct {
	labels []string
}

// Push records that a block, loop or if has been opened. The label is for
// naming only — WASM has no labels — so it need only be unique among the
// levels open at once.
func (s *blockStack) Push(label string) {
	s.labels = append(s.labels, label)
}

// Pop records an `end`.
func (s *blockStack) Pop() {
	if len(s.labels) == 0 {
		panic("compile: blockStack.Pop with no level open")
	}
	s.labels = s.labels[:len(s.labels)-1]
}

// Depth is the `br` operand that targets label from the current position: 0 is
// the innermost open level.
//
// An unknown label panics rather than returning a plausible number, which is
// the whole point — the alternative is the silent misbranch described above.
func (s *blockStack) Depth(label string) byte {
	for i := len(s.labels) - 1; i >= 0; i-- {
		if s.labels[i] == label {
			d := len(s.labels) - 1 - i
			if d > 255 {
				panic(fmt.Sprintf("compile: branch depth %d to %q exceeds a byte", d, label))
			}
			return byte(d)
		}
	}
	panic(fmt.Sprintf("compile: branch to %q, which is not an open block (open: %v)",
		label, s.labels))
}

// Open is the number of levels currently open, for an emitter that wants to
// assert its own nesting is balanced at a known point.
func (s *blockStack) Open() int { return len(s.labels) }
