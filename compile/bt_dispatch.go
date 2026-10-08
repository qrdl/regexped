package compile

import (
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"

	"github.com/qrdl/regexped/internal/utils"
)

// ── Backtracking: first-byte dispatch over an alternation ───────────────────
//
// Go compiles `a|b|c` to a chain of Alts — Alt(Alt(a, b), c) — and the
// ordinary body walks it arm by arm: every Alt pushes a frame for its second
// branch, the first arm fails on its first byte, the frame is popped, and so
// on down the chain. On a 24-arm keyword alternation that is ~23 pushes and
// pops at every position the body visits, almost all of them for arms whose
// first byte cannot match.
//
// The chain's head instead reads the next byte once and branches (`br_table`)
// to a case that pushes frames only for the arms that byte can start, in
// priority order, and enters the first of them. An arm the byte cannot start
// would fail on that byte, so skipping it changes no answer: leftmost-first
// priority is the order of the arms that CAN match, which is kept. The chain's
// inner Alts are then reached only through the head, and are emitted as
// `unreachable`.
//
// First sets are SUPERSETS — an assertion or capture before the first
// consuming instruction is looked through, `(?i)` adds both cases — so an arm
// may be tried and fail, but never skipped when it could match. An arm that
// can reach Match without consuming is tried in every case, end of input
// included.
//
// Only in an ORDINARY body. The fallback body memoises every Alt on (pc, pos),
// which is what terminates it on a zero-width cycle; it keeps the plain chain.
//
// Measured (fuel/byte): Unicode `(\pL+?)(\pL*)` 967 → 133, WAF Backtracking
// members' `scan_any` 48-77% less (`cij_body_04` 732 → 166 over an HTTP log),
// a non-greedy body re-trying `(from|into|set)` at every step 88 → 53.

// btAltDispatch is the dispatch at one chain head.
type btAltDispatch struct {
	arms []uint32 // arm entry pcs, in priority order
	// caseOf maps a byte value — 256 for the end of input — to its case;
	// cases[k] lists the arms (indices into arms) case k tries, in order.
	caseOf [257]int
	cases  [][]int
	// compact: each case sets a mask of the arms after its first and the
	// first arm's pc, and one shared sequence pushes the masked arms. Chosen
	// when the direct encoding — every case pushing its own arms, each push
	// storing every capture register — would emit more pushes than the chain
	// has arms: one WAF member's module grew 44% that way.
	compact bool
}

// btDispatchPlan is a program's dispatch: the chain heads, and the inner Alts
// only those heads reach.
type btDispatchPlan struct {
	heads map[int]*btAltDispatch
	dead  map[int]bool
}

// btCompactMaxArms is the widest chain the compact encoding serves: its mask
// is an i32.
const btCompactMaxArms = 32

// altDispatch is bt's dispatch plan, built on first use.
func (bt *backtrack) altDispatch() *btDispatchPlan {
	if bt.dispatch == nil {
		bt.dispatch = buildBTDispatchPlan(bt.prog)
	}
	return bt.dispatch
}

// btFirst is what an instruction's path can consume first.
type btFirst struct {
	bytes    [256]bool
	nullable bool // can reach Match without consuming
}

// btFirstSets computes, for each pc on demand, a superset of the bytes the
// path from it can consume first. A pc met again while it is being computed —
// a zero-width cycle — counts as anything, nullable.
func btFirstSets(prog *syntax.Prog) func(uint32) *btFirst {
	memo := make([]*btFirst, len(prog.Inst))
	busy := make([]bool, len(prog.Inst))
	var first func(uint32) *btFirst
	first = func(pc uint32) *btFirst {
		if memo[pc] != nil {
			return memo[pc]
		}
		f := &btFirst{}
		if busy[pc] {
			f.nullable = true
			for i := range f.bytes {
				f.bytes[i] = true
			}
			return f
		}
		busy[pc] = true
		in := prog.Inst[pc]
		switch in.Op {
		case syntax.InstMatch:
			f.nullable = true
		case syntax.InstFail:
		case syntax.InstRuneAny:
			for i := range f.bytes {
				f.bytes[i] = true
			}
		case syntax.InstRuneAnyNotNL:
			for i := range f.bytes {
				f.bytes[i] = i != '\n'
			}
		case syntax.InstRune1, syntax.InstRune:
			// As btCheckRune1 / btCheckRuneRanges read it: a byte, ranges
			// saturated at 0xFF, (?i) folding ASCII letters.
			fold := syntax.Flags(in.Arg)&syntax.FoldCase != 0
			add := func(lo, hi rune) {
				if lo > 0xFF {
					return
				}
				hi = min(hi, 0xFF)
				for r := lo; r <= hi; r++ {
					f.bytes[r] = true
					if fold {
						f.bytes[btFoldRune(r)] = true // ASCII letters only: stays a byte
					}
				}
			}
			if in.Op == syntax.InstRune1 || len(in.Rune) == 1 {
				add(in.Rune[0], in.Rune[0])
			} else {
				for i := 0; i+1 < len(in.Rune); i += 2 {
					add(in.Rune[i], in.Rune[i+1])
				}
			}
		case syntax.InstAlt, syntax.InstAltMatch:
			a, b := first(in.Out), first(in.Arg)
			for i := range f.bytes {
				f.bytes[i] = a.bytes[i] || b.bytes[i]
			}
			f.nullable = a.nullable || b.nullable
		default: // Nop, Capture, EmptyWidth: look through
			*f = *first(in.Out)
		}
		busy[pc] = false
		memo[pc] = f
		return f
	}
	return first
}

// buildBTDispatchPlan finds prog's alternation chains of three or more arms
// and builds each one's dispatch, at its WIDEST head: candidates are taken
// widest first, and a candidate head that an accepted chain already flattened
// is dropped, so each chain is dispatched once.
func buildBTDispatchPlan(prog *syntax.Prog) *btDispatchPlan {
	plan := &btDispatchPlan{heads: map[int]*btAltDispatch{}, dead: map[int]bool{}}
	indeg := make([]int, len(prog.Inst))
	indeg[prog.Start]++
	for _, in := range prog.Inst {
		switch in.Op {
		case syntax.InstMatch, syntax.InstFail:
		case syntax.InstAlt, syntax.InstAltMatch:
			indeg[in.Out]++
			indeg[in.Arg]++
		default:
			indeg[in.Out]++
		}
	}
	first := btFirstSets(prog)
	type candidate struct {
		pc    int
		inner []int
		d     *btAltDispatch
	}
	var cands []candidate
	for pc, in := range prog.Inst {
		if in.Op != syntax.InstAlt {
			continue
		}
		// Flatten through Alts reached only from this chain, Out before Arg:
		// that is the arms' priority order.
		var arms []uint32
		var inner []int
		var flatten func(q uint32)
		flatten = func(q uint32) {
			if prog.Inst[q].Op == syntax.InstAlt && indeg[q] == 1 && int(q) != pc {
				inner = append(inner, int(q))
				flatten(prog.Inst[q].Out)
				flatten(prog.Inst[q].Arg)
				return
			}
			arms = append(arms, q)
		}
		flatten(in.Out)
		flatten(in.Arg)
		if len(arms) < 3 {
			continue
		}
		firsts := make([]*btFirst, len(arms))
		for i, a := range arms {
			firsts[i] = first(a)
		}
		d := &btAltDispatch{arms: arms}
		index := map[string]int{}
		for c := 0; c <= 256; c++ {
			var list []int
			var key strings.Builder
			for i, f := range firsts {
				if f.nullable || c < 256 && f.bytes[c] {
					list = append(list, i)
					key.WriteString(strconv.Itoa(i))
					key.WriteByte(',')
				}
			}
			k, ok := index[key.String()]
			if !ok {
				k = len(d.cases)
				index[key.String()] = k
				d.cases = append(d.cases, list)
			}
			d.caseOf[c] = k
		}
		if len(d.cases) == 1 && len(d.cases[0]) == len(arms) {
			continue // every byte starts every arm: nothing to skip
		}
		if len(arms) <= btCompactMaxArms {
			pushes := 0
			for _, l := range d.cases {
				pushes += max(len(l)-1, 0)
			}
			d.compact = pushes > len(arms)-1
		}
		cands = append(cands, candidate{pc, inner, d})
	}
	sort.SliceStable(cands, func(i, j int) bool { return len(cands[i].d.arms) > len(cands[j].d.arms) })
	for _, c := range cands {
		if plan.dead[c.pc] {
			continue
		}
		plan.heads[c.pc] = c.d
		for _, q := range c.inner {
			plan.dead[q] = true
		}
	}
	return plan
}

// btDispatchCharge is what a case charges the work budget: the pops the plain
// chain would have made for the arms the case skips.
func btDispatchCharge(d *btAltDispatch, list []int) int {
	if len(list) == 0 {
		return len(d.arms) - 1 // the failure's own pop charges the last
	}
	// Every skipped arm, as if each were tried and failed — including those
	// after the first candidate, which the chain tries only if the earlier
	// ones fail. Charging only the arms before the first candidate measured
	// the same within 1% except on one WAF set over form data, where the
	// budget then tripped later: 123,328 fuel/byte against 46,648.
	return len(d.arms) - len(list)
}

// emitBTAltDispatch emits a chain head's dispatch at handler top level, brRun
// from loop $run. charge, when the body keeps a work budget, charges each case
// what the plain chain would have: the budget is calibrated in its pops, and
// it bounds time because every cycle passes through an Alt and every Alt used
// to push. A case that enters its only arm directly pushes nothing, and
// charges for the arms it skipped instead — `(?:ab|cd|ef)*x` over (ab)×N
// would otherwise walk every start's run without one charge.
func emitBTAltDispatch(body []byte, d *btAltDispatch, brRun uint32, numCapLocals int, frameSize int32,
	overflowFn func([]byte, uint32) []byte, tableMemIdx int, dyn *btDyn, limitLocal uint32,
	charge func([]byte, int) []byte) []byte {
	n := len(d.cases)
	if d.compact {
		body = append(body, 0x02, 0x40) // block $common
	}
	for i := 0; i < n; i++ {
		body = append(body, 0x02, 0x40) // block $case_i, innermost first
	}
	// The case index: the byte at pos, or 256 at the end of input.
	body = append(body, 0x20, localPos)
	body = btLocalGet(body, limitLocal)
	body = append(body, 0x4F, 0x04, 0x7F) // i32.ge_u; if (result i32)
	body = append(body, 0x41)
	body = utils.AppendSLEB128(body, 256)
	body = append(body, 0x05) // else
	body = append(body, 0x20, localPtr, 0x20, localPos, 0x6A, 0x2D, 0x00, 0x00)
	body = append(body, 0x0B) // end if
	body = append(body, 0x0E) // br_table
	body = utils.AppendULEB128(body, 257)
	for c := 0; c <= 256; c++ {
		body = utils.AppendULEB128(body, uint32(d.caseOf[c]))
	}
	body = utils.AppendULEB128(body, uint32(d.caseOf[256]))

	outer := uint32(0) // blocks around the cases: $common
	if d.compact {
		outer = 1
	}
	for k := 0; k < n; k++ {
		body = append(body, 0x0B) // end $case_k: case k follows
		depth := brRun + uint32(n-1-k) + outer
		list := d.cases[k]
		if c := btDispatchCharge(d, list); c > 0 && charge != nil {
			body = charge(body, c)
		}
		switch {
		case len(list) == 0:
			body = btFail(body, depth)
		case d.compact:
			mask := uint32(0)
			for _, j := range list[1:] {
				mask |= 1 << uint(j)
			}
			body = append(body, 0x41)
			body = utils.AppendSLEB128(body, int32(mask))
			body = append(body, 0x21, localScratch)
			body = append(body, 0x41)
			body = utils.AppendSLEB128(body, int32(d.arms[list[0]]))
			body = append(body, 0x21, localState)
			body = append(body, 0x0C) // br $common
			body = utils.AppendULEB128(body, uint32(n-1-k))
		default:
			for j := len(list) - 1; j >= 1; j-- {
				body = btPushFrame(body, numCapLocals, d.arms[list[j]], frameSize, depth+1, overflowFn, tableMemIdx, dyn)
			}
			body = btSetStateAndBr(body, int32(d.arms[list[0]]), depth)
		}
	}
	if !d.compact {
		return body
	}
	body = append(body, 0x0B) // end $common: push the masked arms, last first
	for j := len(d.arms) - 1; j >= 1; j-- {
		body = append(body, 0x20, localScratch, 0x41)
		body = utils.AppendSLEB128(body, int32(uint32(1)<<uint(j)))
		body = append(body, 0x71, 0x04, 0x40) // i32.and; if
		body = btPushFrame(body, numCapLocals, d.arms[j], frameSize, brRun+2, overflowFn, tableMemIdx, dyn)
		body = append(body, 0x0B) // end if
	}
	body = append(body, 0x0C) // br $run: the state is the first arm
	return utils.AppendULEB128(body, brRun)
}
