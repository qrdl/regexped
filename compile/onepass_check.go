package compile

import "regexp/syntax"

// isOnePass checks if a program can be executed in one-pass mode.
func isOnePass(prog *syntax.Prog) bool {
	if len(prog.Inst) > 100 {
		return false
	}

	for pc, inst := range prog.Inst {
		switch inst.Op {
		case syntax.InstAlt, syntax.InstAltMatch:
			if !isAlternationDeterministic(prog, pc) {
				return false
			}
		}
	}

	return true
}

// isAlternationDeterministic checks if an alternation has distinct first characters
// in each branch, making it deterministic.
func isAlternationDeterministic(prog *syntax.Prog, altPC int) bool {
	if altPC >= len(prog.Inst) {
		return false
	}

	alt := &prog.Inst[altPC]
	if alt.Op != syntax.InstAlt && alt.Op != syntax.InstAltMatch {
		return false
	}

	leftRunes := getFirstRuneSet(prog, int(alt.Out))
	rightRunes := getFirstRuneSet(prog, int(alt.Arg))

	if len(leftRunes) == 0 || len(rightRunes) == 0 {
		return false
	}

	for r := range leftRunes {
		if rightRunes[r] {
			return false
		}
	}

	return true
}

// getFirstRuneSet returns the set of runes that can start execution at the given PC.
func getFirstRuneSet(prog *syntax.Prog, pc int) map[rune]bool {
	if pc >= len(prog.Inst) {
		return make(map[rune]bool)
	}

	runes := make(map[rune]bool)
	visited := make(map[int]bool)

	var collect func(int) bool
	collect = func(pc int) bool {
		if pc >= len(prog.Inst) || visited[pc] {
			return true
		}

		visited[pc] = true
		if len(visited) > 50 {
			return false
		}

		inst := &prog.Inst[pc]

		switch inst.Op {
		case syntax.InstRune1:
			runes[inst.Rune[0]] = true
			return true

		case syntax.InstRune:
			if len(inst.Rune)%2 != 0 {
				return false
			}

			totalChars := 0
			for i := 0; i < len(inst.Rune); i += 2 {
				low, high := inst.Rune[i], inst.Rune[i+1]
				totalChars += int(high - low + 1)
			}

			if totalChars > 100 {
				return false
			}

			for i := 0; i < len(inst.Rune); i += 2 {
				low, high := inst.Rune[i], inst.Rune[i+1]
				for r := low; r <= high; r++ {
					runes[r] = true
				}
			}
			return true

		case syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
			return false

		case syntax.InstCapture, syntax.InstNop:
			return collect(int(inst.Out))

		case syntax.InstEmptyWidth:
			return collect(int(inst.Out))

		case syntax.InstAlt, syntax.InstAltMatch:
			if !collect(int(inst.Out)) {
				return false
			}
			return collect(int(inst.Arg))

		case syntax.InstMatch:
			return false

		default:
			return false
		}
	}

	if !collect(pc) {
		return make(map[rune]bool)
	}

	return runes
}
