package fuzz

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"testing"
)

// The groups half of the find-from channel. The find export now takes a `from`
// position; groups and named_groups still NARROW, so a leading \b, \B or
// (?m:^) is judged against the slice edge on every re-entry.
//
// Nothing covered this before: FuzzGroups is ONE-SHOT (a single call compared
// to a single FindStringSubmatchIndex), and custom-tests.txt has exactly ONE
// row carrying a real col6 value. So the groups path could be converted with
// no way to tell whether it worked.

// groupsIterSeeds: one shape per concern. The leading-assertion cases are the
// ones narrowing gets wrong; the plain ones guard against a conversion
// breaking the ordinary path.
var groupsIterSeeds = []struct {
	pat, input string
}{
	{`(a)`, "aXaXa"},
	{`(a*)`, "bab"},
	{`([a-z]+)@([a-z]+)`, "x@y z@w"},
	// leading zero-width assertions — the (A) shapes
	{`\b(foo)`, "foofoo"},
	{`\B(foo)`, "xfoofoo"},
	{`\B(a)`, "aaa"},
	{`(?m:^)(a)`, "a\naa"},
	// begin-anchored: a match can only start at 0, so iteration must stop
	{`\A(a)(b)`, "abab"},
	{`^(abc)`, "abcabc"},
}

func goGroupsAll(re *regexp.Regexp, input string) [][]int {
	return re.FindAllStringSubmatchIndex(input, -1)
}

func fmtGroups(all [][]int) string {
	if len(all) == 0 {
		return "(none)"
	}
	out := ""
	for i, m := range all {
		if i > 0 {
			out += " | "
		}
		for j := 0; j+1 < len(m); j += 2 {
			if j > 0 {
				out += ","
			}
			out += fmt.Sprintf("%d-%d", m[j], m[j+1])
		}
	}
	return out
}

// runGroupsIter models the generated stubs' groups loop exactly, including
// Go's adjacent-empty suppression rule (half B, already shipped).
func runGroupsIter(t *testing.T, w []byte, input string, numGroups int) ([][]int, bool) {
	t.Helper()
	store, inst, mem, release, err := instantiate(w)
	defer release()
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	fn := inst.GetFunc(store, "groups")
	if fn == nil {
		t.Fatal("module has no groups export")
	}
	copy(mem.UnsafeData(store)[pathsInputBase:], input)

	_, wd := sharedEngine()
	slots := numGroups * 2
	var out [][]int
	pos, prevEnd := 0, -1
	for pos <= len(input) {
		wd.Arm(store)
		// The WHOLE buffer plus a start position, which is what every
		// generated groups stub now passes.
		res, callErr := fn.Call(store, pathsInputBase, int32(len(input)), pathsOutBase, int32(pos))
		wd.Disarm()
		if callErr != nil {
			if isTimeout(callErr) {
				return nil, false
			}
			t.Fatalf("groups call: %v", callErr)
		}
		r := res.(int32)
		if r == int32(abiBTOverflow) {
			return nil, false
		}
		if r < 0 {
			if pos == len(input) {
				break
			}
			pos++
			continue
		}
		buf := mem.UnsafeData(store)
		m := make([]int, slots)
		for i := 0; i < slots; i++ {
			v := int32(binary.LittleEndian.Uint32(buf[int(pathsOutBase)+i*4:]))
			if v < 0 {
				m[i] = -1
			} else {
				m[i] = int(v) // absolute already
			}
		}
		absStart, absEnd := m[0], m[0]
		if m[1] >= 0 {
			absEnd = m[1]
		}
		if absEnd > absStart {
			pos = absEnd
		} else {
			pos = absStart + 1
		}
		if absStart == absEnd && prevEnd == absStart {
			continue
		}
		prevEnd = absEnd
		out = append(out, m)
	}
	return out, true
}

const abiBTOverflow = -2

func TestGroupsIterationMatchesGo(t *testing.T) {
	for _, c := range groupsIterSeeds {
		t.Run(c.pat+"/"+c.input, func(t *testing.T) {
			re, err := regexp.Compile(c.pat)
			if err != nil {
				t.Skipf("Go rejects %q: %v", c.pat, err)
			}
			w, err := compileGroups(c.pat)
			if err != nil {
				t.Skipf("compile %q: %v", c.pat, err)
			}
			got, ok := runGroupsIter(t, w, c.input, re.NumSubexp()+1)
			if !ok {
				t.Skip("watchdog or BT overflow")
			}
			want := goGroupsAll(re, c.input)
			if fmtGroups(got) != fmtGroups(want) {
				t.Errorf("groups iteration over %q:\n  got  %s\n  want %s",
					c.input, fmtGroups(got), fmtGroups(want))
			}
		})
	}
}
