package generate

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The runtime differential: ONE config, driven through every stub language's
// generated code — built, merged (or loaded standalone, for JS/TS) and run —
// and compared operation by operation with Go's regexp. Each operation is
// reduced to a 32-bit hash of its results, the same hash in every language,
// so a driver prints (or returns) one number per operation and the test names
// the operation that differs.
//
// What it drives that no compile-only test can: every match of a find and a
// groups scan, an iterator stopped after its first match and resumed (Go's
// break-and-range-again, a Rust iterator, a JS generator stepped once and
// then run), two iterators interleaved, a find whose drive arms per-search
// notes (`a*b|a` over a×5000), a Backtracking find whose budget trips (the
// memo input), a group `Simplify` removes, and a set's five capabilities. C
// and Rust run the SAME driver source against a component build too: their
// component stubs promise the module stubs' API.

// diffConfig is the config every leg compiles; output: (embedded) is dropped
// for the standalone JS/TS leg and the format switched for the component legs.
const diffConfig = `import_module: rx
wasm_file: rx.wasm
output: merged.wasm
patterns:
  - name: url
    regexp: '(?<scheme>https?)://(?<host>[a-z.]+)/([a-z/]*)'
    match_func: url_match
    find_func: url_find
    groups_func: url_groups
  - name: empty
    regexp: '(a*)'
    find_func: empty_find
    groups_func: empty_groups
  - name: overrun
    regexp: 'a*b|a'
    find_func: overrun_find
  - name: bt
    regexp: '(?:a|b)*a(?:a|b){12}c|a'
    find_func: bt_find
  - name: removed
    regexp: '(x)(?:(b){0})y'
    groups_func: removed_groups
  - name: aws
    regexp: 'AKIA[A-Z0-9]{16}'
  - name: lower
    regexp: '[a-z]+'
sets:
  - name: sec
    patterns: [url, aws, overrun, lower]
    regexps: ['xox[bp]-[0-9]+']
    match_any: sec_match_any
    match_all: sec_match_all
    scan_any: sec_scan_any
    scan_all: sec_scan_all
    find: sec_find
`

// diffInputs are (piece, repeat) pairs: each driver builds the input itself,
// so the long ones are not literals. All ASCII, no quote or backslash.
var diffInputs = []struct {
	piece string
	n     int
}{
	{"x http://a.b/c y https://d/ z http://q/", 1},
	{"baaacaab", 1},
	{"ab", 1},
	{"a", 5000}, // arms `a*b|a`'s notes; trips the Backtracking find's budget
	{"AKIA0123456789ABCDEF http://a.b/ abc xoxb-12 aab", 1},
	{"", 1},
	{"xy x xxy xby", 1},
	{"http://x.y/", 1},
	{"ab", 1500},
}

func (d diffOp) String() string {
	if d.kind == "I" {
		return fmt.Sprintf("%s %s inputs %d,%d", d.kind, d.fn, d.in, d.in2)
	}
	return fmt.Sprintf("%s %s input %d", d.kind, d.fn, d.in)
}

// diffOp is one operation: M match, F find, G groups, R find stopped after
// one match and resumed, I two finds interleaved, S set find, SA/SL scan_any
// / scan_all, MA/ML match_any / match_all.
type diffOp struct {
	kind, fn string
	in, in2  int
}

var (
	diffFinds  = []string{"url_find", "empty_find", "overrun_find", "bt_find"}
	diffGroups = map[string]int{"url_groups": 4, "empty_groups": 2, "removed_groups": 3}
	// diffMembers is the set's members by id: a top-level pattern's index,
	// then the set's own regexp.
	diffMembers = []struct {
		id int
		re string
	}{
		{0, `(?<scheme>https?)://(?<host>[a-z.]+)/([a-z/]*)`},
		{2, `a*b|a`},
		{5, `AKIA[A-Z0-9]{16}`},
		{6, `[a-z]+`},
		{7, `xox[bp]-[0-9]+`},
	}
	diffRegexps = map[string]string{
		"url": `(?<scheme>https?)://(?<host>[a-z.]+)/([a-z/]*)`, "empty": `(a*)`, "overrun": `a*b|a`,
		"bt": `(?:a|b)*a(?:a|b){12}c|a`, "removed": `(x)(?:(b){0})y`,
	}
)

func diffOps() []diffOp {
	var ops []diffOp
	groups := slices.Sorted(func(yield func(string) bool) {
		for g := range diffGroups {
			if !yield(g) {
				return
			}
		}
	})
	for i := range diffInputs {
		ops = append(ops, diffOp{kind: "M", fn: "url_match", in: i})
		for _, f := range diffFinds {
			ops = append(ops, diffOp{kind: "F", fn: f, in: i})
		}
		for _, g := range groups {
			ops = append(ops, diffOp{kind: "G", fn: g, in: i})
		}
		for _, k := range []string{"S", "SA", "SL", "MA", "ML"} {
			ops = append(ops, diffOp{kind: k, fn: "sec", in: i})
		}
	}
	ops = append(ops,
		diffOp{kind: "R", fn: "url_find", in: 0}, diffOp{kind: "R", fn: "empty_find", in: 1},
		diffOp{kind: "R", fn: "overrun_find", in: 3},
		diffOp{kind: "I", fn: "url_find", in: 0, in2: 4}, diffOp{kind: "I", fn: "empty_find", in: 1, in2: 3})
	return ops
}

const (
	diffBasis = uint32(2166136261)
	diffNone  = uint32(0xFFFFFFFF)
)

func diffMix(h, x uint32) uint32 { return (h ^ x) * 16777619 }

func diffMixAll(xs ...uint32) uint32 {
	h := diffBasis
	for _, x := range xs {
		h = diffMix(h, x)
	}
	return h
}

func diffInput(i int) []byte { return []byte(strings.Repeat(diffInputs[i].piece, diffInputs[i].n)) }

// diffOracle is each operation's hash computed from Go's regexp.
func diffOracle(op diffOp) uint32 {
	in := diffInput(op.in)
	stem := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(op.fn, "_find"), "_groups"), "_match")
	findHash := func(ms [][]int) uint32 {
		h := diffBasis
		for _, m := range ms {
			h = diffMix(diffMix(h, uint32(m[0])), uint32(m[1]))
		}
		return diffMix(h, uint32(len(ms)))
	}
	members := func(whole bool) []uint32 {
		var ids []uint32
		for _, m := range diffMembers {
			re := m.re
			if whole {
				re = `\A(?:` + re + `)\z`
			}
			if regexp.MustCompile(re).Match(in) {
				ids = append(ids, uint32(m.id))
			}
		}
		return ids
	}
	listHash := func(ids []uint32) uint32 {
		h := diffBasis
		for _, id := range ids {
			h = diffMix(h, id)
		}
		return diffMix(h, uint32(len(ids)))
	}
	switch op.kind {
	case "M":
		if regexp.MustCompile(`\A(?:` + diffRegexps[stem] + `)\z`).Match(in) {
			return diffMixAll(uint32(len(in)))
		}
		return diffMixAll(diffNone)
	case "F", "R":
		return findHash(regexp.MustCompile(diffRegexps[stem]).FindAllIndex(in, -1))
	case "I":
		re := regexp.MustCompile(diffRegexps[stem])
		a, b := re.FindAllIndex(in, -1), re.FindAllIndex(diffInput(op.in2), -1)
		h, n := diffBasis, 0
		for k := 0; k < len(a) || k < len(b); k++ {
			for _, ms := range [][][]int{a, b} {
				if k < len(ms) {
					h = diffMix(diffMix(h, uint32(ms[k][0])), uint32(ms[k][1]))
					n++
				}
			}
		}
		return diffMix(h, uint32(n))
	case "G":
		h := diffBasis
		ms := regexp.MustCompile(diffRegexps[stem]).FindAllSubmatchIndex(in, -1)
		for _, m := range ms {
			for g := 0; g < len(m)/2; g++ {
				if m[2*g] < 0 {
					h = diffMix(diffMix(h, 0), 0)
				} else {
					h = diffMix(diffMix(h, uint32(m[2*g]+1)), uint32(m[2*g+1]+1))
				}
			}
		}
		return diffMix(h, uint32(len(ms)))
	case "S":
		var sum, n uint32
		for _, m := range diffMembers {
			for _, loc := range regexp.MustCompile(m.re).FindAllIndex(in, -1) {
				sum += diffMixAll(uint32(m.id), uint32(loc[0]), uint32(loc[1]))
				n++
			}
		}
		return diffMixAll(sum, n)
	case "SL":
		return listHash(members(false))
	case "ML":
		return listHash(members(true))
	case "SA":
		return diffMixAll(map[bool]uint32{true: 1, false: 0}[len(members(false)) > 0])
	case "MA":
		return diffMixAll(map[bool]uint32{true: 1, false: 0}[len(members(true)) > 0])
	}
	panic("diffOracle: unknown op " + op.kind)
}

// diffInputsLiteral writes the inputs as `{piece, n}` pairs in a C-like
// syntax every driver language reads (a string literal and an integer).
func diffInputsLiteral(open, sep, close string) string {
	var parts []string
	for _, in := range diffInputs {
		parts = append(parts, open+strconv.Quote(in.piece)+sep+strconv.Itoa(in.n)+close)
	}
	return strings.Join(parts, ", ")
}

// ── Go ──────────────────────────────────────────────────────────────────────

func diffGoDriver() string {
	var b strings.Builder
	b.WriteString(`//go:build wasip1

package main

import (
	"fmt"
	"iter"
	"slices"
	"strings"
)

const basis, none, errV = uint32(2166136261), uint32(0xFFFFFFFF), uint32(0xFFFFFFFE)

func mix(h, x uint32) uint32 { return (h ^ x) * 16777619 }

var inputs = []struct {
	p string
	n int
}{` + diffInputsLiteral("{", ", ", "}") + `}

func in(i int) []byte { return []byte(strings.Repeat(inputs[i].p, inputs[i].n)) }

func ids(seq iter.Seq[int], err error) ([]uint32, bool) {
	if err != nil {
		return nil, false
	}
	var out []uint32
	for id := range seq {
		out = append(out, uint32(id))
	}
	slices.Sort(out)
	return out, true
}

func list(xs []uint32, ok bool) uint32 {
	if !ok {
		return mix(basis, errV)
	}
	h := basis
	for _, x := range xs {
		h = mix(h, x)
	}
	return mix(h, uint32(len(xs)))
}

func one(id int, ok bool, err error, all []uint32) uint32 {
	switch {
	case err != nil:
		return mix(basis, errV)
	case !ok:
		return mix(basis, 0)
	case slices.Contains(all, uint32(id)):
		return mix(basis, 1)
	}
	return mix(basis, 2)
}

func M_url_match(x []byte) uint32 {
	end, ok, err := url_match(x)
	switch {
	case err != nil:
		return mix(basis, errV)
	case !ok:
		return mix(basis, none)
	}
	return mix(basis, uint32(end))
}

func S_sec(x []byte) uint32 {
	it := sec_find(x, 0)
	var sum, n uint32
	for m := range it.Matches() {
		sum += mix(mix(mix(basis, uint32(m.PatternID)), uint32(m.Start)), uint32(m.End))
		n++
	}
	h := mix(mix(basis, sum), n)
	if it.Err() != nil {
		h = mix(h, errV)
	}
	return h
}
func SL_sec(x []byte) uint32 { return list(ids(sec_scan_all(x, 0))) }
func ML_sec(x []byte) uint32 { return list(ids(sec_match_all(x))) }
func SA_sec(x []byte) uint32 {
	all, _ := ids(sec_scan_all(x, 0))
	id, ok, err := sec_scan_any(x, 0)
	return one(id, ok, err, all)
}
func MA_sec(x []byte) uint32 {
	all, _ := ids(sec_match_all(x))
	id, ok, err := sec_match_any(x)
	return one(id, ok, err, all)
}
`)
	for _, f := range diffFinds {
		fmt.Fprintf(&b, `
func F_%[1]s(x []byte) uint32 {
	h, n := basis, uint32(0)
	it := %[1]s(x, 0)
	for s, e := range it.Matches() {
		h, n = mix(mix(h, uint32(s)), uint32(e)), n+1
	}
	if it.Err() != nil {
		h = mix(h, errV)
	}
	return mix(h, n)
}

func R_%[1]s(x []byte) uint32 {
	h, n := basis, uint32(0)
	it := %[1]s(x, 0)
	for s, e := range it.Matches() {
		h, n = mix(mix(h, uint32(s)), uint32(e)), n+1
		break
	}
	for s, e := range it.Matches() {
		h, n = mix(mix(h, uint32(s)), uint32(e)), n+1
	}
	if it.Err() != nil {
		h = mix(h, errV)
	}
	return mix(h, n)
}

func I_%[1]s(a, b []byte) uint32 {
	h, n := basis, uint32(0)
	na, sa := iter.Pull2(%[1]s(a, 0).Matches())
	defer sa()
	nb, sb := iter.Pull2(%[1]s(b, 0).Matches())
	defer sb()
	for {
		s, e, ok := na()
		if ok {
			h, n = mix(mix(h, uint32(s)), uint32(e)), n+1
		}
		s2, e2, ok2 := nb()
		if ok2 {
			h, n = mix(mix(h, uint32(s2)), uint32(e2)), n+1
		}
		if !ok && !ok2 {
			return mix(h, n)
		}
	}
}
`, f)
	}
	for g := range diffGroups {
		fmt.Fprintf(&b, `
func G_%[1]s(x []byte) uint32 {
	h, n := basis, uint32(0)
	it := %[1]s(x, 0)
	for m := range it.Matches() {
		for _, sp := range m {
			if sp.Ok {
				h = mix(mix(h, uint32(sp.Start+1)), uint32(sp.End+1))
			} else {
				h = mix(mix(h, 0), 0)
			}
		}
		n++
	}
	if it.Err() != nil {
		h = mix(h, errV)
	}
	return mix(h, n)
}
`, g)
	}
	b.WriteString("\nfunc main() {\n")
	for _, op := range diffOps() {
		if op.kind == "I" {
			fmt.Fprintf(&b, "\tfmt.Println(I_%s(in(%d), in(%d)))\n", op.fn, op.in, op.in2)
		} else {
			fmt.Fprintf(&b, "\tfmt.Println(%s_%s(in(%d)))\n", op.kind, op.fn, op.in)
		}
	}
	b.WriteString("}\n")
	return b.String()
}

// ── Rust ────────────────────────────────────────────────────────────────────

func diffRustDriver() string {
	var b strings.Builder
	b.WriteString(`include!("stubs.rs");

const BASIS: u32 = 2166136261;
const NONE: u32 = 0xFFFFFFFF;
const ERR: u32 = 0xFFFFFFFE;

fn mix(h: u32, x: u32) -> u32 { (h ^ x).wrapping_mul(16777619) }

const INPUTS: &[(&str, usize)] = &[` + diffInputsLiteral("(", ", ", ")") + `];

fn input(i: usize) -> Vec<u8> { INPUTS[i].0.repeat(INPUTS[i].1).into_bytes() }

fn list(r: Option<Vec<u32>>) -> u32 {
    match r {
        None => mix(BASIS, ERR),
        Some(mut xs) => {
            xs.sort();
            let mut h = BASIS;
            for x in &xs { h = mix(h, *x); }
            mix(h, xs.len() as u32)
        }
    }
}

fn one(r: rx::Result<Option<i32>>, all: &Option<Vec<u32>>) -> u32 {
    match r {
        Err(_) => mix(BASIS, ERR),
        Ok(None) => mix(BASIS, 0),
        Ok(Some(id)) => mix(BASIS, if all.as_ref().map_or(false, |a| a.contains(&(id as u32))) { 1 } else { 2 }),
    }
}

fn scan_all(x: &[u8]) -> Option<Vec<u32>> { rx::sec_scan_all(x, 0).ok().map(|it| it.map(|id| id as u32).collect()) }
fn match_all(x: &[u8]) -> Option<Vec<u32>> { rx::sec_match_all(x).ok().map(|it| it.map(|id| id as u32).collect()) }

fn m_url_match(x: &[u8]) -> u32 {
    match rx::url_match(x) {
        Err(_) => mix(BASIS, ERR),
        Ok(None) => mix(BASIS, NONE),
        Ok(Some(end)) => mix(BASIS, end as u32),
    }
}

fn s_sec(x: &[u8]) -> u32 {
    let (mut sum, mut n, mut err) = (0u32, 0u32, false);
    for m in rx::sec_find(x, 0) {
        match m {
            Ok(m) => {
                sum = sum.wrapping_add(mix(mix(mix(BASIS, m.pattern_id as u32), m.start as u32), m.end as u32));
                n += 1;
            }
            Err(_) => { err = true; break; }
        }
    }
    let h = mix(mix(BASIS, sum), n);
    if err { mix(h, ERR) } else { h }
}
fn sl_sec(x: &[u8]) -> u32 { list(scan_all(x)) }
fn ml_sec(x: &[u8]) -> u32 { list(match_all(x)) }
fn sa_sec(x: &[u8]) -> u32 { one(rx::sec_scan_any(x, 0), &scan_all(x)) }
fn ma_sec(x: &[u8]) -> u32 { one(rx::sec_match_any(x), &match_all(x)) }

fn spans<I: Iterator<Item = rx::Result<(usize, usize)>>>(it: &mut I, h: &mut u32, n: &mut u32, first_only: bool) -> bool {
    while let Some(m) = it.next() {
        match m {
            Ok((s, e)) => { *h = mix(mix(*h, s as u32), e as u32); *n += 1; }
            Err(_) => { *h = mix(*h, ERR); return false; }
        }
        if first_only { break; }
    }
    true
}
`)
	for _, f := range diffFinds {
		fmt.Fprintf(&b, `
fn f_%[1]s(x: &[u8]) -> u32 {
    let (mut h, mut n) = (BASIS, 0u32);
    spans(&mut rx::%[1]s(x, 0), &mut h, &mut n, false);
    mix(h, n)
}
fn r_%[1]s(x: &[u8]) -> u32 {
    let (mut h, mut n) = (BASIS, 0u32);
    let mut it = rx::%[1]s(x, 0);
    if spans(&mut it, &mut h, &mut n, true) { spans(&mut it, &mut h, &mut n, false); }
    mix(h, n)
}
fn i_%[1]s(a: &[u8], b: &[u8]) -> u32 {
    let (mut h, mut n) = (BASIS, 0u32);
    let (mut ia, mut ib) = (rx::%[1]s(a, 0), rx::%[1]s(b, 0));
    loop {
        let x = ia.next();
        if let Some(Ok((s, e))) = &x { h = mix(mix(h, *s as u32), *e as u32); n += 1; }
        let y = ib.next();
        if let Some(Ok((s, e))) = &y { h = mix(mix(h, *s as u32), *e as u32); n += 1; }
        if x.is_none() && y.is_none() { return mix(h, n); }
    }
}
`, f)
	}
	for g := range diffGroups {
		fmt.Fprintf(&b, `
fn g_%[1]s(x: &[u8]) -> u32 {
    let (mut h, mut n) = (BASIS, 0u32);
    for m in rx::%[1]s(x, 0) {
        match m {
            Ok(gs) => {
                for g in gs {
                    match g {
                        Some(sp) => h = mix(mix(h, sp.start as u32 + 1), sp.end as u32 + 1),
                        None => h = mix(mix(h, 0), 0),
                    }
                }
                n += 1;
            }
            Err(_) => { h = mix(h, ERR); break; }
        }
    }
    mix(h, n)
}
`, g)
	}
	b.WriteString("\nfn main() {\n")
	for _, op := range diffOps() {
		if op.kind == "I" {
			fmt.Fprintf(&b, "    println!(\"{}\", i_%s(&input(%d), &input(%d)));\n", op.fn, op.in, op.in2)
		} else {
			fmt.Fprintf(&b, "    println!(\"{}\", %s_%s(&input(%d)));\n", strings.ToLower(op.kind), op.fn, op.in)
		}
	}
	b.WriteString("}\n")
	return b.String()
}

// ── C (module and component: the same source) ───────────────────────────────

func diffCDriver(header string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `#include "%s"

#define BASIS 2166136261u
#define NONE 0xFFFFFFFFu
#define ERRV 0xFFFFFFFEu

static unsigned mix(unsigned h, unsigned x) { h ^= x; return h * 16777619u; }

static const struct { const char *p; int n; } inputs[] = {%s};

/* Two input buffers, for the interleaved scans; notes for each live scan. */
static char buf_a[8192], buf_b[8192];
static unsigned char notes_a[1 << 20], notes_b[1 << 20];

static size_t build(char *buf, int i) {
    size_t k = 0, l = 0;
    while (inputs[i].p[l]) l++;
    for (int r = 0; r < inputs[i].n; r++)
        for (size_t c = 0; c < l; c++) buf[k++] = inputs[i].p[c];
    return k;
}

static unsigned list(int c, const int *ids) {
    if (c < 0) return mix(BASIS, ERRV);
    int s[16];
    for (int i = 0; i < c; i++) s[i] = ids[i];
    for (int i = 1; i < c; i++) for (int j = i; j > 0 && s[j - 1] > s[j]; j--) { int t = s[j]; s[j] = s[j - 1]; s[j - 1] = t; }
    unsigned h = BASIS;
    for (int i = 0; i < c; i++) h = mix(h, (unsigned)s[i]);
    return mix(h, (unsigned)c);
}

static unsigned one(int id, int c, const int *ids) {
    if (id == RX_ERR_BT_OVERFLOW) return mix(BASIS, ERRV);
    if (id < 0) return mix(BASIS, 0);
    for (int i = 0; i < c; i++) if (ids[i] == id) return mix(BASIS, 1);
    return mix(BASIS, 2);
}

static unsigned M_url_match(const char *x, size_t len) {
    ptrdiff_t r = url_match(x, len);
    if (r == RX_ERR_BT_OVERFLOW) return mix(BASIS, ERRV);
    return mix(BASIS, r < 0 ? NONE : (unsigned)r);
}

static unsigned S_sec(const char *x, size_t len) {
    rx_sec_scanner_t s;
    rx_set_match_t m[SEC_PATTERN_COUNT];
    unsigned sum = 0, n = 0;
    int c;
    if (sec_find_init(&s, x, len, 0) != 0) return 1;
    size_t need = sec_find_notes_bytes(len);
    if (need && need <= sizeof notes_a) sec_find_set_notes(&s, notes_a, sizeof notes_a);
    while ((c = sec_find(&s, m, SEC_PATTERN_COUNT)) > 0)
        for (int k = 0; k < c; k++) { sum += mix(mix(mix(BASIS, (unsigned)m[k].pattern_id), (unsigned)m[k].start), (unsigned)m[k].end); n++; }
    sec_find_free(&s);
    unsigned h = mix(mix(BASIS, sum), n);
    return c < 0 ? mix(h, ERRV) : h;
}
static unsigned SL_sec(const char *x, size_t len) { int ids[SEC_PATTERN_COUNT]; return list(sec_scan_all(x, len, 0, ids), ids); }
static unsigned ML_sec(const char *x, size_t len) { int ids[SEC_PATTERN_COUNT]; return list(sec_match_all(x, len, ids), ids); }
static unsigned SA_sec(const char *x, size_t len) { int ids[SEC_PATTERN_COUNT]; int c = sec_scan_all(x, len, 0, ids); return one(sec_scan_any(x, len, 0), c, ids); }
static unsigned MA_sec(const char *x, size_t len) { int ids[SEC_PATTERN_COUNT]; int c = sec_match_all(x, len, ids); return one(sec_match_any(x, len), c, ids); }
`, header, diffInputsLiteral("{", ", ", "}"))
	for _, f := range diffFinds {
		fmt.Fprintf(&b, `
static void start_%[1]s(rx_%[1]s_iter_t *it, const char *x, size_t len, unsigned char *notes) {
    %[1]s_init(it, x, len, 0);
    size_t need = %[1]s_notes_bytes(len);
    if (need && need <= sizeof notes_a) %[1]s_set_notes(it, notes, sizeof notes_a);
}
/* Up to max matches into (h, n); 0 when finished, 1 when stopped, -1 on error. */
static int step_%[1]s(rx_%[1]s_iter_t *it, unsigned *h, unsigned *n, int max) {
    rx_match_t m;
    for (int k = 0; k < max; k++) {
        int r = %[1]s_next(it, &m);
        if (r < 0) { *h = mix(*h, ERRV); return -1; }
        if (r == 0) return 0;
        *h = mix(mix(*h, (unsigned)m.start), (unsigned)m.end); (*n)++;
    }
    return 1;
}
static unsigned F_%[1]s(const char *x, size_t len) {
    rx_%[1]s_iter_t it; unsigned h = BASIS, n = 0;
    start_%[1]s(&it, x, len, notes_a);
    step_%[1]s(&it, &h, &n, 1 << 30);
    %[1]s_free(&it);
    return mix(h, n);
}
static unsigned R_%[1]s(const char *x, size_t len) {
    rx_%[1]s_iter_t it; unsigned h = BASIS, n = 0;
    start_%[1]s(&it, x, len, notes_a);
    if (step_%[1]s(&it, &h, &n, 1) == 1) step_%[1]s(&it, &h, &n, 1 << 30);
    %[1]s_free(&it);
    return mix(h, n);
}
static unsigned I_%[1]s(const char *a, size_t la, const char *b, size_t lb) {
    rx_%[1]s_iter_t ia, ib; unsigned h = BASIS, n = 0;
    start_%[1]s(&ia, a, la, notes_a);
    start_%[1]s(&ib, b, lb, notes_b);
    int ra = 1, rb = 1;
    while (ra == 1 || rb == 1) {
        if (ra == 1) ra = step_%[1]s(&ia, &h, &n, 1);
        if (rb == 1) rb = step_%[1]s(&ib, &h, &n, 1);
    }
    %[1]s_free(&ia); %[1]s_free(&ib);
    return mix(h, n);
}
`, f)
	}
	for g, ng := range diffGroups {
		fmt.Fprintf(&b, `
static unsigned G_%[1]s(const char *x, size_t len) {
    rx_%[1]s_iter_t it; rx_group_t gs[%[2]d]; unsigned h = BASIS, n = 0; int r;
    %[1]s_init(&it, x, len, 0);
    size_t need = %[1]s_notes_bytes(len);
    if (need && need <= sizeof notes_a) %[1]s_set_notes(&it, notes_a, sizeof notes_a);
    while ((r = %[1]s_next(&it, gs)) == 1) {
        for (int g = 0; g < %[2]d; g++)
            h = gs[g].start < 0 ? mix(mix(h, 0), 0) : mix(mix(h, (unsigned)gs[g].start + 1), (unsigned)gs[g].end + 1);
        n++;
    }
    %[1]s_free(&it);
    if (r < 0) h = mix(h, ERRV);
    return mix(h, n);
}
`, g, ng)
	}
	ops := diffOps()
	fmt.Fprintf(&b, "\nstatic unsigned lines[%d];\nstatic int done;\n\nstatic void compute(void) {\n    size_t la, lb;\n", len(ops))
	for k, op := range ops {
		if op.kind == "I" {
			fmt.Fprintf(&b, "    la = build(buf_a, %d); lb = build(buf_b, %d); lines[%d] = I_%s(buf_a, la, buf_b, lb);\n", op.in, op.in2, k, op.fn)
		} else {
			fmt.Fprintf(&b, "    la = build(buf_a, %d); lines[%d] = %s_%s(buf_a, la);\n", op.in, k, op.kind, op.fn)
		}
	}
	fmt.Fprintf(&b, `    done = 1;
}

__attribute__((export_name("run")))
int run(void) {
    if (!done) compute();
    unsigned h = BASIS;
    for (int k = 0; k < %[1]d; k++) h = mix(h, lines[k]);
    return (int)h;
}

__attribute__((export_name("line")))
int line(int k) {
    if (!done) compute();
    return k >= 0 && k < %[1]d ? (int)lines[k] : 0;
}
`, len(ops))
	return b.String()
}

// ── AssemblyScript ──────────────────────────────────────────────────────────

func diffASDriver() string {
	var b strings.Builder
	b.WriteString(`import * as rx from "./stubs";

const BASIS: u32 = 2166136261;
const NONE: u32 = 0xFFFFFFFF;
const ERRV: u32 = 0xFFFFFFFE;

function mix(h: u32, x: u32): u32 { return (h ^ x) * 16777619; }

const PIECES: string[] = [` + diffASPieces() + `];
const REPS: i32[] = [` + diffASReps() + `];

function input(i: i32): ArrayBuffer { return String.UTF8.encode(PIECES[i].repeat(REPS[i])); }

function list(ids: Array<i32> | null): u32 {
  if (ids == null) return mix(BASIS, ERRV);
  const s = ids.slice(0);
  s.sort((a: i32, b: i32): i32 => a - b);
  let h = BASIS;
  for (let i = 0; i < s.length; i++) h = mix(h, u32(s[i]));
  return mix(h, u32(s.length));
}

function one(id: i32, ids: Array<i32> | null): u32 {
  if (id == rx.RX_ERR_BT_OVERFLOW) return mix(BASIS, ERRV);
  if (id < 0) return mix(BASIS, 0);
  if (ids != null && ids.includes(id)) return mix(BASIS, 1);
  return mix(BASIS, 2);
}

function M_url_match(x: ArrayBuffer): u32 {
  const r = rx.url_match(x);
  if (r == rx.RX_ERR_BT_OVERFLOW) return mix(BASIS, ERRV);
  return mix(BASIS, r < 0 ? NONE : u32(r));
}

function S_sec(x: ArrayBuffer): u32 {
  const it = rx.sec_find(x, 0);
  let sum: u32 = 0, n: u32 = 0;
  let m = it.next();
  while (m != null) {
    sum += mix(mix(mix(BASIS, u32(m.patternId)), m.start), m.end);
    n++;
    m = it.next();
  }
  const h = mix(mix(BASIS, sum), n);
  return it.err() != 0 ? mix(h, ERRV) : h;
}
function SL_sec(x: ArrayBuffer): u32 { return list(rx.sec_scan_all(x, 0)); }
function ML_sec(x: ArrayBuffer): u32 { return list(rx.sec_match_all(x)); }
function SA_sec(x: ArrayBuffer): u32 { return one(rx.sec_scan_any(x, 0), rx.sec_scan_all(x, 0)); }
function MA_sec(x: ArrayBuffer): u32 { return one(rx.sec_match_any(x), rx.sec_match_all(x)); }

// h and n of a scan in progress, through globals: an AS function returns one value.
let H: u32 = 0;
let N: u32 = 0;
`)
	for _, f := range diffFinds {
		fmt.Fprintf(&b, `
// Up to max matches into H, N; 0 finished, 1 stopped, -1 error.
function step_%[1]s(it: rx.%[1]s_iter, max: i32): i32 {
  for (let k = 0; k < max; k++) {
    const p = it.next();
    if (p == -2) { H = mix(H, ERRV); return -1; }
    if (p < 0) return 0;
    H = mix(mix(H, u32(p >> 32)), u32(p & 0xFFFFFFFF));
    N++;
  }
  return 1;
}
function F_%[1]s(x: ArrayBuffer): u32 {
  H = BASIS; N = 0;
  step_%[1]s(rx.%[1]s(x, 0), 1 << 30);
  return mix(H, N);
}
function R_%[1]s(x: ArrayBuffer): u32 {
  H = BASIS; N = 0;
  const it = rx.%[1]s(x, 0);
  if (step_%[1]s(it, 1) == 1) step_%[1]s(it, 1 << 30);
  return mix(H, N);
}
function I_%[1]s(a: ArrayBuffer, b: ArrayBuffer): u32 {
  H = BASIS; N = 0;
  const ia = rx.%[1]s(a, 0), ib = rx.%[1]s(b, 0);
  let ra = 1, rb = 1;
  while (ra == 1 || rb == 1) {
    if (ra == 1) ra = step_%[1]s(ia, 1);
    if (rb == 1) rb = step_%[1]s(ib, 1);
  }
  return mix(H, N);
}
`, f)
	}
	for g, ng := range diffGroups {
		fmt.Fprintf(&b, `
function G_%[1]s(x: ArrayBuffer): u32 {
  let h = BASIS, n: u32 = 0;
  const it = rx.%[1]s(x, 0);
  let p = it.next();
  while (p != 0 && p != rx.RX_ITER_ERROR) {
    for (let g = 0; g < %[2]d; g++) {
      const s = load<i32>(usize(p) + usize(8 * g)), e = load<i32>(usize(p) + usize(8 * g + 4));
      h = s < 0 ? mix(mix(h, 0), 0) : mix(mix(h, u32(s) + 1), u32(e) + 1);
    }
    n++;
    p = it.next();
  }
  if (p == rx.RX_ITER_ERROR) h = mix(h, ERRV);
  return mix(h, n);
}
`, g, ng)
	}
	ops := diffOps()
	fmt.Fprintf(&b, "\nconst LINES = new StaticArray<u32>(%d);\nlet computed = false;\n\nfunction compute(): void {\n", len(ops))
	for k, op := range ops {
		if op.kind == "I" {
			fmt.Fprintf(&b, "  LINES[%d] = I_%s(input(%d), input(%d));\n", k, op.fn, op.in, op.in2)
		} else {
			fmt.Fprintf(&b, "  LINES[%d] = %s_%s(input(%d));\n", k, op.kind, op.fn, op.in)
		}
	}
	fmt.Fprintf(&b, `  computed = true;
}

export function run(): i32 {
  if (!computed) compute();
  let h = BASIS;
  for (let k = 0; k < %[1]d; k++) h = mix(h, LINES[k]);
  return i32(h);
}

export function line(k: i32): i32 {
  if (!computed) compute();
  return k >= 0 && k < %[1]d ? i32(LINES[k]) : 0;
}
`, len(ops))
	return b.String()
}

func diffASPieces() string {
	var parts []string
	for _, in := range diffInputs {
		parts = append(parts, strconv.Quote(in.piece))
	}
	return strings.Join(parts, ", ")
}

func diffASReps() string {
	var parts []string
	for _, in := range diffInputs {
		parts = append(parts, strconv.Itoa(in.n))
	}
	return strings.Join(parts, ", ")
}

// ── JavaScript (and TypeScript, transpiled to it) ───────────────────────────

func diffJSDriver() string {
	var b strings.Builder
	b.WriteString(`import { readFile } from 'node:fs/promises';
import * as rx from './stubs.js';
await rx.init(await readFile(new URL('./rx.wasm', import.meta.url)));

const BASIS = 2166136261, NONE = 0xFFFFFFFF, ERRV = 0xFFFFFFFE;
const mix = (h, x) => Math.imul((h ^ x) >>> 0, 16777619) >>> 0;
const INPUTS = [` + diffInputsLiteral("[", ", ", "]") + `];
const input = (i) => INPUTS[i][0].repeat(INPUTS[i][1]);

function guard(f) { try { return f(); } catch (e) { if (e instanceof Error && !(e instanceof RangeError)) return mix(BASIS, ERRV); throw e; } }
function list(ids) { const s = [...ids].sort((a, b) => a - b); let h = BASIS; for (const x of s) h = mix(h, x); return mix(h, s.length); }
function one(id, ids) { return mix(BASIS, id === null ? 0 : ids.includes(id) ? 1 : 2); }
function spans(it, max, st) {
  for (let k = 0; k < max; k++) {
    let r;
    try { r = it.next(); } catch (e) { st.h = mix(st.h, ERRV); return -1; }
    if (r.done) return 0;
    st.h = mix(mix(st.h, r.value[0]), r.value[1]); st.n++;
  }
  return 1;
}
const F = (f, x) => { const st = { h: BASIS, n: 0 }; spans(f(x), Infinity, st); return mix(st.h, st.n); };
const R = (f, x) => { const st = { h: BASIS, n: 0 }; const it = f(x); if (spans(it, 1, st) === 1) spans(it, Infinity, st); return mix(st.h, st.n); };
const I = (f, a, b) => {
  const st = { h: BASIS, n: 0 }; const ia = f(a), ib = f(b); let ra = 1, rb = 1;
  while (ra === 1 || rb === 1) { if (ra === 1) ra = spans(ia, 1, st); if (rb === 1) rb = spans(ib, 1, st); }
  return mix(st.h, st.n);
};
const G = (f, x) => guard(() => {
  let h = BASIS, n = 0;
  for (const gs of f(x)) { for (const g of gs) h = g === null ? mix(mix(h, 0), 0) : mix(mix(h, g[0] + 1), g[1] + 1); n++; }
  return mix(h, n);
});
const M = (f, x) => guard(() => { const r = f(x); return mix(BASIS, r === null ? NONE : r); });
const S = (x) => guard(() => {
  let sum = 0, n = 0;
  for (const m of rx.sec_find(x)) { sum = (sum + mix(mix(mix(BASIS, m.patternId), m.start), m.end)) >>> 0; n++; }
  return mix(mix(BASIS, sum), n);
});
const SL = (x) => guard(() => list(rx.sec_scan_all(x)));
const ML = (x) => guard(() => list(rx.sec_match_all(x)));
const SA = (x) => guard(() => one(rx.sec_scan_any(x), rx.sec_scan_all(x)));
const MA = (x) => guard(() => one(rx.sec_match_any(x), rx.sec_match_all(x)));
const out = [];
`)
	for _, op := range diffOps() {
		switch op.kind {
		case "I":
			fmt.Fprintf(&b, "out.push(I(rx.%s, input(%d), input(%d)));\n", op.fn, op.in, op.in2)
		case "S", "SL", "ML", "SA", "MA":
			fmt.Fprintf(&b, "out.push(%s(input(%d)));\n", op.kind, op.in)
		default:
			fmt.Fprintf(&b, "out.push(%s(rx.%s, input(%d)));\n", op.kind, op.fn, op.in)
		}
	}
	b.WriteString("console.log(out.join('\\n'));\n")
	return b.String()
}

// ── the test ────────────────────────────────────────────────────────────────

func TestStubRuntimeDifferential(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a program per stub language; skipped in -short")
	}
	if _, err := exec.LookPath("wasmtime"); err != nil {
		t.Skip("wasmtime not on PATH")
	}
	ops := diffOps()
	want := make([]uint32, len(ops))
	for k, op := range ops {
		want[k] = diffOracle(op)
	}
	bin := filepath.Join(t.TempDir(), "regexped")
	if out, err := exec.Command("go", "build", "-o", bin, "github.com/qrdl/regexped").CombinedOutput(); err != nil {
		t.Fatalf("build regexped: %v\n%s", err, out)
	}
	merge := wasmMergeForTest(t)
	// compare checks a leg's per-operation hashes, naming each that differs.
	compare := func(t *testing.T, got []uint32) {
		t.Helper()
		if len(got) != len(ops) {
			t.Fatalf("%d results, want %d", len(got), len(ops))
		}
		bad := 0
		for k, op := range ops {
			if got[k] != want[k] {
				t.Errorf("%v: %d, Go's regexp gives %d", op, got[k], want[k])
				if bad++; bad > 20 {
					t.Fatal("too many differences")
				}
			}
		}
	}
	parse := func(t *testing.T, out []byte) []uint32 {
		t.Helper()
		var got []uint32
		for _, f := range strings.Fields(string(out)) {
			v, err := strconv.ParseUint(f, 10, 32)
			if err != nil {
				t.Fatalf("driver printed %q:\n%s", f, out)
			}
			got = append(got, uint32(v))
		}
		return got
	}
	// invoked compares a C or AssemblyScript build through its run() export
	// and, when that differs, line(k) for each operation.
	// A core module's export is invoked by name with its arguments after the
	// module, a component's as an expression.
	invoked := func(t *testing.T, dir, wasm string, comp bool) {
		t.Helper()
		call := func(name string, args ...int) uint32 {
			argv := []string{"run", "--invoke", name, wasm}
			var as []string
			for _, a := range args {
				as = append(as, strconv.Itoa(a))
			}
			expr := name + "(" + strings.Join(as, ", ") + ")"
			if comp {
				argv = []string{"run", "--invoke", expr, wasm}
			} else {
				argv = append(argv, as...)
			}
			cmd := exec.Command("wasmtime", argv...)
			cmd.Dir = dir
			out, err := cmd.Output() // stderr carries an "experimental" warning for a core module's result
			if err != nil {
				t.Fatalf("wasmtime --invoke %s: %v\n%s", expr, err, out)
			}
			v, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
			if err != nil {
				t.Fatalf("wasmtime --invoke %s printed %q", expr, out)
			}
			return uint32(v)
		}
		total := diffBasis
		for _, w := range want {
			total = diffMix(total, w)
		}
		if call("run") == total {
			return
		}
		got := make([]uint32, len(ops))
		for k := range ops {
			got[k] = call("line", k)
		}
		compare(t, got)
	}
	setup := func(t *testing.T, cfg string, files map[string]string) string {
		t.Helper()
		dir := t.TempDir()
		files["regexped.yaml"] = cfg
		for name, body := range files {
			if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		run(t, dir, nil, bin, "compile", "--config=regexped.yaml")
		run(t, dir, nil, bin, "generate", "--config=regexped.yaml")
		return dir
	}
	embedded := func(stub string) string {
		return strings.Replace(diffConfig, "output: merged.wasm\n",
			"output: merged.wasm\nstub_file: "+stub+"\nwasm_merge_path: '"+merge+"'\n", 1)
	}
	component := func(stub, extra string) string {
		return strings.Replace(diffConfig, "output: merged.wasm\n",
			"wasm_format: component\noutput: composed.wasm\nstub_file: "+stub+"\n"+extra, 1)
	}
	needMerge := func(t *testing.T) {
		t.Helper()
		if merge == "" {
			t.Skip("wasm-merge not found")
		}
	}

	t.Run("go", func(t *testing.T) {
		needMerge(t)
		dir := setup(t, embedded("stubs.go")+"go_package: main\n", map[string]string{
			"go.mod": "module drive\n\ngo 1.23\n", "main.go": diffGoDriver()})
		run(t, dir, []string{"GOOS=wasip1", "GOARCH=wasm"}, "go", "build", "-o", "main.wasm", ".")
		run(t, dir, nil, bin, "merge", "--config=regexped.yaml", "--main=main.wasm", "rx.wasm")
		out, err := exec.Command("wasmtime", "run", filepath.Join(dir, "merged.wasm")).CombinedOutput()
		if err != nil {
			t.Fatalf("wasmtime: %v\n%s", err, out)
		}
		compare(t, parse(t, out))
	})

	rustLeg := func(t *testing.T, cfg, target string, deps string, final string) {
		t.Helper()
		if _, err := exec.LookPath("cargo"); err != nil {
			t.Skip("cargo not on PATH")
		}
		dir := setup(t, cfg, map[string]string{
			"Cargo.toml": "[package]\nname = \"drive\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[[bin]]\nname = \"drive\"\npath = \"main.rs\"\n\n[dependencies]\n" + deps,
			"main.rs":    diffRustDriver()})
		cmd := exec.Command("cargo", "build", "--offline", "--release", "--target", target)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			if strings.Contains(string(out), "target may not be installed") || strings.Contains(string(out), "offline") {
				t.Skipf("cannot build for %s offline:\n%s", target, out)
			}
			t.Fatalf("cargo build: %v\n%s", err, out)
		}
		run(t, dir, nil, bin, "merge", "--config=regexped.yaml", "--main=target/"+target+"/release/drive.wasm", "rx.wasm")
		out, err := exec.Command("wasmtime", "run", filepath.Join(dir, final)).CombinedOutput()
		if err != nil {
			t.Fatalf("wasmtime: %v\n%s", err, out)
		}
		compare(t, parse(t, out))
	}
	t.Run("rust", func(t *testing.T) {
		needMerge(t)
		rustLeg(t, embedded("stubs.rs"), "wasm32-wasip1", "", "merged.wasm")
	})
	t.Run("rust-component", func(t *testing.T) {
		for _, tool := range []string{"wasm-tools", "wac"} {
			if _, err := exec.LookPath(tool); err != nil {
				t.Skipf("%s not on PATH", tool)
			}
		}
		rustLeg(t, component("stubs.rs", ""), "wasm32-wasip2", "wit-bindgen = \"0.61\"\n", "composed.wasm")
	})

	cLeg := func(t *testing.T, cfg, header, cfile string, comp bool) {
		t.Helper()
		clang := wasiClang(t)
		if clang == "" {
			t.Skip("no clang that targets wasm32-wasi")
		}
		dir := setup(t, cfg, map[string]string{"guest.c": diffCDriver(header)})
		if !comp {
			run(t, dir, nil, clang, "--target=wasm32-wasi", "-nostdlib", "-Wl,--no-entry",
				"-DRX_SET_CACHE=0", "-o", "guest.wasm", "guest.c", cfile)
			run(t, dir, nil, bin, "merge", "--config=regexped.yaml", "--main=guest.wasm", "rx.wasm")
			invoked(t, dir, "merged.wasm", false)
			return
		}
		cw, err := os.ReadFile(filepath.Join(dir, "wit", "consumer.wit"))
		if err != nil {
			t.Fatalf("generate wrote no consumer world: %v", err)
		}
		end := strings.LastIndex(string(cw), "}")
		world := string(cw[:end]) + "    export run: func() -> s32;\n    export line: func(k: s32) -> s32;\n" + string(cw[end:])
		if err := os.WriteFile(filepath.Join(dir, "wit", "consumer.wit"), []byte(world), 0o644); err != nil {
			t.Fatal(err)
		}
		m := regexp.MustCompile(`world (\S+) \{`).FindStringSubmatch(world)
		if m == nil {
			t.Fatalf("no world in the consumer WIT:\n%s", world)
		}
		run(t, dir, nil, clang, "--target=wasm32-wasi", "-nostdlib", "-Wl,--no-entry",
			"-DRX_SET_CACHE=0", "-o", "core.wasm", "guest.c", cfile)
		run(t, dir, nil, "wasm-tools", "component", "embed", "wit", "core.wasm", "--world", m[1], "-o", "embedded.wasm")
		run(t, dir, nil, "wasm-tools", "component", "new", "embedded.wasm", "-o", "guest.wasm")
		run(t, dir, nil, bin, "merge", "--config=regexped.yaml", "--main=guest.wasm", "rx.wasm")
		invoked(t, dir, "composed.wasm", true)
	}
	t.Run("c", func(t *testing.T) {
		needMerge(t)
		cLeg(t, embedded("stubs.h"), "stubs.h", "stubs.c", false)
	})
	t.Run("c-component", func(t *testing.T) {
		for _, tool := range []string{"wasm-tools", "wac"} {
			if _, err := exec.LookPath(tool); err != nil {
				t.Skipf("%s not on PATH", tool)
			}
		}
		cLeg(t, component("stub.h", ""), "stub.h", "stub.c", true)
	})

	t.Run("as", func(t *testing.T) {
		needMerge(t)
		asc, err := exec.LookPath("asc")
		if err != nil {
			t.Skip("asc not on PATH")
		}
		dir := setup(t, embedded("stubs.ts")+"stub_type: as\n", map[string]string{"main.ts": diffASDriver()})
		run(t, dir, nil, asc, "main.ts", "--runtime", "stub", "--use", "abort=", "-O2", "-o", "main.wasm")
		run(t, dir, nil, bin, "merge", "--config=regexped.yaml", "--main=main.wasm", "rx.wasm")
		invoked(t, dir, "merged.wasm", false)
	})

	for _, ext := range []string{"js", "ts"} {
		t.Run(ext, func(t *testing.T) {
			if _, err := exec.LookPath("node"); err != nil {
				t.Skip("node not on PATH")
			}
			standalone := strings.Replace(diffConfig, "output: merged.wasm\n", "stub_file: stubs."+ext+"\n", 1)
			dir := setup(t, standalone, map[string]string{"drive.mjs": diffJSDriver()})
			if ext == "ts" {
				src, err := os.ReadFile(filepath.Join(dir, "stubs.ts"))
				if err != nil {
					t.Fatal(err)
				}
				js, err := transpileTS(t, dir, string(src))
				if err != nil {
					t.Skip(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "stubs.js"), []byte(js), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			writeESMPackageJSON(t, dir)
			cmd := exec.Command("node", "drive.mjs")
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("node: %v\n%s", err, out)
			}
			compare(t, parse(t, out))
		})
	}
}
