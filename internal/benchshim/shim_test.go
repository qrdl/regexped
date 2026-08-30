package benchshim

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/qrdl/regexped/internal/utils"
)

// The shim modules are hand-assembled WASM. That makes a structural check
// ("starts with the magic header") worthless — compile/compile_test.go's B15
// note records a module that passed exactly such a check while containing a
// function body that never once type-checked. So the primary test here is a
// real validator, and the secondary ones pin the link-time contract: the
// import and export NAMES the harnesses' Go side looks up by string, where a
// rename fails at instantiation rather than at build.

// shims enumerates every emitter, with the import name it is documented to
// wrap.
var shims = []struct {
	name   string
	fnName string
	build  func() []byte
}{
	{"match", "match", BuildMatch},
	{"find", "find", BuildFind},
	{"groups", "groups", BuildGroups},
}

// wasmValidator locates a WASM validator once per test binary. Copied in shape
// from compile/compile_test.go: this module has no wasmtime dependency
// (CLAUDE.md lists it under tools/ only), so validation shells out.
var wasmValidator = sync.OnceValue(func() []string {
	if p, err := exec.LookPath("wasm-tools"); err == nil {
		return []string{p, "validate"}
	}
	if p, err := exec.LookPath("wasmtime"); err == nil {
		return []string{p, "compile", "-o", os.DevNull}
	}
	return nil
})

// TestShimsValidate type-checks every emitted shim. A missing validator warns
// rather than fails, so a toolchain gap does not block the suite — but a
// machine that HAS the tool cannot miss an invalid module.
func TestShimsValidate(t *testing.T) {
	argv := wasmValidator()
	if argv == nil {
		t.Skip("neither wasm-tools nor wasmtime found in PATH: cannot validate")
	}
	for _, s := range shims {
		t.Run(s.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "shim.wasm")
			if err := os.WriteFile(path, s.build(), 0o600); err != nil {
				t.Fatalf("write module: %v", err)
			}
			cmd := exec.Command(argv[0], append(append([]string{}, argv[1:]...), path)...)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s shim fails %s: %v\n%s", s.name, argv[0], err, out)
			}
		})
	}
}

// TestShimLinkContract pins the names the harness binds by string. The Go side
// supplies clock_time_get and the regexp export as named imports and then
// looks up "bench" and "memory" on the instance; every one of those is a
// runtime lookup, so a typo here is invisible until a benchmark run dies.
func TestShimLinkContract(t *testing.T) {
	for _, s := range shims {
		t.Run(s.name, func(t *testing.T) {
			mod := s.build()
			imports := decodeImports(t, mod)
			want := [][2]string{
				{"wasi_snapshot_preview1", "clock_time_get"},
				{"regexped", s.fnName},
			}
			if len(imports) != len(want) {
				t.Fatalf("imports = %v, want %v", imports, want)
			}
			for i, w := range want {
				if imports[i] != w {
					t.Errorf("import %d = %v, want %v", i, imports[i], w)
				}
			}
			exports := decodeExports(t, mod)
			for _, name := range []string{"memory", "bench"} {
				if _, ok := exports[name]; !ok {
					t.Errorf("missing export %q (have %v)", name, exports)
				}
			}
		})
	}
}

// TestMemoryHoldsTimingsAndScratch covers the one arithmetic invariant in the
// memory layout: the timing array and the 8-byte clock scratch must both fit
// in MemPages, and the scratch must be 8-byte aligned for the i64.load the
// shims emit at align=3. Raising Iters without raising MemPages would
// otherwise silently write samples out of bounds.
func TestMemoryHoldsTimingsAndScratch(t *testing.T) {
	const scratchBytes = 8
	need := TimingsBytes + scratchBytes
	if have := MemPages * 65536; need > have {
		t.Errorf("layout needs %d bytes but MemPages=%d provides %d", need, MemPages, have)
	}
	if TimingsBytes != Iters*4 {
		t.Errorf("TimingsBytes = %d, want %d samples × 4", TimingsBytes, Iters)
	}
	if int32(TimingsBytes) != ClockScratch {
		t.Errorf("ClockScratch = %d, want it to start where the timings end (%d)", ClockScratch, TimingsBytes)
	}
	if ClockScratch%8 != 0 {
		t.Errorf("ClockScratch = %d is not 8-byte aligned; the shims i64.load it at align=3", ClockScratch)
	}
}

// TestComputeStat covers the reducer likelytest's reported p50 comes out of.
// The percentile arm must sort, so the answer cannot depend on sample order,
// and it must clamp rather than run off the end at pct=100.
func TestComputeStat(t *testing.T) {
	// 1..100 ns, deliberately shuffled so an unsorted implementation differs.
	vals := make([]uint32, 100)
	for i := range vals {
		vals[i] = uint32((i*37)%100 + 1)
	}
	data := encodeSamples(vals)

	t.Run("pct 0 is the mean", func(t *testing.T) {
		if got := ComputeStat(data, 0); got != 50 { // (1+…+100)/100 = 50.5, integer-divided
			t.Errorf("ComputeStat(pct=0) = %v, want 50ns", got)
		}
	})
	t.Run("percentiles", func(t *testing.T) {
		for _, c := range []struct {
			pct  int
			want int64
		}{{1, 2}, {50, 51}, {90, 91}, {99, 100}, {100, 100}} {
			if got := ComputeStat(data, c.pct); int64(got) != c.want {
				t.Errorf("ComputeStat(pct=%d) = %v, want %dns", c.pct, got, c.want)
			}
		}
	})
	t.Run("order does not change the answer", func(t *testing.T) {
		asc := make([]uint32, len(vals))
		for i := range asc {
			asc[i] = uint32(i + 1)
		}
		if a, b := ComputeStat(data, 50), ComputeStat(encodeSamples(asc), 50); a != b {
			t.Errorf("shuffled p50 = %v but sorted p50 = %v; the reducer is order-sensitive", a, b)
		}
	})
	t.Run("trailing partial sample is ignored", func(t *testing.T) {
		// len/4 truncates, so three stray bytes must not shift the answer.
		if got := ComputeStat(append(data, 0xFF, 0xFF, 0xFF), 50); int64(got) != 51 {
			t.Errorf("p50 with a partial trailing sample = %v, want 51ns", got)
		}
	})
}

// --------------------------------------------------------------------------
// helpers

func encodeSamples(vals []uint32) []byte {
	b := make([]byte, 4*len(vals))
	for i, v := range vals {
		binary.LittleEndian.PutUint32(b[i*4:], v)
	}
	return b
}

// sectionOf returns the content of the first section with the given id.
func sectionOf(t *testing.T, mod []byte, id byte) []byte {
	t.Helper()
	if len(mod) < 8 || string(mod[:4]) != "\x00asm" {
		t.Fatalf("not a WASM module (len=%d)", len(mod))
	}
	p := 8
	for p < len(mod) {
		sid := mod[p]
		p++
		size, n, err := utils.DecodeULEB128(mod[p:])
		if err != nil {
			t.Fatalf("malformed section size at %d: %v", p, err)
		}
		p += n
		end := p + int(size)
		if end > len(mod) {
			t.Fatalf("section %d claims %d bytes but only %d remain", sid, size, len(mod)-p)
		}
		if sid == id {
			return mod[p:end]
		}
		p = end
	}
	t.Fatalf("no section with id %d", id)
	return nil
}

func readName(t *testing.T, b []byte, p int) (string, int) {
	t.Helper()
	n, w, err := utils.DecodeULEB128(b[p:])
	if err != nil {
		t.Fatalf("malformed name length at %d: %v", p, err)
	}
	p += w
	return string(b[p : p+int(n)]), p + int(n)
}

func decodeImports(t *testing.T, mod []byte) [][2]string {
	t.Helper()
	c := sectionOf(t, mod, 0x02)
	count, p, err := utils.DecodeULEB128(c)
	if err != nil {
		t.Fatalf("malformed import count: %v", err)
	}
	var out [][2]string
	for i := uint64(0); i < count; i++ {
		var mod, name string
		mod, p = readName(t, c, p)
		name, p = readName(t, c, p)
		kind := c[p]
		p++
		if kind != 0x00 {
			t.Fatalf("import %s.%s has kind %d; the shims import only functions", mod, name, kind)
		}
		_, w, err := utils.DecodeULEB128(c[p:]) // type index
		if err != nil {
			t.Fatalf("malformed type index: %v", err)
		}
		p += w
		out = append(out, [2]string{mod, name})
	}
	return out
}

func decodeExports(t *testing.T, mod []byte) map[string]byte {
	t.Helper()
	c := sectionOf(t, mod, 0x07)
	count, p, err := utils.DecodeULEB128(c)
	if err != nil {
		t.Fatalf("malformed export count: %v", err)
	}
	out := make(map[string]byte, count)
	for i := uint64(0); i < count; i++ {
		var name string
		name, p = readName(t, c, p)
		kind := c[p]
		p++
		_, w, err := utils.DecodeULEB128(c[p:]) // index
		if err != nil {
			t.Fatalf("malformed export index: %v", err)
		}
		p += w
		out[name] = kind
	}
	return out
}
