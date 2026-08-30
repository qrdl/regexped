package utils

import (
	"math"
	"os"
	"path/filepath"
	"testing"
)

// The WASM readers in this package all answer the same question — where is it
// safe to put the regexp tables — from a module someone else produced. Their
// happy paths are exercised constantly by every harness that loads a compiled
// module; their REFUSALS were not exercised at all.
//
// That asymmetry matters more here than usual. These functions return an
// address, and every failure mode returns one too: a truncated section, a
// section length that runs off the end, a module that is not WASM. If a
// malformed input yields a plausible-looking address instead of an error, the
// caller places tables over live data and the corruption surfaces somewhere
// else entirely.

// wasmHeader is the eight-byte preamble every module starts with: magic then
// version.
func wasmHeader() []byte {
	return []byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}
}

// section appends one section with an id and a LEB128 length.
func section(out []byte, id byte, content []byte) []byte {
	out = append(out, id)
	out = AppendULEB128(out, uint32(len(content)))
	return append(out, content...)
}

func TestParseDataSectionBytesRejectsNonWasm(t *testing.T) {
	for _, c := range []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"too short to hold a header", []byte{0x00, 'a', 's'}},
		{"right length, wrong magic", []byte("NOTWASM!")},
		{"ELF rather than WASM", []byte{0x7f, 'E', 'L', 'F', 0, 0, 0, 0}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseDataSectionBytes(c.in); err == nil {
				t.Error("accepted something that is not a WASM binary")
			}
		})
	}
}

// TestParseDataSectionBytesNoDataSection: a valid module with no data section
// is not an error — it has no tables to sit above — so the answer is zero and
// a nil error, not a refusal.
func TestParseDataSectionBytesNoDataSection(t *testing.T) {
	// A type section (id 1) holding an empty vector, and nothing else.
	mod := section(wasmHeader(), 1, []byte{0x00})
	got, err := ParseDataSectionBytes(mod)
	if err != nil {
		t.Fatalf("valid module with no data section: %v", err)
	}
	if got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

// TestParseDataSectionBytesTruncatedSection: a section whose declared length
// runs past the end of the module must stop the walk rather than read beyond
// it.
func TestParseDataSectionBytesTruncatedSection(t *testing.T) {
	mod := append(wasmHeader(), 1)               // section id
	mod = append(mod, AppendULEB128(nil, 99)...) // claims 99 bytes
	mod = append(mod, 0x00, 0x01)                // but only two are present
	got, err := ParseDataSectionBytes(mod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 0 {
		t.Errorf("got %d from a truncated module, want 0", got)
	}
}

// TestParseDataSectionBytesFindsActiveSegment builds a data section with one
// active segment at a known offset and checks the reported top is the segment's
// end.
func TestParseDataSectionBytesFindsActiveSegment(t *testing.T) {
	const offset = 4096
	payload := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	var seg []byte
	seg = append(seg, 0x01)                        // one segment
	seg = append(seg, 0x00)                        // active, memory 0
	seg = append(seg, 0x41)                        // i32.const
	seg = AppendSLEB128(seg, offset)               // its operand
	seg = append(seg, 0x0B)                        // end
	seg = AppendULEB128(seg, uint32(len(payload))) // payload length
	seg = append(seg, payload...)

	mod := section(wasmHeader(), 11, seg)
	got, err := ParseDataSectionBytes(mod)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if want := int64(offset + len(payload)); got != want {
		t.Errorf("data top = %d, want %d", got, want)
	}
}

func TestParseMemorySectionShapes(t *testing.T) {
	const pageSize = 65536
	cases := []struct {
		name string
		in   []byte
		want int64
		bad  bool
	}{
		// One memory, flags=0 (min only), min = 2 pages.
		{"single memory, min only", []byte{0x01, 0x00, 0x02}, 2 * pageSize, false},
		// flags=1 means a max follows; the MINIMUM is still what matters,
		// because that is what the runtime reserves without growing.
		{"single memory with a maximum", []byte{0x01, 0x01, 0x03, 0x10}, 3 * pageSize, false},
		// Several memories yield the LARGEST minimum, not their sum: the
		// question being answered is "what address is reserved before anyone
		// grows", and each memory has its own address space.
		{"two memories take the largest minimum", []byte{0x02, 0x00, 0x01, 0x00, 0x02}, 2 * pageSize, false},
		{"no memories", []byte{0x00}, 0, false},
		{"truncated count", []byte{0x80}, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseMemorySection(c.in)
			if c.bad {
				if err == nil {
					t.Error("accepted a malformed memory section")
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
			}
		})
	}
}

func TestParseGlobalSectionRejectsMalformed(t *testing.T) {
	for _, c := range []struct {
		name string
		in   []byte
	}{
		{"truncated count", []byte{0x80}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseGlobalSection(c.in); err == nil {
				t.Errorf("accepted a malformed global section: %v", c.in)
			}
		})
	}
	// A count that promises more globals than the section holds is TOLERATED:
	// the walk simply stops and reports what it read. That is deliberate
	// leniency about a section this reader only consults for an upper bound,
	// so it is pinned as behaviour rather than asserted to be an error.
	if _, err := ParseGlobalSection([]byte{0x01}); err != nil {
		t.Errorf("a short global section should be tolerated, got %v", err)
	}
}

// TestWasmMemTopAndTableBaseOnMissingFile: both readers take a PATH, so "the
// file is not there" is a real caller mistake and has to be reported as one.
func TestWasmMemTopAndTableBaseOnMissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.wasm")
	if _, err := WasmMemTop(missing); err == nil {
		t.Error("WasmMemTop accepted a path that does not exist")
	}
	if _, err := WasmTableBase(missing); err == nil {
		t.Error("WasmTableBase accepted a path that does not exist")
	}
}

// TestWasmMemTopOnNonWasmFile: a file that exists but is not a module.
func TestWasmMemTopOnNonWasmFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not.wasm")
	if err := os.WriteFile(path, []byte("this is not a wasm module"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := WasmMemTop(path); err == nil {
		t.Error("WasmMemTop accepted a file that is not a WASM module")
	}
	if _, err := WasmTableBase(path); err == nil {
		t.Error("WasmTableBase accepted a file that is not a WASM module")
	}
}

// TestWasmMemTopReadsAModule drives the happy path from a file, which is how
// every caller actually uses it.
func TestWasmMemTopReadsAModule(t *testing.T) {
	const offset = 8192
	payload := []byte{9, 9, 9, 9}
	var seg []byte
	seg = append(seg, 0x01, 0x00, 0x41)
	seg = AppendSLEB128(seg, offset)
	seg = append(seg, 0x0B)
	seg = AppendULEB128(seg, uint32(len(payload)))
	seg = append(seg, payload...)
	// A memory section too, so the reader has to consider both and take the
	// higher.
	mod := section(wasmHeader(), 5, []byte{0x01, 0x00, 0x01}) // one memory, 1 page
	mod = section(mod, 11, seg)

	path := filepath.Join(t.TempDir(), "m.wasm")
	if err := os.WriteFile(path, mod, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := WasmMemTop(path)
	if err != nil {
		t.Fatalf("WasmMemTop: %v", err)
	}
	// The data segment ends at 8196, above the single reserved page (65536)?
	// No — one page IS 65536, so the memory reservation wins. Either way the
	// answer must cover both, so assert that rather than a single source.
	if got < int64(offset+len(payload)) {
		t.Errorf("memTop %d is below the data segment end %d", got, offset+len(payload))
	}
	if got < 65536 {
		t.Errorf("memTop %d is below the reserved memory minimum 65536", got)
	}
}

// activeSegment builds one active data segment for memory 0 at `offset`.
func activeSegment(offset int32, payload []byte) []byte {
	var seg []byte
	seg = append(seg, 0x00) // segment type 0: active, memory 0
	seg = append(seg, 0x41) // i32.const
	seg = AppendSLEB128(seg, offset)
	seg = append(seg, 0x0B) // end
	seg = AppendULEB128(seg, uint32(len(payload)))
	return append(seg, payload...)
}

// TestWasmTableBaseFindsTheReservation covers the reservation sentinel: a
// regexped module marks where its tables may start by putting an 8-byte magic
// at the front of an active data segment, and WasmTableBase reports that
// segment's memory offset.
//
// The searcher has to WALK segments to find it, so a module whose reservation
// sits behind other segments — a passive one, an active one with an explicit
// memory index, a short one that cannot hold the magic — exercises the arms
// that a single-segment module never reaches.
func TestWasmTableBaseFindsTheReservation(t *testing.T) {
	const want = 262144
	magic := ReservationMagic[:]

	var segs []byte
	segs = AppendULEB128(segs, 4) // four segments
	// 1: an active segment TOO SHORT to hold the magic.
	segs = append(segs, activeSegment(16, []byte{1, 2, 3})...)
	// 2: an active segment of the right length whose bytes do not match.
	segs = append(segs, activeSegment(64, []byte("NOTMAGIC"))...)
	// 3: a PASSIVE segment, which carries no offset at all.
	passive := []byte{0x01}
	passive = AppendULEB128(passive, 4)
	passive = append(passive, 9, 9, 9, 9)
	segs = append(segs, passive...)
	// 4: the real reservation.
	segs = append(segs, activeSegment(want, append(append([]byte{}, magic...), 0, 0))...)

	mod := section(wasmHeader(), 11, segs)
	path := filepath.Join(t.TempDir(), "m.wasm")
	if err := os.WriteFile(path, mod, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := WasmTableBase(path)
	if err != nil {
		t.Fatalf("WasmTableBase: %v", err)
	}
	if got != want {
		t.Errorf("table base = %d, want %d", got, want)
	}
}

// TestWasmTableBaseWithoutReservation: a module that carries no sentinel is
// not an error — it simply has no reserved base — so the answer is zero.
func TestWasmTableBaseWithoutReservation(t *testing.T) {
	segs := AppendULEB128(nil, 1)
	segs = append(segs, activeSegment(4096, []byte("ordinary data"))...)
	mod := section(wasmHeader(), 11, segs)
	path := filepath.Join(t.TempDir(), "m.wasm")
	if err := os.WriteFile(path, mod, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := WasmTableBase(path)
	if err != nil {
		t.Fatalf("WasmTableBase: %v", err)
	}
	if got != 0 {
		t.Errorf("got %d for a module with no reservation, want 0", got)
	}
}

// TestWasmTableBaseNoDataSection: likewise for a module with no data section
// to search at all.
func TestWasmTableBaseNoDataSection(t *testing.T) {
	mod := section(wasmHeader(), 1, []byte{0x00}) // an empty type section
	path := filepath.Join(t.TempDir(), "m.wasm")
	if err := os.WriteFile(path, mod, 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := WasmTableBase(path); err != nil || got != 0 {
		t.Errorf("got (%d, %v), want (0, nil)", got, err)
	}
}

// TestFindMagicRejectsMalformedSegment: an active segment must begin with an
// i32.const offset. Anything else is a module this reader cannot make sense
// of, and it has to say so rather than return a plausible address.
func TestFindMagicRejectsMalformedSegment(t *testing.T) {
	segs := AppendULEB128(nil, 1)
	segs = append(segs, 0x00) // active, memory 0
	segs = append(segs, 0x42) // i64.const — not what an active segment uses
	segs = AppendSLEB128(segs, 4096)
	segs = append(segs, 0x0B, 0x02, 0xAA, 0xBB)

	mod := section(wasmHeader(), 11, segs)
	path := filepath.Join(t.TempDir(), "m.wasm")
	if err := os.WriteFile(path, mod, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := WasmTableBase(path); err == nil {
		t.Error("accepted a data segment whose offset is not an i32.const")
	}
}

// TestParseDataSectionSegmentKinds drives the three segment kinds through
// ParseDataSection, whose answer is the highest address any ACTIVE segment
// reaches — passive segments have no address and must not contribute.
func TestParseDataSectionSegmentKinds(t *testing.T) {
	var segs []byte
	segs = AppendULEB128(segs, 3)
	segs = append(segs, activeSegment(1000, []byte{1, 2, 3, 4})...) // ends at 1004
	passive := []byte{0x01}
	passive = AppendULEB128(passive, 8)
	passive = append(passive, make([]byte, 8)...)
	segs = append(segs, passive...) // no address at all
	// Active with an EXPLICIT memory index (type 2).
	explicit := []byte{0x02}
	explicit = AppendULEB128(explicit, 0) // memory 0
	explicit = append(explicit, 0x41)
	explicit = AppendSLEB128(explicit, 5000)
	explicit = append(explicit, 0x0B)
	explicit = AppendULEB128(explicit, 2)
	explicit = append(explicit, 7, 7)
	segs = append(segs, explicit...) // ends at 5002

	got, err := ParseDataSection(segs)
	if err != nil {
		t.Fatalf("ParseDataSection: %v", err)
	}
	if got != 5002 {
		t.Errorf("data top = %d, want 5002 (the explicit-memory segment's end)", got)
	}
}

// TestParsersSurviveEveryTruncation feeds each reader a valid module truncated
// at EVERY length.
//
// The readers walk untrusted bytes with explicit offsets, so every one of them
// has a scatter of bounds checks and `if err != nil` returns that no
// well-formed module reaches. Rather than hand-craft a corruption per branch,
// this cuts one good module at every possible point: a truncated section
// header, a length running past the end, a segment cut mid-operand, an
// operand cut mid-LEB128 — all of them, without having to enumerate which is
// which.
//
// The contract asserted is the one that matters for a reader of other
// people's bytes: return an answer or return an error, and NEVER panic.
// A panic here is an out-of-range read on attacker-shaped input.
func TestParsersSurviveEveryTruncation(t *testing.T) {
	// A module with the three sections these readers care about: memory (5),
	// global (6) and data (11), the last carrying the reservation sentinel.
	var segs []byte
	segs = AppendULEB128(segs, 2)
	segs = append(segs, activeSegment(4096, []byte("payload!"))...)
	segs = append(segs, activeSegment(262144, append(append([]byte{}, ReservationMagic[:]...), 0, 0))...)

	global := []byte{0x01, 0x7F, 0x00, 0x41} // one i32 global, mutable=0, i32.const
	global = AppendSLEB128(global, 131072)
	global = append(global, 0x0B)

	mod := section(wasmHeader(), 5, []byte{0x01, 0x00, 0x02}) // memory: min 2 pages
	mod = section(mod, 6, global)
	mod = section(mod, 11, segs)

	// The whole module must parse cleanly first, or the sweep below is
	// truncating something that was never right.
	if _, err := ParseDataSectionBytes(mod); err != nil {
		t.Fatalf("the intact module does not parse: %v", err)
	}

	dir := t.TempDir()
	for n := 0; n <= len(mod); n++ {
		prefix := mod[:n]
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ParseDataSectionBytes panicked on a %d-byte prefix: %v", n, r)
				}
			}()
			_, _ = ParseDataSectionBytes(prefix)
		}()

		path := filepath.Join(dir, "t.wasm")
		if err := os.WriteFile(path, prefix, 0o644); err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("WasmMemTop panicked on a %d-byte prefix: %v", n, r)
				}
			}()
			_, _ = WasmMemTop(path)
		}()
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("WasmTableBase panicked on a %d-byte prefix: %v", n, r)
				}
			}()
			_, _ = WasmTableBase(path)
		}()
	}
}

// TestSectionParsersSurviveEveryTruncation is the same sweep for the readers
// that take a section PAYLOAD rather than a whole module, which is how
// WasmMemTop reaches them.
func TestSectionParsersSurviveEveryTruncation(t *testing.T) {
	memory := []byte{0x02, 0x00, 0x01, 0x01, 0x03, 0x10} // two memories, one with a max
	global := []byte{0x02, 0x7F, 0x00, 0x41}
	global = AppendSLEB128(global, 65536)
	global = append(global, 0x0B, 0x7F, 0x01, 0x41)
	global = AppendSLEB128(global, 131072)
	global = append(global, 0x0B)

	var data []byte
	data = AppendULEB128(data, 3)
	data = append(data, activeSegment(1000, []byte{1, 2, 3, 4})...)
	passive := []byte{0x01}
	passive = AppendULEB128(passive, 4)
	passive = append(passive, 5, 6, 7, 8)
	data = append(data, passive...)
	explicit := []byte{0x02}
	explicit = AppendULEB128(explicit, 0)
	explicit = append(explicit, 0x41)
	explicit = AppendSLEB128(explicit, 9000)
	explicit = append(explicit, 0x0B)
	explicit = AppendULEB128(explicit, 2)
	explicit = append(explicit, 1, 2)
	data = append(data, explicit...)

	for name, pair := range map[string]struct {
		payload []byte
		parse   func([]byte) (int64, error)
	}{
		"memory": {memory, ParseMemorySection},
		"global": {global, ParseGlobalSection},
		"data":   {data, ParseDataSection},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := pair.parse(pair.payload); err != nil {
				t.Fatalf("the intact %s section does not parse: %v", name, err)
			}
			for n := 0; n <= len(pair.payload); n++ {
				prefix := pair.payload[:n]
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("%s parser panicked on a %d-byte prefix: %v", name, n, r)
						}
					}()
					_, _ = pair.parse(prefix)
				}()
			}
		})
	}
}

// hugeULEB is the 10-byte ULEB128 encoding of 1<<63 — a legal LEB128 whose
// value has bit 63 set. Converted to a Go `int` it is NEGATIVE, which is what
// made every `off + int(size)` bounds check fail open before
func hugeULEB() []byte {
	return []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}
}

// TestParsersRejectOversizedLengths feeds each reader a module whose SECTION
// size, and then whose SEGMENT size, is that value.
//
// The contract is the truncation sweep's: an answer or an error, never a
// panic. Before the fix, section ids 5/6/11 sliced raw[off:secEnd] with
// secEnd < off (an inverted-bounds panic) and every other id set off negative
// (an out-of-range index).
func TestParsersRejectOversizedLengths(t *testing.T) {
	var segs []byte
	segs = AppendULEB128(segs, 1)
	segs = append(segs, activeSegment(4096, []byte("payload!"))...)

	cases := map[string][]byte{}

	// A data section whose declared size is 1<<63.
	m := wasmHeader()
	m = append(m, 11)
	m = append(m, hugeULEB()...)
	m = append(m, segs...)
	cases["section size 1<<63"] = m

	// A well-sized data section holding a segment whose payload length is 1<<63.
	var badSeg []byte
	badSeg = AppendULEB128(badSeg, 1)
	badSeg = append(badSeg, 0x00, 0x41)
	badSeg = AppendSLEB128(badSeg, 4096)
	badSeg = append(badSeg, 0x0B)
	badSeg = append(badSeg, hugeULEB()...)
	badSeg = append(badSeg, "payload!"...)
	cases["segment size 1<<63"] = section(wasmHeader(), 11, badSeg)

	// The same, on the explicit-memory-index segment flavour.
	var badSeg2 []byte
	badSeg2 = AppendULEB128(badSeg2, 1)
	badSeg2 = append(badSeg2, 0x02, 0x01, 0x41)
	badSeg2 = AppendSLEB128(badSeg2, 4096)
	badSeg2 = append(badSeg2, 0x0B)
	badSeg2 = append(badSeg2, hugeULEB()...)
	badSeg2 = append(badSeg2, "payload!"...)
	cases["segment size 1<<63, memidx form"] = section(wasmHeader(), 11, badSeg2)

	dir := t.TempDir()
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked: %v", r)
				}
			}()
			_, _ = ParseDataSectionBytes(mod)
			path := filepath.Join(dir, "t.wasm")
			if err := os.WriteFile(path, mod, 0o644); err != nil {
				t.Fatalf("write: %v", err)
			}
			_, _ = WasmMemTop(path)
			_, _ = WasmTableBase(path)
		})
	}
}

// TestLEBDecodersRejectOverlongPayloads pins the other half of K1: a tenth
// LEB128 byte whose payload bits would be shifted out of the 64-bit result is
// refused rather than silently truncated.
func TestLEBDecodersRejectOverlongPayloads(t *testing.T) {
	// 0x02 in the tenth byte carries bit 1, which lands at bit 64.
	bad := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02}
	if _, _, err := DecodeULEB128(bad); err == nil {
		t.Error("DecodeULEB128 accepted a payload bit above 63")
	}
	if _, _, err := DecodeSLEB128(bad); err == nil {
		t.Error("DecodeSLEB128 accepted a payload bit above 63")
	}
	// The canonical 10-byte encodings still round-trip.
	for _, v := range []int64{math.MinInt64, math.MaxInt64, -1, 0, 1} {
		got, _, err := DecodeSLEB128(AppendSLEB128_64(nil, v))
		if err != nil || got != v {
			t.Errorf("DecodeSLEB128 round-trip of %d: got %d, %v", v, got, err)
		}
	}
	if got, _, err := DecodeULEB128(hugeULEB()); err != nil || got != 1<<63 {
		t.Errorf("DecodeULEB128(1<<63): got %d, %v", got, err)
	}
}
