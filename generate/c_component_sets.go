package generate

import (
	"fmt"
	"strings"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/abi"
)

// The C COMPONENT stub for sets.
//
// The HEADER is the module-format one: the constants and every declaration come
// from the shared emitters in c_stub.go, so the two formats' C API is identical
// by construction. Only the FFI imports and the bodies live here.
//
// Three things differ from the module bodies, and each is forced by the
// interface rather than chosen:
//
//   - the `_all` pair receives a LIST OF IDS, not a bitmask or a bitmap, so the
//     body copies rather than scanning bits. The conversion happens inside the
//     regexp component, where it was measured cheaper.
//   - `find` is a RESOURCE. The scanner struct is still caller-owned and still
//     the same type, but what it holds is a HANDLE: the input, the position and
//     the gates all live inside the regexp component now.
//   - `<func>_free` drops the handle, and skipping it strands the scan's state
//     for the life of the process. In the module format it frees only the
//     answer cache an overlapping scanner may own.

// genCComponentSetParts renders the set half of the component C stub.
//
// `wsets` is the ALREADY VALIDATED WIT view of cfg.Sets, in the same order, so
// every kebab name here is one the WIT document also contains and nothing can
// fail. Re-deriving them from the config would add an error branch for a failure
// witSets has already ruled out.
func genCComponentSetParts(cfg config.BuildConfig, wsets []witSet, setsImportModule string, shapes *setShapes) (hPart, cPart string) {
	if len(wsets) == 0 {
		return "", ""
	}
	var hb, cb strings.Builder

	for si, s := range cfg.Sets {
		ws := wsets[si]
		n := patternsInSet(s, cfg)
		konst := screamingCase(s.Name) + "_PATTERN_COUNT"
		idKonst := screamingCase(s.Name) + "_ID_SPACE"
		idN := idSpaceSize(s, cfg)
		scannerType := "rx_" + setConstBase(s.Name) + "_scanner_t"
		gateField := fmt.Sprintf("    unsigned gates[%s];\n    unsigned scratch[4];\n", idKonst)
		// The two answer-cache fields the MODULE header declares for a
		// cache-eligible overlapping set. They stay zero here — the resource
		// owns the cache, inside the component — but the struct is part of the
		// PUBLIC header, and the two formats promise an identical one. Omitting
		// them made the headers differ for exactly the configs the parity test
		// did not cover.
		if sh := shapes.cacheShape(si); s.Overlapping && sh.Eligible && s.Find != "" {
			// Byte-for-byte what c_stub.go emits, comments included: the parity
			// test compares header TEXT, and a field that explains itself
			// differently in the two formats is a difference. They are simply
			// unused here — the resource inside the component owns the cache —
			// and a caller never touches them in either format.
			gateField += "    unsigned *cache;\n    size_t cache_words;\n"
		}

		hb.WriteString(cSetConstDecls(s.Name, konst, idKonst, n, idN))

		for _, c := range s.Capabilities() {
			kebab := witSetKebab(ws, c)
			ffi := "ffi_" + c.Name
			switch c.Field {
			case "match_any":
				hb.WriteString(cSetMatchAnyDecl(c.Name))
				cb.WriteString(cComponentSetAnyBody(setsImportModule, kebab, c.Name, ffi, false))
			case "scan_any":
				hb.WriteString(cSetScanAnyDecl(c.Name))
				cb.WriteString(cComponentSetAnyBody(setsImportModule, kebab, c.Name, ffi, true))
			case "match_all":
				hb.WriteString(cSetMatchAllDecl(c.Name, konst))
				cb.WriteString(cComponentSetAllBody(setsImportModule, kebab, c.Name, ffi, konst, false))
			case "scan_all":
				hb.WriteString(cSetScanAllDecl(c.Name, konst))
				cb.WriteString(cComponentSetAllBody(setsImportModule, kebab, c.Name, ffi, konst, true))
			case "find":
				hb.WriteString(cSetScannerDecls(c.Name, konst, gateField, scannerType))
				cb.WriteString(cComponentSetFindBody(setsImportModule, kebab, c.Name, scannerType, konst))
			}
		}
	}
	if hasEmitNameMap(cfg) {
		hb.WriteString("const char *pattern_name(int id);\n\n")
		cb.WriteString(cPatternNameTable(cfg))
	}
	return hb.String(), cb.String()
}

// witSetKebab is the WIT name of one capability, from the validated view.
//
// The find capability is the resource, and the others are ordinary functions, so
// the lookup differs — which is the whole reason this is a helper rather than a
// map: a map keyed by config name would have to hold both and lose the
// distinction.
func witSetKebab(ws witSet, c config.SetCapability) string {
	if c.Field == "find" {
		return ws.resource
	}
	for _, cap := range ws.caps {
		if cap.origin == c.Name {
			return cap.kebab
		}
	}
	panic("generate: capability " + c.Field + " " + c.Name + " has no WIT name — witSets and Capabilities disagree")
}

// cComponentImportDecl is one lowered import declaration, for every shape.
func cComponentImportDecl(module, field, ffi, params string) string {
	return fmt.Sprintf(`__attribute__((__import_module__("%s"), __import_name__("%s")))
extern void %s(%s);

`, module, field, ffi, params)
}

// cComponentSetAnyBody wraps match_any / scan_any.
//
//	result<option<u32>, error-code>:  @0 result disc, @4 option disc, @8 id
func cComponentSetAnyBody(module, kebab, name, ffi string, hasOffset bool) string {
	params := "const unsigned char *ptr, unsigned int len, unsigned char *ret"
	sig := "int %s(const char *input, size_t len)"
	callArgs := "(const unsigned char *)input, (unsigned int)len, area"
	if hasOffset {
		params = "const unsigned char *ptr, unsigned int len, unsigned int start, unsigned char *ret"
		sig = "int %s(const char *input, size_t len, size_t offset)"
		callArgs = "(const unsigned char *)input, (unsigned int)len, (unsigned int)offset, area"
	}
	var b strings.Builder
	b.WriteString(cComponentImportDecl(module, kebab, ffi, params))
	fmt.Fprintf(&b, sig+` {
    __attribute__((aligned(4))) unsigned char area[12] = {0};
    %[2]s(%[3]s);
    /* The error arm is UNKNOWN, not "no match": a Backtracking member of this
       set exhausted its frame budget. Returning -1 here would report a
       confident negative the engine never established. */
    if (area[0] != 0) return RX_ERR_BT_OVERFLOW;
    if (area[4] == 0) return -1;
    return (int)rx_cabi_u32(area + 8);
}

`, name, ffi, callArgs)
	return b.String()
}

// cComponentSetAllBody wraps match_all / scan_all.
//
//	result<list<u32>, error-code>:  @0 result disc, @4 list ptr, @8 list len
//
// The ids arrive already extracted — the regexp component walked its own bitmask
// or bitmap with ctz — so this copies a list instead of scanning bits. The list
// lives in OUR memory (the canonical ABI lowers a returned list into the
// caller's) and at most PATTERN_COUNT ids can be in it, which is exactly what
// the declaration's `static` size promises.
func cComponentSetAllBody(module, kebab, name, ffi, konst string, hasOffset bool) string {
	params := "const unsigned char *ptr, unsigned int len, unsigned char *ret"
	sig := "int %s(const char *input, size_t len, int patterns[static %s])"
	callArgs := "(const unsigned char *)input, (unsigned int)len, area"
	if hasOffset {
		params = "const unsigned char *ptr, unsigned int len, unsigned int start, unsigned char *ret"
		sig = "int %s(const char *input, size_t len, size_t offset, int patterns[static %s])"
		callArgs = "(const unsigned char *)input, (unsigned int)len, (unsigned int)offset, area"
	}
	var b strings.Builder
	b.WriteString(cComponentImportDecl(module, kebab, ffi, params))
	// EXPLICIT argument indices throughout. The signature already consumes two,
	// so a plain verb after them silently picks up the wrong one — which it did:
	// the clamp came out as the call's argument list.
	fmt.Fprintf(&b, sig+` {
    __attribute__((aligned(4))) unsigned char area[12] = {0};
    /* The id list is lowered into OUR memory through cabi_realloc. Rewind only
       what THIS call allocates, on every return: without it each call leaked
       the list from the heap for the life of the process. */
    unsigned mark = regexped_cabi_mark();
    %[3]s(%[4]s);
    if (area[0] != 0) { regexped_cabi_release(mark); return RX_ERR_BT_OVERFLOW; } /* result unknown, not empty */
    const unsigned char *ids = (const unsigned char *)(size_t)rx_cabi_u32(area + 4);
    unsigned int count = rx_cabi_u32(area + 8);
    /* The interface cannot report more ids than the set has patterns, and the
       declaration promises the caller's array is at least that long. The clamp
       is here anyway: it costs nothing and it bounds the write by something
       this translation unit can see. */
    if (count > (unsigned int)%[2]s) count = (unsigned int)%[2]s;
    for (unsigned int i = 0; i < count; i++) patterns[i] = (int)rx_cabi_u32(ids + 4 * i);
    regexped_cabi_release(mark);
    return (int)count;
}

`, name, konst, ffi, callArgs)
	return b.String()
}

// cComponentSetFindBody wraps the scanner resource as the module stub's
// fill-and-count API.
//
// The scanner struct is the module one, unchanged, because the header is shared —
// so this body reuses its fields for what it actually needs:
//
//	scratch[0]  the resource HANDLE, 0 when there is none — the canonical ABI
//	            never hands out handle 0
//	scratch[1]  unused
//	done        as before
//
// `_init` writes the struct and never reads it: `_free` comes before
// initialising the same scanner again, as with any C resource.
//
// `scratch` is the same field the MODULE stub builds its ABI descriptor in, and
// the struct is shared because the header is. Neither format uses both: a module
// scanner fills the descriptor and owns the gates, a component scanner holds a
// handle and owns neither — the gate array lives inside the regexp component
// with the rest of the scan.
func cComponentSetFindBody(module, kebab, name, scannerType, konst string) string {
	// ffi_<find>__res_*: a double underscore and a suffix no WIT name can
	// produce, so a capability named like `<find>_next` cannot collide with the
	// resource's own imports — and no leading underscore, which C reserves at
	// file scope.
	ctor := "ffi_" + name + "__res_new"
	next := "ffi_" + name + "__res_next"
	drop := "ffi_" + name + "__res_drop"
	var b strings.Builder

	// The constructor RETURNS the handle, so it does not take a return area and
	// cannot use the void-returning shape the others do.
	fmt.Fprintf(&b, `__attribute__((__import_module__("%s"), __import_name__("[constructor]%s")))
extern int %s(const unsigned char *ptr, unsigned int len, unsigned int start);

`, module, kebab, ctor)
	b.WriteString(cComponentImportDecl(module, "[method]"+kebab+".next", next,
		"int handle, unsigned char *ret"))
	b.WriteString(cComponentImportDecl(module, "[resource-drop]"+kebab, drop, "int handle"))

	fmt.Fprintf(&b, `int %[1]s_init(%[2]s *s, const char *input, size_t len, size_t offset) {
    if (!s || !input) return RX_ERR_NULL_ARG;
    /* The interface is u32. */
    if (len > 0x7FFFFFFF || offset > 0x7FFFFFFF) return RX_ERR_RANGE;
    /* Writes only: a live scanner must be _free'd before it is initialised
       again, so nothing here reads what the struct held. */
    s->input = input; s->len = len; s->offset = offset; s->done = 0;
    /* scratch[0] holds the resource handle: the real gate array is inside the
       regexp component, along with the input and the position. */
    s->scratch[0] = (unsigned)%[3]s((const unsigned char *)input, (unsigned int)len, (unsigned int)offset);
    s->scratch[1] = 0;
    return 0;
}

int %[1]s(%[2]s *s, rx_set_match_t *buf, size_t cap) {
    if (!s || !buf) return RX_ERR_NULL_ARG;
    if (cap > 0x7FFFFFFF) return RX_ERR_RANGE;
    /* One position's worst case is one match per pattern, and the resource moves
       past a position as it answers it: a smaller buffer could be neither grown
       nor asked again, so it is refused before anything is called. */
    if (cap < (size_t)%[5]s) return RX_ERR_RANGE;
    if (s->done) return 0;
    /* result<list<set-match>, error-code>: @0 disc, @4 list ptr, @8 list len */
    __attribute__((aligned(4))) unsigned char area[12] = {0};
    /* The tuple list is lowered into OUR memory; rewind it on every return. */
    unsigned mark = regexped_cabi_mark();
    %[4]s((int)s->scratch[0], area);
    /* Negative would be a count in the module format; here the error is the
       result's discriminant, and WHICH error is the payload beside it -- the
       error-code enum, 0 = backtrack-overflow, 1 = malformed-cache,
       2 = out-of-order, one byte. Any of them means UNKNOWN, so the scan ends
       AND says which rather than reporting "no more matches". */
    if (area[0] != 0) {
        unsigned char code = area[4];
        s->done = 1;
        regexped_cabi_release(mark);
        return code == 2 ? RX_ERR_OUT_OF_ORDER
             : code == 1 ? RX_ERR_MALFORMED_CACHE
             : RX_ERR_BT_OVERFLOW;
    }
    const unsigned char *raw = (const unsigned char *)(size_t)rx_cabi_u32(area + 4);
    unsigned int count = rx_cabi_u32(area + 8);
    if (count == 0) { s->done = 1; regexped_cabi_release(mark); return 0; }
    /* cap >= %[5]s >= count, so every match of this position fits. */
    for (unsigned int i = 0; i < count; i++) {
        buf[i].pattern_id = (int)rx_cabi_u32(raw + %[7]d * i);
        buf[i].start = (ptrdiff_t)rx_cabi_u32(raw + %[7]d * i + 4);
        buf[i].end = (ptrdiff_t)rx_cabi_u32(raw + %[7]d * i + 8);
    }
    /* Every tuple in one call shares a start. The component already advanced
       its own position; the struct records the MODULE format's meaning, the
       next position to try — one past this start — so it reads the same in
       both formats. */
    s->offset = (size_t)rx_cabi_u32(raw + 4) + 1;
    regexped_cabi_release(mark);
    return (int)count;
}

void %[1]s_free(%[2]s *s) {
    if (!s || s->scratch[0] == 0) return;
    %[6]s((int)s->scratch[0]);
    /* The handle is cleared, so a second call does nothing rather than drop it
       twice. Only for a scanner that went through _init. */
    s->scratch[0] = 0;
    s->done = 1;
}

`, name, scannerType, ctor, next, konst, drop, abi.SetMatchTupleBytes)
	return b.String()
}
