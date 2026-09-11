package generate

import (
	"fmt"
	"strings"

	"github.com/qrdl/regexped/config"
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
//     regexp component, where it was measured cheaper (§9.2).
//   - `find` is a RESOURCE. The scanner struct is still caller-owned and still
//     the same type, but what it holds is a HANDLE: the input, the position and
//     the gates all live inside the regexp component now.
//   - `<func>_free` does something. In the module format it is a no-op; here it
//     drops the handle, and skipping it strands the scan's state for the life of
//     the process.

// genCComponentSetParts renders the set half of the component C stub.
//
// `wsets` is the ALREADY VALIDATED WIT view of cfg.Sets, in the same order, so
// every kebab name here is one the WIT document also contains and nothing can
// fail. Re-deriving them from the config would add an error branch for a failure
// witSets has already ruled out.
func genCComponentSetParts(cfg config.BuildConfig, wsets []witSet, setsImportModule string) (hPart, cPart string) {
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
		gateField := fmt.Sprintf("    unsigned gates[%s];\n", idKonst)

		hb.WriteString(cSetConstDecls(s.Name, konst, idKonst, n, idN))

		for _, c := range s.Capabilities() {
			kebab := witSetKebab(ws, c)
			ffi := "_ffi_" + c.Name
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

// cComponentImportDecl is one lowered import declaration.
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
    return (int)(*(unsigned int *)(area + 8));
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
    %[3]s(%[4]s);
    if (area[0] != 0) return RX_ERR_BT_OVERFLOW; /* result unknown, not empty */
    const unsigned int *ids = *(const unsigned int **)(area + 4);
    unsigned int count = *(unsigned int *)(area + 8);
    /* The interface cannot report more ids than the set has patterns, and the
       declaration promises the caller's array is at least that long. The clamp
       is here anyway: it costs nothing and it bounds the write by something
       this translation unit can see. */
    if (count > (unsigned int)%[2]s) count = (unsigned int)%[2]s;
    for (unsigned int i = 0; i < count; i++) patterns[i] = (int)ids[i];
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
//	gates[0]  the resource HANDLE, which is the only state that matters here
//	done      as before
//
// Putting the handle in gates[0] is not a trick played on the caller: the gate
// array is documented as opaque, the only operation on it is zeroing, and a
// component consumer has no gate array to own — the real one lives inside the
// regexp component with the rest of the scan.
func cComponentSetFindBody(module, kebab, name, scannerType, konst string) string {
	ctor := "_ffi_" + name + "_new"
	next := "_ffi_" + name + "_next"
	drop := "_ffi_" + name + "_drop"
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
    s->input = input; s->len = len; s->offset = offset; s->done = 0;
    /* gates[0] holds the resource handle: the real gate array is inside the
       regexp component, along with the input and the position. */
    s->gates[0] = (unsigned)%[3]s((const unsigned char *)input, (unsigned int)len, (unsigned int)offset);
    return 0;
}

int %[1]s(%[2]s *s, rx_set_match_t *buf, size_t cap) {
    if (!s || !buf) return RX_ERR_NULL_ARG;
    if (cap > 0x7FFFFFFF) return RX_ERR_RANGE;
    if (s->done) return 0;
    /* result<list<set-match>, error-code>: @0 disc, @4 list ptr, @8 list len */
    __attribute__((aligned(4))) unsigned char area[12] = {0};
    %[4]s((int)s->gates[0], area);
    /* Negative would be a count in the module format; here the error is the
       result's discriminant. Either way it means UNKNOWN, so the scan ends AND
       says so rather than reporting "no more matches". */
    if (area[0] != 0) { s->done = 1; return RX_ERR_BT_OVERFLOW; }
    const unsigned int *raw = *(const unsigned int **)(area + 4);
    unsigned int count = *(unsigned int *)(area + 8);
    if (count == 0) { s->done = 1; return 0; }
    /* Unlike the module format there is no transactional overflow to resume
       from: the component sized its own buffer at PATTERN_COUNT, the exact
       worst case for one position, so every match of this position is here.
       A caller that offers less than it asked for gets what fits, and the rest
       are DISCARDED rather than re-reported — which is why cap should be
       %[5]s, exactly as in the module format. */
    unsigned int take = count;
    if (take > (unsigned int)cap) take = (unsigned int)cap;
    for (unsigned int i = 0; i < take; i++) {
        buf[i].pattern_id = (int)raw[i * 3];
        buf[i].start = (ptrdiff_t)raw[i * 3 + 1];
        buf[i].end = (ptrdiff_t)raw[i * 3 + 2];
    }
    /* Every tuple in one call shares a start; the component already advanced
       its own position, and this mirrors it so the struct stays informative. */
    s->offset = (size_t)raw[1];
    return (int)count;
}

void %[1]s_free(%[2]s *s) {
    if (!s || s->gates[0] == 0) return;
    %[6]s((int)s->gates[0]);
    /* Idempotent: a second call, or a call on a finished scan, must do nothing
       rather than drop a handle twice. */
    s->gates[0] = 0;
    s->done = 1;
}

`, name, scannerType, ctor, next, konst, drop)
	return b.String()
}
