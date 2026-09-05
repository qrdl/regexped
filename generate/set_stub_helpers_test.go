package generate

import (
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// ── The set-stub descriptor helpers ────────────────────────────────────────
//
// The six language templates each used to hand-roll the argument list of every
// set export. They agreed at the time; what the shared descriptor removes is
// FORWARD drift — the cross-batch empty-match suppression that ended up in the
// find path and not the groups path is what that looks like when it happens.
//
// These helpers are pure functions over the config, so their refusals and
// their boundaries are testable directly rather than through six generated
// files.

// TestCapByKind covers the lookup, including the miss.
//
// A nil result means "the set did not declare this capability", and every
// caller must handle it — spellJSArgs is handed one directly. Returning a
// zero-valued capability instead would spell an argument list for an export
// that does not exist.
func TestCapByKind(t *testing.T) {
	caps := []setCapability{
		{Kind: "find", Export: "s_find"},
		{Kind: "scan_any", Export: "s_scan_any"},
	}
	if got := capByKind(caps, "find"); got == nil || got.Export != "s_find" {
		t.Errorf("capByKind(find) = %+v, want the find capability", got)
	}
	if got := capByKind(caps, "match_all"); got != nil {
		t.Errorf("capByKind(undeclared) = %+v, want nil", got)
	}
	if got := capByKind(nil, "find"); got != nil {
		t.Errorf("capByKind over no capabilities = %+v, want nil", got)
	}
}

// TestSpellJSArgs covers the renderer, every ABI parameter it can be handed,
// and both of its refusals.
//
// The nil guard matters because capByKind returns nil for an undeclared
// capability and the templates call straight through; the panic matters
// because a new ABI parameter with no JS spelling must stop the build rather
// than silently render an argument list one short.
func TestSpellJSArgs(t *testing.T) {
	s := jsArgSpelling{
		inPtr: "inPtr", inLen: "inLen", from: "from", gate: "gatePtr",
		bitmap: "bitmapPtr", tuple: "tuplePtr", outCap: "outCap", cursor: "cursor",
	}
	t.Run("nil capability spells nothing", func(t *testing.T) {
		if got := spellJSArgs(nil, s); got != "" {
			t.Errorf("spellJSArgs(nil) = %q, want the empty string", got)
		}
	})
	t.Run("every parameter has a spelling", func(t *testing.T) {
		all := &setCapability{Kind: "find", Params: []abiParam{
			abiInputPtr, abiInputLen, abiFrom, abiGatePtr,
			abiBitmapPtr, abiTuplePtr, abiOutCap, abiCursor,
		}}
		got := spellJSArgs(all, s)
		want := "inPtr, inLen, from, gatePtr, bitmapPtr, tuplePtr, outCap, cursor"
		if got != want {
			t.Errorf("spellJSArgs = %q, want %q", got, want)
		}
	})
	t.Run("order follows the ABI, not the spelling struct", func(t *testing.T) {
		// Reversing the params must reverse the output: the renderer walks the
		// capability's list, which IS the export's signature.
		rev := &setCapability{Params: []abiParam{abiCursor, abiInputLen, abiInputPtr}}
		if got := spellJSArgs(rev, s); got != "cursor, inLen, inPtr" {
			t.Errorf("spellJSArgs = %q, want the parameters in ABI order", got)
		}
	})
	t.Run("an unspellable parameter stops the build", func(t *testing.T) {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("an unknown ABI parameter rendered instead of panicking")
			}
			if msg, ok := r.(string); !ok || !strings.Contains(msg, "JS spelling") {
				t.Errorf("panic %v does not name the cause", r)
			}
		}()
		// A parameter value no case handles. If a real one is ever added past
		// abiCursor this test starts passing for the wrong reason, which the
		// message above is there to make obvious.
		bogus := &setCapability{Params: []abiParam{abiCursor + 99}}
		_ = spellJSArgs(bogus, s)
	})
}

// TestDerivedFuncName covers the naming rule that keeps every generated symbol
// in the config's own casing: url_groups + index -> url_groups_index, but
// urlGroups + index -> urlGroupsIndex.
//
// The empty-suffix arm is the one no generator reaches today; it exists so a
// caller asking for the base name gets it rather than a trailing separator.
func TestDerivedFuncName(t *testing.T) {
	cases := []struct{ base, suffix, want string }{
		{"url_groups", "index", "url_groups_index"},
		{"url_groups", "", "url_groups"},
		{"urlGroups", "index", "urlGroupsIndex"},
		{"urlGroups", "", "urlGroups"},
		{"p", "names", "p_names"},
	}
	for _, c := range cases {
		if got := derivedFuncName(c.base, c.suffix); got != c.want {
			t.Errorf("derivedFuncName(%q, %q) = %q, want %q",
				c.base, c.suffix, got, c.want)
		}
	}
}

// TestDefaultBatchCapBounds covers the batch buffer sizing, which is clamped from
// BELOW by a floor and from ABOVE by what the cursor's count field can encode.
//
// The upper clamp is the interesting one: a buffer larger than the cursor can
// count would let a call report more matches than the resume cursor could
// describe, and the next call would restart in the wrong place.
func TestDefaultBatchCapBounds(t *testing.T) {
	mk := func(n int) (config.SetConfig, config.BuildConfig) {
		entries := make([]config.RegexEntry, n)
		for i := range entries {
			entries[i] = config.RegexEntry{
				Name: string(rune('a'+i%26)) + string(rune('0'+i/26)), Pattern: `x`,
			}
		}
		s := config.SetConfig{
			Name: "s", Find: "s_find", Patterns: config.PatternSelector{All: true},
		}
		return s, config.BuildConfig{Regexps: entries, Sets: []config.SetConfig{s}}
	}
	t.Run("small sets take the floor", func(t *testing.T) {
		s, cfg := mk(3)
		if got := defaultBatchCap(s, cfg); got != 256 {
			t.Errorf("defaultBatchCap for 3 patterns = %d, want the 256 floor", got)
		}
	})
	t.Run("never exceeds what the cursor can count", func(t *testing.T) {
		s, cfg := mk(40)
		got := defaultBatchCap(s, cfg)
		if max := int(cursorMaxCount(s, cfg)); got > max {
			t.Errorf("defaultBatchCap = %d exceeds the cursor's maximum count %d", got, max)
		}
		if got < 1 {
			t.Errorf("defaultBatchCap = %d, want at least 1", got)
		}
	})
}
