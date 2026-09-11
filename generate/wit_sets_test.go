package generate

import (
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

func witSetsCfg() config.BuildConfig {
	return config.BuildConfig{
		WasmFormat:   "component",
		ImportModule: "t",
		WitPackage:   "t",
		WasmFile:     "t.wasm",
		Regexps: []config.RegexEntry{
			{Pattern: `ghp_[A-Za-z0-9]{4}`, MatchFunc: "token_match"},
			{Pattern: `AKIA[A-Z0-9]{6}`},
		},
		Sets: []config.SetConfig{{
			Name:     "s",
			Patterns: config.PatternSelector{All: true},
			MatchAny: "which_matches",
			MatchAll: "all_matches",
			ScanAny:  "any_hit",
			ScanAll:  "all_hits",
			Find:     "scan_it",
		}},
	}
}

// The interface, the resource, and the world's imports. Checked as TEXT because
// the text is what wasm-tools reads, and because the export names the adapters
// are stamped with are derived from the same shapes.
func TestWitSetsInterface(t *testing.T) {
	text, err := WitText(witSetsCfg())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"interface sets {",
		"record set-match { id: u32, start: u32, end: u32 }",
		"which-matches: func(input: list<u8>) -> result<option<u32>, error-code>;",
		"all-matches: func(input: list<u8>) -> result<list<u32>, error-code>;",
		"any-hit: func(input: list<u8>, start: u32) -> result<option<u32>, error-code>;",
		"all-hits: func(input: list<u8>, start: u32) -> result<list<u32>, error-code>;",
		"resource scan-it {",
		"constructor(input: list<u8>, start: u32);",
		"next: func() -> result<list<set-match>, error-code>;",
		// Both interfaces exist here, so the world exports both.
		"export matcher;",
		"export sets;",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("WIT is missing %q:\n%s", want, text)
		}
	}
	// `sets` declares its OWN error-code rather than `use matcher.{…}`, so a
	// sets-only config needs no matcher interface at all.
	if strings.Count(text, "enum error-code { backtrack-overflow }") != 2 {
		t.Error("each interface must declare its own error-code")
	}
}

// A config with sets and NO pattern exports must not emit an empty `matcher`
// interface, nor export one from the world: an interface with no functions is
// legal WIT and pointless, and a world exporting one makes a consumer bind it.
func TestWitSetsOnlyOmitsMatcher(t *testing.T) {
	cfg := witSetsCfg()
	cfg.Regexps = []config.RegexEntry{{Pattern: `abc`}, {Pattern: `def`}}
	text, err := WitText(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, "interface matcher") || strings.Contains(text, "export matcher") {
		t.Errorf("a sets-only config emitted a matcher interface:\n%s", text)
	}
	if !strings.Contains(text, "export sets;") {
		t.Error("the world must export sets")
	}
}

// The canonical export names, which compile/ stamps into its adapters. The
// resource's three are NOT interchangeable, and the dtor has no counterpart in
// the interface at all — `component new` binds it by name.
func TestSetExportNames(t *testing.T) {
	_, _, setNames, _, err := ComponentArtifactsWithSets(witSetsCfg())
	if err != nil {
		t.Fatal(err)
	}
	n, ok := setNames["s"]
	if !ok {
		t.Fatal("no names for set s")
	}
	for cfgName, want := range map[string]string{
		"which_matches": "regexped:t/sets#which-matches",
		"all_matches":   "regexped:t/sets#all-matches",
		"any_hit":       "regexped:t/sets#any-hit",
		"all_hits":      "regexped:t/sets#all-hits",
	} {
		if got := n.Caps[cfgName]; got != want {
			t.Errorf("Caps[%q] = %q, want %q", cfgName, got, want)
		}
	}
	for _, c := range []struct{ got, want string }{
		{n.Constructor, "regexped:t/sets#[constructor]scan-it"},
		{n.Next, "regexped:t/sets#[method]scan-it.next"},
		{n.Dtor, "regexped:t/sets#[dtor]scan-it"},
		{n.ResourceImport, "[export]regexped:t/sets"},
		{n.ResourceNew, "[resource-new]scan-it"},
	} {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
}

// The version follows the INTERFACE name in the sets prefix too. Putting it after
// the package makes wasm-tools fail with "failed to find export of interface" —
// the phase 1 bug, which would otherwise be free to recur here.
func TestSetExportNamesVersioned(t *testing.T) {
	cfg := witSetsCfg()
	cfg.WitVersion = "2.3.0"
	_, _, setNames, _, err := ComponentArtifactsWithSets(cfg)
	if err != nil {
		t.Fatal(err)
	}
	n := setNames["s"]
	if !strings.HasPrefix(n.Caps["any_hit"], "regexped:t/sets@2.3.0#") {
		t.Errorf("version misplaced: %q", n.Caps["any_hit"])
	}
	if !strings.HasPrefix(n.Constructor, "regexped:t/sets@2.3.0#[constructor]") {
		t.Errorf("version misplaced on the constructor: %q", n.Constructor)
	}
	if n.ResourceImport != "[export]regexped:t/sets@2.3.0" {
		t.Errorf("version misplaced on the builtin's module: %q", n.ResourceImport)
	}
}

// A set capability name that is not a WIT identifier is REFUSED, naming the set
// and the key, rather than mangled into something the caller did not ask for.
func TestWitSetsRejectsUnrepresentableName(t *testing.T) {
	cfg := witSetsCfg()
	cfg.Sets[0].ScanAny = "_leading"
	_, err := WitText(cfg)
	if err == nil {
		t.Fatal("an unrepresentable capability name was accepted")
	}
	for _, want := range []string{"set \"s\"", "scan_any", "_leading"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// A set capability whose kebab form collides with a pattern function's is
// refused. It is legal WIT — the two live in different interfaces — and a trap:
// every generated stub would declare the symbol twice.
func TestWitSetsRejectsCollisionWithMatcher(t *testing.T) {
	cfg := witSetsCfg()
	cfg.Regexps[0].MatchFunc = "any_hit"
	_, err := WitText(cfg)
	if err == nil {
		t.Fatal("a name colliding across interfaces was accepted")
	}
	if !strings.Contains(err.Error(), "any-hit") {
		t.Errorf("error %q does not name the colliding WIT identifier", err)
	}
}

// Two capabilities of the same set colliding is the same rule, reported the same
// way.
func TestWitSetsRejectsCollisionWithinSet(t *testing.T) {
	cfg := witSetsCfg()
	cfg.Sets[0].ScanAny = cfg.Sets[0].MatchAny
	_, err := WitText(cfg)
	if err == nil {
		t.Fatal("two capabilities sharing a name were accepted")
	}
}

// An unknown capability field is a programming error in the caller, not a config
// error, so both descriptors are loud rather than silently emitting nothing.
func TestSetCapSigAndDocPanicOnUnknownField(t *testing.T) {
	for _, f := range []func(){
		func() { setCapSig("no_such_capability") },
		func() { setCapDoc("no_such_capability") },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("an unknown capability field returned silently")
				}
			}()
			f()
		}()
	}
}

// witSets with no sets returns nothing, and setExportNames likewise: every
// caller is then free to pass the nil map on without a branch.
func TestWitSetsEmpty(t *testing.T) {
	cfg := witSetsCfg()
	cfg.Sets = nil
	sets, err := witSets(cfg, nil)
	if err != nil || sets != nil {
		t.Errorf("witSets(no sets) = %v, %v; want nil, nil", sets, err)
	}
	if got := setExportNames("regexped:t/sets", nil); got != nil {
		t.Errorf("setExportNames(no sets) = %v, want nil", got)
	}
	if got := renderWitSets(nil); got != "" {
		t.Errorf("renderWitSets(no sets) = %q, want empty", got)
	}
}
