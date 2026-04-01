package compile

import (
	"testing"
)

func TestFindMandatoryLit(t *testing.T) {
	cases := []struct {
		pattern string
		wantNil bool
		wantLit string
		wantMin int32
	}{
		// Simple literal: the whole thing is mandatory.
		{"foo", false, "foo", 0},
		// Literal inside a non-capturing group.
		{"(?:foo)", false, "foo", 0},
		// Literal after a mandatory prefix — minOff reflects prefix length.
		{"bar://", false, "bar://", 0},
		// Alternation: no guaranteed literal.
		{"a|b", true, "", 0},
		// Kleene star: body not mandatory.
		{"a*", true, "", 0},
		// Plus: body mandatory at least once.
		{"a+b", false, "a", 0},
		// Sequence: first literal is mandatory at offset 0.
		{"foo.*bar", false, "foo", 0},
		// Invalid pattern: returns nil.
		{"[invalid", true, "", 0},
		// Empty pattern: returns nil.
		{"", true, "", 0},
		// URL-like: mandatory literal ://, minOff=2 (minimum 2 chars before it).
		{`[a-zA-Z]{2,8}://[^\s]+`, false, "://", 2},
	}
	for _, c := range cases {
		got := findMandatoryLit(c.pattern)
		if c.wantNil {
			if got != nil {
				t.Errorf("findMandatoryLit(%q): got %v, want nil", c.pattern, got)
			}
			continue
		}
		if got == nil {
			t.Errorf("findMandatoryLit(%q): got nil, want lit=%q", c.pattern, c.wantLit)
			continue
		}
		if string(got.bytes) != c.wantLit {
			t.Errorf("findMandatoryLit(%q): lit=%q, want %q", c.pattern, got.bytes, c.wantLit)
		}
		if got.minOff != c.wantMin {
			t.Errorf("findMandatoryLit(%q): minOff=%d, want %d", c.pattern, got.minOff, c.wantMin)
		}
		if got.maxOff < got.minOff {
			t.Errorf("findMandatoryLit(%q): maxOff %d < minOff %d", c.pattern, got.maxOff, got.minOff)
		}
	}
}
