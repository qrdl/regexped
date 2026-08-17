package compile

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
)

// captureWarnings installs a temporary slog handler at Warn level and returns
// the captured output plus a restore func.
func captureWarnings(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	return &buf, func() { slog.SetDefault(prev) }
}

// TestCompileFallback_WarnsOnStateLimitDrop covers plans/OPUS.md §N3: a pattern
// excluded from a set because its suffix DFA exceeds maxFallbackStates must be
// reported at warning level, not dropped silently.
//
// The branch is driven via CompileSetOptions.MaxFallbackStates rather than by
// finding a pathological pattern: the reachable window for the default limit is
// only (1024, maxHelperDFAStates] == (1024, 2048], and DFA state counts for the
// exponential-blowup pattern families that get anywhere near it jump in powers
// of the class size, so they skip straight over the window. Lowering the limit
// exercises exactly the same branch with an ordinary pattern.
func TestCompileFallback_WarnsOnStateLimitDrop(t *testing.T) {
	var prefixPool, suffixPool dfaPool
	// No literal anywhere, so this lands in the fallback bucket rather than a
	// literal bucket. ~200 suffix DFA states, comfortably over the limit below.
	info, err := analyzePattern(config.RegexEntry{Pattern: `[a-z0-9]{200}`}, &prefixPool, &suffixPool)
	if err != nil {
		t.Fatalf("analyzePattern: %v", err)
	}

	buf, restore := captureWarnings(t)
	defer restore()

	opts := CompileSetOptions{MaxFallbackStates: 8}
	buckets := compileFallback([]*PatternInfo{info}, opts, nil)

	if len(buckets) != 0 {
		t.Fatalf("expected the pattern to be dropped (0 buckets), got %d", len(buckets))
	}
	out := buf.String()
	if !strings.Contains(out, "Pattern dropped from set") {
		t.Errorf("dropped pattern produced no warning; slog output was %q", out)
	}
	if !strings.Contains(out, "limit=8") {
		t.Errorf("warning should report the limit that was exceeded; got %q", out)
	}
}

// TestCompileFallback_NoWarnWhenAdmitted guards the other direction: a pattern
// that fits must not emit the warning. Without this, a future change that warns
// unconditionally would still pass the test above.
func TestCompileFallback_NoWarnWhenAdmitted(t *testing.T) {
	var prefixPool, suffixPool dfaPool
	info, err := analyzePattern(config.RegexEntry{Pattern: `[a-z0-9]{200}`}, &prefixPool, &suffixPool)
	if err != nil {
		t.Fatalf("analyzePattern: %v", err)
	}

	buf, restore := captureWarnings(t)
	defer restore()

	buckets := compileFallback([]*PatternInfo{info}, CompileSetOptions{}, nil)

	if len(buckets) != 1 {
		t.Fatalf("expected the pattern to be admitted (1 bucket), got %d", len(buckets))
	}
	if out := buf.String(); strings.Contains(out, "Pattern dropped from set") {
		t.Errorf("admitted pattern must not warn; got %q", out)
	}
}

// TestCompileFallback_WarnsWithNilDiag is the specific regression for §N3's
// corrected mechanism. The warning must not be nested inside the
// `if diag != nil` bookkeeping guards: CompileSet always allocates a SetDiag so
// those guards always pass, but the struct is discarded unless --diag-json was
// requested. Passing an explicitly nil diag here asserts the warning is
// independent of diagnostics being collected.
func TestCompileFallback_WarnsWithNilDiag(t *testing.T) {
	var prefixPool, suffixPool dfaPool
	info, err := analyzePattern(config.RegexEntry{Pattern: `[a-z0-9]{200}`}, &prefixPool, &suffixPool)
	if err != nil {
		t.Fatalf("analyzePattern: %v", err)
	}

	buf, restore := captureWarnings(t)
	defer restore()

	compileFallback([]*PatternInfo{info}, CompileSetOptions{MaxFallbackStates: 8}, nil /* diag */)

	if out := buf.String(); !strings.Contains(out, "Pattern dropped from set") {
		t.Errorf("warning must fire with a nil diag; got %q", out)
	}
}
