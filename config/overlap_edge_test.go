package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSetOverlapRowEndOff pins the row shape against the arithmetic the
// writer and both readers used to spell separately.
func TestSetOverlapRowEndOff(t *testing.T) {
	if SetOverlapRowMaskOff != 0 {
		t.Fatalf("mask offset = %d, want 0", SetOverlapRowMaskOff)
	}
	for k := 0; k < 8; k++ {
		if got, want := SetOverlapRowEndOff(k), 4+4*k; got != want {
			t.Errorf("SetOverlapRowEndOff(%d) = %d, want %d", k, got, want)
		}
	}
	// The last end must sit inside the row, and the row must hold nothing
	// beyond it: a row is exactly a mask plus one end per pattern.
	for _, pats := range []int{1, 3, 64} {
		row := SetOverlapBlockRowBytes(pats)
		if got := SetOverlapRowEndOff(pats-1) + 4; got != row {
			t.Errorf("pats=%d: last end ends at %d, row is %d bytes", pats, got, row)
		}
	}
}

// TestSetOverlapSizingClampsNonPositiveLen covers the m<1 guards in all three
// sizing helpers. A caller that asks about an empty-or-negative input must get
// the one-position answer, not a negative region — the stubs reproduce this
// arithmetic and would allocate nothing.
func TestSetOverlapSizingClampsNonPositiveLen(t *testing.T) {
	const cells, pats = 6, 3
	for _, n := range []int{-1, -7, -1 << 20} {
		if got, want := SetOverlapCheckpointStride(n, cells, pats), 1; got != want {
			t.Errorf("Stride(%d) = %d, want %d", n, got, want)
		}
		want := SetOverlapCheckpointBytes(0, cells, pats)
		if got := SetOverlapCheckpointBytes(n, cells, pats); got != want {
			t.Errorf("Bytes(%d) = %d, want Bytes(0) = %d", n, got, want)
		}
		wantK := SetOverlapCheckpointBytesForStride(0, cells, pats, 1)
		if got := SetOverlapCheckpointBytesForStride(n, cells, pats, 1); got != wantK {
			t.Errorf("BytesForStride(%d,k=1) = %d, want %d", n, got, wantK)
		}
	}
}

// TestSetOverlapStrideClampsSqrt covers the two clamps on the square-root
// optimum. Both need a region ABOVE the budget, since below it the stride is
// the whole span and neither clamp is reached.
func TestSetOverlapStrideClampsSqrt(t *testing.T) {
	// Low floor: many patterns make a row wide, so sqrt(m*cells*4/row) lands
	// under 16 while m*row still blows the budget. A stride below 16 would
	// make the checkpoint column cost more than the block it saves.
	const pats = 1000
	const m = 20000
	if n := singleBlockBytes(m, 1, pats); n > 0 && n <= SetOverlapCacheMaxBytes {
		t.Fatalf("single-block region %d is within the budget; the clamp is unreachable", n)
	}
	if got := SetOverlapCheckpointStride(m-1, 1, pats); got != 16 {
		t.Errorf("Stride(%d,1,%d) = %d, want the floor 16", m-1, pats, got)
	}

	// High ceiling: a very wide column over a two-position span. The optimum
	// exceeds the span, and a stride past the span would size a block for
	// positions that do not exist.
	const cells = 17_000_000
	if n := singleBlockBytes(2, cells, 0); n > 0 && n <= SetOverlapCacheMaxBytes {
		t.Fatalf("single-block region %d is within the budget; the clamp is unreachable", n)
	}
	if got := SetOverlapCheckpointStride(1, cells, 0); got != 2 {
		t.Errorf("Stride(1,%d,0) = %d, want the span 2", cells, got)
	}
}

// TestSingleBlockBytesReportsOverflow covers both of singleBlockBytes' refusals.
// It answers 0 rather than a wrapped size, because a wrapped size is a region
// the sweep's validation would reject only by luck.
func TestSingleBlockBytesReportsOverflow(t *testing.T) {
	// m*b overflows: the guard fires before the multiply.
	if got := singleBlockBytes(1<<62, 6, 3); got != 0 {
		t.Errorf("singleBlockBytes(1<<62,6,3) = %d, want 0", got)
	}
	// The COLUMN alone overflows, which the m*b guard cannot see: the sum
	// itself goes negative.
	if got := singleBlockBytes(1, 1<<61, 0); got != 0 {
		t.Errorf("singleBlockBytes(1,1<<61,0) = %d, want 0", got)
	}
	// And the stride helper above it must not return a nonsense stride when
	// that happens — 0 is treated as "does not fit", so it sweeps to sqrt.
	if got := SetOverlapCheckpointStride(1, 1<<61, 0); got < 1 {
		t.Errorf("Stride over an overflowing column = %d, want >= 1", got)
	}
}

// TestSetOverlapBytesForStrideClampsAboveSpan pins the k>m clamp, which is the
// one-block mode a caller reaches by asking for a stride larger than the input.
func TestSetOverlapBytesForStrideClampsAboveSpan(t *testing.T) {
	const cells, pats = 6, 3
	whole := SetOverlapCheckpointBytesForStride(100, cells, pats, 101)
	if got := SetOverlapCheckpointBytesForStride(100, cells, pats, 1<<30); got != whole {
		t.Errorf("k past the span = %d, want the whole-span %d", got, whole)
	}
}

// TestLoadConfigUnresolvablePath covers the filepath.Abs failure. It is
// reachable only with no working directory, which is why the error is reported
// by the path rather than assumed impossible.
func TestLoadConfigUnresolvablePath(t *testing.T) {
	gone := t.TempDir()
	sub := filepath.Join(gone, "cwd")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(sub)
	if err := os.Remove(sub); err != nil {
		t.Skipf("cannot remove the working directory on this platform: %v", err)
	}
	if _, err := os.Getwd(); err == nil {
		t.Skip("this platform still resolves a removed working directory")
	}
	_, err := LoadConfig("regexped.yaml")
	if err == nil {
		t.Fatal("LoadConfig with no working directory succeeded")
	}
	if !strings.Contains(err.Error(), "resolve config path") {
		t.Errorf("error = %v, want it to name the path resolution", err)
	}
}
