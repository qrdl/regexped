package merge

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qrdl/regexped/config"
	"github.com/qrdl/regexped/internal/utils"
)

func buildImportSection(mod, field string, kind byte) []byte {
	var b []byte
	b = utils.AppendULEB128(b, uint32(1))
	b = utils.AppendULEB128(b, uint32(len(mod)))
	b = append(b, []byte(mod)...)
	b = utils.AppendULEB128(b, uint32(len(field)))
	b = append(b, []byte(field)...)
	b = append(b, kind)
	if kind == 0x02 {
		b = append(b, 0x00)
		b = utils.AppendULEB128(b, uint32(1))
	} else if kind == 0x00 {
		b = utils.AppendULEB128(b, uint32(0))
	}
	return b
}

func TestHasMemoryImportFromMain(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"memory import from main", buildImportSection("main", "memory", 0x02), true},
		{"memory import from env", buildImportSection("env", "memory", 0x02), false},
		{"func import from main", buildImportSection("main", "foo", 0x00), false},
		{"empty section", []byte{0x00}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := hasMemoryImportFromMain(c.data)
			if got != c.want {
				t.Errorf("hasMemoryImportFromMain: got %v, want %v", got, c.want)
			}
		})
	}
}

func buildWasmWithMemory(minPages uint32) []byte {
	var secContent []byte
	secContent = utils.AppendULEB128(secContent, uint32(1))
	secContent = append(secContent, 0x00)
	secContent = utils.AppendULEB128(secContent, minPages)
	var out []byte
	out = append(out, 0x00, 0x61, 0x73, 0x6d)
	out = append(out, 0x01, 0x00, 0x00, 0x00)
	out = append(out, 0x05)
	out = utils.AppendULEB128(out, uint32(len(secContent)))
	out = append(out, secContent...)
	return out
}

func TestPatchMemoryMin(t *testing.T) {
	raw := buildWasmWithMemory(1)
	patched, err := patchMemoryMin(raw, 4)
	if err != nil {
		t.Fatalf("patchMemoryMin: %v", err)
	}
	off := 8
	for off < len(patched) {
		secID := patched[off]
		off++
		secSize, n := utils.DecodeULEB128(patched[off:])
		off += n
		secEnd := off + int(secSize)
		if secID == 5 {
			sec := patched[off:secEnd]
			_, cn := utils.DecodeULEB128(sec)
			flags := sec[cn]
			minVal, _ := utils.DecodeULEB128(sec[cn+1:])
			if flags != 0x00 {
				t.Errorf("patchMemoryMin: flags = %d, want 0", flags)
			}
			if minVal != 4 {
				t.Errorf("patchMemoryMin: min = %d, want 4", minVal)
			}
			return
		}
		off = secEnd
	}
	t.Error("patchMemoryMin: memory section not found in patched output")
}

func TestPatchMemoryMinNotWasm(t *testing.T) {
	_, err := patchMemoryMin([]byte("not wasm"), 1)
	if err == nil {
		t.Error("patchMemoryMin: expected error for non-WASM input, got nil")
	}
}

func TestModuleNameForWasm(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.BuildConfig
		path string
		want string
	}{
		{"top-level ImportModule", config.BuildConfig{ImportModule: "global"}, "anything.wasm", "global"},
		{"basename fallback", config.BuildConfig{}, "/dir/other.wasm", "other"},
		{"bare filename fallback", config.BuildConfig{}, "tokens.wasm", "tokens"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := moduleNameForWasm(c.cfg, c.path)
			if got != c.want {
				t.Errorf("moduleNameForWasm: got %q, want %q", got, c.want)
			}
		})
	}
}

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home directory:", err)
	}
	cases := []struct {
		input string
		want  string
	}{
		{"~/foo/bar", filepath.Join(home, "foo/bar")},
		{"/absolute/path", "/absolute/path"},
		{"relative/path", "relative/path"},
	}
	for _, c := range cases {
		got := expandHome(c.input)
		if got != c.want {
			t.Errorf("expandHome(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestExpandHomeNoTilde(t *testing.T) {
	input := "~user/foo"
	got := expandHome(input)
	if strings.HasPrefix(got, "/") {
		t.Errorf("expandHome(%q) = %q, should not expand ~user", input, got)
	}
}
