package generate

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/qrdl/regexped/config"
)

// CmdStub generates language stub files for each regex in cfg.
func CmdStub(cfg config.BuildConfig, outDir string, rust bool) error {
	if !rust {
		return nil
	}
	if err := os.MkdirAll(filepath.Join(outDir, "src"), 0o755); err != nil {
		return fmt.Errorf("mkdir %s/src: %w", outDir, err)
	}
	for _, re := range cfg.Regexes {
		stubPath := filepath.Join(outDir, "src", re.StubFile)
		var content string
		if re.Mode == "find" {
			content = genRustFindStubs(re.Pattern, re.ImportModule, re.ExportName, re.FuncName)
		} else {
			content = genRustStubs(re.Pattern, re.ImportModule, re.ExportName, re.FuncName)
		}
		if err := os.WriteFile(stubPath, []byte(content), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", stubPath, err)
		}
		fmt.Fprintf(os.Stderr, "Written %s\n", stubPath)
	}
	return nil
}
