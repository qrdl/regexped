module github.com/qrdl/regexped

go 1.26

// Pinned below 1.26.11: from that release `go` refuses a linker input
// carrying an LTO section (CVE-2026-97038), and wasmtime-go's prebuilt
// libwasmtime.a (v48-v50), which the tools/ harnesses link, carries
// `.llvmbc` in most of its objects. setup-go installs this version.
toolchain go1.26.10

require github.com/goccy/go-yaml v1.19.2
