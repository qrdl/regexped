module github.com/qrdl/regexped/perftest

go 1.25

replace github.com/qrdl/regexped => ../

require (
	github.com/bytecodealliance/wasmtime-go/v42 v42.0.0
	github.com/qrdl/regexped v0.0.0-00010101000000-000000000000
)

require github.com/goccy/go-yaml v1.19.2 // indirect
