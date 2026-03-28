WASM_TARGET := wasm32-wasip1

.PHONY: run harnesses clean

run: harnesses
	go run .

harnesses:
	cargo build --manifest-path regex_bench/Cargo.toml --target $(WASM_TARGET) --release

clean:
	cargo clean --manifest-path regex_bench/Cargo.toml
