WASM_TARGET := wasm32-wasip1

.PHONY: harnesses clean

harnesses:
	cargo build --manifest-path regex_harness/Cargo.toml --target $(WASM_TARGET) --release
	cargo build --manifest-path regexped_harness/Cargo.toml --target $(WASM_TARGET) --release
	cargo build --manifest-path regex_find_harness/Cargo.toml --target $(WASM_TARGET) --release
	cargo build --manifest-path regexped_find_harness/Cargo.toml --target $(WASM_TARGET) --release

clean:
	rm -rf out/
	cargo clean --manifest-path regex_harness/Cargo.toml
	cargo clean --manifest-path regexped_harness/Cargo.toml
	cargo clean --manifest-path regex_find_harness/Cargo.toml
	cargo clean --manifest-path regexped_find_harness/Cargo.toml
