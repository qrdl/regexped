WASM_TARGET := wasm32-wasip1

.PHONY: run run-sets harnesses baseline perftest-check clean

run: harnesses
	go run .

run-sets: harnesses
	go run . --sets

harnesses:
	cargo build --manifest-path regex_bench/Cargo.toml --target $(WASM_TARGET) --release

# Capture all three baselines from the current codebase.
# Run this once before Phase 1 starts; commit the resulting files.
baseline: harnesses
	go run . -fuel 2>/dev/null > baseline_fuel.txt
	go run . -p 50  2>/dev/null > baseline_time.txt
	go run . -size-only 2>/dev/null > baseline_size.txt
	@echo "Baselines captured."

# Regression gate: compare current run against all three baselines.
# Tolerances:
#   - fuel:  exact match — WASM emission is deterministic.
#   - size:  exact match — same reasoning as fuel.
#   - ratio: ±10% on speedup ratio (rxp p50 / rped p50); patterns where
#             min(rxp,rped) < 1µs are skipped as too noisy.
# To update baselines: run 'make baseline' and commit the resulting txt files.
perftest-check: harnesses
	@echo "Checking fuel baseline (exact)..."
	@go run . -compare-fuel baseline_fuel.txt 2>/dev/null || \
		(echo "BASELINE REGRESSION: fuel — run 'make baseline' if intentional" && exit 1)
	@echo "Checking WASM size baseline (exact)..."
	@go run . -compare-size baseline_size.txt 2>/dev/null || \
		(echo "BASELINE REGRESSION: WASM size — run 'make baseline' if intentional" && exit 1)
	@echo "Checking speedup ratio (±10%)..."
	@go run . -compare-time baseline_time.txt 2>/dev/null || \
		(echo "BASELINE REGRESSION: speedup ratio — run 'make baseline' if intentional" && exit 1)
	@echo "All baseline checks passed."

clean:
	cargo clean --manifest-path regex_bench/Cargo.toml
