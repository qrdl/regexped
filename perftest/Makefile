WASM_TARGET := wasm32-wasip1

.PHONY: run run-sets harnesses baseline perftest-check baseline-sets sets-check clean

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

# Capture all three set baselines from the current codebase.
baseline-sets: harnesses
	go run . --sets -p 50  2>/dev/null > baseline_sets_time.txt
	go run . --sets -fuel  2>/dev/null > baseline_sets_fuel.txt
	go run . --size-only-sets 2>/dev/null > baseline_sets_size.txt
	@echo "Set baselines captured."

# Regression gate for set benchmarks.
# Tolerances: time ±10%, fuel ±20%, size ±5%.
sets-check: harnesses
	@echo "Checking set time baseline (±10%)..."
	@go run . --compare-sets-time baseline_sets_time.txt 2>/dev/null || \
		(echo "SET REGRESSION: time — run 'make baseline-sets' if intentional" && exit 1)
	@echo "Checking set fuel baseline (±20%)..."
	@go run . --compare-sets-fuel baseline_sets_fuel.txt 2>/dev/null || \
		(echo "SET REGRESSION: fuel — run 'make baseline-sets' if intentional" && exit 1)
	@echo "Checking set size baseline (±5%)..."
	@go run . --compare-sets-size baseline_sets_size.txt 2>/dev/null || \
		(echo "SET REGRESSION: size — run 'make baseline-sets' if intentional" && exit 1)
	@echo "All set baseline checks passed."

clean:
	cargo clean --manifest-path regex_bench/Cargo.toml
