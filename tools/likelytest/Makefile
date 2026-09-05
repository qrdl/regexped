.PHONY: run sets baseline clean

# Run the 3x3 likely/unlikely/neutral matrix tool.
run:
	go run .

# Run only the set-composition cases (mode == modeSet).
sets:
	go run . -sets

# Capture a baseline snapshot of the current numbers.
baseline:
	go run . > baseline_likely.txt
	@echo "Likely baseline captured."

clean:
	rm -f baseline_likely.txt
