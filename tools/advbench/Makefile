.PHONY: adversary list run clean

# Every adversarial drive shape found so far, plus the drives already measured
# linear. Rows expected LINEAR fail the run when their fuel ratio per input
# doubling exceeds 2.5 at the largest size, or when a ratio RISES past 2.1
# (a quadratic share climbs; fixed costs only fade); rows expected QUADRATIC are known
# open drives, reported with their ratio; REPORT rows print memory and
# correctness evidence. Fuel is exact, so the run needs no quiet machine —
# but it is memory-hungry: run it alone.
adversary:
	go run . -suite $(ARGS)

list:
	go run . -suite -list

# One drive, e.g.:
#   make run ARGS="-pattern 'a*b|a' -fn find -gen rep:a -sizes 4096,8192,16384"
#   make run ARGS="-config cfg/ovl.yaml -fn find -gen rep:foo -cache=false"
run:
	go run . $(ARGS)

clean:
	go clean
