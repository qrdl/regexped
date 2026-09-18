package compile

import (
	"math/rand"
	"testing"
)

// TestSequentializeCopiesMatchesReference pins the fast parallel-copy
// sequencer to the reference implementation it replaced.
//
// The two must agree op for op, not merely produce a valid order: the emitted
// sequence ends up as WASM register moves, and a sequence that orders them
// differently can read a register an earlier move in the same batch already
// overwrote. That failure is silent — the module validates and answers wrongly
// — which is why this is a differential rather than a property test.
//
// Random bijections over a small register pool are exactly the interesting
// input, because a bijection is what the rename produces and cycles (A needs
// B's slot, B needs A's) are what force the scratch-register break.
func TestSequentializeCopiesMatchesReference(t *testing.T) {
	rnd := rand.New(rand.NewSource(20260918))
	var cyclic int
	const iters = 200000
	for iter := 0; iter < iters; iter++ {
		n := 1 + rnd.Intn(10)
		extra := rnd.Intn(3) // some sources outside the destination set
		pool := make([]int, n+extra)
		for i := range pool {
			pool[i] = i
		}
		rnd.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
		ops := make([]tdfaTagOp, 0, n)
		ok := true
		for i := 0; i < n; i++ {
			if pool[i] == i { // a self-copy: the rename never emits one
				ok = false
				break
			}
			ops = append(ops, tdfaTagOp{dst: i, src: pool[i]})
		}
		if !ok {
			continue
		}
		want := sequentializeCopiesRoundwise(append([]tdfaTagOp(nil), ops...))
		got := sequentializeCopies(append([]tdfaTagOp(nil), ops...))
		if len(want) != len(got) {
			t.Fatalf("length differs for %v:\n reference %v\n fast      %v", ops, want, got)
		}
		for i := range want {
			if want[i] != got[i] {
				t.Fatalf("op %d differs for %v:\n reference %v\n fast      %v", i, ops, want, got)
			}
		}
		if len(want) > len(ops) {
			cyclic++
		}
	}
	// A run that never needed the scratch register would not have tested the
	// cycle-breaking arm at all, which is the half most likely to diverge.
	if cyclic < iters/10 {
		t.Fatalf("only %d of %d cases needed cycle-breaking; the generator is not producing cycles", cyclic, iters)
	}
	t.Logf("%d cases, %d required cycle-breaking through the scratch register", iters, cyclic)
}
