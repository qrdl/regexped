package compile

import (
	"errors"
	"fmt"

	"github.com/qrdl/regexped/internal/utils"
)

// maxWasmFunctionBytes is WebAssembly's cap on one function body: wasmparser's
// MAX_WASM_FUNCTION_SIZE, which wasmtime validates every module against, and
// the JS API's implementation limit, which browsers enforce. A module with a
// larger body does not load anywhere, so it must not compile.
//
// Only a Backtracking body comes near it: one br_table case per program
// instruction, measured at 86 bytes per instruction in byte mode and 121-127
// in Unicode mode — the cap at ~89,000 and ~60,000 instructions, against
// max_bt_instructions' default of 20,000. Splitting such a body into several
// functions was weighed and not done: no real pattern measured (the WAF
// rules, the examples) comes within reach of it.
const maxWasmFunctionBytes = 7_654_321

// ErrFunctionTooLarge is a module that would carry a function body over
// WebAssembly's cap.
var ErrFunctionTooLarge = errors.New("compile: a generated function is over WebAssembly's function size cap")

// codeOwner marks where one owner's bodies start in a code section's content:
// a pattern, a set, or a set member whose Backtracking body sits in the set's
// run of functions.
type codeOwner struct {
	at   int
	name string
}

// codeOwners is filled by the assemblers (asmOpts.owners) as they append
// bodies; nil-safe, so an assembly nobody checks records nothing.
type codeOwners []codeOwner

func (o *codeOwners) mark(at int, name string) {
	if o != nil {
		*o = append(*o, codeOwner{at: at, name: name})
	}
}

// ownerAt is the owner of the body starting at offset at.
func (o codeOwners) ownerAt(at int) string {
	name := ""
	for _, c := range o {
		if c.at > at {
			break
		}
		name = c.name
	}
	return name
}

// checkFunctionSizes refuses a module with a function body over
// maxWasmFunctionBytes, naming its owner. wasm is the whole module; the
// owners' offsets are into its code section's content.
func checkFunctionSizes(wasm []byte, owners codeOwners) error {
	code := sectionContent(wasm, 10)
	if code == nil {
		return nil
	}
	n, k, err := utils.DecodeULEB128(code)
	if err != nil {
		return nil
	}
	p := k
	for i := uint64(0); i < n && p < len(code); i++ {
		size, k, err := utils.DecodeULEB128(code[p:])
		if err != nil {
			return nil
		}
		start := p
		p += k + int(size)
		if size <= maxWasmFunctionBytes {
			continue
		}
		owner := owners.ownerAt(start)
		if owner == "" {
			owner = "the module's own glue"
		}
		return fmt.Errorf("%w: one function generated for %s is %d bytes, over WebAssembly's cap of %d bytes "+
			"per function, so no runtime would load the module. It is a Backtracking body, which grows with "+
			"the pattern's program: lower max_bt_instructions below the program's size, raise max_dfa_states "+
			"to keep the pattern on a DFA, or simplify the pattern",
			ErrFunctionTooLarge, owner, size, maxWasmFunctionBytes)
	}
	return nil
}

// sectionContent is the content of wasm's section id (10 = code, 11 = data),
// or nil.
func sectionContent(wasm []byte, id byte) []byte {
	if len(wasm) < 8 {
		return nil
	}
	p := 8
	for p < len(wasm) {
		sec := wasm[p]
		size, k, err := utils.DecodeULEB128(wasm[p+1:])
		if err != nil {
			return nil
		}
		start := p + 1 + k
		end := start + int(size)
		if end > len(wasm) {
			return nil
		}
		if sec == id {
			return wasm[start:end]
		}
		p = end
	}
	return nil
}
