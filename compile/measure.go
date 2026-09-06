package compile

// Measurement scaffolding for LENGTH-HINT.md's T0.6 — the narrow-vs-wide scope
// decision. NOT part of the compiler's contract and NOT reachable from YAML.
//
// # Why a package-level knob rather than a CompileOptions field
//
// T0.6 has to answer one question: for each mechanism the input-length hint
// might de-emit, what does removing it WIN on a short input and COST on a long
// one? Answering it needs each mechanism switched off independently, at its own
// detection site, several of which sit behind layout structs that
// CompileOptions does not currently reach. Threading four new fields through
// those structs is most of T0.1's plumbing — and T0.1 comes AFTER this
// measurement precisely because its scope depends on the answer.
//
// So this is deliberately the cheap shape: one process-global mask, set by
// tools/lentest before it compiles and cleared after. It is not safe for
// concurrent compilation and does not try to be. When the mechanisms are wired
// to CompileOptions.InputLength for real, this file goes.
//
// The zero value changes nothing, which `make byteident` asserts.
type MeasureMask uint32

const (
	// MeasurePrefixScanSIMD suppresses the prefix scan's SIMD arm entirely, so
	// the scalar tail — a complete implementation on its own — answers. A3.
	MeasurePrefixScanSIMD MeasureMask = 1 << iota

	// MeasureTDFABulkSkip suppresses the TDFA capture body's bulk skip. A5.
	MeasureTDFABulkSkip

	// MeasureDominantFind suppresses BOTH dominant self-loop channels in find
	// bodies — the mid-accept one, which is emitted in every mode, and the
	// non-mid one, which only prefer-match adds. A1.
	MeasureDominantFind

	// MeasureDominantMatch suppresses the anchored match body's Phase-4
	// dominant load. A2.
	MeasureDominantMatch

	// ---- the NARROW set: mechanisms a prefer-* hint ADDED ----
	//
	// De-emitting one of these lands the caller on the neutral build, so the
	// worst a mispredicting caller can lose is the hint's own win. Measured
	// separately from the wide set because that bound makes them the only
	// candidates left after T0.6.

	// MeasureNonMidShufti suppresses the non-mid Shufti self-loop channel that
	// prefer-match adds to find bodies. A1's narrow half — and the row that
	// started this whole plan (tdfa-capture-body-short, +10.2%).
	MeasureNonMidShufti

	// MeasureClassChain suppresses the class-chain SIMD verify. A4.
	MeasureClassChain

	// MeasureDenseSwitch suppresses the adaptive dense switch and its neutral
	// twin, which prefer-no-match adds. A6.
	MeasureDenseSwitch

	// MeasureUnionStride suppresses the union scan's SIMD stride, which
	// prefer-no-match adds. B4.
	MeasureUnionStride

	// MeasureMemberSkip suppresses the sparse bucket member self-loop skip,
	// which prefer-match adds. B5 (and B1's narrow half).
	MeasureMemberSkip
)

// measureDisabled is the active mask. Package-level for the reason above.
var measureDisabled MeasureMask

// SetMeasureDisabled sets the mask and returns the previous value, so a caller
// can restore it. Measurement only — see the type's doc comment.
func SetMeasureDisabled(m MeasureMask) MeasureMask {
	prev := measureDisabled
	measureDisabled = m
	return prev
}

// measureOff reports whether mechanism m is switched off for measurement.
func measureOff(m MeasureMask) bool { return measureDisabled&m != 0 }

// measureMemberWalkStates is memberWalkStates with T0.6's gate.
func measureMemberWalkStates(t *dfaTable) []dominantWalkState {
	if measureOff(MeasureMemberSkip) {
		return nil
	}
	return memberWalkStates(t)
}
