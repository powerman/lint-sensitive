package analyzer_test

import (
	"slices"
	"testing"

	"github.com/powerman/lint-sensitive/analyzer"
)

// reliabilityTypes is the set of fake test types for reliability-level tests.
// It mirrors testTypes from analyzer_test.go but omits fakeplayground
// (which no reliability testdata uses).
var reliabilityTypes = []string{"fakesensitive", "fakesecrecy.Secret", "fakelogfusc", "fakeconceal.Text", "fakeconceal.Bytes"}

// TestRequireMarshalJSON verifies that -require-marshal-json emits diagnostics
// for safe types that lack encoding.TextMarshaler and json.Marshaler.
func TestRequireMarshalJSON(t *testing.T) {
	t.Parallel()

	runNew(t, analyzer.Config{Types: reliabilityTypes, RequireMarshalJSON: true}, "sensitivefields", "reliability_marshal_json")
}

// TestRequireMarshalText verifies that -require-marshal-text emits diagnostics
// for safe types that lack encoding.TextMarshaler.
func TestRequireMarshalText(t *testing.T) {
	t.Parallel()

	runNew(t, analyzer.Config{Types: reliabilityTypes, RequireMarshalText: true}, "sensitivefields", "reliability_marshal_text")
}

// TestRequireFormat verifies that -require-format emits diagnostics
// for safe types that lack fmt.Formatter and structural protection.
func TestRequireFormat(t *testing.T) {
	t.Parallel()

	runNew(t, analyzer.Config{Types: reliabilityTypes, RequireFormat: true}, "sensitivefields", "reliability_format")
}

// TestRequireGoString verifies that -require-gostring emits
// diagnostics for safe types that lack fmt.GoStringer, fmt.Formatter,
// and structural protection.
func TestRequireGoString(t *testing.T) {
	t.Parallel()

	runNew(t, analyzer.Config{Types: reliabilityTypes, RequireGoString: true}, "sensitivefields", "reliability_gostring")
}

// TestRequireString verifies that -require-string emits
// diagnostics for safe types that lack fmt.Stringer, fmt.Formatter,
// and structural protection.
func TestRequireString(t *testing.T) {
	t.Parallel()

	runNew(t, analyzer.Config{Types: reliabilityTypes, RequireString: true}, "sensitivefields", "reliability_string")
}

// TestNoReliabilityFlags verifies that without any reliability flags,
// no reliability diagnostics are produced for the same code.
func TestNoReliabilityFlags(t *testing.T) {
	t.Parallel()

	runNew(t, analyzer.Config{Types: reliabilityTypes}, "sensitivefields", "reliability_none")
}

// TestRequireFormatAlias verifies that -require-format sees a safe type
// referenced only through an alias declared in another package.
func TestRequireFormatAlias(t *testing.T) {
	t.Parallel()

	runNew(t, analyzer.Config{Types: reliabilityTypes, RequireFormat: true}, "sensitivefields", "reliability_alias")
}

// TestRequireFormatGeneric verifies that instances of one generic safe type
// which fail for the same reason are reported once.
func TestRequireFormatGeneric(t *testing.T) {
	t.Parallel()

	types := append(slices.Clone(reliabilityTypes), "reliability_generic.Wrap")
	runNew(t, analyzer.Config{Types: types, RequireFormat: true}, "sensitivefields", "reliability_generic")
}
