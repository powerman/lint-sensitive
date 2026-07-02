package analyzer_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/powerman/lint-sensitive/analyzer"
)

// reliabilityTypes is the set of fake test types for reliability-level tests.
// It mirrors testTypes from analyzer_test.go but omits fakeplayground
// (which no reliability testdata uses).
var reliabilityTypes = []string{"fakesensitive", "fakesecrecy.Secret", "fakelogfusc"}

// TestRequireMarshalJSON verifies that -require-marshal-json emits diagnostics
// for safe types that lack encoding.TextMarshaler and json.Marshaler.
func TestRequireMarshalJSON(t *testing.T) {
	t.Parallel()

	analyzers := analyzer.New(analyzer.Config{
		Types:              reliabilityTypes,
		RequireMarshalJSON: true,
	})
	for _, a := range analyzers {
		if a.Name == "sensitivefields" {
			analysistest.Run(t, analysistest.TestData(), a, "reliability_marshal_json")
			return
		}
	}
	t.Fatal("sensitivefields not found in New() result")
}

// TestRequireMarshalText verifies that -require-marshal-text emits diagnostics
// for safe types that lack encoding.TextMarshaler.
func TestRequireMarshalText(t *testing.T) {
	t.Parallel()

	analyzers := analyzer.New(analyzer.Config{
		Types:              reliabilityTypes,
		RequireMarshalText: true,
	})
	for _, a := range analyzers {
		if a.Name == "sensitivefields" {
			analysistest.Run(t, analysistest.TestData(), a, "reliability_marshal_text")
			return
		}
	}
	t.Fatal("sensitivefields not found in New() result")
}

// TestRequireFormat verifies that -require-format emits diagnostics
// for safe types that lack fmt.Formatter and structural protection.
func TestRequireFormat(t *testing.T) {
	t.Parallel()

	analyzers := analyzer.New(analyzer.Config{
		Types:         reliabilityTypes,
		RequireFormat: true,
	})
	for _, a := range analyzers {
		if a.Name == "sensitivefields" {
			analysistest.Run(t, analysistest.TestData(), a, "reliability_format")
			return
		}
	}
	t.Fatal("sensitivefields not found in New() result")
}

// TestRequireGoString verifies that -require-gostring emits
// diagnostics for safe types that lack fmt.GoStringer, fmt.Formatter,
// and structural protection.
func TestRequireGoString(t *testing.T) {
	t.Parallel()

	analyzers := analyzer.New(analyzer.Config{
		Types:           reliabilityTypes,
		RequireGoString: true,
	})
	for _, a := range analyzers {
		if a.Name == "sensitivefields" {
			analysistest.Run(t, analysistest.TestData(), a, "reliability_gostring")
			return
		}
	}
	t.Fatal("sensitivefields not found in New() result")
}

// TestRequireString verifies that -require-string emits
// diagnostics for safe types that lack fmt.Stringer, fmt.Formatter,
// and structural protection.
func TestRequireString(t *testing.T) {
	t.Parallel()

	analyzers := analyzer.New(analyzer.Config{
		Types:         reliabilityTypes,
		RequireString: true,
	})
	for _, a := range analyzers {
		if a.Name == "sensitivefields" {
			analysistest.Run(t, analysistest.TestData(), a, "reliability_string")
			return
		}
	}
	t.Fatal("sensitivefields not found in New() result")
}

// TestNoReliabilityFlags verifies that without any reliability flags,
// no reliability diagnostics are produced for the same code.
func TestNoReliabilityFlags(t *testing.T) {
	t.Parallel()

	analyzers := analyzer.New(analyzer.Config{
		Types: reliabilityTypes,
	})
	for _, a := range analyzers {
		if a.Name == "sensitivefields" {
			analysistest.Run(t, analysistest.TestData(), a, "reliability_none")
			return
		}
	}
	t.Fatal("sensitivefields not found in New() result")
}
