package analyzer_test

import (
	"strings"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/powerman/lint-sensitive/analyzer"
)

// TestSkipTests verifies that with SkipTests: true, diagnostics from _test.go
// files are suppressed while diagnostics from regular files are still reported.
// The WITHOUT case (test files NOT skipped) is covered by the existing
// TestInTestFile and TestFieldsAnalyzer tests — we already proved that
// inTestFile returns false for regular files and that the linter processes
// _test.go files by default.
func TestSkipTests(t *testing.T) {
	t.Parallel()

	analyzers := analyzer.New(analyzer.Config{
		Types:     strings.Split(testTypes, ","),
		SkipTests: true,
	})
	for _, a := range analyzers {
		if a.Name == "sensitivefields" {
			// skiptests package has a regular file (pkg.go) that should be flagged,
			// and a _test.go file (pkg_test.go) whose diagnostic is suppressed.
			analysistest.Run(t, analysistest.TestData(), a, "skiptests")
			return
		}
	}
	t.Fatal("sensitivefields not found in New() result")
}

// TestSkipGenerated verifies that with SkipGenerated: true, diagnostics from
// generated files are suppressed while diagnostics from regular files are
// still reported.
func TestSkipGenerated(t *testing.T) {
	t.Parallel()

	analyzers := analyzer.New(analyzer.Config{
		Types:         strings.Split(testTypes, ","),
		SkipGenerated: true,
	})
	for _, a := range analyzers {
		if a.Name == "sensitivefields" {
			// skipgen package has a regular file (pkg.go) that should be flagged,
			// and a generated file (pkg_generated.go) whose diagnostic is suppressed.
			analysistest.Run(t, analysistest.TestData(), a, "skipgen")
			return
		}
	}
	t.Fatal("sensitivefields not found in New() result")
}

// TestSkipReliability verifies that skip-tests and skip-generated
// also apply to the reliability-level diagnostics:
// references in skipped files are ignored,
// and a type referenced both there and in a regular file is reported in the regular file.
func TestSkipReliability(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  analyzer.Config
		pkg  string
	}{
		{"skip-tests", analyzer.Config{SkipTests: true}, "skiptests_reliability"},
		{"skip-generated", analyzer.Config{SkipGenerated: true}, "skipgen_reliability"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.cfg.Types = reliabilityTypes
			tc.cfg.RequireMarshalJSON = true
			for _, a := range analyzer.New(tc.cfg) {
				if a.Name == "sensitivefields" {
					analysistest.Run(t, analysistest.TestData(), a, tc.pkg)
					return
				}
			}
			t.Fatal("sensitivefields not found in New() result")
		})
	}
}
