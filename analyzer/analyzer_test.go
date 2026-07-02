package analyzer_test

import (
	"strings"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/powerman/lint-sensitive/analyzer"
)

const testTypes = "fakesensitive,fakeplayground,fakelogfusc,fakesecrecy.Secret"

func TestMain(m *testing.M) {
	err := analyzer.FlagAnalyzer.Flags.Set("types", testTypes)
	if err != nil {
		panic("failed to set -types flag: " + err.Error())
	}
	m.Run()
}

func TestFieldsAnalyzer(t *testing.T) {
	t.Parallel()
	analysistest.Run(t, analysistest.TestData(), analyzer.FieldsAnalyzer, "fields")
}

func TestPrintAnalyzer(t *testing.T) {
	t.Parallel()
	analysistest.Run(t, analysistest.TestData(), analyzer.PrintAnalyzer, "printcheck")
}

func TestNewFieldsAnalyzer(t *testing.T) {
	t.Parallel()

	analyzers := analyzer.New(analyzer.Config{Types: strings.Split(testTypes, ",")})
	for _, a := range analyzers {
		if a.Name == "sensitivefields" {
			analysistest.Run(t, analysistest.TestData(), a, "fields")
			return
		}
	}
	t.Fatal("sensitivefields not found in New() result")
}

func TestNewPrintAnalyzer(t *testing.T) {
	t.Parallel()

	analyzers := analyzer.New(analyzer.Config{Types: strings.Split(testTypes, ",")})
	for _, a := range analyzers {
		if a.Name == "sensitiveprint" {
			analysistest.Run(t, analysistest.TestData(), a, "printcheck")
			return
		}
	}
	t.Fatal("sensitiveprint not found in New() result")
}
