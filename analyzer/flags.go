package analyzer

import (
	"errors"
	"reflect"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
)

// errTypesFlagNotRegistered is returned when the -types flag is missing.
var errTypesFlagNotRegistered = errors.New("-types flag not registered on analyzer")

// FlagAnalyzer provides shared configuration for all sensitive-check analyzers.
// It registers a -sensitive.types and -sensitive.no-default-types flags,
// consumed by both sensitivefields and sensitiveprint via Requires.
//
//nolint:gochecknoglobals // Required by go/analysis framework.
var FlagAnalyzer = &analysis.Analyzer{
	Name:       "sensitive",
	Doc:        "shared configuration for sensitive-value analyzers",
	ResultType: reflect.TypeFor[matcher](),
	Run:        runFlag,
}

// FieldsAnalyzer is the standalone (flag-driven) variant of the fields check.
// It depends on FlagAnalyzer for its config.
//
//nolint:gochecknoglobals // Standalone flag-driven analyzers for the binary.
var FieldsAnalyzer = newFieldsAnalyzer(
	[]*analysis.Analyzer{inspect.Analyzer, FlagAnalyzer}, matcherFromFlag)

// PrintAnalyzer is the standalone (flag-driven) variant of the print check.
// It depends on FlagAnalyzer for its config.
//
//nolint:gochecknoglobals // Standalone flag-driven analyzers for the binary.
var PrintAnalyzer = newPrintAnalyzer(
	[]*analysis.Analyzer{inspect.Analyzer, FlagAnalyzer}, matcherFromFlag)

func init() { //nolint:gochecknoinits // Required for flag registration.
	FlagAnalyzer.Flags.String("types", "",
		"Comma-separated list of sensitive type package import paths "+
			"(optionally with .TypeName suffix to restrict to a specific type)")
	FlagAnalyzer.Flags.Bool("no-default-types", false,
		"Do not seed the built-in default sensitive type list")
}

func matcherFromFlag(pass *analysis.Pass) (matcher, error) {
	return pass.ResultOf[FlagAnalyzer].(matcher), nil
}

func runFlag(pass *analysis.Pass) (any, error) {
	typesFlag := pass.Analyzer.Flags.Lookup("types")
	if typesFlag == nil {
		return nil, errTypesFlagNotRegistered
	}
	noDefaults := false
	if f := pass.Analyzer.Flags.Lookup("no-default-types"); f != nil {
		noDefaults = f.Value.String() == "true"
	}
	return newMatcher(Config{
		Types:          splitCSV(typesFlag.Value.String()),
		NoDefaultTypes: noDefaults,
	}), nil
}

// splitCSV splits a comma-separated string, trims whitespace from each element,
// and drops empty entries.
func splitCSV(s string) []string {
	var result []string
	for entry := range strings.SplitSeq(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry != "" {
			result = append(result, entry)
		}
	}
	return result
}
