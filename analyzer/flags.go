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

const trueStr = "true"

// FlagAnalyzer provides shared configuration for all sensitive-check analyzers.
// It registers -sensitive.types, -sensitive.no-default-types,
// -sensitive.skip-tests, and -sensitive.skip-generated flags,
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
	FlagAnalyzer.Flags.Bool("skip-tests", false,
		"Do not report diagnostics in _test.go files")
	FlagAnalyzer.Flags.Bool("skip-generated", false,
		"Do not report diagnostics in generated files (Code generated ... DO NOT EDIT)")
	FlagAnalyzer.Flags.Bool("require-marshal-json", false,
		"Require all configured safe types to implement encoding.TextMarshaler or json.Marshaler")
	FlagAnalyzer.Flags.Bool("require-marshal-text", false,
		"Require all configured safe types to implement encoding.TextMarshaler")
	FlagAnalyzer.Flags.Bool("require-format", false,
		"Require all configured safe types to implement fmt.Formatter or be structurally protected")
	FlagAnalyzer.Flags.Bool("require-gostring", false,
		"Require all configured safe types to implement fmt.GoStringer, fmt.Formatter, or be structurally protected")
	FlagAnalyzer.Flags.Bool("require-string", false,
		"Require all configured safe types to implement fmt.Stringer, fmt.Formatter, or be structurally protected")
	FlagAnalyzer.Flags.Bool("debug", false,
		"Print sensitive type classification to stderr")
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
		noDefaults = f.Value.String() == trueStr
	}
	skipTests := false
	if f := pass.Analyzer.Flags.Lookup("skip-tests"); f != nil {
		skipTests = f.Value.String() == trueStr
	}
	skipGenerated := false
	if f := pass.Analyzer.Flags.Lookup("skip-generated"); f != nil {
		skipGenerated = f.Value.String() == trueStr
	}
	debug := false
	if f := pass.Analyzer.Flags.Lookup("debug"); f != nil {
		debug = f.Value.String() == trueStr
	}
	requireMarshalJSON := false
	if f := pass.Analyzer.Flags.Lookup("require-json-safety"); f != nil {
		requireMarshalJSON = f.Value.String() == trueStr
	}
	requireMarshalText := false
	if f := pass.Analyzer.Flags.Lookup("require-marshal-text"); f != nil {
		requireMarshalText = f.Value.String() == trueStr
	}
	requireFormat := false
	if f := pass.Analyzer.Flags.Lookup("require-format"); f != nil {
		requireFormat = f.Value.String() == trueStr
	}
	requireGoString := false
	if f := pass.Analyzer.Flags.Lookup("require-gostring"); f != nil {
		requireGoString = f.Value.String() == trueStr
	}
	requireString := false
	if f := pass.Analyzer.Flags.Lookup("require-string"); f != nil {
		requireString = f.Value.String() == trueStr
	}
	return newMatcher(Config{
		Types:              splitCSV(typesFlag.Value.String()),
		NoDefaultTypes:     noDefaults,
		SkipTests:          skipTests,
		SkipGenerated:      skipGenerated,
		RequireMarshalJSON: requireMarshalJSON,
		RequireMarshalText: requireMarshalText,
		RequireFormat:      requireFormat,
		RequireGoString:    requireGoString,
		RequireString:      requireString,
		Debug:              debug,
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
