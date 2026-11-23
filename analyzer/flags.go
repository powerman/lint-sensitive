package analyzer

import (
	"reflect"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
)

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

// Flag values are read through the pointers returned at registration,
// so a typo in a flag name cannot silently disconnect a flag from its Config field.
//
//nolint:gochecknoglobals // Registered in init(), read in runFlag.
var (
	flagTypes              *string
	flagNoDefaultTypes     *bool
	flagSkipTests          *bool
	flagSkipGenerated      *bool
	flagRequireMarshalJSON *bool
	flagRequireMarshalText *bool
	flagRequireFormat      *bool
	flagRequireGoString    *bool
	flagRequireString      *bool
	flagDebug              *bool
)

func init() { //nolint:gochecknoinits // Required for flag registration.
	fs := &FlagAnalyzer.Flags
	flagTypes = fs.String("types", "",
		"Comma-separated list of sensitive type package import paths "+
			"(optionally with .TypeName suffix to restrict to a specific type)")
	flagNoDefaultTypes = fs.Bool("no-default-types", false,
		"Do not seed the built-in default sensitive type list")
	flagSkipTests = fs.Bool("skip-tests", false,
		"Do not report diagnostics in _test.go files")
	flagSkipGenerated = fs.Bool("skip-generated", false,
		"Do not report diagnostics in generated files (Code generated ... DO NOT EDIT)")
	flagRequireMarshalJSON = fs.Bool("require-marshal-json", false,
		"Require all configured safe types to implement encoding.TextMarshaler or json.Marshaler")
	flagRequireMarshalText = fs.Bool("require-marshal-text", false,
		"Require all configured safe types to implement encoding.TextMarshaler")
	flagRequireFormat = fs.Bool("require-format", false,
		"Require all configured safe types to implement fmt.Formatter or be structurally protected")
	flagRequireGoString = fs.Bool("require-gostring", false,
		"Require all configured safe types to implement fmt.GoStringer, fmt.Formatter, or be structurally protected")
	flagRequireString = fs.Bool("require-string", false,
		"Require all configured safe types to implement fmt.Stringer, fmt.Formatter, or be structurally protected")
	flagDebug = fs.Bool("debug", false,
		"Print sensitive type classification to stderr")
}

func matcherFromFlag(pass *analysis.Pass) (matcher, error) {
	return pass.ResultOf[FlagAnalyzer].(matcher), nil
}

func runFlag(*analysis.Pass) (any, error) {
	return newMatcher(Config{
		Types:              splitCSV(*flagTypes),
		NoDefaultTypes:     *flagNoDefaultTypes,
		SkipTests:          *flagSkipTests,
		SkipGenerated:      *flagSkipGenerated,
		RequireMarshalJSON: *flagRequireMarshalJSON,
		RequireMarshalText: *flagRequireMarshalText,
		RequireFormat:      *flagRequireFormat,
		RequireGoString:    *flagRequireGoString,
		RequireString:      *flagRequireString,
		Debug:              *flagDebug,
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
