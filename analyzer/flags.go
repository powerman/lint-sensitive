package analyzer

import (
	"reflect"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
)

// FlagAnalyzer provides shared configuration for all sensitive-check analyzers.
// It registers the -sensitive.* flags
// and passes them to sensitivefields and sensitiveprint via Requires.
// The -sensitive.require-* and -sensitive.debug flags affect only sensitivefields.
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

// Flags are bound to the fields of flagConfig at registration,
// so a typo in a flag name cannot silently disconnect a flag from its Config field.
// Types and PublicFields are the exception:
// they are comma-separated strings which runFlag splits.
//
//nolint:gochecknoglobals // Registered in init(), read in runFlag.
var (
	flagConfig Config
	flagTypes  string
	flagPublic string
)

func init() { //nolint:gochecknoinits // Required for flag registration.
	fs := &FlagAnalyzer.Flags
	fs.StringVar(&flagTypes, "types", "",
		"Comma-separated list of sensitive type package import paths "+
			"(optionally with .TypeName suffix to restrict to a specific type)")
	fs.StringVar(&flagPublic, "public", "",
		"Comma-separated list of fields of sensitive types which never hold the secret "+
			"(import/path.TypeName.FieldName)")
	fs.BoolVar(&flagConfig.NoDefaultTypes, "no-default-types", false,
		"Do not seed the built-in default sensitive type list")
	fs.BoolVar(&flagConfig.SkipTests, "skip-tests", false,
		"Do not report diagnostics in _test.go files")
	fs.BoolVar(&flagConfig.SkipGenerated, "skip-generated", false,
		"Do not report diagnostics in generated files (Code generated ... DO NOT EDIT)")
	fs.BoolVar(&flagConfig.RequireMarshalJSON, "require-marshal-json", false,
		"Require all configured safe types to implement encoding.TextMarshaler or json.Marshaler, "+
			"or be opaque structs")
	fs.BoolVar(&flagConfig.RequireMarshalText, "require-marshal-text", false,
		"Require all configured safe types to implement encoding.TextMarshaler, "+
			"or be opaque String-level safe structs")
	fs.BoolVar(&flagConfig.RequireFormat, "require-format", false,
		"Require all configured safe types to implement fmt.Formatter or be structurally protected")
	fs.BoolVar(&flagConfig.RequireGoString, "require-gostring", false,
		"Require all configured safe types to implement fmt.GoStringer, fmt.Formatter, or be structurally protected")
	fs.BoolVar(&flagConfig.RequireString, "require-string", false,
		"Require all configured safe types to implement fmt.Stringer, fmt.Formatter, or be structurally protected")
	fs.BoolVar(&flagConfig.Debug, "debug", false,
		"Print sensitive type classification to stderr")
}

func matcherFromFlag(pass *analysis.Pass) (matcher, error) {
	return pass.ResultOf[FlagAnalyzer].(matcher), nil
}

func runFlag(*analysis.Pass) (any, error) {
	cfg := flagConfig
	cfg.Types = splitCSV(flagTypes)
	cfg.PublicFields = splitCSV(flagPublic)
	m := newMatcher(cfg)
	if m.err != nil {
		return nil, m.err
	}
	return m, nil
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
