package analyzer

import (
	"errors"
	"flag"
	"reflect"
	"strings"
	"sync"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
)

// NewFlagAnalyzers returns the analyzers of the lint-sensitive binary:
// sensitive, sensitivefields, sensitiveprint and sensitivefmt.
// The first one registers the -sensitive.* flags
// and passes the resulting configuration to the others via Requires.
// The -sensitive.detect-fields, -sensitive.require-* and -sensitive.debug flags
// affect only sensitivefields.
// Each call returns an independent set.
func NewFlagAnalyzers() []*analysis.Analyzer {
	var (
		cfg           Config
		types, public string
		printed       sync.Map // Shared by the matchers built for every package.
	)
	fa := &analysis.Analyzer{
		Name:       "sensitive",
		Doc:        "shared configuration for sensitive-value analyzers",
		ResultType: reflect.TypeFor[matcher](),
	}
	registerFlags(&fa.Flags, &cfg, &types, &public)
	fa.Run = func(*analysis.Pass) (any, error) {
		c := cfg
		c.Types = splitCSV(types)
		c.PublicFields = splitCSV(public)
		m := newMatcher(c)
		if m.err != nil {
			return nil, m.err
		}
		m.debugPrinted = &printed
		return m, nil
	}
	get := func(pass *analysis.Pass) (matcher, error) {
		m, ok := pass.ResultOf[fa].(matcher)
		if !ok {
			return matcher{}, errNoMatcher
		}
		return m, nil
	}
	req := []*analysis.Analyzer{inspect.Analyzer, fa}
	return []*analysis.Analyzer{
		fa, newFieldsAnalyzer(req, get), newPrintAnalyzer(req, get),
		newFormatAnalyzer(req, get),
	}
}

var errNoMatcher = errors.New("sensitive analyzer result is not a matcher")

// registerFlags binds the flags to the fields of cfg,
// so a typo in a flag name cannot silently disconnect a flag from its Config field.
// Types and PublicFields are the exception:
// they are comma-separated strings which the caller splits.
func registerFlags(fs *flag.FlagSet, cfg *Config, types, public *string) {
	fs.StringVar(types, "types", "",
		"Comma-separated list of sensitive type package import paths "+
			"(optionally with .TypeName suffix to restrict to a specific type)")
	fs.StringVar(public, "public", "",
		"Comma-separated list of fields of sensitive types which never hold the secret "+
			"(import/path.TypeName.FieldName)")
	fs.BoolVar(&cfg.NoDefaultTypes, "no-default-types", false,
		"Do not seed the built-in default sensitive type list")
	fs.BoolVar(&cfg.SkipTests, "skip-tests", false,
		"Do not report diagnostics in _test.go files")
	fs.BoolVar(&cfg.SkipGenerated, "skip-generated", false,
		"Do not report diagnostics in generated files (Code generated ... DO NOT EDIT)")
	fs.BoolVar(&cfg.DetectFields, "detect-fields", false,
		"Report struct fields through which fmt could print a safe type's secret "+
			"even if no such print exists (sensitivefields only)")
	fs.BoolVar(&cfg.RequireMarshalJSON, "require-marshal-json", false,
		"Require all configured safe types to implement encoding.TextMarshaler or json.Marshaler, "+
			"or be opaque structs")
	fs.BoolVar(&cfg.RequireMarshalText, "require-marshal-text", false,
		"Require all configured safe types to implement encoding.TextMarshaler, "+
			"or be opaque String-level safe structs")
	fs.BoolVar(&cfg.RequireFormat, "require-format", false,
		"Require all configured safe types to implement fmt.Formatter or be structurally protected")
	fs.BoolVar(&cfg.RequireGoString, "require-gostring", false,
		"Require all configured safe types to implement fmt.GoStringer, fmt.Formatter, or be structurally protected")
	fs.BoolVar(&cfg.RequireString, "require-string", false,
		"Require all configured safe types to implement fmt.Stringer, fmt.Formatter, or be structurally protected")
	fs.BoolVar(&cfg.Debug, "debug", false,
		"Print sensitive type classification to stderr")
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
