// Package analyzer provides analyzers for detecting sensitive value leaks
// through Go's fmt reflection and builtin print/println.
//
// By default, sensitive types are those defined in github.com/powerman/sensitive,
// github.com/go-playground/sensitive, github.com/negrel/secrecy.Secret, and
// github.com/angusgmorrison/logfusc.
package analyzer

import (
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
)

// defaultTypes is the default set of sensitive package import paths.
var defaultTypes = []string{ // Const.
	"github.com/powerman/sensitive",
	"github.com/go-playground/sensitive",
	"github.com/negrel/secrecy.Secret",
	"github.com/angusgmorrison/logfusc.Secret",
}

// matcherFunc is the type of functions that retrieve a matcher from an analysis pass.
// It abstracts over the two ways to obtain a matcher:
// from New() (always returns the same pre-built matcher)
// and from FlagAnalyzer (reads the matcher from pass.ResultOf).
type matcherFunc func(*analysis.Pass) (matcher, error)

// Config controls which packages' named types are considered sensitive.
type Config struct {
	// Types lists sensitive types.
	// Each entry is either an import path (every named type in the package is sensitive)
	// or "import/path.TypeName" (only that named type).
	Types []string

	// NoDefaultTypes, when true, omits the built-in default types list
	// so that only Types are considered sensitive.
	NoDefaultTypes bool

	// SkipTests, when true, suppresses diagnostics in _test.go files.
	SkipTests bool

	// SkipGenerated, when true, suppresses diagnostics in generated files
	// (those containing the standard "// Code generated ... DO NOT EDIT." header).
	SkipGenerated bool

	// RequireMarshalJSON, when true, emits diagnostics for safe types
	// that do not implement encoding.TextMarshaler or json.Marshaler.
	RequireMarshalJSON bool

	// RequireMarshalText, when true, emits diagnostics for safe types
	// that do not implement encoding.TextMarshaler.
	RequireMarshalText bool

	// RequireFormat, when true, emits diagnostics for safe types
	// that do not implement fmt.Formatter
	// and are not structurally protected
	// (**T, *interface{}, chan T, func() T, unsafe.Pointer, *<non-compound>).
	RequireFormat bool

	// RequireGoString, when true, emits diagnostics for safe types
	// that do not implement fmt.GoStringer, fmt.Formatter,
	// and are not structurally protected.
	RequireGoString bool

	// RequireString, when true, emits diagnostics for safe types
	// that do not implement fmt.Stringer, fmt.Formatter,
	// and are not structurally protected.
	RequireString bool

	// Verbose flag enables diagnostic output to stderr
	// showing the classification of each sensitive type.
	Debug bool
}

// New returns analyzers configured by cfg.
func New(cfg Config) []*analysis.Analyzer {
	m := newMatcher(cfg)
	req := []*analysis.Analyzer{inspect.Analyzer}
	get := func(*analysis.Pass) (matcher, error) { return m, nil }
	return []*analysis.Analyzer{
		newFieldsAnalyzer(req, get),
		newPrintAnalyzer(req, get),
	}
}
