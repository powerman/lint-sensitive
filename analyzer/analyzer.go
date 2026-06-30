// Package analyzer provides analyzers for detecting sensitive value leaks
// through Go's fmt reflection and builtin print/println.
//
// By default, sensitive types are those defined in github.com/powerman/sensitive,
// github.com/go-playground/sensitive, github.com/negrel/secrecy, and
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
	"github.com/negrel/secrecy",
	"github.com/angusgmorrison/logfusc",
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
