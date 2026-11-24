// Package analyzer provides analyzers for detecting sensitive value leaks
// through Go's fmt reflection and builtin print/println,
// and for optionally checking that safe types implement the interfaces needed to stay redacted
// in JSON, text marshaling and fmt output.
//
// By default, sensitive types are those defined in github.com/powerman/sensitive,
// github.com/go-playground/sensitive, github.com/negrel/secrecy.Secret,
// github.com/angusgmorrison/logfusc.Secret,
// github.com/rsjethani/secret/v2.Text and /v3.Text,
// github.com/shoenig/go-conceal.Text and .Bytes,
// and github.com/rbranson/camo.Secret.
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
	"github.com/rsjethani/secret/v2.Text",
	"github.com/rsjethani/secret/v3.Text",
	"github.com/shoenig/go-conceal.Text",
	"github.com/shoenig/go-conceal.Bytes",
	"github.com/rbranson/camo.Secret",
}

// revealingMethods lists methods of known types which match a fmt/encoding interface
// by signature but output the secret, so they fail every surface they serve.
// They apply to a matched type whether it comes from defaultTypes or not.
var revealingMethods = map[string][]string{ // Const.
	"github.com/shoenig/go-conceal.Text": {methodMarshalText},
}

// publicFields lists fields of known types which fmt prints but which never hold the secret,
// so they do not break the structural protection of the type.
// They apply to a matched type whether it comes from defaultTypes or not.
// Only top-level fields of the listed type are skipped, not fields of nested types.
var publicFields = map[string][]string{ // Const.
	// A maphash fingerprint with a per-process seed, used for ==.
	"github.com/rbranson/camo.Secret": {"hash"},
}

// matcherFunc retrieves a matcher from an analysis pass,
// see ARCHITECTURE.md ("Lifecycle and configuration").
// The error reports an invalid Config.
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

	// PublicFields lists fields of configured types which never hold the secret,
	// as "import/path.TypeName.FieldName".
	// They are ignored when deciding whether the type is structurally protected
	// or an opaque struct, like the built-in entries for known types.
	// A malformed entry makes every analyzer fail with an error.
	PublicFields []string

	// SkipTests, when true, suppresses diagnostics in _test.go files.
	SkipTests bool

	// SkipGenerated, when true, suppresses diagnostics in generated files
	// (those containing the standard "// Code generated ... DO NOT EDIT." header).
	SkipGenerated bool

	// RequireMarshalJSON, when true, emits diagnostics for safe types
	// that neither implement encoding.TextMarshaler or json.Marshaler
	// nor are opaque structs (all fields unexported, none embedded).
	RequireMarshalJSON bool

	// RequireMarshalText, when true, emits diagnostics for safe types
	// that neither implement encoding.TextMarshaler
	// nor are opaque structs which are String-level safe.
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

	// When Debug is true, the analyzer prints diagnostic output to stderr
	// showing the classification of each sensitive type.
	Debug bool
}

// New returns analyzers configured by cfg.
func New(cfg Config) []*analysis.Analyzer {
	m := newMatcher(cfg)
	req := []*analysis.Analyzer{inspect.Analyzer}
	get := func(*analysis.Pass) (matcher, error) { return m, m.err }
	return []*analysis.Analyzer{
		newFieldsAnalyzer(req, get),
		newPrintAnalyzer(req, get),
		newFormatAnalyzer(req, get),
	}
}
