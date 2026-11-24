package analyzer

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"strings"
	"sync"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/types/typeutil"
)

type matcher struct {
	packages      map[string]bool
	types         map[packageType]bool
	skipTests     bool
	skipGenerated bool
	debug         bool

	// debugPrinted holds the debug lines already printed,
	// see ARCHITECTURE.md ("Lifecycle and configuration").
	debugPrinted *sync.Map

	// public maps a qualifiedName of a type to the names of its fields
	// which never hold the secret: the built-in publicFields plus Config.PublicFields.
	public map[string][]string

	// err is the first error found in Config, reported by every analyzer run.
	err error

	detectFields bool

	requireMarshalJSON bool
	requireMarshalText bool
	requireFormat      bool
	requireGoString    bool
	requireString      bool
}

// checker is the per-pass state of the fields analyzer.
// A checker must not outlive its pass, see ARCHITECTURE.md ("Lifecycle and configuration").
type checker struct {
	matcher

	classes typeutil.Map // types.Type -> *typeClass
	msets   typeutil.MethodSetCache
}

func newChecker(m matcher) *checker { return &checker{matcher: m} }

type packageType struct {
	Pkg  string
	Name string
}

func newMatcher(cfg Config) matcher {
	m := matcher{
		packages:      make(map[string]bool),
		types:         make(map[packageType]bool),
		skipTests:     cfg.SkipTests,
		skipGenerated: cfg.SkipGenerated,
		debug:         cfg.Debug,
		debugPrinted:  new(sync.Map),
		public:        make(map[string][]string, len(publicFields)+len(cfg.PublicFields)),

		detectFields: cfg.DetectFields,

		requireMarshalJSON: cfg.RequireMarshalJSON,
		requireMarshalText: cfg.RequireMarshalText,
		requireFormat:      cfg.RequireFormat,
		requireGoString:    cfg.RequireGoString,
		requireString:      cfg.RequireString,
	}
	if !cfg.NoDefaultTypes {
		for _, e := range defaultTypes {
			m.addEntry(e)
		}
	}
	for _, e := range cfg.Types {
		m.addEntry(e)
	}
	for k, names := range publicFields {
		m.public[k] = slices.Clone(names)
	}
	for _, e := range cfg.PublicFields {
		key, field, err := parsePublicField(e)
		if err != nil {
			m.err = fmt.Errorf("invalid -sensitive.public entry %q: %w", e, err)
			break
		}
		m.public[key] = append(m.public[key], field)
	}
	return m
}

var errBadPublicField = errors.New("want import/path.TypeName.FieldName with an exported TypeName")

// parsePublicField splits "import/path.TypeName.FieldName"
// into the key of the type (as returned by qualifiedName) and the field name.
func parsePublicField(entry string) (typeKey, field string, err error) {
	typeKey, field, ok := cutLast(entry)
	if !ok || !token.IsIdentifier(field) {
		return "", "", errBadPublicField
	}
	if _, _, valid := parseTypeEntry(typeKey); !valid {
		return "", "", errBadPublicField
	}
	return typeKey, field, nil
}

// cutLast splits s around the last dot.
// The standard library has no such function in Go 1.26, the version required by go.mod.
func cutLast(s string) (before, after string, found bool) {
	i := strings.LastIndexByte(s, '.')
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+1:], true
}

// parseTypeEntry splits "import/path.TypeName" with an exported TypeName.
// It reports false for any other entry,
// e.g. an import path which ends with a dot-suffix like "gopkg.in/yaml.v3".
func parseTypeEntry(entry string) (pkg, name string, ok bool) {
	pkg, name, ok = cutLast(entry)
	if !ok || pkg == "" || !token.IsIdentifier(name) || !token.IsExported(name) {
		return "", "", false
	}
	return pkg, name, true
}

// addEntry adds one entry to the matcher:
// a type if [parseTypeEntry] accepts it, otherwise an import path.
func (m matcher) addEntry(entry string) {
	if pkg, name, ok := parseTypeEntry(entry); ok {
		m.types[packageType{Pkg: pkg, Name: name}] = true
		return
	}
	m.packages[entry] = true
}

// isSensitiveNamed reports whether t is a named type
// whose defining package is in the configured set.
// Uses the defining package (named.Obj().Pkg().Path()),
// which is robust against renamed imports and dot-imports.
//
// When a package-only entry is used (no explicit type name),
// interface and unexported types are not considered sensitive.
func (m matcher) isSensitiveNamed(t types.Type) bool {
	_, ok := m.sensitiveNamed(t)
	return ok
}

// sensitiveNamed is like [matcher.isSensitiveNamed]
// but also returns the unaliased named type.
func (m matcher) sensitiveNamed(t types.Type) (*types.Named, bool) {
	named, ok := types.Unalias(t).(*types.Named)
	if !ok {
		return nil, false
	}
	pkg := named.Obj().Pkg()
	if pkg == nil {
		return nil, false
	}
	if m.packages[pkg.Path()] {
		// A package-only entry matches all named types,
		// but interface and unexported types should not be treated as sensitive.
		_, isInterface := named.Underlying().(*types.Interface)
		return named, !isInterface && named.Obj().Exported()
	}
	return named, m.types[packageType{Pkg: pkg.Path(), Name: named.Obj().Name()}]
}

// isSensitiveBasic reports whether t is a sensitive named type
// whose underlying type is a basic kind (string, bool, numeric).
// Only such types reveal their actual content when passed by value to builtin print/println.
func (m matcher) isSensitiveBasic(t types.Type) bool {
	named, ok := m.sensitiveNamed(t)
	if !ok {
		return false
	}
	// Slices, pointers, structs, etc. either print header info or don't compile.
	_, isBasic := named.Underlying().(*types.Basic)
	return isBasic
}

// newShouldCheck returns a function which reports
// whether diagnostics should be emitted for the given position.
// When skipTests is true, positions in _test.go files are skipped.
// When skipGenerated is true, positions in generated files are skipped.
//
// The result is bound to pass and must not outlive it:
// the set of generated files is computed once here,
// because the matcher is shared between passes and cannot hold it.
func (m matcher) newShouldCheck(pass *analysis.Pass) func(pos token.Pos) bool {
	var generated map[string]bool
	if m.skipGenerated {
		generated = generatedFiles(pass)
	}
	return func(pos token.Pos) bool {
		if m.skipTests && inTestFile(pass, pos) {
			return false
		}
		if m.skipGenerated {
			f := pass.Fset.File(pos)
			if f != nil && generated[f.Name()] {
				return false
			}
		}
		return true
	}
}

// inTestFile reports whether pos falls within a _test.go file.
func inTestFile(pass *analysis.Pass, pos token.Pos) bool {
	f := pass.Fset.File(pos)
	return f != nil && strings.HasSuffix(f.Name(), "_test.go")
}

// generatedFiles returns the names of the pass files which are generated
// (a file whose first line matches the standard
// "// Code generated ... DO NOT EDIT." pattern).
func generatedFiles(pass *analysis.Pass) map[string]bool {
	res := make(map[string]bool)
	for _, file := range pass.Files {
		if ast.IsGenerated(file) {
			res[pass.Fset.File(file.Pos()).Name()] = true
		}
	}
	return res
}
