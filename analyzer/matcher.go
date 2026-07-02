package analyzer

import (
	"go/ast"
	"go/token"
	"go/types"
	"log"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/tools/go/analysis"
)

type matcher struct {
	packages      map[string]bool
	types         map[packageType]bool
	skipTests     bool
	skipGenerated bool
	debug         bool

	requireMarshalJSON bool
	requireMarshalText bool
	requireFormat      bool
	requireGoString    bool
	requireString      bool

	typeClasses map[*types.Named]*typeClass // classification cache (shared by copy)
	typeMu      *sync.Mutex                 // guards typeClasses
}

// typeClass records the classification of a configured safe type.
type typeClass struct {
	fmtFormatter     bool // t or *t implements fmt.Formatter
	fmtStringer      bool // t or *t implements fmt.Stringer
	fmtGoStringer    bool // t or *t implements fmt.GoStringer
	jsonMarshaler    bool // t or *t implements json.Marshaler
	textMarshaler    bool // t or *t implements encoding.TextMarshaler
	structurallySafe bool
	anyFmtInterface  bool // = fmtFormatter || fmtStringer || fmtGoStringer
}

// disableFactor records the first factor on the path
// that disables [Formatter]/[Stringer]/[GoStringer] interface dispatch.
type disableFactor struct {
	kind string // "unexportedField" or "nonFormatterPointer"
	name string // field name or pointer type description
}

const (
	factorUnexportedField     = "unexportedField"
	factorNonFormatterPointer = "nonFormatterPointer"
)

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

		requireMarshalJSON: cfg.RequireMarshalJSON,
		requireMarshalText: cfg.RequireMarshalText,
		requireFormat:      cfg.RequireFormat,
		requireGoString:    cfg.RequireGoString,
		requireString:      cfg.RequireString,

		typeClasses: make(map[*types.Named]*typeClass),
		typeMu:      &sync.Mutex{},
	}
	if !cfg.NoDefaultTypes {
		for _, e := range defaultTypes {
			m.addEntry(e)
		}
	}
	for _, e := range cfg.Types {
		m.addEntry(e)
	}
	return m
}

// addEntry adds one entry to the matcher,
// determining whether it is a plain package path or a package.Type combination.
func (m matcher) addEntry(entry string) {
	if i := strings.LastIndex(entry, "."); i >= 0 {
		tail := entry[i+1:]
		head := entry[:i]
		if head != "" && tail != "" && unicode.IsUpper(rune(tail[0])) {
			m.types[packageType{Pkg: head, Name: tail}] = true
			return
		}
	}
	m.packages[entry] = true
}

// isSensitiveNamed reports whether t is a named type
// whose defining package is in the configured set.
// Uses the defining package (named.Obj().Pkg().Path()),
// which is robust against renamed imports and dot-imports.
func (m matcher) isSensitiveNamed(t types.Type) bool {
	named, ok := types.Unalias(t).(*types.Named)
	if !ok {
		return false
	}
	pkg := named.Obj().Pkg()
	if pkg == nil {
		return false
	}
	if m.packages[pkg.Path()] {
		return true
	}
	return m.types[packageType{Pkg: pkg.Path(), Name: named.Obj().Name()}]
}

// isSensitiveBasic reports whether t is a sensitive named type
// whose underlying type is a basic kind (string, bool, numeric).
// Only such types reveal their actual content when passed by value to builtin print/println.
func (m matcher) isSensitiveBasic(t types.Type) bool {
	if !m.isSensitiveNamed(t) {
		return false
	}
	// isSensitiveNamed confirmed t is *types.Named, so this assertion is safe.
	// Only basic-kind underlying types leak their content through builtin print/println
	// (string, bool, numeric).
	// Slices, pointers, structs, etc. either print header info or don't compile.
	named := types.Unalias(t).(*types.Named)
	_, isBasic := named.Underlying().(*types.Basic)
	return isBasic
}

// shouldCheck reports whether diagnostics should be emitted for the given position.
// When skipTests is true, positions in _test.go files are skipped.
// When skipGenerated is true, positions in generated files are skipped.
func (m matcher) shouldCheck(pass *analysis.Pass, pos token.Pos) bool {
	if m.skipTests && inTestFile(pass, pos) {
		return false
	}
	if m.skipGenerated && inGeneratedFile(pass, pos) {
		return false
	}
	return true
}

// inTestFile reports whether pos falls within a _test.go file.
func inTestFile(pass *analysis.Pass, pos token.Pos) bool {
	f := pass.Fset.File(pos)
	return f != nil && strings.HasSuffix(f.Name(), "_test.go")
}

// inGeneratedFile reports whether pos falls within a generated file
// (a file whose first line matches the standard
// "// Code generated ... DO NOT EDIT." pattern).
func inGeneratedFile(pass *analysis.Pass, pos token.Pos) bool {
	f := pass.Fset.File(pos)
	if f == nil {
		return false
	}
	for _, file := range pass.Files {
		if pass.Fset.Position(file.Pos()).Filename == f.Name() {
			return ast.IsGenerated(file)
		}
	}
	return false
}

// hasMethod reports whether t or *t has a method with the given name.
// It checks the full method set, including promoted value-receiver methods on *t.
// The check is by name only — signature verification is intentionally loose
// because in practice a type having a method named "Format"/"String"/etc.
// is overwhelmingly likely to be the fmt interface method.
func (matcher) hasMethod(t types.Type, name string) bool {
	// Check the method set of t directly.
	// types.NewMethodSet correctly handles all types including pointers,
	// returning all methods available on the type (including promoted
	// value-receiver methods for pointer types).
	mset := types.NewMethodSet(t)
	for method := range mset.Methods() {
		if method.Obj().Name() == name {
			return true
		}
	}
	// For non-pointer types, also check *t for promoted value-receiver methods.
	if _, ok := t.(*types.Pointer); !ok {
		ptr := types.NewPointer(t)
		mset = types.NewMethodSet(ptr)
		for method := range mset.Methods() {
			if method.Obj().Name() == name {
				return true
			}
		}
	}
	return false
}

// classify performs lazy classification of a configured safe type.
// It caches the result in m.typeClasses.
func (m matcher) classify(t *types.Named) *typeClass {
	// Lock the entire operation: check cache, compute, store.
	m.typeMu.Lock()
	defer m.typeMu.Unlock()

	if tc, ok := m.typeClasses[t]; ok {
		return tc
	}

	tc := &typeClass{}
	tc.fmtFormatter = m.hasMethod(t, "Format")
	tc.fmtStringer = m.hasMethod(t, "String")
	tc.fmtGoStringer = m.hasMethod(t, "GoString")
	tc.jsonMarshaler = m.hasMethod(t, "MarshalJSON")
	tc.textMarshaler = m.hasMethod(t, "MarshalText")
	tc.anyFmtInterface = tc.fmtFormatter || tc.fmtStringer || tc.fmtGoStringer
	tc.structurallySafe = m.isStructurallySafe(t.Underlying(), make(map[types.Type]bool))

	m.typeClasses[t] = tc

	if m.debug {
		m.debugClassify(t, tc)
	}

	return tc
}

// isQualifier reports whether t is one of the structurally-protected kinds:
// *Pointer, *Interface, Chan, Func, UnsafePointer,
// or *<non-compound> (*string, *int, *bool, etc.).
func (matcher) isQualifier(t types.Type) bool {
	t = types.Unalias(t)
	switch u := t.(type) {
	case *types.Chan:
		return true
	case *types.Signature: // Func
		return true
	case *types.Basic:
		return u.Kind() == types.UnsafePointer
	case *types.Pointer:
		elem := types.Unalias(u.Elem())
		switch e := elem.(type) {
		case *types.Pointer: // **T
			return true
		case *types.Interface: // *Interface
			return true
		case *types.Basic: // *<non-compound> (*string, *int, etc.)
			return true
		case *types.Named:
			// Check if the named type's underlying is a qualifier kind.
			switch ue := e.Underlying().(type) {
			case *types.Pointer:
				return true
			case *types.Interface:
				return true
			case *types.Signature:
				return true
			case *types.Chan:
				return true
			case *types.Basic:
				return ue.Kind() == types.UnsafePointer
			default:
				return false
			}
		default:
			return false // *<compound> — pointee is a compound type
		}
	default:
		return false
	}
}

// isStructurallySafe reports whether the type
// (when ALL of Formatter/Stringer/GoStringer are disabled)
// still protects its content structurally — i.e. it reaches at least one qualifying field.
func (m matcher) isStructurallySafe(t types.Type, visited map[types.Type]bool) bool {
	t = types.Unalias(t)
	if visited[t] {
		return false
	}
	visited[t] = true

	switch u := t.(type) {
	case *types.Named:
		return m.isStructurallySafe(u.Underlying(), visited)
	case *types.Struct:
		for f := range u.Fields() {
			ft := types.Unalias(f.Type())
			if m.isQualifier(ft) {
				return true
			}
			// Recurse into named type fields (they may contain qualifiers,
			// e.g. unique.Handle[T] wrapping *T).
			if _, ok := ft.(*types.Named); ok {
				if m.isStructurallySafe(ft, visited) {
					return true
				}
			}
		}
		return false
	default:
		return false
	}
}

// debugClassify prints one classification line to stderr.
func (matcher) debugClassify(t *types.Named, tc *typeClass) {
	// Format the type name including package and type arguments.
	typeName := t.Obj().Name()
	if t.TypeParams() != nil && t.TypeArgs() != nil {
		typeName += "[" + typeArgsString(t.TypeArgs()) + "]"
	}
	log.Printf("sensitive type %s: Formatter=%v Stringer=%v GoStringer=%v json.Marshaler=%v encoding.TextMarshaler=%v structurallySafe=%v",
		packageTypeName(t)+"."+typeName,
		tc.fmtFormatter, tc.fmtStringer, tc.fmtGoStringer,
		tc.jsonMarshaler, tc.textMarshaler, tc.structurallySafe)
}

// typeArgsString formats type arguments for debug output.
func typeArgsString(targs *types.TypeList) string {
	var b strings.Builder
	for i := range targs.Len() {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(targs.At(i).String())
	}
	return b.String()
}

// packageTypeName returns the full package path of a named type for debug output.
func packageTypeName(t *types.Named) string {
	if pkg := t.Obj().Pkg(); pkg != nil {
		return pkg.Path()
	}
	return ""
}

// isCompoundKind reports whether t is a compound kind
// (Struct/Slice/Array/Map) that fmt dereferences under badVerb at depth 0.
// Non-compound kinds (Pointer, Interface, Chan, Signature, Basic, UnsafePointer)
// always print as address via fmtPointer.
func isCompoundKind(t types.Type) bool {
	switch t.Underlying().(type) {
	case *types.Struct, *types.Slice, *types.Array, *types.Map:
		return true
	default:
		return false
	}
}

// walkSafeType handles the safe-type terminal in the Formatter-termination walk.
// Returns true if the safe type would leak under the current fd/bp state.
func (matcher) walkSafeType(cls *typeClass, fd, bp bool) bool { //nolint:revive // By design.
	if !fd && !bp {
		return false // interfaces fire → safe
	}
	// Path is disabled. If the safe type implements any fmt interface
	// AND has no structural-protection, content leaks.
	return cls.anyFmtInterface && !cls.structurallySafe
}

// Linter logic (Formatter-termination reachability):
//
// The linter knows a set of safe types for secrets (configured via -sensitive.types).
// Safe types can protect secrets through a combination of mechanisms:
//   - Storing the secret in an unexported field.
//     This is the most reliable protection against JSON serialization etc.
//   - Implementing [encoding.TextMarshaler] and/or [json.Marshaler].
//     This is an alternative way to protect against JSON serialization etc.
//   - Storing the secret in one of the types that [fmt.Printf] never follows:
//     *Pointer (**T), *Interface (*any(T)), Chan (<-chan T), Func (func() T),
//     UnsafePointer, *<non-compound> (*string, *int, *bool, etc.).
//     This is the only structural protection against [fmt.Printf].
//   - Implementing [fmt.Formatter] and/or [fmt.Stringer] and/or [fmt.GoStringer].
//     These are varying degrees of protection against the [fmt.Printf] family.
//     Support for these methods can be disabled depending on the path to the value.
//
// The linter's tasks:
//   - Unconditional: warn about weakening the base protection level of safe types.
//     Detect places where Formatter/Stringer/GoStringer support
//     is disabled for types that implement some of these interfaces
//     and do not contain structurally-protected types.
//   - Optional reliability-level: warn about using safe types that
//     do not provide the required level of protection for the configured attack surface.
//
// Even though a safe type having interface implementations
// or structurally-protected types inside does not guarantee
// that this functionality is used specifically for secret protection,
// the linter assumes it is (any other approach is useless).
//
// For safe types implementing ([fmt.Formatter] or [fmt.Stringer] or [fmt.GoStringer])
// AND not containing one of the structurally-protected types inside:
//   - The linter checks the path leading to these types
//     for factors that disable support for these interfaces:
//     1. unexported field
//     2. Pointer type not implementing Formatter (may be in an exported field too)
//   - If such a factor is detected, it reports incorrect use of the safe type.
//
// Rationale:
//   - If a safe type contains the secret in a structurally-protected type inside,
//     disabling Formatter/Stringer/GoStringer only blocks replacing
//     the secret value with "REDACTED" or similar,
//     while instead of the secret the address of the intermediate pointer will be printed.
//   - The [fmt.Printf] family disables interface support in only two cases:
//     1. entering an unexported field;
//     2. calling badVerb.
//   - For badVerb the linter must consider ALL situations where badVerb CAN trigger
//     (because the linter cannot know which verb will actually be used
//     and must assume the one that triggers badVerb).
//     The only type relevant to the linter is Pointer, because non-compound types
//     (bool/numeric/String/Chan/Func/UnsafePointer/Invalid plus []byte)
//     are either themselves the safe type with Formatter
//     or have no relation to storing secrets.
//     The only remaining type where badVerb can occur is Pointer.
//     The only exception: if this Pointer type itself implements Formatter —
//     in this case it is also a terminal type and cannot cause problems
//     (because fmt encounters this Pointer BEFORE calling badVerb,
//     and if it implements Formatter, the badVerb call simply won't happen —
//     Formatter by definition supports all verbs).
//
// walk is the Formatter-termination walk.
// It returns true when a safe type reachable through t would leak its secret content
// under the given fd/bp (format-disabled / bad-verb-possible) state.
// visited prevents infinite recursion on cyclic types.
// factorAt receives the first disable factor on the path, if any.
//
//nolint:funlen,gocognit // Walk matches fmt complexity; extracting would harm readability.
func (m matcher) walk(t types.Type, fd, bp bool, visited map[types.Type]bool, factorAt *disableFactor) bool { //nolint:revive // control flags by design
	t = types.Unalias(t)
	if visited[t] {
		return false
	}

	// Safe-type terminal.
	if m.isSensitiveNamed(t) {
		named := types.Unalias(t).(*types.Named)
		cls := m.classify(named)
		return m.walkSafeType(cls, fd, bp)
	}

	visited[t] = true

	switch u := t.(type) {
	case *types.Pointer:
		// A Formatter pointer reached with fd==false AND bp==false is a safe terminal.
		if m.hasMethod(t, "Format") && !fd && !bp {
			return false
		}
		// Under badVerb (bp=true) at depth 0, fmt only dereferences the
		// pointer when the pointee is a compound kind (Struct/Slice/Array/Map).
		// *<non-compound> pointers always go to fmtPointer → address printed.
		if !isCompoundKind(u.Elem()) {
			return false
		}
		// Non-Formatter pointer to compound (or reached under disable):
		// badVerb is possible, and the pointee can be dereferenced.
		if factorAt == nil || factorAt.kind == "" {
			if factorAt == nil {
				factorAt = &disableFactor{
					kind: factorNonFormatterPointer,
					name: u.Elem().String(),
				}
			} else {
				factorAt.kind = factorNonFormatterPointer
				factorAt.name = u.Elem().String()
			}
		}
		return m.walk(u.Elem(), true, true, visited, factorAt)

	case *types.Struct:
		for f := range u.Fields() {
			fd2 := fd || !f.Exported()
			newFactor := factorAt
			if !f.Exported() && (factorAt == nil || factorAt.kind == "") {
				tmp := &disableFactor{
					kind: factorUnexportedField,
					name: f.Name(),
				}
				newFactor = tmp
			}
			if m.walk(f.Type(), fd2, bp, visited, newFactor) {
				if newFactor != factorAt && factorAt != nil && factorAt.kind == "" {
					*factorAt = *newFactor
				}
				return true
			}
		}
		return false

	case *types.Slice:
		return m.walk(u.Elem(), fd, bp, visited, factorAt)

	case *types.Array:
		return m.walk(u.Elem(), fd, bp, visited, factorAt)

	case *types.Map:
		return m.walk(u.Key(), fd, bp, visited, factorAt) ||
			m.walk(u.Elem(), fd, bp, visited, factorAt)

	case *types.Interface:
		// Dynamic value could be a safe type reachable under this fd/bp.
		// Conservative: report iff fd or bp is set.
		return fd || bp

	case *types.Chan, *types.Signature, *types.Basic:
		return false // address/header/primitive

	case *types.Named:
		return m.walk(u.Underlying(), fd, bp, visited, factorAt)
	default:
		return false
	}
}
