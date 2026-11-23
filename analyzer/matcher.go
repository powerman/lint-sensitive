package analyzer

import (
	"fmt"
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

	typeClasses map[string]*typeClass // classification cache keyed by type identity
	typeMu      *sync.Mutex           // guards typeClasses
}

// typeClass records the classification of a configured safe type.
type typeClass struct {
	fmtFormatter     bool // t implements fmt.Formatter
	fmtStringer      bool // t implements fmt.Stringer
	fmtGoStringer    bool // t implements fmt.GoStringer
	jsonMarshaler    bool // t implements json.Marshaler
	textMarshaler    bool // t implements encoding.TextMarshaler
	structurallySafe bool
	anyFmtInterface  bool // = fmtFormatter || fmtStringer || fmtGoStringer

	// ptrOnly holds names of the methods above which only *t has,
	// so they are not called on a t value and do not count as implemented.
	ptrOnly map[string]bool
}

// require plumbing shared state across every per-package matcher in the
// flag-driven path, which the go/analysis framework does not support.
//
//nolint:gochecknoglobals // Debug-only global dedup — the alternative would
var debugPrinted sync.Map

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

		typeClasses: make(map[string]*typeClass),
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
	if head, tail, ok := strings.CutLast(entry, "."); ok {
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
//
// When a package-only entry is used (no explicit type name),
// interface and unexported types are not considered sensitive.
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
		// A package-only entry matches all named types,
		// but interface and unexported types should not be treated as sensitive.
		if _, isInterface := named.Underlying().(*types.Interface); isInterface {
			return false
		}
		if !named.Obj().Exported() {
			return false
		}
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

// Names of the fmt/encoding interface methods the analyzer relies on.
const (
	methodFormat      = "Format"
	methodString      = "String"
	methodGoString    = "GoString"
	methodMarshalJSON = "MarshalJSON"
	methodMarshalText = "MarshalText"
)

// methodShape returns a predicate for the signature of the fmt/encoding interface method
// with the given name.
// The check is structural (no stdlib interface resolution),
// so a same-named method with another signature is not mistaken for the interface method.
func methodShape(name string) func(*types.Signature) bool {
	switch name {
	case methodFormat:
		return isFormatSig
	case methodString, methodGoString:
		return isNoArgsResult(types.Typ[types.String])
	case methodMarshalJSON, methodMarshalText:
		return isMarshalSig
	default:
		panic("hasMethod: unsupported method name " + name)
	}
}

// isFormatSig reports whether sig is func(fmt.State, rune).
func isFormatSig(sig *types.Signature) bool {
	if sig.Params().Len() != 2 || sig.Results().Len() != 0 || sig.Variadic() {
		return false
	}
	state, ok := types.Unalias(sig.Params().At(0).Type()).(*types.Named)
	if !ok || state.Obj().Pkg() == nil ||
		state.Obj().Pkg().Path() != "fmt" || state.Obj().Name() != "State" {
		return false
	}
	return types.Identical(sig.Params().At(1).Type(), types.Typ[types.Int32])
}

// isNoArgsResult returns a predicate for func() <result>.
func isNoArgsResult(result types.Type) func(*types.Signature) bool {
	return func(sig *types.Signature) bool {
		return sig.Params().Len() == 0 && sig.Results().Len() == 1 &&
			types.Identical(sig.Results().At(0).Type(), result)
	}
}

// isMarshalSig reports whether sig is func() ([]byte, error).
func isMarshalSig(sig *types.Signature) bool {
	if sig.Params().Len() != 0 || sig.Results().Len() != 2 {
		return false
	}
	return types.Identical(sig.Results().At(0).Type(), types.NewSlice(types.Typ[types.Byte])) &&
		types.Identical(sig.Results().At(1).Type(), types.Universe.Lookup("error").Type())
}

// hasMethod reports whether the method set of t contains a method
// with the given name and the signature of the corresponding fmt/encoding interface method.
// The method set is taken as is, so for a non-pointer t
// methods declared on *t are not counted:
// fmt and encoding/json never call them on a non-addressable value.
// Promoted value-receiver methods are part of the method set of both t and *t.
func (matcher) hasMethod(t types.Type, name string) bool {
	hasShape := methodShape(name)
	for method := range types.NewMethodSet(t).Methods() {
		if method.Obj().Name() != name {
			continue
		}
		sig, ok := method.Type().(*types.Signature)
		if ok && hasShape(sig) {
			return true
		}
	}
	return false
}

// ptrOnlyMethods returns the names of the fmt/encoding interface methods
// which are in the method set of *t but not of t.
func (m matcher) ptrOnlyMethods(t types.Type) map[string]bool {
	ptr := types.NewPointer(t)
	res := make(map[string]bool)
	for _, name := range [...]string{methodFormat, methodString, methodGoString, methodMarshalJSON, methodMarshalText} {
		if !m.hasMethod(t, name) && m.hasMethod(ptr, name) {
			res[name] = true
		}
	}
	return res
}

// isSecretExposer reports whether t is a SecretExposer interface —
// an interface that declares an ExposeSecret method.
// This is the convention used by github.com/powerman/sensitive.Secret[T]
// and github.com/negrel/secrecy.SecretExposer[T].
// The check is by method name only; the exact return type is not verified.
func (matcher) isSecretExposer(t *types.Interface) bool {
	for method := range t.Methods() {
		if method.Name() == "ExposeSecret" {
			return true
		}
	}
	return false
}

// typeKey returns a string key that uniquely identifies a [*types.Named]
// across packages, allowing the classification cache to work correctly
// when the same logical type is encountered from different importing packages
// (each has its own [*types.Named] pointer).
func typeKey(t *types.Named) string {
	typeName := t.Obj().Name()
	if t.TypeParams() != nil && t.TypeArgs() != nil {
		typeName += "[" + typeArgsString(t.TypeArgs()) + "]"
	}
	return packageTypeName(t) + "." + typeName
}

// classify performs lazy classification of a configured safe type.
// It caches the result in m.typeClasses.
func (m matcher) classify(t *types.Named) *typeClass {
	key := typeKey(t)

	// Lock the entire operation: check cache, compute, store.
	m.typeMu.Lock()
	defer m.typeMu.Unlock()

	if tc, ok := m.typeClasses[key]; ok {
		return tc
	}

	tc := &typeClass{}
	tc.fmtFormatter = m.hasMethod(t, methodFormat)
	tc.fmtStringer = m.hasMethod(t, methodString)
	tc.fmtGoStringer = m.hasMethod(t, methodGoString)
	tc.jsonMarshaler = m.hasMethod(t, methodMarshalJSON)
	tc.textMarshaler = m.hasMethod(t, methodMarshalText)
	tc.ptrOnly = m.ptrOnlyMethods(t)
	tc.anyFmtInterface = tc.fmtFormatter || tc.fmtStringer || tc.fmtGoStringer
	tc.structurallySafe = m.isStructurallySafe(t.Underlying(), make(map[types.Type]bool))

	m.typeClasses[key] = tc

	if m.debug {
		// Use base type name (without type args) for dedup —
		// classification characteristics (Formatter, Stringer, etc.)
		// depend on the type's method set, which is the same regardless
		// of generic instantiation. Global dedup avoids printing the
		// same classification when the type appears in different packages.
		debugKey := packageTypeName(t) + "." + t.Obj().Name()
		if _, loaded := debugPrinted.LoadOrStore(debugKey, struct{}{}); !loaded {
			m.debugClassify(t, tc)
		}
	}

	return tc
}

// isQualifier reports whether t is one of the structurally-protected kinds:
// *Pointer, *Interface, Chan, Func, UnsafePointer,
// or *<non-compound> (*string, *int, *bool, etc.),
// or *TypeParam where the constraint excludes all compound kinds.
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
		case *types.TypeParam: // *TypeParam: safe iff constraint excludes compound kinds
			return !typeParamHasCompoundConstraint(e)
		case *types.Named:
			// fmt dereferences a depth-0 pointer only for compound kinds,
			// so a pointer to any non-compound named type (e.g. *MyString)
			// prints as an address.
			return !isCompoundKind(e)
		default:
			return false // *<compound> — pointee is a compound type
		}
	default:
		return false
	}
}

// typeParamHasCompoundConstraint reports whether any type-set term in the
// type parameter's constraint is a compound kind (Struct/Slice/Array/Map).
// Returns true (conservative: treat as potentially compound) when the
// constraint is absent, unconstrained (any/interface{}), or method-only.
func typeParamHasCompoundConstraint(tp *types.TypeParam) bool {
	constraint := tp.Constraint()
	if constraint == nil {
		return true
	}
	t := types.Unalias(constraint)
	if named, ok := t.(*types.Named); ok {
		t = named.Underlying()
	}
	iface, ok := t.(*types.Interface)
	if !ok {
		return true
	}
	return interfaceHasCompoundTerm(iface)
}

// interfaceHasCompoundTerm reports whether any type-set term in iface
// (or its embedded interfaces and unions) is a compound kind (Struct/Slice/Array/Map).
// A method-only interface (including any/interface{}) returns true: its type
// set is unbounded and allows compound types.
func interfaceHasCompoundTerm(iface *types.Interface) bool {
	// No type elements: type set is unconstrained — any type allowed, incl. compound.
	if iface.IsMethodSet() {
		return true
	}
	for etyp := range iface.EmbeddedTypes() {
		if typeElemHasCompoundTerm(etyp) {
			return true
		}
	}
	return false
}

// typeElemHasCompoundTerm reports whether a single embedded type element
// (union, interface, named type, or unknown) contains a compound kind term.
func typeElemHasCompoundTerm(elem types.Type) bool {
	e := types.Unalias(elem)
	switch u := e.(type) {
	case *types.Union:
		for term := range u.Terms() {
			if isCompoundKind(term.Type()) {
				return true
			}
		}
		return false
	case *types.Interface:
		return interfaceHasCompoundTerm(u)
	case *types.Named:
		nested, ok := u.Underlying().(*types.Interface)
		if !ok {
			return true // named non-interface element: conservative
		}
		return interfaceHasCompoundTerm(nested)
	default:
		return true // unknown element kind: conservative
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
	log.Printf("sensitive type %s: Formatter=%v Stringer=%v GoStringer=%v json.Marshaler=%v encoding.TextMarshaler=%v structurallySafe=%v",
		packageTypeName(t)+"."+t.Obj().Name(),
		tc.fmtFormatter, tc.fmtStringer, tc.fmtGoStringer,
		tc.jsonMarshaler, tc.textMarshaler, tc.structurallySafe)
}

// typeArgsString formats type arguments for the classification cache key.
// For TypeParam arguments, the constraint string is used instead of just the name,
// so that instantiations with different constraints get distinct cache entries
// (structural safety depends on the constraint, not the TypeParam identity).
func typeArgsString(targs *types.TypeList) string {
	var b strings.Builder
	for i := range targs.Len() {
		if i > 0 {
			b.WriteString(", ")
		}
		t := targs.At(i)
		if tp, ok := t.(*types.TypeParam); ok {
			b.WriteString("~{")
			b.WriteString(tp.Constraint().String())
			b.WriteString("}")
		} else {
			b.WriteString(t.String())
		}
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

// walkKey is the memoization key of walk.
type walkKey struct {
	t  types.Type
	fd bool
	bp bool
}

// walkStep is one hop of the path which walk found from a checked field to a leaking safe type.
type walkStep struct {
	pos  token.Pos // May be token.NoPos or unresolvable, e.g. for types without a declaration.
	desc string
}

// shortTypeString formats t with package names instead of package paths.
func shortTypeString(t types.Type) string {
	return types.TypeString(t, func(p *types.Package) string { return p.Name() })
}

// leakStep describes the safe type at the end of a leaking path.
func leakStep(named *types.Named) walkStep {
	return walkStep{
		pos:  named.Obj().Pos(),
		desc: "safe type " + shortTypeString(named),
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
// visited prevents infinite recursion on cyclic types;
// it is keyed by the fd/bp state too, because a type is safe or leaking depending on it.
// factorAt receives the first disable factor on the path, if any.
// When walk returns true, path receives the hops of the leaking path
// ordered from the innermost (the safe type) to the outermost,
// excluding the walked type itself.
//
//nolint:funlen,gocognit // Walk matches fmt complexity; extracting would harm readability.
func (m matcher) walk(t types.Type, fd, bp bool, visited map[walkKey]bool, factorAt *disableFactor, path *[]walkStep) bool { //nolint:revive // control flags by design
	t = types.Unalias(t)
	key := walkKey{t: t, fd: fd, bp: bp}
	if visited[key] {
		return false
	}

	// Safe-type terminal.
	if m.isSensitiveNamed(t) {
		named := types.Unalias(t).(*types.Named)
		cls := m.classify(named)
		leaks := m.walkSafeType(cls, fd, bp)
		if leaks {
			*path = append(*path, leakStep(named))
		}
		return leaks
	}

	visited[key] = true

	switch u := t.(type) {
	case *types.Pointer:
		// A Formatter pointer reached with fd==false AND bp==false is a safe terminal.
		if m.hasMethod(t, methodFormat) && !fd && !bp {
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
		if !m.walk(u.Elem(), true, true, visited, factorAt, path) {
			return false
		}
		// A Formatter pointer gets here only under fd/bp, so it is not called "non-Formatter".
		step := walkStep{desc: "pointer to " + shortTypeString(u.Elem())}
		if !m.hasMethod(t, methodFormat) {
			step.desc = "non-Formatter " + step.desc
		}
		if named, ok := types.Unalias(u.Elem()).(*types.Named); ok {
			step.pos = named.Obj().Pos()
		}
		*path = append(*path, step)
		return true

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
			if m.walk(f.Type(), fd2, bp, visited, newFactor, path) {
				if newFactor != factorAt && factorAt != nil && factorAt.kind == "" {
					*factorAt = *newFactor
				}
				kind := "field"
				if !f.Exported() {
					kind = "unexported field"
				}
				*path = append(*path, walkStep{
					pos:  f.Pos(),
					desc: fmt.Sprintf("%s %q of type %s", kind, f.Name(), shortTypeString(f.Type())),
				})
				return true
			}
		}
		return false

	case *types.Slice:
		return m.walk(u.Elem(), fd, bp, visited, factorAt, path)

	case *types.Array:
		return m.walk(u.Elem(), fd, bp, visited, factorAt, path)

	case *types.Map:
		return m.walk(u.Key(), fd, bp, visited, factorAt, path) ||
			m.walk(u.Elem(), fd, bp, visited, factorAt, path)

	case *types.Interface:
		// Flag only SecretExposer interfaces — those that have an ExposeSecret method,
		// the convention used by github.com/powerman/sensitive.Secret[T] and
		// github.com/negrel/secrecy.SecretExposer[T].
		// Generic any/interface{} and all other arbitrary interfaces are NOT flagged:
		// the static analyzer cannot know what concrete type will be stored in them,
		// and flagging them causes a torrent of false positives from external library
		// internals (e.g. prometheus.Metric or error deep inside a metrics struct).
		if m.isSecretExposer(u) {
			return fd || bp
		}
		return false

	case *types.Chan, *types.Signature, *types.Basic:
		return false // address/header/primitive

	case *types.Named:
		// A named type with fmt.Formatter reached with fmt interfaces still enabled
		// redacts under every verb, so it is a safe terminal (same trust as *types.Pointer).
		// Under fd/bp the method may not fire, so it must not be trusted there.
		if !fd && !bp && m.hasMethod(t, methodFormat) {
			return false
		}
		if !m.walk(u.Underlying(), fd, bp, visited, factorAt, path) {
			return false
		}
		// A SecretExposer interface is a terminal which has no step of its own,
		// because the walk sees only the unnamed interface type.
		if _, ok := u.Underlying().(*types.Interface); ok {
			*path = append(*path, leakStep(u))
		}
		return true
	default:
		return false
	}
}
