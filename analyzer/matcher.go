package analyzer

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"log"
	"maps"
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

	requireMarshalJSON bool
	requireMarshalText bool
	requireFormat      bool
	requireGoString    bool
	requireString      bool
}

// checker is the per-pass state of the fields analyzer.
// Its caches are keyed by type identity,
// which is exact only within one pass, so a checker must not outlive its pass.
// A process-wide cache would keep the types of every pass alive in long-running drivers
// (gopls, golangci-lint daemons), and a string key cannot tell apart local types
// of different functions which share a name.
type checker struct {
	matcher

	classes typeutil.Map // types.Type -> *typeClass
	msets   typeutil.MethodSetCache
}

func newChecker(m matcher) *checker { return &checker{matcher: m} }

// typeClass records the classification of a configured safe type.
type typeClass struct {
	fmtFormatter     bool // t implements fmt.Formatter
	fmtStringer      bool // t implements fmt.Stringer
	fmtGoStringer    bool // t implements fmt.GoStringer
	jsonMarshaler    bool // t implements json.Marshaler
	textMarshaler    bool // t implements encoding.TextMarshaler
	structurallySafe bool

	// ptrOnly holds names of the methods above which only *t has,
	// so they are not called on a t value and do not count as implemented.
	ptrOnly map[string]bool

	// revealing holds names of the methods which match an interface by signature
	// but output the secret (see revealingMethods), so they are treated as absent.
	revealing map[string]bool
}

// debugPrinted holds the debug lines already printed.
// It is keyed by the whole line, which includes the type arguments,
// so instances of one generic type with different classification are all printed,
// while the same type seen in several packages is printed only once.
// The alternative would require plumbing shared state
// across every per-package matcher in the flag-driven path,
// which the go/analysis framework does not support.
//
//nolint:gochecknoglobals // Debug-only global dedup.
var debugPrinted sync.Map

// disableFactor records the first factor on the path
// that disables [Formatter]/[Stringer]/[GoStringer] interface dispatch.
type disableFactor struct {
	kind string // one of the factor* constants
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

// addEntry adds one entry to the matcher.
// An entry whose part after the last dot is an exported identifier names a type,
// any other entry is an import path
// (which may itself end with a dot-suffix, e.g. "gopkg.in/yaml.v3").
func (m matcher) addEntry(entry string) {
	if head, tail, ok := strings.CutLast(entry, "."); ok &&
		head != "" && token.IsIdentifier(tail) && token.IsExported(tail) {
		m.types[packageType{Pkg: head, Name: tail}] = true
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
	// Only basic-kind underlying types leak their content through builtin print/println
	// (string, bool, numeric).
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
func (c *checker) hasMethod(t types.Type, name string) bool {
	hasShape := methodShape(name)
	for method := range c.msets.MethodSet(t).Methods() {
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
func (c *checker) ptrOnlyMethods(t types.Type) map[string]bool {
	ptr := types.NewPointer(t)
	res := make(map[string]bool)
	for _, name := range [...]string{methodFormat, methodString, methodGoString, methodMarshalJSON, methodMarshalText} {
		if !c.hasMethod(t, name) && c.hasMethod(ptr, name) {
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

// classify performs lazy classification of a configured safe type.
// It caches the result in c.classes.
func (c *checker) classify(t *types.Named) *typeClass {
	if tc, ok := c.classes.At(t).(*typeClass); ok {
		return tc
	}

	tc := &typeClass{
		fmtFormatter:     c.hasMethod(t, methodFormat),
		fmtStringer:      c.hasMethod(t, methodString),
		fmtGoStringer:    c.hasMethod(t, methodGoString),
		jsonMarshaler:    c.hasMethod(t, methodMarshalJSON),
		textMarshaler:    c.hasMethod(t, methodMarshalText),
		ptrOnly:          c.ptrOnlyMethods(t),
		structurallySafe: c.isStructurallySafe(t.Underlying(), make(map[types.Type]bool)),
	}
	for _, name := range revealingMethods[qualifiedName(t)] {
		if tc.revealing == nil {
			tc.revealing = make(map[string]bool)
		}
		tc.revealing[name] = true
		delete(tc.ptrOnly, name)
		switch name {
		case methodFormat:
			tc.fmtFormatter = false
		case methodString:
			tc.fmtStringer = false
		case methodGoString:
			tc.fmtGoStringer = false
		case methodMarshalJSON:
			tc.jsonMarshaler = false
		case methodMarshalText:
			tc.textMarshaler = false
		}
	}

	c.classes.Set(t, tc)

	if c.debug {
		debugClassify(t, tc)
	}

	return tc
}

// isQualifier reports whether t is one of the structurally-protected kinds:
// *Pointer, *Interface, Chan, Func, UnsafePointer,
// or *<non-compound> (*string, *int, *bool, etc.),
// or *TypeParam where the constraint excludes all compound kinds,
// or a named type whose underlying type is one of these.
func (matcher) isQualifier(t types.Type) bool {
	switch u := t.Underlying().(type) {
	case *types.Chan, *types.Signature: // Chan, Func
		return true
	case *types.Basic:
		return u.Kind() == types.UnsafePointer
	case *types.Pointer:
		elem := types.Unalias(u.Elem())
		switch e := elem.(type) {
		case *types.Pointer, *types.Interface, *types.Basic: // **T, *Interface, *<non-compound>
			return true
		case *types.TypeParam: // *TypeParam: safe iff constraint excludes compound kinds
			// Conservative (compound) when the constraint is absent, any, or method-only.
			return !typeElemHasCompoundTerm(e.Constraint())
		case *types.Named:
			// fmt dereferences a depth-0 pointer only for compound kinds,
			// so a pointer to any non-compound named type (e.g. *MyString)
			// prints as an address.
			return !isCompoundKind(e)
		}
		return false // *<compound> — pointee is a compound type
	}
	return false
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
// still protects its content structurally:
// it reaches at least one qualifier through fields,
// non-empty array and slice elements, and map keys and values, but never through pointers.
func (m matcher) isStructurallySafe(t types.Type, visited map[types.Type]bool) bool {
	t = types.Unalias(t)
	if visited[t] {
		return false
	}
	visited[t] = true

	if m.isQualifier(t) {
		return true
	}
	switch u := t.Underlying().(type) {
	case *types.Struct:
		for f := range u.Fields() {
			if m.isStructurallySafe(f.Type(), visited) {
				return true
			}
		}
	case *types.Array:
		// A zero-length array holds no value, e.g. the `_ [0]func()` not-comparable idiom.
		return u.Len() > 0 && m.isStructurallySafe(u.Elem(), visited)
	case *types.Slice:
		return m.isStructurallySafe(u.Elem(), visited)
	case *types.Map:
		return m.isStructurallySafe(u.Key(), visited) || m.isStructurallySafe(u.Elem(), visited)
	}
	return false
}

// ptrFmt reports whether *t has a fmt method,
// i.e. whether fmt holding a *t can redact it when the path does not disable the method.
func (c *typeClass) ptrFmt() bool {
	return c.fmtFormatter || c.fmtStringer || c.fmtGoStringer ||
		c.ptrOnly[methodFormat] || c.ptrOnly[methodString] || c.ptrOnly[methodGoString]
}

// debugClassify prints one classification line to stderr
// unless the same line was already printed.
func debugClassify(t *types.Named, tc *typeClass) {
	line := fmt.Sprintf("sensitive type %s: Formatter=%v Stringer=%v GoStringer=%v json.Marshaler=%v encoding.TextMarshaler=%v structurallySafe=%v",
		t,
		tc.fmtFormatter, tc.fmtStringer, tc.fmtGoStringer,
		tc.jsonMarshaler, tc.textMarshaler, tc.structurallySafe)
	if len(tc.revealing) > 0 {
		line += fmt.Sprintf(" revealing=%v", slices.Sorted(maps.Keys(tc.revealing)))
	}
	if _, loaded := debugPrinted.LoadOrStore(line, struct{}{}); !loaded {
		log.Print(line)
	}
}

// qualifiedName returns the type name prefixed with the full package path, if it has one.
func qualifiedName(t *types.Named) string {
	if pkg := t.Obj().Pkg(); pkg != nil {
		return pkg.Path() + "." + t.Obj().Name()
	}
	return t.Obj().Name()
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
//   - A pointer directly to a safe type is not a factor on its own:
//     fmt holds *T, so it is judged by the method set of *T,
//     and on a clean path the methods of *T fire.
//     A pointer to a holder struct is a factor, as any non-Formatter pointer.
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
// under the given fd state.
// fd means that fmt interfaces may not fire here:
// either an unexported field was entered,
// or a non-Formatter pointer was passed, after which badVerb may print the pointee.
// visited prevents infinite recursion on cyclic types;
// it is keyed by fd too, because a type is safe or leaking depending on it.
// factorAt must not be nil;
// when walk returns true, it holds the first disable factor on the path, if any.
// It is left unchanged when walk returns false.
// When walk returns true, path receives the hops of the leaking path
// ordered from the innermost (the safe type) to the outermost,
// excluding the walked type itself.
//
//nolint:funlen,gocognit // Walk matches fmt complexity; extracting would harm readability.
func (c *checker) walk(t types.Type, fd bool, visited map[walkKey]bool, factorAt *disableFactor, path *[]walkStep) bool { //nolint:revive // control flag by design
	t = types.Unalias(t)
	key := walkKey{t: t, fd: fd}
	if visited[key] {
		return false
	}

	// Safe-type terminal.
	if named, ok := c.sensitiveNamed(t); ok {
		// With fmt interfaces enabled the safe type is safe.
		// Otherwise, if it implements any of them
		// AND has no structural protection, its content leaks.
		cls := c.classify(named)
		leaks := fd &&
			(cls.fmtFormatter || cls.fmtStringer || cls.fmtGoStringer) && !cls.structurallySafe
		if leaks {
			*path = append(*path, leakStep(named))
		}
		return leaks
	}

	visited[key] = true

	switch u := t.(type) {
	case *types.Pointer:
		// A Formatter pointer reached with fd==false is a safe terminal.
		isFormatter := c.hasMethod(t, methodFormat)
		if isFormatter && !fd {
			return false
		}
		// Under badVerb at depth 0, fmt only dereferences the
		// pointer when the pointee is a compound kind (Struct/Slice/Array/Map).
		// *<non-compound> pointers always go to fmtPointer → address printed.
		if !isCompoundKind(u.Elem()) {
			return false
		}
		// A pointer directly to a safe type is judged by the method set of *T:
		// that is the form fmt holds.
		if named, ok := c.sensitiveNamed(u.Elem()); ok {
			return c.walkPtrToSafe(u, named, fd, path)
		}
		// Non-Formatter pointer to compound (or reached under disable):
		// badVerb is possible, and the pointee can be dereferenced.
		// The factor is published to factorAt only when the walk leaks,
		// otherwise it would be reported as the reason of an unrelated leak found later.
		factor := *factorAt
		if factor.kind == "" {
			factor = disableFactor{kind: factorNonFormatterPointer, name: u.Elem().String()}
		}
		if !c.walk(u.Elem(), true, visited, &factor, path) {
			return false
		}
		*factorAt = factor
		// A Formatter pointer gets here only under fd, so it is not called "non-Formatter".
		step := walkStep{desc: "pointer to " + shortTypeString(u.Elem())}
		if !isFormatter {
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
			if !f.Exported() && factorAt.kind == "" {
				newFactor = &disableFactor{kind: factorUnexportedField, name: f.Name()}
			}
			if c.walk(f.Type(), fd2, visited, newFactor, path) {
				if newFactor != factorAt && factorAt.kind == "" {
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
		return c.walk(u.Elem(), fd, visited, factorAt, path)

	case *types.Array:
		return u.Len() > 0 && c.walk(u.Elem(), fd, visited, factorAt, path)

	case *types.Map:
		return c.walk(u.Key(), fd, visited, factorAt, path) ||
			c.walk(u.Elem(), fd, visited, factorAt, path)

	case *types.Interface:
		// Flag only SecretExposer interfaces — those that have an ExposeSecret method,
		// the convention used by github.com/powerman/sensitive.Secret[T] and
		// github.com/negrel/secrecy.SecretExposer[T].
		// Generic any/interface{} and all other arbitrary interfaces are NOT flagged:
		// the static analyzer cannot know what concrete type will be stored in them,
		// and flagging them causes a torrent of false positives from external library
		// internals (e.g. prometheus.Metric or error deep inside a metrics struct).
		if c.isSecretExposer(u) {
			return fd
		}
		return false

	case *types.Chan, *types.Signature, *types.Basic:
		return false // address/header/primitive

	case *types.Named:
		// A named type with fmt.Formatter reached with fmt interfaces still enabled
		// redacts under every verb, so it is a safe terminal (same trust as *types.Pointer).
		// Under fd the method may not fire, so it must not be trusted there.
		if !fd && c.hasMethod(t, methodFormat) {
			return false
		}
		if !c.walk(u.Underlying(), fd, visited, factorAt, path) {
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

// walkPtrToSafe handles a pointer p directly to the configured safe type named,
// reached with fmt interfaces disabled or not.
// On a clean path the methods of *T fire,
// and the verbs which they do not handle are the concern of -require-format, as for a T value.
// Otherwise the pointer leaks if *T has a fmt method which is disabled by the path
// and T has no structural protection.
// The path is extended like in [checker.walk].
func (c *checker) walkPtrToSafe(p *types.Pointer, named *types.Named, fd bool, path *[]walkStep) bool { //nolint:revive // control flag by design
	cls := c.classify(named)
	if !fd || !cls.ptrFmt() || cls.structurallySafe {
		return false
	}
	// The disable factor is already published by whatever disabled the path.
	*path = append(*path, leakStep(named))
	step := walkStep{desc: "pointer to " + shortTypeString(p.Elem()), pos: named.Obj().Pos()}
	if !c.hasMethod(p, methodFormat) {
		step.desc = "non-Formatter " + step.desc
	}
	*path = append(*path, step)
	return true
}
