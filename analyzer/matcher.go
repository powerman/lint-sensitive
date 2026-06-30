package analyzer

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"
	"unicode"

	"golang.org/x/tools/go/analysis"
)

type matcher struct {
	packages      map[string]bool
	types         map[packageType]bool
	skipTests     bool
	skipGenerated bool
}

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

// containsSensitive reports whether a value of type t can contain
// a sensitive value that would leak when fmt formats it through reflection
// (i.e., when reached via an unexported struct field).
//
// It checks the named type FIRST (so sensitive.Bytes matches before descending into []byte),
// then unwraps pointer/slice/array/channel/map and descends struct fields transitively.
//
// visited is a cycle-breaking set, required for recursive types
// (e.g. type Node struct{ next *Node; secret sensitive.String })
// to avoid stack overflow.
// This is a reachability query for a path-independent property:
// any sensitive node returns true on entry (short-circuit)
// before it could ever be cached as non-sensitive,
// and cycle edges correctly contribute false,
// so the visited set yields NO false negatives.
func (m matcher) containsSensitive(t types.Type, visited map[types.Type]bool) bool {
	t = types.Unalias(t)
	if visited[t] {
		return false
	}
	visited[t] = true

	if m.isSensitiveNamed(t) {
		// A sensitive named struct that keeps its value behind a double pointer
		// (sensitive.Boxed[T] = struct{ pp **T }) is unreachable through fmt
		// reflection, since fmt never follows two pointer levels.
		// This is the only sensitive named type treated as safe;
		// every other one leaks and is flagged.
		if namedStructIsBoxed(t) {
			return false
		}
		return true
	}

	switch u := t.(type) {
	case *types.Pointer:
		return m.containsSensitive(u.Elem(), visited)
	case *types.Slice:
		return m.containsSensitive(u.Elem(), visited)
	case *types.Array:
		return m.containsSensitive(u.Elem(), visited)
	case *types.Chan:
		return m.containsSensitive(u.Elem(), visited)
	case *types.Map:
		return m.containsSensitive(u.Key(), visited) || m.containsSensitive(u.Elem(), visited)
	case *types.Named:
		return m.containsSensitive(u.Underlying(), visited)
	case *types.Struct:
		for field := range u.Fields() {
			// Exported OR not: once the parent field is unexported,
			// fmt's flagRO propagates and every nested field leaks too.
			if m.containsSensitive(field.Type(), visited) {
				return true
			}
		}
	}
	return false
}

// namedStructIsBoxed reports whether t is a named struct type that stores a
// value behind a double pointer (**T), like sensitive.Boxed[T].
// Such a value is unreachable through fmt reflection, so the type is safe.
// The double-pointer field may sit anywhere among other fields, in any order;
// a single such field is enough.
func namedStructIsBoxed(t types.Type) bool {
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	for f := range st.Fields() {
		if isDoublePointer(f.Type()) {
			return true
		}
	}
	return false
}

// isDoublePointer reports whether a type is a pointer-to-pointer (**T or deeper).
func isDoublePointer(t types.Type) bool {
	p, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return false
	}
	_, ok = p.Elem().(*types.Pointer)
	return ok
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
