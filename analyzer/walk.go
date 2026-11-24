package analyzer

import (
	"fmt"
	"go/token"
	"go/types"
)

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

// printState is how fmt prints the values which walk reaches, see ARCHITECTURE.md ("The walk").
type printState uint8

const (
	stateClean     printState = iota // Methods are called, the verb of the caller is used.
	stateNoMethods                   // Inside an unexported field: no methods, the verb is kept.
	stateErroring                    // Inside the pointer which caused badVerb.
)

// walkKey is the memoization key of walk.
type walkKey struct {
	t  types.Type
	st printState
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

// fieldStep describes the struct field on a leaking path.
func fieldStep(f *types.Var) walkStep {
	kind := "field"
	if !f.Exported() {
		kind = "unexported field"
	}
	return walkStep{
		pos:  f.Pos(),
		desc: fmt.Sprintf("%s %q of type %s", kind, f.Name(), shortTypeString(f.Type())),
	}
}

// leakStep describes the safe type at the end of a leaking path.
func leakStep(named *types.Named) walkStep {
	return walkStep{
		pos:  named.Obj().Pos(),
		desc: "safe type " + shortTypeString(named),
	}
}

// walk is the Formatter-termination walk, see ARCHITECTURE.md ("The walk").
// It returns true when a safe type reachable through t would leak its secret content
// when fmt prints t in the print state st.
// visited prevents infinite recursion on cyclic types;
// it is keyed by st too, because a type is safe or leaking depending on it.
// factorAt must not be nil;
// when walk returns true, it holds the first disable factor on the path, if any.
// It is left unchanged when walk returns false.
// When walk returns true, path receives the hops of the leaking path
// ordered from the innermost (the safe type) to the outermost,
// excluding the walked type itself.
func (c *checker) walk(t types.Type, st printState, visited map[walkKey]bool, factorAt *disableFactor, path *[]walkStep) bool {
	t = types.Unalias(t)
	key := walkKey{t: t, st: st}
	if visited[key] {
		return false
	}

	if named, ok := c.sensitiveNamed(t); ok {
		return c.walkSafe(named, st, path)
	}

	visited[key] = true

	switch u := t.(type) {
	case *types.Pointer:
		return c.walkPointer(t, u, st, visited, factorAt, path)
	case *types.Struct:
		return c.walkStruct(u, st, visited, factorAt, path)
	case *types.Slice:
		return c.walk(u.Elem(), st, visited, factorAt, path)
	case *types.Array:
		return u.Len() > 0 && c.walk(u.Elem(), st, visited, factorAt, path)
	case *types.Map:
		return c.walk(u.Key(), st, visited, factorAt, path) ||
			c.walk(u.Elem(), st, visited, factorAt, path)
	case *types.Interface:
		// Only SecretExposer interfaces are flagged, see ARCHITECTURE.md ("The walk").
		return c.isSecretExposer(u) && st != stateClean
	case *types.Named:
		return c.walkNamed(u, st, visited, factorAt, path)
	default:
		return false // Chan, Signature, Basic: address/header/primitive.
	}
}

// walkSafe is walk for the safe type named, which is a terminal.
// With fmt interfaces enabled the safe type is safe.
// Otherwise, if it implements any of them
// AND has no structural protection, its content leaks.
func (c *checker) walkSafe(named *types.Named, st printState, path *[]walkStep) bool {
	cls := c.classify(named)
	leaks := st != stateClean &&
		(cls.fmtFormatter || cls.fmtStringer || cls.fmtGoStringer) && !cls.structurallySafe
	if leaks {
		*path = append(*path, leakStep(named))
	}
	return leaks
}

// walkStruct is walk for the struct type u.
func (c *checker) walkStruct(u *types.Struct, st printState,
	visited map[walkKey]bool, factorAt *disableFactor, path *[]walkStep,
) bool {
	for f := range u.Fields() {
		fst, factor := enterField(f, st, factorAt)
		if !c.walk(f.Type(), fst, visited, factor, path) {
			continue
		}
		// A new factor is published only when the walk leaks (see walkPointer).
		if factor != factorAt {
			*factorAt = *factor
		}
		*path = append(*path, fieldStep(f))
		return true
	}
	return false
}

// enterField returns the print state and the disable factor to walk the type of the field f
// of a struct which fmt prints in the state st with the factor factorAt.
// An unexported field turns methods off,
// and becomes the factor unless the path already has one.
func enterField(f *types.Var, st printState, factorAt *disableFactor) (printState, *disableFactor) {
	if f.Exported() {
		return st, factorAt
	}
	if st == stateClean {
		st = stateNoMethods
	}
	if factorAt.kind == "" {
		factorAt = &disableFactor{kind: factorUnexportedField, name: f.Name()}
	}
	return st, factorAt
}

// walkNamed is walk for the named type u which is not a safe type.
func (c *checker) walkNamed(u *types.Named, st printState,
	visited map[walkKey]bool, factorAt *disableFactor, path *[]walkStep,
) bool {
	// A defined pointer type has no methods.
	if p, ok := u.Underlying().(*types.Pointer); ok {
		return c.walkPointer(u, p, st, visited, factorAt, path)
	}
	// A Formatter reached with fmt interfaces still enabled is a safe terminal
	// (see ARCHITECTURE.md, "What fmt does").
	if st == stateClean && c.hasMethod(u, methodFormat) {
		return false
	}
	if !c.walk(u.Underlying(), st, visited, factorAt, path) {
		return false
	}
	// A SecretExposer interface has no step of its own.
	if _, ok := u.Underlying().(*types.Interface); ok {
		*path = append(*path, leakStep(u))
	}
	return true
}

// walkPointer is walk for the pointer type p which fmt holds as holder:
// p itself or a defined type whose underlying type is p.
// The method set is always taken from holder, which is empty for a defined pointer type.
func (c *checker) walkPointer(holder types.Type, p *types.Pointer, st printState,
	visited map[walkKey]bool, factorAt *disableFactor, path *[]walkStep,
) bool {
	// Under badVerb every pointer below the one which caused it prints as an address.
	if st == stateErroring {
		return false
	}
	// A Formatter pointer reached on a clean path is a safe terminal.
	isFormatter := c.hasMethod(holder, methodFormat)
	if isFormatter && st == stateClean {
		return false
	}
	// Under badVerb at depth 0, fmt only dereferences the pointer
	// when the pointee is a compound kind (Struct/Slice/Array/Map).
	// *<non-compound> pointers always go to fmtPointer, which prints the address.
	if !isCompoundKind(p.Elem()) {
		return false
	}
	// The factor is published to factorAt only when the walk leaks,
	// otherwise it would be reported as the reason of an unrelated leak found later.
	factor := *factorAt
	if factor.kind == "" {
		factor = disableFactor{kind: factorNonFormatterPointer, name: p.Elem().String()}
	}
	if named, ok := c.sensitiveNamed(p.Elem()); ok {
		// fmt calls the methods of *T only when it holds *T itself on a clean path.
		// Otherwise the pointer leaks if *T has a fmt method which is disabled by the path
		// and T has no structural protection.
		_, definedPtr := holder.(*types.Named)
		cls := c.classify(named)
		if st == stateClean && !definedPtr || !cls.ptrFmt() || cls.structurallySafe {
			return false
		}
		*path = append(*path, leakStep(named))
	} else if !c.walk(p.Elem(), stateErroring, visited, &factor, path) {
		return false
	}
	*factorAt = factor
	*path = append(*path, c.pointerStep(holder, p))
	return true
}

// pointerStep describes the hop through a pointer which fmt holds as holder.
// A Formatter pointer gets here only where methods are off,
// so it is not called "non-Formatter".
func (c *checker) pointerStep(holder types.Type, p *types.Pointer) walkStep {
	if named, ok := holder.(*types.Named); ok {
		return walkStep{
			pos: named.Obj().Pos(),
			desc: "non-Formatter pointer type " + shortTypeString(holder) +
				" to " + shortTypeString(p.Elem()),
		}
	}
	step := walkStep{desc: "pointer to " + shortTypeString(p.Elem())}
	if !c.hasMethod(holder, methodFormat) {
		step.desc = "non-Formatter " + step.desc
	}
	if named, ok := types.Unalias(p.Elem()).(*types.Named); ok {
		step.pos = named.Obj().Pos()
	}
	return step
}
