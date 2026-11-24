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

// printState is how fmt prints the values which walk reaches.
type printState uint8

const (
	// stateClean: fmt calls methods of the value and uses the verb of the caller.
	stateClean printState = iota
	// stateNoMethods: the path entered an unexported field.
	// fmt does not call methods there, but keeps the verb of the caller,
	// so a pointer may still cause badVerb, which dereferences it.
	stateNoMethods
	// stateErroring: badVerb reprints the pointer which caused it with %v and without methods.
	// It dereferences only that pointer:
	// every pointer nested in the pointee prints as an address.
	stateErroring
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
//     and are not structurally protected (see [matcher.isStructurallySafe]).
//   - Optional reliability-level: warn about using safe types that
//     do not provide the required level of protection for the configured attack surface.
//
// Even though a safe type having interface implementations does not guarantee
// that this functionality is used specifically for secret protection,
// the linter assumes it is (any other approach is useless).
// Structural protection is not assumed this way:
// it counts only when every field of the type is protected,
// so an unrelated field (a callback, a counter, a cache) cannot fake it.
//
// For safe types implementing ([fmt.Formatter] or [fmt.Stringer] or [fmt.GoStringer])
// AND not structurally protected:
//   - The linter checks the path leading to these types
//     for factors that disable support for these interfaces:
//     1. unexported field
//     2. Pointer type not implementing Formatter (may be in an exported field too)
//   - If such a factor is detected, it reports incorrect use of the safe type.
//   - A pointer directly to a safe type is not a factor on its own:
//     fmt holds *T, so it is judged by the method set of *T,
//     and on a clean path the methods of *T fire.
//     A pointer to a holder struct is a factor, as any non-Formatter pointer.
//   - A defined pointer type (type PT *T) has no methods,
//     so it is a non-Formatter pointer even when *T has fmt methods.
//
// Rationale:
//   - If a safe type is structurally protected,
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
//   - badVerb reprints the value with %v and with methods off,
//     and dereferences only the pointer which caused it,
//     so pointers nested deeper in the pointee print as addresses.
//   - An unexported field turns methods off but keeps the verb,
//     so a pointer under it can still cause badVerb.
//
// walk is the Formatter-termination walk.
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
		// Flag only SecretExposer interfaces — those that have an ExposeSecret method,
		// the convention used by github.com/powerman/sensitive.Secret[T] and
		// github.com/negrel/secrecy.SecretExposer[T].
		// Generic any/interface{} and all other arbitrary interfaces are NOT flagged:
		// the static analyzer cannot know what concrete type will be stored in them,
		// and flagging them causes a torrent of false positives from external library
		// internals (e.g. prometheus.Metric or error deep inside a metrics struct).
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
	// A defined pointer type has no methods,
	// so fmt calls neither the methods of *T nor Format of the pointee through it.
	if p, ok := u.Underlying().(*types.Pointer); ok {
		return c.walkPointer(u, p, st, visited, factorAt, path)
	}
	// A named type with fmt.Formatter reached with fmt interfaces still enabled
	// redacts under every verb, so it is a safe terminal (same trust as *types.Pointer).
	// Where methods are off the method may not fire, so it must not be trusted there.
	if st == stateClean && c.hasMethod(u, methodFormat) {
		return false
	}
	if !c.walk(u.Underlying(), st, visited, factorAt, path) {
		return false
	}
	// A SecretExposer interface is a terminal which has no step of its own,
	// because the walk sees only the unnamed interface type.
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
