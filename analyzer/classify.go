package analyzer

import (
	"fmt"
	"go/types"
	"log"
	"maps"
	"slices"
)

// typeClass records the classification of a configured safe type.
type typeClass struct {
	fmtFormatter     bool // t implements fmt.Formatter
	fmtStringer      bool // t implements fmt.Stringer
	fmtGoStringer    bool // t implements fmt.GoStringer
	jsonMarshaler    bool // t implements json.Marshaler
	textMarshaler    bool // t implements encoding.TextMarshaler
	structurallySafe bool
	opaque           bool // t is a struct whose non-public fields are all unexported and not embedded

	// publicFields holds names of the fields skipped by the structural and opaque checks
	// as known not to hold the secret (see matcher.public).
	publicFields []string

	// ptrOnly holds names of the methods above which only *t has,
	// so they are not called on a t value and do not count as implemented.
	ptrOnly map[string]bool

	// revealing holds names of the methods which match an interface by signature
	// but output the secret (see revealingMethods).
	// They are removed from the flags above and from ptrOnly,
	// and they fail every surface they serve (see surfaces).
	revealing map[string]bool
}

// classify performs lazy classification of a configured safe type.
// It caches the result in c.classes.
func (c *checker) classify(t *types.Named) *typeClass {
	if tc, ok := c.classes.At(t).(*typeClass); ok {
		return tc
	}

	tc := &typeClass{
		fmtFormatter:  c.hasMethod(t, methodFormat),
		fmtStringer:   c.hasMethod(t, methodString),
		fmtGoStringer: c.hasMethod(t, methodGoString),
		jsonMarshaler: c.hasMethod(t, methodMarshalJSON),
		textMarshaler: c.hasMethod(t, methodMarshalText),
		ptrOnly:       c.ptrOnlyMethods(t),
	}
	key := qualifiedName(t)
	public := c.public[key]
	tc.opaque = isOpaqueStruct(t.Underlying(), public)
	tc.structurallySafe, tc.publicFields = c.isStructurallySafeNamed(t, public)
	for _, name := range revealingMethods[key] {
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
		c.debugClassify(t, tc)
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

// isStructurallySafe reports whether fmt prints every value the type can carry
// as an address or header, so that the type protects its content
// even when ALL of Formatter/Stringer/GoStringer are disabled.
// It must have at least one qualifier;
// zero-size parts (`_ [0]func()`, struct{}) carry nothing and do not matter.
func (m matcher) isStructurallySafe(t types.Type, visited map[types.Type]bool) bool {
	safe, protected := m.structural(t, visited)
	return safe && protected
}

// structural reports whether every value t can carry is printed as an address or header (safe)
// and whether t has at least one qualifier (protected).
// A type seen again (a recursive type, or a type shared by sibling fields)
// is neutral: its first visit already contributed to the result,
// because the results of all parts are combined with AND (safe) and OR (protected).
func (m matcher) structural(t types.Type, visited map[types.Type]bool) (safe, protected bool) {
	t = types.Unalias(t)
	if visited[t] {
		return true, false
	}
	visited[t] = true

	if m.isQualifier(t) {
		return true, true
	}
	switch u := t.Underlying().(type) {
	case *types.Struct:
		safe = true
		for f := range u.Fields() {
			s, p := m.structural(f.Type(), visited)
			safe, protected = safe && s, protected || p
		}
		return safe, protected
	case *types.Array:
		if u.Len() == 0 {
			return true, false
		}
		return m.structural(u.Elem(), visited)
	case *types.Slice:
		return m.structural(u.Elem(), visited)
	case *types.Map:
		sk, pk := m.structural(u.Key(), visited)
		sv, pv := m.structural(u.Elem(), visited)
		return sk && sv, pk || pv
	}
	return false, false
}

// isStructurallySafeNamed is [matcher.isStructurallySafe] for a configured named type,
// ignoring its top-level fields named in public (see matcher.public).
// It also returns the names of the fields which were ignored:
// a listed name which the struct does not have is not ignored
// (the library changed), so the type falls back to the plain rule, which is the safe direction.
func (m matcher) isStructurallySafeNamed(t *types.Named, public []string) (bool, []string) {
	st, ok := t.Underlying().(*types.Struct)
	if !ok || len(public) == 0 {
		return m.isStructurallySafe(t.Underlying(), make(map[types.Type]bool)), nil
	}
	visited := map[types.Type]bool{t.Underlying(): true}
	var ignored []string
	safe, protected := true, false
	for f := range st.Fields() {
		if slices.Contains(public, f.Name()) {
			ignored = append(ignored, f.Name())
			continue
		}
		s, p := m.structural(f.Type(), visited)
		safe, protected = safe && s, protected || p
	}
	return safe && protected, ignored
}

// isOpaqueStruct reports whether reflection-based encoders such as encoding/json
// write t empty: it is a struct whose fields are all unexported and none is embedded.
// Fields named in public (see matcher.public) are skipped
// even if they are exported or embedded;
// a listed name which the struct does not have is not applied.
func isOpaqueStruct(t types.Type, public []string) bool {
	st, ok := t.(*types.Struct)
	if !ok {
		return false
	}
	for f := range st.Fields() {
		if slices.Contains(public, f.Name()) {
			continue
		}
		if f.Exported() || f.Embedded() {
			return false
		}
	}
	return true
}

// ptrFmt reports whether *t has a fmt method,
// i.e. whether fmt holding a *t can redact it when the path does not disable the method.
func (c *typeClass) ptrFmt() bool {
	return c.fmtFormatter || c.fmtStringer || c.fmtGoStringer ||
		c.ptrOnly[methodFormat] || c.ptrOnly[methodString] || c.ptrOnly[methodGoString]
}

// debugClassify prints one classification line to stderr
// unless the same line was already printed.
func (m matcher) debugClassify(t *types.Named, tc *typeClass) {
	line := fmt.Sprintf("sensitive type %s: Formatter=%v Stringer=%v GoStringer=%v json.Marshaler=%v encoding.TextMarshaler=%v structurallySafe=%v opaque=%v",
		t,
		tc.fmtFormatter, tc.fmtStringer, tc.fmtGoStringer,
		tc.jsonMarshaler, tc.textMarshaler, tc.structurallySafe, tc.opaque)
	if len(tc.publicFields) > 0 {
		line += fmt.Sprintf(" publicFields=%v", tc.publicFields)
	}
	if len(tc.revealing) > 0 {
		line += fmt.Sprintf(" revealing=%v", slices.Sorted(maps.Keys(tc.revealing)))
	}
	if _, loaded := m.debugPrinted.LoadOrStore(line, struct{}{}); !loaded {
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
