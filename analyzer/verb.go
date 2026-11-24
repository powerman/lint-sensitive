package analyzer

import "go/types"

// fmtVerb is the verb which fmt prints a value with.
// The zero value is anyVerb: the declaration check, which cannot know the verb of the caller,
// assumes the verb which triggers badVerb.
type fmtVerb struct {
	verb  rune // 0 for anyVerb.
	sharp bool // The '#' flag, which matters only for 'v'.
}

func (v fmtVerb) known() bool { return v.verb != 0 }

// pointerPrintsAddress reports whether fmt prints a pointer reached below the top level
// as an address under v, instead of calling badVerb which dereferences it.
func (v fmtVerb) pointerPrintsAddress() bool {
	switch v.verb {
	case 'v', 'p', 'b', 'o', 'd', 'x', 'X':
		return true
	default:
		return false
	}
}

// firesFor reports whether fmt calls a method of a value for the verb v
// (handleMethods), where has tells which fmt methods the value has.
// %w of an error behaves like %v; %w of a value which is not an error is badVerb.
func firesFor(v fmtVerb, has func(method string) bool) bool {
	if v.verb == 'w' {
		if !has(methodError) {
			return false
		}
		v.verb = 'v'
	}
	if has(methodFormat) {
		return true
	}
	if v.verb == 'v' && v.sharp {
		return has(methodGoString)
	}
	switch v.verb {
	case 'v', 's', 'x', 'X', 'q':
		return has(methodError) || has(methodString)
	default:
		return false
	}
}

// methodsOf returns a predicate for the fmt methods of a value which fmt holds as t.
// The classification of a safe type (or a pointer to it) is used as is:
// it drops the revealing methods, which must not count as protection.
func (c *checker) methodsOf(t types.Type) func(method string) bool {
	ptr := false
	elem := t
	if p, ok := t.(*types.Pointer); ok {
		ptr, elem = true, p.Elem()
	}
	named, ok := c.sensitiveNamed(elem)
	if !ok {
		return func(method string) bool { return c.hasMethod(t, method) }
	}
	cls := c.classify(named)
	return func(method string) bool {
		switch method {
		case methodFormat:
			return cls.fmtFormatter || ptr && cls.ptrOnly[method]
		case methodString:
			return cls.fmtStringer || ptr && cls.ptrOnly[method]
		case methodGoString:
			return cls.fmtGoStringer || ptr && cls.ptrOnly[method]
		default:
			return c.hasMethod(t, method)
		}
	}
}

// fires reports whether fmt calls a method of a value which it holds as t in the state st.
// With anyVerb only Formatter is certain to fire, because it serves every verb.
func (c *checker) fires(t types.Type, st printState) bool {
	if st.mode != stateClean {
		return false
	}
	if !st.verb.known() {
		return c.hasMethod(t, methodFormat)
	}
	return firesFor(st.verb, c.methodsOf(t))
}

// wrapsNonError reports whether a value which fmt holds as t is printed with %w
// while not being an error: handleMethods then calls badVerb for the whole value.
func (c *checker) wrapsNonError(t types.Type, st printState) bool {
	return st.mode == stateClean && st.verb.verb == 'w' &&
		!types.IsInterface(t) && !c.methodsOf(t)(methodError)
}

// leaksAsArg reports whether fmt exposes the secret of a safe type
// when a value of type t is the argument of an operation with the verb v,
// see ARCHITECTURE.md ("The walk").
// The disable factor and the path are described at [checker.walk].
func (c *checker) leaksAsArg(t types.Type, v fmtVerb, path *[]walkStep) (bool, *disableFactor) {
	factor := &disableFactor{}
	t = types.Unalias(t)
	visited := make(map[walkKey]bool)
	clean := printState{mode: stateClean, verb: v}

	switch {
	case v.verb == 'T' || types.IsInterface(t):
		// The dynamic type of an interface is unknown.
		return false, factor
	case v.verb == 'p':
		// printArg handles %p before methods: an address, or badVerb for a value without one.
		if printsAddress(t) {
			return false, factor
		}
		return c.walk(t, printState{mode: stateErroring, verb: v}, visited, factor, path), factor
	}
	if p, ok := t.Underlying().(*types.Pointer); ok {
		return c.walkArgPointer(t, p, clean, visited, factor, path), factor
	}
	return c.walk(t, clean, visited, factor, path), factor
}

// walkArgPointer is walk for the pointer type p which is the argument itself (depth 0).
// Unlike a nested pointer, fmt dereferences it for every verb when the pointee is compound,
// and prints the pointee with the same verb at depth 1.
func (c *checker) walkArgPointer(holder types.Type, p *types.Pointer, st printState,
	visited map[walkKey]bool, factorAt *disableFactor, path *[]walkStep,
) bool {
	if c.fires(holder, st) || !isCompoundKind(p.Elem()) {
		return false
	}
	if c.wrapsNonError(holder, st) {
		st.mode = stateErroring
	}
	return c.walk(p.Elem(), st, visited, factorAt, path)
}

// printsAddress reports whether %p prints t as an address.
func printsAddress(t types.Type) bool {
	switch u := t.Underlying().(type) {
	case *types.Pointer, *types.Chan, *types.Signature, *types.Map, *types.Slice:
		return true
	case *types.Basic:
		return u.Kind() == types.UnsafePointer
	default:
		return false
	}
}
