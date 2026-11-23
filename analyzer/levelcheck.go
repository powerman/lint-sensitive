package analyzer

import (
	"cmp"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/types/typeutil"
)

// requires captures which surfaces a typeClass satisfies
// (used as the return type of levelCheck).
type requires struct {
	marshalJSONSafe bool
	marshalTextSafe bool
	formatSafe      bool
	goStringSafe    bool
	stringSafe      bool
}

// levelCheck evaluates a typeClass against the reliability surfaces.
// Each returned field reports whether the typeClass satisfies that surface.
func levelCheck(c typeClass) requires {
	return requires{
		marshalJSONSafe: c.textMarshaler || c.jsonMarshaler,
		marshalTextSafe: c.textMarshaler,
		formatSafe:      c.fmtFormatter || c.structurallySafe,
		goStringSafe:    c.fmtGoStringer || c.fmtFormatter || c.structurallySafe,
		stringSafe:      c.fmtStringer || c.fmtFormatter || c.structurallySafe,
	}
}

// collectType records pos in first
// if t is a configured safe type (after resolving aliases),
// pos is not skipped by skip-tests or skip-generated,
// and it precedes the position recorded earlier for this type.
// The map is keyed by type identity because instances of one generic type
// created in different packages are different pointers.
func (m matcher) collectType(
	shouldCheck func(token.Pos) bool,
	t types.Type,
	pos token.Pos,
	first *typeutil.Map,
) {
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || !m.isSensitiveNamed(named) {
		return
	}
	if prev, seen := first.At(named).(token.Pos); seen && prev <= pos {
		return
	}
	if shouldCheck(pos) {
		first.Set(named, pos)
	}
}

// runReliabilityLevels checks all configured safe types found in the analyzed package
// against user-selected reliability-level flags
// and emits diagnostics for any that do not meet the required protection level.
// It reports at the type usage site within the analyzed package.
// (Declaration-site reporting is not practical because the declaration of most
// configured safe types — the built-in defaults — lives in an external package.)
// A generic type is checked as the instance the code uses, e.g. SinglePtr[string],
// and an alias is resolved to the type it stands for.
// References in files skipped by skip-tests or skip-generated are ignored,
// so a type used both there and in a regular file is reported in the regular one.
// Only the first occurrence of each type is kept,
// and the diagnostics are emitted in the order of these positions (deterministic).
// Instances of one generic type which fail for the same reason are reported once.
func (c *checker) runReliabilityLevels(pass *analysis.Pass, shouldCheck func(token.Pos) bool) {
	demanded := requires{
		marshalJSONSafe: c.requireMarshalJSON,
		marshalTextSafe: c.requireMarshalText,
		formatSafe:      c.requireFormat,
		goStringSafe:    c.requireGoString,
		stringSafe:      c.requireString,
	}
	if demanded == (requires{}) {
		return
	}

	// The first position of each configured safe type.
	var first typeutil.Map

	// Local type declarations.
	// A generic type is collected as its origin: there it is the type for any type argument.
	for id, obj := range pass.TypesInfo.Defs {
		if tn, ok := obj.(*types.TypeName); ok {
			c.collectType(shouldCheck, tn.Type(), id.Pos(), &first)
		}
	}

	// External type references.
	for id, obj := range pass.TypesInfo.Uses {
		tn, ok := obj.(*types.TypeName)
		// The instance of a generic type or alias is collected from Instances below:
		// its object has unbound type parameters.
		if _, inst := pass.TypesInfo.Instances[id]; !ok || inst {
			continue
		}
		c.collectType(shouldCheck, tn.Type(), id.Pos(), &first)
	}

	// Instances of generic types.
	// Instances of generic functions are not Named and are skipped.
	for id, inst := range pass.TypesInfo.Instances {
		c.collectType(shouldCheck, inst.Type, id.Pos(), &first)
	}

	keys := first.Keys()
	slices.SortFunc(keys, func(a, b types.Type) int {
		return cmp.Compare(first.At(a).(token.Pos), first.At(b).(token.Pos))
	})
	reported := make(map[levelReport]bool)
	for _, t := range keys {
		c.emitLevelDiagnostics(pass, first.At(t).(token.Pos), t.(*types.Named), demanded, reported)
	}
}

// levelReport identifies a diagnostic emitted by emitLevelDiagnostics.
// The message names a generic type without type arguments,
// so the diagnostics of its instances which fail for the same reason are indistinguishable.
// One of them is enough: once it is fixed, the next run reports the next one.
type levelReport struct {
	origin *types.TypeName
	msg    string
}

// emitLevelDiagnostics emits one diagnostic per unmet reliability requirement
// for the given named type at the given position,
// unless the same diagnostic is already in reported.
func (c *checker) emitLevelDiagnostics(
	pass *analysis.Pass,
	pos token.Pos,
	named *types.Named,
	demanded requires,
	reported map[levelReport]bool,
) {
	cls := c.classify(named)
	satisfies := levelCheck(*cls)
	typeName := qualifiedName(named)

	for _, d := range [...]struct {
		demand, satisfy bool
		msg             string
		methods         []string // methods which would satisfy the surface
	}{
		{
			demanded.marshalJSONSafe, satisfies.marshalJSONSafe,
			"JSON marshal safety: " +
				"the type neither implements encoding.TextMarshaler nor json.Marshaler",
			[]string{methodMarshalJSON, methodMarshalText},
		},
		{
			demanded.marshalTextSafe, satisfies.marshalTextSafe,
			"text marshal safety: " +
				"the type does not implement encoding.TextMarshaler",
			[]string{methodMarshalText},
		},
		{
			demanded.formatSafe, satisfies.formatSafe,
			"format-level safety: " +
				"the type does not implement fmt.Formatter " +
				"and is not structurally protected",
			[]string{methodFormat},
		},
		{
			demanded.goStringSafe, satisfies.goStringSafe,
			"GoString-level safety: " +
				"the type does not implement fmt.GoStringer or fmt.Formatter, " +
				"and is not structurally protected",
			[]string{methodFormat, methodGoString},
		},
		{
			demanded.stringSafe, satisfies.stringSafe,
			"String-level safety: " +
				"the type does not implement fmt.Stringer or fmt.Formatter, " +
				"and is not structurally protected",
			[]string{methodFormat, methodString},
		},
	} {
		if !d.demand || d.satisfy {
			continue
		}
		msg := "configured safe type " + typeName + " does not guarantee " + d.msg +
			ptrOnlyHint(cls.ptrOnly, d.methods)
		key := levelReport{origin: named.Origin().Obj(), msg: msg}
		if reported[key] {
			continue
		}
		reported[key] = true
		pass.Report(analysis.Diagnostic{Pos: pos, Message: msg})
	}
}

// ptrOnlyHint explains why a type with a suitable method on a pointer receiver
// is still reported:
// fmt and encoding/json do not call such a method for a non-addressable value.
// It returns an empty string when none of the methods is pointer-receiver-only.
func ptrOnlyHint(ptrOnly map[string]bool, methods []string) string {
	var found []string
	for _, name := range methods {
		if ptrOnly[name] {
			found = append(found, name)
		}
	}
	if len(found) == 0 {
		return ""
	}
	return " (declared only on a pointer receiver, so not called for a T value: " +
		strings.Join(found, ", ") + ")"
}
