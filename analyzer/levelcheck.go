package analyzer

import (
	"cmp"
	"go/token"
	"go/types"
	"maps"
	"slices"
	"strings"

	"golang.org/x/tools/go/analysis"
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
// if obj, taken from Defs/Uses, is a configured safe type,
// pos is not skipped by skip-tests or skip-generated,
// and it precedes the position recorded earlier for this type.
func (m matcher) collectType(
	shouldCheck func(token.Pos) bool,
	obj types.Object,
	pos token.Pos,
	first map[*types.Named]token.Pos,
) {
	tn, ok := obj.(*types.TypeName)
	if !ok {
		return
	}
	named, ok := tn.Type().(*types.Named)
	if !ok || !m.isSensitiveNamed(named) {
		return
	}
	if prev, seen := first[named]; seen && prev <= pos {
		return
	}
	if shouldCheck(pos) {
		first[named] = pos
	}
}

// runReliabilityLevels checks all configured safe types found in the analyzed package
// against user-selected reliability-level flags
// and emits diagnostics for any that do not meet the required protection level.
// It reports at the type usage site within the analyzed package.
// (Declaration-site reporting is not practical because the declaration of most
// configured safe types — the built-in defaults — lives in an external package.)
// References in files skipped by skip-tests or skip-generated are ignored,
// so a type used both there and in a regular file is reported in the regular one.
// Only the first occurrence of each type is kept,
// and the diagnostics are emitted in the order of these positions (deterministic).
func (m matcher) runReliabilityLevels(pass *analysis.Pass, shouldCheck func(token.Pos) bool) {
	demanded := requires{
		marshalJSONSafe: m.requireMarshalJSON,
		marshalTextSafe: m.requireMarshalText,
		formatSafe:      m.requireFormat,
		goStringSafe:    m.requireGoString,
		stringSafe:      m.requireString,
	}
	if demanded == (requires{}) {
		return
	}

	// The first position of each configured safe type.
	first := make(map[*types.Named]token.Pos)

	// Local type declarations.
	for id, obj := range pass.TypesInfo.Defs {
		m.collectType(shouldCheck, obj, id.Pos(), first)
	}

	// External type references.
	for id, obj := range pass.TypesInfo.Uses {
		m.collectType(shouldCheck, obj, id.Pos(), first)
	}

	for _, named := range slices.SortedFunc(maps.Keys(first), func(a, b *types.Named) int {
		return cmp.Compare(first[a], first[b])
	}) {
		m.emitLevelDiagnostics(pass, first[named], named, demanded)
	}
}

// emitLevelDiagnostics emits one diagnostic per unmet reliability requirement
// for the given named type at the given position.
func (m matcher) emitLevelDiagnostics(
	pass *analysis.Pass,
	pos token.Pos,
	named *types.Named,
	demanded requires,
) {
	cls := m.classify(named)
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
		if d.demand && !d.satisfy {
			pass.Report(analysis.Diagnostic{
				Pos: pos,
				Message: "configured safe type " + typeName + " does not guarantee " + d.msg +
					ptrOnlyHint(cls.ptrOnly, d.methods),
			})
		}
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
