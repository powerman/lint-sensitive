package analyzer

import (
	"cmp"
	"go/token"
	"go/types"
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

// typeRef records a reference to a configured safe type found in an analysis pass.
type typeRef struct {
	pos   token.Pos
	named *types.Named
}

// collectType validates an object from Defs/Uses and appends it to refs
// if it matches a configured safe type and its position is not skipped
// by skip-tests or skip-generated.
func (m matcher) collectType(
	pass *analysis.Pass,
	obj types.Object,
	pos token.Pos,
	refs []typeRef,
) []typeRef {
	tn, ok := obj.(*types.TypeName)
	if !ok {
		return refs
	}
	named, ok := tn.Type().(*types.Named)
	if !ok || !m.isSensitiveNamed(named) || !m.shouldCheck(pass, pos) {
		return refs
	}
	return append(refs, typeRef{pos: pos, named: named})
}

// runReliabilityLevels checks all configured safe types found in the analyzed package
// against user-selected reliability-level flags
// and emits diagnostics for any that do not meet the required protection level.
// It reports at the type usage site within the analyzed package.
// (Declaration-site reporting is not practical because the declaration of most
// configured safe types — the built-in defaults — lives in an external package.)
// References in files skipped by skip-tests or skip-generated are ignored,
// so a type used both there and in a regular file is reported in the regular one.
// References are collected then sorted by position so the diagnostic always
// lands at the first occurrence (deterministic).
func (m matcher) runReliabilityLevels(pass *analysis.Pass) {
	demanded := requires{
		marshalJSONSafe: m.requireMarshalJSON,
		marshalTextSafe: m.requireMarshalText,
		formatSafe:      m.requireFormat,
		goStringSafe:    m.requireGoString,
		stringSafe:      m.requireString,
	}
	if !demanded.marshalJSONSafe && !demanded.marshalTextSafe && !demanded.formatSafe &&
		!demanded.goStringSafe && !demanded.stringSafe {
		return
	}

	// Collect all references to configured safe types with their positions.
	var refs []typeRef

	// Local type declarations.
	for id, obj := range pass.TypesInfo.Defs {
		refs = m.collectType(pass, obj, id.Pos(), refs)
	}

	// External type references.
	for id, obj := range pass.TypesInfo.Uses {
		refs = m.collectType(pass, obj, id.Pos(), refs)
	}

	// Sort by position for deterministic diagnostic placement.
	slices.SortFunc(refs, func(a, b typeRef) int { return cmp.Compare(a.pos, b.pos) })

	// Deduplicate only after sorting, so the first occurrence wins.
	seen := make(map[*types.Named]bool)
	for _, r := range refs {
		if seen[r.named] {
			continue
		}
		seen[r.named] = true
		m.emitLevelDiagnostics(pass, r.pos, r.named, demanded)
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
	typeName := named.Obj().Name()
	if pkg := named.Obj().Pkg(); pkg != nil {
		typeName = pkg.Path() + "." + typeName
	}

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
