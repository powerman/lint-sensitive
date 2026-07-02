package analyzer

import (
	"cmp"
	"go/token"
	"go/types"
	"slices"

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

// runReliabilityLevels checks all configured safe types found in the analyzed package
// against user-selected reliability-level flags
// and emits diagnostics for any that do not meet the required protection level.
// It reports at the type usage site within the analyzed package.
// (Declaration-site reporting is not practical because the declaration of most
// configured safe types — the built-in defaults — lives in an external package.)
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
	type ref struct {
		pos   token.Pos
		named *types.Named
	}
	var refs []ref
	seen := make(map[*types.Named]bool)

	// Local type declarations.
	for id, obj := range pass.TypesInfo.Defs {
		tn, ok := obj.(*types.TypeName)
		if !ok {
			continue
		}
		named, ok := tn.Type().(*types.Named)
		if !ok || !m.isSensitiveNamed(named) || seen[named] {
			continue
		}
		seen[named] = true
		refs = append(refs, ref{pos: id.Pos(), named: named})
	}

	// External type references.
	for id, obj := range pass.TypesInfo.Uses {
		tn, ok := obj.(*types.TypeName)
		if !ok {
			continue
		}
		named, ok := tn.Type().(*types.Named)
		if !ok || !m.isSensitiveNamed(named) || seen[named] {
			continue
		}
		seen[named] = true
		refs = append(refs, ref{pos: id.Pos(), named: named})
	}

	// Sort by position for deterministic diagnostic placement.
	slices.SortFunc(refs, func(a, b ref) int { return cmp.Compare(a.pos, b.pos) })

	for _, r := range refs {
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
	}{
		{
			demanded.marshalJSONSafe, satisfies.marshalJSONSafe,
			"JSON marshal safety: " +
				"the type neither implements encoding.TextMarshaler nor json.Marshaler",
		},
		{
			demanded.marshalTextSafe, satisfies.marshalTextSafe,
			"text marshal safety: " +
				"the type does not implement encoding.TextMarshaler",
		},
		{
			demanded.formatSafe, satisfies.formatSafe,
			"format-level safety: " +
				"the type does not implement fmt.Formatter " +
				"and is not structurally protected",
		},
		{
			demanded.goStringSafe, satisfies.goStringSafe,
			"GoString-level safety: " +
				"the type does not implement fmt.GoStringer or fmt.Formatter, " +
				"and is not structurally protected",
		},
		{
			demanded.stringSafe, satisfies.stringSafe,
			"String-level safety: " +
				"the type does not implement fmt.Stringer or fmt.Formatter, " +
				"and is not structurally protected",
		},
	} {
		if d.demand && !d.satisfy {
			pass.Report(analysis.Diagnostic{
				Pos:     pos,
				Message: "configured safe type " + typeName + " does not guarantee " + d.msg,
			})
		}
	}
}
