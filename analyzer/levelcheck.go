package analyzer

import (
	"cmp"
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
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
// With viaPointer the type is used only as *T, so the methods of *T count too.
func levelCheck(c typeClass, viaPointer bool) requires {
	has := func(flag bool, name string) bool { return flag || viaPointer && c.ptrOnly[name] }
	formatter := has(c.fmtFormatter, methodFormat)
	stringer := has(c.fmtStringer, methodString)
	goStringer := has(c.fmtGoStringer, methodGoString)
	jsonMarshaler := has(c.jsonMarshaler, methodMarshalJSON)
	textMarshaler := has(c.textMarshaler, methodMarshalText)
	stringSafe := stringer || formatter || c.structurallySafe
	return requires{
		marshalJSONSafe: textMarshaler || jsonMarshaler || c.opaque,
		marshalTextSafe: textMarshaler || c.opaque && stringSafe,
		formatSafe:      formatter || c.structurallySafe,
		goStringSafe:    goStringer || formatter || c.structurallySafe,
		stringSafe:      stringSafe,
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

// typeUse is a configured safe type found in the analyzed package.
type typeUse struct {
	named      *types.Named
	pos        token.Pos
	viaPointer bool // Every use of the type is the pointer form.
}

// typeIdent returns the identifier of the type name which e denotes,
// looking through parentheses, package qualifiers and type arguments.
// It returns nil when e is not a type name.
func typeIdent(e ast.Expr) *ast.Ident {
	for {
		switch x := e.(type) {
		case *ast.Ident:
			return x
		case *ast.ParenExpr:
			e = x.X
		case *ast.SelectorExpr:
			return x.Sel
		case *ast.IndexExpr:
			e = x.X
		case *ast.IndexListExpr:
			e = x.X
		default:
			return nil
		}
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
//
// A type is checked by the method set of T if the package has any value-form use of it,
// and by the method set of *T only if every use is the pointer form.
// The method set of *T contains that of T,
// so a failed check of *T implies a failed check of T:
// one check per type is enough.
// A use is a type name (a declaration, a reference or an instantiation)
// or an expression whose type is T or *T.
// The pointer form is a type name which is the operand of a pointer type,
// like *conceal.Text, []*conceal.Text or *Secret[string].
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

	reported := make(map[levelReport]bool)
	for _, u := range c.collectUses(pass, shouldCheck) {
		c.emitLevelDiagnostics(pass, u, demanded, reported)
	}
}

// collectUses returns the configured safe types found in the analyzed package,
// each with the position of its first use, ordered by position.
// See [checker.runReliabilityLevels] for what a use is.
func (c *checker) collectUses(pass *analysis.Pass, shouldCheck func(token.Pos) bool) []typeUse {
	ptrIdents := pointerIdents(pass)

	// The first position of each configured safe type, by the form of its use.
	var firstValue, firstPtr typeutil.Map
	collectIdent := func(id *ast.Ident, t types.Type) {
		first := &firstValue
		if ptrIdents[id] {
			first = &firstPtr
		}
		c.collectType(shouldCheck, t, id.Pos(), first)
	}

	// Local type declarations.
	// A generic type is collected as its origin: there it is the type for any type argument.
	for id, obj := range pass.TypesInfo.Defs {
		if tn, ok := obj.(*types.TypeName); ok {
			collectIdent(id, tn.Type())
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
		collectIdent(id, tn.Type())
	}

	// Instances of generic types.
	// Instances of generic functions are not Named and are skipped.
	for id, inst := range pass.TypesInfo.Instances {
		collectIdent(id, inst.Type)
	}

	// Expressions of the type, even when the code never names it,
	// e.g. a result of a constructor.
	for expr, tv := range pass.TypesInfo.Types {
		if !tv.IsValue() {
			continue
		}
		if ptr, ok := types.Unalias(tv.Type).(*types.Pointer); ok {
			c.collectType(shouldCheck, ptr.Elem(), expr.Pos(), &firstPtr)
		} else {
			c.collectType(shouldCheck, tv.Type, expr.Pos(), &firstValue)
		}
	}

	return sortedUses(&firstValue, &firstPtr)
}

// pointerIdents returns the identifiers of type names which are the operand of a pointer type.
func pointerIdents(pass *analysis.Pass) map[*ast.Ident]bool {
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	res := make(map[*ast.Ident]bool)
	for star := range inspector.All[*ast.StarExpr](insp) {
		if id := typeIdent(star.X); id != nil {
			res[id] = true
		}
	}
	return res
}

// sortedUses merges the first positions of the value and pointer forms into uses:
// a type with a value form is a value use, the others are pointer uses.
func sortedUses(firstValue, firstPtr *typeutil.Map) []typeUse {
	var uses []typeUse
	for _, t := range firstValue.Keys() {
		uses = append(uses, typeUse{named: t.(*types.Named), pos: firstValue.At(t).(token.Pos)})
	}
	for _, t := range firstPtr.Keys() {
		if firstValue.At(t) == nil {
			uses = append(uses, typeUse{named: t.(*types.Named), pos: firstPtr.At(t).(token.Pos), viaPointer: true})
		}
	}
	slices.SortFunc(uses, func(a, b typeUse) int {
		return cmp.Or(
			cmp.Compare(a.pos, b.pos),
			strings.Compare(a.named.String(), b.named.String()),
		)
	})
	return uses
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
// for the given type use,
// unless the same diagnostic is already in reported.
func (c *checker) emitLevelDiagnostics(
	pass *analysis.Pass,
	use typeUse,
	demanded requires,
	reported map[levelReport]bool,
) {
	named := use.named
	cls := c.classify(named)
	satisfies := levelCheck(*cls, use.viaPointer)
	typeName := qualifiedName(named)
	if use.viaPointer {
		typeName = "*" + typeName
	}

	for _, d := range surfaces(demanded, satisfies) {
		// A revealing method fails the surface whatever other safeguards the type has.
		revealing := revealingServing(cls.revealing, d.servedBy)
		if !d.demand || d.satisfy && revealing == "" {
			continue
		}
		msg := "configured safe type " + typeName + " does not guarantee " + d.name
		if revealing != "" {
			msg += ": " + revealing + " outputs the secret"
		} else {
			msg += ": " + d.reason
			if !use.viaPointer {
				msg += ptrOnlyHint(cls.ptrOnly, d.methods)
			}
		}
		key := levelReport{origin: named.Origin().Obj(), msg: msg}
		if reported[key] {
			continue
		}
		reported[key] = true
		pass.Report(analysis.Diagnostic{Pos: use.pos, Message: msg})
	}
}

// surface is one reliability requirement and whether the type satisfies it.
type surface struct {
	demand, satisfy bool
	name, reason    string
	methods         []string // methods which would satisfy the surface
	servedBy        []string // methods which may output the secret on the surface
}

// surfaces lists the reliability requirements in the order of their diagnostics.
func surfaces(demanded, satisfies requires) []surface {
	return []surface{
		{
			demanded.marshalJSONSafe, satisfies.marshalJSONSafe,
			"JSON marshal safety",
			"the type neither implements encoding.TextMarshaler nor json.Marshaler, " +
				"and is not an opaque struct",
			[]string{methodMarshalJSON, methodMarshalText},
			[]string{methodMarshalJSON, methodMarshalText},
		},
		{
			demanded.marshalTextSafe, satisfies.marshalTextSafe,
			"text marshal safety",
			"the type does not implement encoding.TextMarshaler, " +
				"and is not an opaque String-level safe struct",
			[]string{methodMarshalText},
			// log/slog TextHandler falls back to %+v when there is no MarshalText.
			[]string{methodMarshalText, methodString, methodFormat},
		},
		{
			demanded.formatSafe, satisfies.formatSafe,
			"format-level safety",
			"the type does not implement fmt.Formatter and is not structurally protected",
			[]string{methodFormat},
			[]string{methodFormat},
		},
		{
			demanded.goStringSafe, satisfies.goStringSafe,
			"GoString-level safety",
			"the type does not implement fmt.GoStringer or fmt.Formatter, " +
				"and is not structurally protected",
			[]string{methodFormat, methodGoString},
			[]string{methodFormat, methodGoString},
		},
		{
			demanded.stringSafe, satisfies.stringSafe,
			"String-level safety",
			"the type does not implement fmt.Stringer or fmt.Formatter, " +
				"and is not structurally protected",
			[]string{methodFormat, methodString},
			[]string{methodFormat, methodString},
		},
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

// revealingServing returns the names of the methods in servedBy
// which are known to output the secret, joined by ", ".
func revealingServing(revealing map[string]bool, servedBy []string) string {
	var found []string
	for _, name := range servedBy {
		if revealing[name] {
			found = append(found, name)
		}
	}
	return strings.Join(found, ", ")
}
