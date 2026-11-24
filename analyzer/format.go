package analyzer

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/types"
	"slices"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/analysis/passes/printf"
	"golang.org/x/tools/go/ast/inspector"
	"golang.org/x/tools/go/types/typeutil"
)

// newFormatAnalyzer creates a format analyzer with the given dependencies and matcher provider.
func newFormatAnalyzer(requires []*analysis.Analyzer, get matcherFunc) *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:     "sensitivefmt",
		Doc:      "detect calls of print functions which print the content of a sensitive value",
		Requires: append(slices.Clone(requires), printf.Analyzer),
		Run: func(pass *analysis.Pass) (any, error) {
			m, err := get(pass)
			if err != nil {
				return nil, err
			}
			return runFormat(pass, m)
		},
	}
}

// printedArg is an argument of a call together with the verb fmt prints it with.
type printedArg struct {
	expr ast.Expr
	typ  types.Type
	idx  int // Index among the arguments of the call, with a tuple expanded.
	verb fmtVerb
}

// runFormat is the shared core used by both flag-driven and New()-based format analyzers.
func runFormat(pass *analysis.Pass, m matcher) (any, error) {
	inspectResult := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	printfResult := pass.ResultOf[printf.Analyzer].(*printf.Result)

	c := newChecker(m)
	shouldCheck := m.newShouldCheck(pass)
	for call := range inspector.All[*ast.CallExpr](inspectResult) {
		if !shouldCheck(call.Pos()) {
			continue
		}
		reported := make(map[int]bool) // One diagnostic per argument.
		for _, arg := range printedArgs(pass, printfResult, call) {
			if !reported[arg.idx] && c.checkPrinted(pass, arg) {
				reported[arg.idx] = true
			}
		}
	}

	//nolint:nilnil // Returning nil, nil is standard for go/analysis analyzers.
	return nil, nil
}

// checkPrinted reports the argument if fmt prints the content of a safe type through it.
func (c *checker) checkPrinted(pass *analysis.Pass, arg printedArg) bool {
	var path []walkStep
	leaks, factor := c.leaksAsArg(arg.typ, arg.verb, &path)
	if !leaks {
		return false
	}
	pass.Report(analysis.Diagnostic{
		Pos:     arg.expr.Pos(),
		Message: printedDiagnostic(arg.typ, arg.verb, factor, path),
		Related: relatedInformation(pass.Fset, path),
	})
	return true
}

// printedDiagnostic builds the diagnostic message for a value of type t
// whose safe type leaks when printed with verb.
func printedDiagnostic(t types.Type, verb fmtVerb, factor *disableFactor, path []walkStep) string {
	msg := fmt.Sprintf("sensitive value of type %s printed with %s exposes the secret", shortTypeString(t), verb)
	if len(path) > 0 {
		if safe, ok := strings.CutPrefix(path[0].desc, "safe type "); ok {
			msg += " of safe type " + safe
		}
	}
	switch factor.kind {
	case factorUnexportedField:
		msg += fmt.Sprintf(" through an unexported field %q", factor.name)
	case factorNonFormatterPointer:
		msg += fmt.Sprintf(" through a pointer to %s", factor.name)
	}
	return msg
}

// String returns the verb as it is written in a format string, e.g. %#v.
func (v fmtVerb) String() string {
	if v.sharp {
		return "%#" + string(v.verb)
	}
	return "%" + string(v.verb)
}

// printedArgs returns the arguments of call which a print function prints
// with the verbs of the format string,
// or nil if call is not such a call or its arguments cannot be matched statically.
func printedArgs(pass *analysis.Pass, res *printf.Result, call *ast.CallExpr) []printedArg {
	if call.Ellipsis.IsValid() { // Arguments are forwarded as a slice.
		return nil
	}
	fn, ok := typeutil.Callee(pass.TypesInfo, call).(*types.Func)
	if !ok {
		return nil
	}
	kind := res.Kind(fn)
	if fn.FullName() == "fmt.Errorf" { // Kind reports it as KindPrintf.
		kind = printf.KindErrorf
	}
	sig, ok := fn.Type().(*types.Signature)
	if kind == printf.KindNone || !ok || !sig.Variadic() {
		return nil
	}
	argsIdx := sig.Params().Len() - 1 // The variadic parameter.
	all := callArgs(pass, call)
	if len(all) < argsIdx {
		return nil
	}
	if kind == printf.KindPrint {
		args := all[argsIdx:]
		for i := range args {
			args[i].verb = fmtVerb{verb: 'v'}
		}
		return args
	}

	formatIdx := argsIdx - 1
	if formatIdx < 0 {
		return nil
	}
	// The format which is a result of a tuple call is not a constant.
	tv := pass.TypesInfo.Types[all[formatIdx].expr]
	if tv.Value == nil || tv.Value.Kind() != constant.String {
		return nil
	}
	args := all[formatIdx+1:]
	var res2 []printedArg
	for _, op := range parseFormat(constant.StringVal(tv.Value)) {
		// %w is an error of vet outside of Errorf, and fmt prints it with badVerb there.
		if op.arg >= len(args) || op.verb == 'w' && kind != printf.KindErrorf {
			continue
		}
		arg := args[op.arg]
		arg.verb = fmtVerb{verb: op.verb, sharp: op.sharp}
		res2 = append(res2, arg)
	}
	return res2
}

// callArgs returns the arguments of call with their types.
// A call of a function with several results, which can only be the sole argument,
// is expanded into its results, all of them at the position of that call.
func callArgs(pass *analysis.Pass, call *ast.CallExpr) []printedArg {
	if len(call.Args) == 1 {
		if tuple, ok := pass.TypesInfo.TypeOf(call.Args[0]).(*types.Tuple); ok {
			res := make([]printedArg, tuple.Len())
			for i := range res {
				res[i] = printedArg{expr: call.Args[0], typ: tuple.At(i).Type(), idx: i}
			}
			return res
		}
	}
	res := make([]printedArg, len(call.Args))
	for i, expr := range call.Args {
		res[i] = printedArg{expr: expr, typ: pass.TypesInfo.TypeOf(expr), idx: i}
	}
	return res
}
