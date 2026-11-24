package analyzer

import "go/types"

// Names of the fmt/encoding interface methods the analyzer relies on.
const (
	methodFormat      = "Format"
	methodString      = "String"
	methodError       = "Error"
	methodGoString    = "GoString"
	methodMarshalJSON = "MarshalJSON"
	methodMarshalText = "MarshalText"
)

// methodShape returns a predicate for the signature of the fmt/encoding interface method
// with the given name.
// The check is structural (no stdlib interface resolution),
// so a same-named method with another signature is not mistaken for the interface method.
// The second result is false for an unknown name.
func methodShape(name string) (func(*types.Signature) bool, bool) {
	switch name {
	case methodFormat:
		return isFormatSig, true
	case methodString, methodGoString, methodError:
		return isNoArgsResult(types.Typ[types.String]), true
	case methodMarshalJSON, methodMarshalText:
		return isMarshalSig, true
	default:
		return nil, false
	}
}

// isFormatSig reports whether sig is func(fmt.State, rune).
func isFormatSig(sig *types.Signature) bool {
	if sig.Params().Len() != 2 || sig.Results().Len() != 0 || sig.Variadic() {
		return false
	}
	state, ok := types.Unalias(sig.Params().At(0).Type()).(*types.Named)
	if !ok || state.Obj().Pkg() == nil ||
		state.Obj().Pkg().Path() != "fmt" || state.Obj().Name() != "State" {
		return false
	}
	return types.Identical(sig.Params().At(1).Type(), types.Typ[types.Int32])
}

// isNoArgsResult returns a predicate for func() <result>.
func isNoArgsResult(result types.Type) func(*types.Signature) bool {
	return func(sig *types.Signature) bool {
		return sig.Params().Len() == 0 && sig.Results().Len() == 1 &&
			types.Identical(sig.Results().At(0).Type(), result)
	}
}

// isMarshalSig reports whether sig is func() ([]byte, error).
func isMarshalSig(sig *types.Signature) bool {
	if sig.Params().Len() != 0 || sig.Results().Len() != 2 {
		return false
	}
	return types.Identical(sig.Results().At(0).Type(), types.NewSlice(types.Typ[types.Byte])) &&
		types.Identical(sig.Results().At(1).Type(), types.Universe.Lookup("error").Type())
}

// hasMethod reports whether the method set of t contains a method
// with the given name and the signature of the corresponding fmt/encoding interface method.
// The method set is taken as is, so for a non-pointer t
// methods declared on *t are not counted:
// fmt and encoding/json never call them on a non-addressable value.
// Promoted value-receiver methods are part of the method set of both t and *t.
func (c *checker) hasMethod(t types.Type, name string) bool {
	hasShape, known := methodShape(name)
	if !known {
		return false
	}
	for method := range c.msets.MethodSet(t).Methods() {
		if method.Obj().Name() != name {
			continue
		}
		sig, ok := method.Type().(*types.Signature)
		if ok && hasShape(sig) {
			return true
		}
	}
	return false
}

// ptrOnlyMethods returns the names of the fmt/encoding interface methods
// which are in the method set of *t but not of t.
func (c *checker) ptrOnlyMethods(t types.Type) map[string]bool {
	ptr := types.NewPointer(t)
	res := make(map[string]bool)
	for _, name := range [...]string{methodFormat, methodString, methodGoString, methodMarshalJSON, methodMarshalText} {
		if !c.hasMethod(t, name) && c.hasMethod(ptr, name) {
			res[name] = true
		}
	}
	return res
}

// isSecretExposer reports whether t is a SecretExposer interface —
// an interface that declares an ExposeSecret method.
// This is the convention used by github.com/powerman/sensitive.Secret[T]
// and github.com/negrel/secrecy.SecretExposer[T].
// The check is by method name only; the exact return type is not verified.
func (matcher) isSecretExposer(t *types.Interface) bool {
	for method := range t.Methods() {
		if method.Name() == "ExposeSecret" {
			return true
		}
	}
	return false
}
