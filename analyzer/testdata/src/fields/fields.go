package fields

import (
	"fakelogfusc"
	"fakeplayground"
	"fakesecrecy"
	"fakesensitive"
	. "fakesensitive"
	fs "fakesensitive"
)

// SomeStruct is a simple struct used as a type parameter.
type SomeStruct struct {
	s string
}

// inner is a struct containing a sensitive field, without fmt interfaces.
type inner struct {
	secret fakesensitive.String // want "is reachable behind a"
}

// exportedOK tests that exported fields of a sensitive type are NOT flagged.
type exportedOK struct {
	X fakesensitive.String
}

type directFakeSensitive struct {
	// An unexported field of a sensitive type should be flagged.
	x fakesensitive.String // want "is reachable behind a"
}

type directFakePlayground struct {
	x fakeplayground.String // want "is reachable behind a"
}

type directFakeLogfusc struct {
	x fakelogfusc.Secret[string] // want "is reachable behind a"
}

type directFakeSecrecy struct {
	x fakesecrecy.Secret[string] // want "is reachable behind a"
}

// SecretString is not itself a configured safe type, but its inner
// fakesecrecy.Secret[[]byte] field is — so the walk catches it transitively.
type directFakeSecrecyString struct {
	x fakesecrecy.SecretString // want "is reachable behind a"
}

// Slice variant.
type sliceField struct {
	xs []fakesensitive.String // want "is reachable behind a"
}

// Array variant.
type arrayField struct {
	xs [3]fakesensitive.String // want "is reachable behind a"
}

// Pointer variant — *fakesensitive.String is *<non-compound>.
// Even under badVerb fmt never dereferences it — the address is printed.
type pointerField struct {
	px *fakesensitive.String // No diagnostic: *<non-compound> is safe under badVerb.
}

// Map key variant.
type mapKeyField struct {
	m map[fakesensitive.String]int // want "is reachable behind a"
}

// Map value variant.
type mapValueField struct {
	m map[int]fakesensitive.String // want "is reachable behind a"
}

// Chan variant — channels print address, not content, so no leak.
type chanField struct {
	ch chan fakesensitive.String
}

// RenamedImport tests detection with a renamed import alias.
type renamedImport struct {
	y fs.String // want "is reachable behind a"
}

// DotImport tests detection with a dot-import.
type dotImport struct {
	z String // want "is reachable behind a"
}

// NestedTransitive tests transitive detection: an unexported struct field
// whose type contains a sensitive field.
type middleInner struct {
	secret fakesensitive.String // want "is reachable behind a"
}

type nestedTransitive struct {
	inner middleInner // want "is reachable behind a"
}

// RecursiveNode tests that recursive types don't hang and still detect
// sensitive fields.
type RecursiveNode struct {
	next  *RecursiveNode // want "is reachable behind a"
	inner middleInner    // want "is reachable behind a"
}

// RecursiveSensitive tests that a recursive type WITH a sensitive field
// directly is still detected (no false negative from visited set).
type recursiveSensitive struct {
	self *recursiveSensitive  // want "is reachable behind a"
	x    fakesensitive.String // want "is reachable behind a"
}

// InterfaceField — interface-typed field is conservatively flagged
// when reachable under a disable factor because the dynamic value
// could be a safe type that would leak.
type ifaceField struct {
	v any // want "is reachable behind a"
}

// RefField tests that a Ref[T] struct field (double-pointer-backed)
// is NOT flagged as a leak — fmt reflection cannot reach the value.
type RefField struct {
	x fakesensitive.Ref[string] // No diagnostic: Ref is reflection-proof.
}

// SinglePtrStringField — SinglePtr[string] has *string (a *<non-compound>)
// which provides structural protection (structurallySafe=true).
// SinglePtr has no fmt interfaces so it does not flag unconditionally;
// a reliability check would also see it as safe.
type SinglePtrStringField struct {
	x fakesensitive.SinglePtr[string] // No diagnostic: structurallySafe, no fmt interfaces.
}

// SinglePtrStructField — SinglePtr[SomeStruct] has *SomeStruct
// (a *<compound>), so structurallySafe=false. SinglePtr has no fmt
// interfaces, so the unconditional check does not flag it.
// A reliability check would flag this as needing explicit fmt interfaces.
type SinglePtrStructField struct {
	x fakesensitive.SinglePtr[SomeStruct] // No diagnostic: reliability check territory (no fmt interfaces).
}

// FuncWrapField — FuncWrap implements no fmt interfaces,
// so there is no interface to disable.
type FuncWrapField struct {
	x fakesensitive.FuncWrap[string] // No diagnostic: no fmt interfaces.
}

// ChanWrapField — ChanWrap implements no fmt interfaces.
type ChanWrapField struct {
	x fakesensitive.ChanWrap[string] // No diagnostic: no fmt interfaces.
}

// DoublePtrAndOtherField tests that a struct with a double-pointer field
// AND other fields (int) is NOT flagged — the double-pointer field is
// assumed to hold the secret.
type DoublePtrAndOtherField struct {
	x fakesensitive.DoublePtrAndOther[string] // No diagnostic: has **T field.
}

// HandlePrimitiveField — Handle[string] has *string which is *<non-compound>,
// providing structural protection (structurallySafe=true).
// Even under a disabled path the content is safe.
type HandlePrimitiveField struct {
	x fakesensitive.Handle[string] // No diagnostic: structurallySafe.
}

// HandleStructField — Handle[SomeStruct] has *SomeStruct which is
// *<compound>, so structurallySafe=false. Under a disabled path
// the Format interface is bypassed and content leaks.
type HandleStructField struct {
	x fakesensitive.Handle[SomeStruct] // want "is reachable behind a"
}

// StarInnerExported — an exported *inner field: the pointer is
// non-Formatter, so bp=true, disabling interfaces for the subtree.
// The walk reaches fakesensitive.String inside inner and reports a leak.
type StarInnerExported struct {
	M *inner // want "is reachable behind a"
}

// StarInnerUnexported — an unexported *inner field: fd=true from
// the field itself AND bp=true from the non-Formatter pointer.
// inner is *<compound> (a struct), so badVerb dereferences it.
// The safe type fakesensitive.String inside inner leaks.
type StarInnerUnexported struct {
	m *inner // want "is reachable behind a"
}

// WrapTPlayground is the playground reproducer:
// an unexported pointer to a struct whose field is a Formatter type.
// The non-Formatter pointer triggers badVerb, disabling interfaces,
// and the Formatter type's content leaks.
type WrapTPlayground struct {
	t *outerT // want "is reachable behind a"
}

type outerT struct {
	Secret fakesensitive.String
}

// StarStringClean — *fakesensitive.String on a clean (exported, no non-Formatter pointer)
// path: the promoted value-receiver Format method is available on *String,
// so handleMethods fires it before badVerb could trigger, making this a safe terminal.
type StarStringClean struct {
	P *fakesensitive.String // No diagnostic: clean path, promoted Format fires safely.
}

// orderIndependent tests that detection works regardless of field order.
type orderIndependent struct {
	First  int
	second fakesensitive.String // want "is reachable behind a"
}
