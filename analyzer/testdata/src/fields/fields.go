package fields

import (
	"fakeconceal"
	"fakecamo"
	"fakelogfusc"
	"fakeplayground"
	"fakesecrecy"
	"fakesensitive"
	. "fakesensitive"
	fs "fakesensitive"
	"fieldsdep"
	"fmt"
)

// SomeStruct is a simple struct used as a type parameter.
type SomeStruct struct {
	s string
}

// inner is a struct containing a sensitive field, without fmt interfaces.
type inner struct {
	secret fakesensitive.String // want "is reachable through"
}

// exportedOK tests that exported fields of a sensitive type are NOT flagged.
type exportedOK struct {
	X fakesensitive.String
}

type directFakeSensitive struct {
	// An unexported field of a sensitive type should be flagged.
	x fakesensitive.String // want "is reachable through"
}

type directFakePlayground struct {
	x fakeplayground.String // want "is reachable through"
}

type directFakeLogfusc struct {
	x fakelogfusc.Secret[string] // want "is reachable through"
}

type directFakeSecrecy struct {
	x fakesecrecy.Secret[string] // want "is reachable through"
}

// SecretString is not itself a configured safe type, but its inner
// fakesecrecy.Secret[[]byte] field is — so the walk catches it transitively.
type directFakeSecrecyString struct {
	x fakesecrecy.SecretString // want "is reachable through"
}

// Slice variant.
type sliceField struct {
	xs []fakesensitive.String // want "is reachable through"
}

// Array variant.
type arrayField struct {
	xs [3]fakesensitive.String // want "is reachable through"
}

type notComparableField struct {
	x fakesensitive.NotComparable // want "is reachable through"
}

// A zero-length array holds no value, so fmt prints only [].
type zeroArrayField struct {
	xs [0]fakesensitive.String
}

// Pointer variant — *fakesensitive.String is *<non-compound>.
// Even under badVerb fmt never dereferences it — the address is printed.
type pointerField struct {
	px *fakesensitive.String // No diagnostic: *<non-compound> is safe under badVerb.
}

// Map key variant.
type mapKeyField struct {
	m map[fakesensitive.String]int // want "is reachable through"
}

// Map value variant.
type mapValueField struct {
	m map[int]fakesensitive.String // want "is reachable through"
}

// Chan variant — channels print address, not content, so no leak.
type chanField struct {
	ch chan fakesensitive.String
}

// RenamedImport tests detection with a renamed import alias.
type renamedImport struct {
	y fs.String // want "is reachable through"
}

// DotImport tests detection with a dot-import.
type dotImport struct {
	z String // want "is reachable through"
}

// NestedTransitive tests transitive detection: an unexported struct field
// whose type contains a sensitive field.
type middleInner struct {
	secret fakesensitive.String // want "is reachable through"
}

type nestedTransitive struct {
	inner middleInner // want "is reachable through"
}

// RecursiveNode tests that recursive types don't hang and still detect
// sensitive fields.
type RecursiveNode struct {
	next  *RecursiveNode // want "is reachable through"
	inner middleInner    // want "is reachable through"
}

// RecursiveSensitive tests that a recursive type WITH a sensitive field
// directly is still detected (no false negative from visited set).
type recursiveSensitive struct {
	self *recursiveSensitive  // want "is reachable through"
	x    fakesensitive.String // want "is reachable through"
}

// SecretExposerField — a field of a SecretExposer interface type (ExposeSecret method)
// is flagged when reachable under a disable factor:
// the concrete value's Formatter won't fire, and the content may leak.
type secretExposerField struct {
	s fakesensitive.Secret[string] // want "is reachable through"
}

// ExposerField — a user-defined named SecretExposer interface (not a configured safe type)
// is flagged the same way.
type exposer interface{ ExposeSecret() string }

type exposerField struct {
	e exposer // want "is reachable through"
}

// EmptyInterfaceField — any/interface{} is NOT flagged:
// the static analyzer cannot know what concrete type will be stored.
type emptyInterfaceField struct {
	v any // No diagnostic: empty interface, cannot determine if it holds sensitive data.
}

// ArbitraryInterfaceField — an arbitrary interface without ExposeSecret is NOT flagged,
// even when reachable under a disable factor, to avoid false positives from external
// library types that use interface fields for their own implementation.
type arbitraryInterfaceField struct {
	v interface{ Foo() } // No diagnostic: no ExposeSecret, not a secret container.
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
// AND other fields (int) is not structurally protected,
// yet nothing is reported: it has no fmt protection to disable.
type DoublePtrAndOtherField struct {
	x fakesensitive.DoublePtrAndOther[string] // No diagnostic: no fmt interfaces.
}

// CallbackField — Callback has a value-receiver String
// but its func field does not make it structurally protected,
// so the String method is the only protection and it is not guaranteed.
type CallbackField struct {
	x fakesensitive.Callback // want "is reachable through"
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
	x fakesensitive.Handle[SomeStruct] // want "is reachable through"
}

// HandleGenericNonCompound — Handle[T] where T is constrained to non-compound types.
// The *T inside Handle is always *<non-compound> → structurallySafe=true.
// No diagnostic expected even in an unexported field.
type HandleGenericNonCompound[T fakesensitive.NonCompound] struct {
	x fakesensitive.Handle[T] // No diagnostic: *TypeParam is non-compound by constraint.
}

// HandleGenericCompound — Handle[T] where T can be a compound type (SomeStruct).
// The *T inside Handle could be *<compound> → structurallySafe=false.
type HandleGenericCompound[T fakesensitive.CompoundOrPrimitive] struct {
	x fakesensitive.Handle[T] // want "is reachable through"
}

// HandleGenericAny — Handle[T] where T is unconstrained (any).
// The *T inside Handle can be anything → structurallySafe=false.
type HandleGenericAny[T any] struct {
	x fakesensitive.Handle[T] // want "is reachable through"
}

// FormatFuncWrapField — FormatFuncWrap holds a named func type, which fmt prints as an address.
type FormatFuncWrapField struct {
	x fakesensitive.FormatFuncWrap // No diagnostic: structurallySafe through a named func type.
}

// StarInnerExported — an exported *inner field: the pointer is
// non-Formatter, so badVerb may dereference it and the subtree is printed without methods.
// The walk reaches fakesensitive.String inside inner and reports a leak.
type StarInnerExported struct {
	M *inner // want "is reachable through"
}

// StarInnerUnexported — an unexported *inner field: methods are off
// because of the field itself AND because of the non-Formatter pointer.
// inner is *<compound> (a struct), so badVerb dereferences it.
// The safe type fakesensitive.String inside inner leaks.
type StarInnerUnexported struct {
	m *inner // want "is reachable through"
}

// WrapTPlayground is the playground reproducer:
// an unexported pointer to a struct whose field is a Formatter type.
// The non-Formatter pointer triggers badVerb, disabling interfaces,
// and the Formatter type's content leaks.
type WrapTPlayground struct {
	t *outerT // want "is reachable through"
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
	second fakesensitive.String // want "is reachable through"
}

// visitedCleanFirst tests that a type reached first via a clean path (exported field)
// is still walked when reached later via a dirty path (unexported field).
type visitedCleanFirst struct {
	M fieldsdep.MidCleanFirst // want "is reachable through"
}

// visitedDirtyFirst is the same as visitedCleanFirst with the opposite field order.
type visitedDirtyFirst struct {
	M fieldsdep.MidDirtyFirst // want "is reachable through"
}

// fmtWrapper redacts itself via fmt.Formatter, so it is a safe terminal.
type fmtWrapper struct {
	secret fakesensitive.String
}

func (fmtWrapper) Format(fmt.State, rune) {}

// FormatterWrapperClean — a named type with Format on a clean path is a safe terminal.
type FormatterWrapperClean struct {
	W fmtWrapper // No diagnostic: Format fires and overrides every verb.
}

// noFormatWrapper is the same as fmtWrapper without Format.
type noFormatWrapper struct {
	secret fakesensitive.String // want "is reachable through"
}

// NoFormatWrapperFlagged — a wrapper without Format is not a terminal.
type NoFormatWrapperFlagged struct {
	W noFormatWrapper // want "is reachable through"
}

// wrongSigWrapper has a Format method which is not fmt.Formatter.
type wrongSigWrapper struct {
	secret fakesensitive.String // want "is reachable through"
}

func (wrongSigWrapper) Format(int) {}

// WrongSigWrapperFlagged — Format with a wrong signature is not a terminal.
type WrongSigWrapperFlagged struct {
	W wrongSigWrapper // want "is reachable through"
}

// ptrFmtWrapper has Format only on the pointer receiver.
type ptrFmtWrapper struct {
	secret fakesensitive.String // want "is reachable through"
}

func (*ptrFmtWrapper) Format(fmt.State, rune) {}

// PtrFmtWrapperFlagged — fmt never calls a pointer-only Format on a value.
type PtrFmtWrapperFlagged struct {
	W ptrFmtWrapper // want "is reachable through"
}

// UnexportedPtrFmtWrapper — under an unexported field Format of a pointer does not fire either.
type UnexportedPtrFmtWrapper struct {
	p *ptrFmtWrapper // want "is reachable through"
}

// UnexportedFmtWrapper — under an unexported field Format does not fire.
type UnexportedFmtWrapper struct {
	w fmtWrapper // want "is reachable through"
}

// fmtWrapperHolder is a plain struct holding a Formatter wrapper.
type fmtWrapperHolder struct {
	W fmtWrapper
}

// FmtWrapperBehindPointer — a non-Formatter pointer disables Format of the pointee's fields.
type FmtWrapperBehindPointer struct {
	P *fmtWrapperHolder // want "is reachable through"
}

// fmtNestedWrapper — anonymous structs nested in a Formatter type are reachable only through it.
type fmtNestedWrapper struct {
	Inner struct {
		s fakesensitive.String // No diagnostic: covered by fmtNestedWrapper.Format.
	}
}

func (fmtNestedWrapper) Format(fmt.State, rune) {}

// fmtSliceWrapper — the same holds for a non-struct Formatter type.
type fmtSliceWrapper []struct {
	s fakesensitive.String // No diagnostic: covered by fmtSliceWrapper.Format.
}

func (fmtSliceWrapper) Format(fmt.State, rune) {}

// plainTarget holds nothing sensitive, so a pointer to it leaks nothing.
type plainTarget struct{ X int }

// staleFactorHolder — the leak is behind the unexported field s, not behind the pointer P,
// so the reason must not be taken from the pointer walked before s.
type staleFactorHolder struct {
	P *plainTarget
	s fakesensitive.String // want `sensitive field "s" is reachable through an unexported field "s"`
}

// StaleFactorOuter checks the reason reported for a field which reaches staleFactorHolder.
type StaleFactorOuter struct {
	H staleFactorHolder // want `sensitive field "H" is reachable through an unexported field "s"`
}

// staleFactorLeaf is the value of StaleFactorMap.
type staleFactorLeaf struct {
	s fakesensitive.String // want `sensitive field "s" is reachable through an unexported field "s"`
}

// StaleFactorMap — a pointer in the map key leaks nothing and must not hide the reason in the value.
type StaleFactorMap struct {
	M map[*plainTarget]staleFactorLeaf // want `sensitive field "M" is reachable through an unexported field "s"`
}

// Local types with the same name in different functions are different types,
// so their instances of a safe type are classified separately.
func localSafeK() {
	type k string
	type s struct {
		x fakesensitive.Handle[k] // No diagnostic: *k is *<non-compound>.
	}
	_ = s{}
}

func localLeakK() {
	type k struct{ v string }
	type s struct {
		x fakesensitive.Handle[k] // want "is reachable through"
	}
	_ = s{}
}

// A pointer directly to a safe type is judged by the method set of *T:
// on a clean path its methods fire, on an unexported path they are disabled.

type PtrSecrecyExported struct {
	X *fakesecrecy.Secret[string] // No diagnostic: *T's String fires on a clean path.
}

type ptrSecrecyUnexported struct {
	x *fakesecrecy.Secret[string] // want "is reachable through"
}

type PtrConcealExported struct {
	X *fakeconceal.Text // No diagnostic: *T's String fires on a clean path.
}

type ptrConcealUnexported struct {
	x *fakeconceal.Text // want "is reachable through"
}

type PtrConcealBytesExported struct {
	X *fakeconceal.Bytes // No diagnostic: *T's String fires on a clean path.
}

type ptrConcealBytesUnexported struct {
	x *fakeconceal.Bytes // want "is reachable through"
}

// T itself has no fmt methods: there is no protection to disable,
// -sensitive.require-* reports it.
type valueConcealUnexported struct {
	x fakeconceal.Text
}

// badVerb dereferences only the pointer which caused it,
// so a pointer nested in the pointee prints as an address.
type PtrToHolderOfConceal struct {
	H *holderOfConceal // No diagnostic: S prints as an address.
}

type holderOfConceal struct {
	S *fakeconceal.Text
}

type ptrToHolderOfConcealUnexported struct {
	h *holderOfConceal // No diagnostic: the same after an unexported field.
}

// A nested pointer to a holder with a leaking value prints as an address too:
// P is reported at its own declaration, but not through H.
type PtrToPtrToInner struct {
	H *ptrToInnerHolder // No diagnostic: P prints as an address.
}

type ptrToInnerHolder struct {
	P *inner // want "is reachable through"
}

// A defined pointer type has no methods,
// so fmt calls neither the methods of *T nor Format of the pointee through it.
type ptrToSecrecy *fakesecrecy.Secret[string]

type NamedPtrToSecrecy struct {
	X ptrToSecrecy // want "is reachable through a non-Formatter pointer"
}

type ptrToConceal *fakeconceal.Text

type NamedPtrToConceal struct {
	X ptrToConceal // want "is reachable through a non-Formatter pointer"
}

type ptrToPtrFmtWrapper *ptrFmtWrapper

type NamedPtrToPtrFmtWrapper struct {
	P ptrToPtrFmtWrapper // want "is reachable through a non-Formatter pointer"
}

type ptrToString *fakesensitive.String

type NamedPtrToNonCompound struct {
	X ptrToString // No diagnostic: badVerb does not dereference a pointer to a string kind.
}

// Structurally protected once the hash field of fakecamo.Secret is ignored,
// so disabling fmt methods has nothing to weaken.
type camoUnexported struct {
	x fakecamo.Secret[string]
}

// Unlisted keeps its hash field in the check, so it is not structurally protected,
// but it has no fmt methods either:
// there is nothing to disable, -sensitive.require-* reports it.
type camoUnlistedUnexported struct {
	x fakecamo.Unlisted
}
