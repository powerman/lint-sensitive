package fields

import (
	"fakesensitive"
	"fakeplayground"
	"fakelogfusc"
	"fakesecrecy"
	fs "fakesensitive"
	. "fakesensitive"
)

// exportedOK tests that exported fields of a sensitive type are NOT flagged.
type exportedOK struct {
	X fakesensitive.String
}

type directFakeSensitive struct {
	// An unexported field of a sensitive type should be flagged.
	x fakesensitive.String // want "sensitive value in unexported field \"x\" is leaked by fmt"
}

type directFakePlayground struct {
	x fakeplayground.String // want "sensitive value in unexported field \"x\" is leaked by fmt"
}

type directFakeLogfusc struct {
	x fakelogfusc.Secret[string] // want "sensitive value in unexported field \"x\" is leaked by fmt"
}

type directFakeSecrecy struct {
	x fakesecrecy.Secret[string] // want "sensitive value in unexported field \"x\" is leaked by fmt"
}

type directFakeSecrecyString struct {
	x fakesecrecy.SecretString // want "sensitive value in unexported field \"x\" is leaked by fmt"
}

// Slice variant.
type sliceField struct {
	xs []fakesensitive.String // want "sensitive value in unexported field \"xs\" is leaked by fmt"
}

// Array variant.
type arrayField struct {
	xs [3]fakesensitive.String // want "sensitive value in unexported field \"xs\" is leaked by fmt"
}

// Pointer variant.
type pointerField struct {
	px *fakesensitive.String // want "sensitive value in unexported field \"px\" is leaked by fmt"
}

// Map key variant.
type mapKeyField struct {
	m map[fakesensitive.String]int // want "sensitive value in unexported field \"m\" is leaked by fmt"
}

// Map value variant.
type mapValueField struct {
	m map[int]fakesensitive.String // want "sensitive value in unexported field \"m\" is leaked by fmt"
}

// Chan variant.
type chanField struct {
	ch chan fakesensitive.String // want "sensitive value in unexported field \"ch\" is leaked by fmt"
}

// RenamedImport tests detection with a renamed import alias.
type renamedImport struct {
	y fs.String // want "sensitive value in unexported field \"y\" is leaked by fmt"
}

// DotImport tests detection with a dot-import.
type dotImport struct {
	z String // want "sensitive value in unexported field \"z\" is leaked by fmt"
}

// NestedTransitive tests transitive detection: an unexported struct field
// whose type contains a sensitive field.
type middleInner struct {
	secret fakesensitive.String // want "sensitive value in unexported field \"secret\" is leaked by fmt"
}

type nestedTransitive struct {
	inner middleInner // want "sensitive value in unexported field \"inner\" is leaked by fmt"
}

// RecursiveNode tests that recursive types don't hang and still detect
// sensitive fields.
type RecursiveNode struct {
	next  *RecursiveNode // want "sensitive value in unexported field \"next\" is leaked by fmt"
	inner middleInner    // want "sensitive value in unexported field \"inner\" is leaked by fmt"
}

// RecursiveSensitive tests that a recursive type WITH a sensitive field
// directly is still detected (no false negative from visited set).
type recursiveSensitive struct {
	self *recursiveSensitive // want "sensitive value in unexported field \"self\" is leaked by fmt"
	x    fakesensitive.String // want "sensitive value in unexported field \"x\" is leaked by fmt"
}

// InterfaceField tests that interface-typed unexported fields are NOT
// flagged (cannot prove statically).
type ifaceField struct {
	v any
}

// OrderIndependent tests that detection works regardless of field order.
type orderIndependent struct {
	First  int
	second fakesensitive.String // want "sensitive value in unexported field \"second\" is leaked by fmt"
}
