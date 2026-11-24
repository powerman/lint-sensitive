package reliability_gostring

import (
	"fakesensitive"
	"fakesecrecy"
)

// fakesecrecy.Secret has GoString → passes GoString-level safety.
// fakesensitive.String has fmt.Formatter → passes GoString-level safety.
// fakesensitive.SinglePtr has no fmt interfaces and *struct{ a int }
// is not structurally safe (*<compound>), so it fails GoString-level safety.
//
// Fields are EXPORTED to avoid field-walk diagnostic.

type CheckSecret struct {
	X fakesecrecy.Secret[string]
}

type CheckString struct {
	X fakesensitive.String
}

// The instance has *string, a *<non-compound>, so it passes GoString-level safety.
type CheckSinglePtrString struct {
	X fakesensitive.SinglePtr[string]
}

type CheckSinglePtr struct {
	X fakesensitive.SinglePtr[struct{ a int }] // want "configured safe type fakesensitive.SinglePtr does not guarantee GoString-level safety"
}

// Wrong-signature decoys and pointer-receiver-only methods do not count.

type CheckDecoy struct {
	X fakesensitive.Decoy // want "configured safe type fakesensitive.Decoy does not guarantee GoString-level safety"
}

type CheckPtrRecv struct {
	X fakesensitive.PtrRecv // want "configured safe type fakesensitive.PtrRecv does not guarantee GoString-level safety.*declared only on a pointer receiver.*: Format, GoString\\)"
}

// The type has a value-receiver GoString method, so it passes GoString-level safety.
type CheckNotComparable struct {
	X fakesensitive.NotComparable
}
