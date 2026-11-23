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

type CheckSinglePtr struct {
	X fakesensitive.SinglePtr[struct{ a int }] // want "configured safe type fakesensitive.SinglePtr does not guarantee GoString-level safety"
}

// Wrong-signature decoys and pointer-receiver-only methods do not count.

type CheckDecoy struct {
	X fakesensitive.Decoy // want "configured safe type fakesensitive.Decoy does not guarantee GoString-level safety"
}

type CheckPtrRecv struct {
	X fakesensitive.PtrRecv // want "configured safe type fakesensitive.PtrRecv does not guarantee GoString-level safety"
}
