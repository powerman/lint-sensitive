package reliability_string

import (
	"fakesensitive"
	"fakesecrecy"
)

// fakesecrecy.Secret has String → passes String-level safety.
// fakesensitive.String has fmt.Formatter → passes String-level safety.
// fakesensitive.SinglePtr has no fmt interfaces and *struct{ a int }
// is not structurally safe (*<compound>), so it fails String-level safety.
//
// Fields are EXPORTED to avoid field-walk diagnostic.

type CheckSecret struct {
	X fakesecrecy.Secret[string]
}

type CheckString struct {
	X fakesensitive.String
}

// The instance has *string, a *<non-compound>, so it passes String-level safety.
type CheckSinglePtrString struct {
	X fakesensitive.SinglePtr[string]
}

type CheckSinglePtr struct {
	X fakesensitive.SinglePtr[struct{ a int }] // want "configured safe type fakesensitive.SinglePtr does not guarantee String-level safety"
}

// *Label (named string) prints as an address, so PtrToLabel is structurally safe;
// *SomeCompound (named struct) is dereferenced by fmt, so PtrToCompound is not.

type CheckPtrToLabel struct {
	X fakesensitive.PtrToLabel
}

type CheckPtrToCompound struct {
	X fakesensitive.PtrToCompound // want "configured safe type fakesensitive.PtrToCompound does not guarantee String-level safety"
}

// Wrong-signature decoys and pointer-receiver-only methods do not count.

type CheckDecoy struct {
	X fakesensitive.Decoy // want "configured safe type fakesensitive.Decoy does not guarantee String-level safety"
}

type CheckPtrRecv struct {
	X fakesensitive.PtrRecv // want "configured safe type fakesensitive.PtrRecv does not guarantee String-level safety.*declared only on a pointer receiver.*: Format, String\\)"
}
