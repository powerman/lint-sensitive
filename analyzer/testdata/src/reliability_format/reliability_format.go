package reliability_format

import (
	"fakesensitive"
	"fakesecrecy"
)

// Type that fails format-level safety (no fmt.Formatter, no structural protection).
// Field is EXPORTED to avoid field-walk diagnostic.
type CheckSecret struct {
	X fakesecrecy.Secret[string] // want "configured safe type fakesecrecy.Secret does not guarantee format-level safety"
}

// Type that PASSES format-level safety (has fmt.Formatter).
type CheckString struct {
	X fakesensitive.String
}

// Type that PASSES format-level safety (structurally safe via **T).
type CheckRef struct {
	X fakesensitive.Ref[string]
}

// Type that PASSES format-level safety: the instance has *string, a *<non-compound>.
type CheckSinglePtrString struct {
	X fakesensitive.SinglePtr[string]
}

// Type that fails format-level safety: the instance has *struct{ a int }, a *<compound>.
type CheckSinglePtrStruct struct {
	X fakesensitive.SinglePtr[struct{ a int }] // want "configured safe type fakesensitive.SinglePtr does not guarantee format-level safety"
}

// Wrong-signature decoys and pointer-receiver-only methods do not count.

type CheckDecoy struct {
	X fakesensitive.Decoy // want "configured safe type fakesensitive.Decoy does not guarantee format-level safety"
}

type CheckPtrRecv struct {
	X fakesensitive.PtrRecv // want "configured safe type fakesensitive.PtrRecv does not guarantee format-level safety.*declared only on a pointer receiver.*: Format\\)"
}

// Types that PASS format-level safety: the qualifier is behind a named type
// or nested in an anonymous struct or array.

type CheckNamedFuncWrap struct {
	X fakesensitive.NamedFuncWrap
}

type CheckNestedRef struct {
	X fakesensitive.NestedRef
}

type CheckArrayRef struct {
	X fakesensitive.ArrayRef
}
