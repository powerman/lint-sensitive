package reliability_marshal_text

import (
	"fakecamo"
	"fakesensitive"
	"fakesecrecy"
)

// A configured safe type fails text marshal safety
// unless it implements encoding.TextMarshaler or is an opaque String-level safe struct.
//
// Fields are EXPORTED to avoid field-walk diagnostic.

type CheckString struct {
	X fakesensitive.String // want "configured safe type fakesensitive.String does not guarantee text marshal safety"
}

// The fakes below are opaque structs which are String-level safe.

type CheckSecret struct {
	X fakesecrecy.Secret[string]
}

type CheckRef struct {
	X fakesensitive.Ref[string]
}

// Wrong-signature decoys and pointer-receiver-only methods do not count.

type CheckDecoy struct {
	X fakesensitive.Decoy // want "configured safe type fakesensitive.Decoy does not guarantee text marshal safety"
}

type CheckPtrRecv struct {
	X fakesensitive.PtrRecv // want "configured safe type fakesensitive.PtrRecv does not guarantee text marshal safety.*declared only on a pointer receiver.*: MarshalText\\)"
}

// fakecamo.Secret has no marshalers, but it is an opaque struct and structurally protected.

type CheckCamo struct {
	X fakecamo.Secret[string]
}

// An opaque struct which is not String-level safe is written by log/slog TextHandler with %+v.

type CheckOpaque struct {
	X fakesensitive.Opaque
}

type CheckOpaqueBare struct {
	X fakesensitive.OpaqueBare // want "configured safe type fakesensitive.OpaqueBare does not guarantee text marshal safety: .*not an opaque String-level safe struct"
}

type CheckEmbedsExported struct {
	X fakesensitive.EmbedsExported // want "configured safe type fakesensitive.EmbedsExported does not guarantee text marshal safety: .*not an opaque String-level safe struct"
}

type CheckExportedField struct {
	X fakesensitive.ExportedField // want "configured safe type fakesensitive.ExportedField does not guarantee text marshal safety: .*not an opaque String-level safe struct"
}
