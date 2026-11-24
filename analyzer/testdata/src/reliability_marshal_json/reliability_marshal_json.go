package reliability_marshal_json

import (
	"fakecamo"
	"fakesensitive"
	"fakesecrecy"
	"fakelogfusc"
)

// A configured safe type fails JSON safety
// unless it implements encoding.TextMarshaler or json.Marshaler or is an opaque struct.
//
// Fields are EXPORTED so the field walk does NOT produce a diagnostic
// (exported fields do not disable fmt interfaces).

type CheckString struct {
	X fakesensitive.String // want "configured safe type fakesensitive.String does not guarantee JSON marshal safety"
}

// The fakes below are opaque structs: encoding/json writes them empty.

type CheckSecret struct {
	X fakesecrecy.Secret[string]
}

type CheckLogfusc struct {
	X fakelogfusc.Secret[string]
}

type CheckRef struct {
	X fakesensitive.Ref[string]
}

// Wrong-signature decoys and pointer-receiver-only methods do not count.

type CheckDecoy struct {
	X fakesensitive.Decoy // want "configured safe type fakesensitive.Decoy does not guarantee JSON marshal safety"
}

type CheckPtrRecv struct {
	X fakesensitive.PtrRecv // want "configured safe type fakesensitive.PtrRecv does not guarantee JSON marshal safety.*declared only on a pointer receiver.*: MarshalJSON, MarshalText\\)"
}

// fakecamo.Secret has no marshalers, but it is an opaque struct.

type CheckCamo struct {
	X fakecamo.Secret[string]
}

// Opaque structs are safe whatever methods they have.
// Exported fields, including those promoted from an embedded struct, are not opaque.

type CheckOpaque struct {
	X fakesensitive.Opaque
	Y fakesensitive.OpaqueBare
}

type CheckEmbedsExported struct {
	X fakesensitive.EmbedsExported // want "configured safe type fakesensitive.EmbedsExported does not guarantee JSON marshal safety: .*not an opaque struct"
}

type CheckExportedField struct {
	X fakesensitive.ExportedField // want "configured safe type fakesensitive.ExportedField does not guarantee JSON marshal safety: .*not an opaque struct"
}
