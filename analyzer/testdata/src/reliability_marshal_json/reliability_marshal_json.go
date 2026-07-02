package reliability_marshal_json

import (
	"fakesensitive"
	"fakesecrecy"
	"fakelogfusc"
)

// Every configured safe type in this package fails JSON safety
// (none implements encoding.TextMarshaler or json.Marshaler).
//
// Fields are EXPORTED so the field walk does NOT produce a diagnostic
// (exported fields do not disable fmt interfaces).

type CheckString struct {
	X fakesensitive.String // want "configured safe type fakesensitive.String does not guarantee JSON marshal safety"
}

type CheckSecret struct {
	X fakesecrecy.Secret[string] // want "configured safe type fakesecrecy.Secret does not guarantee JSON marshal safety"
}

type CheckLogfusc struct {
	X fakelogfusc.Secret[string] // want "configured safe type fakelogfusc.Secret does not guarantee JSON marshal safety"
}

type CheckRef struct {
	X fakesensitive.Ref[string] // want "configured safe type fakesensitive.Ref does not guarantee JSON marshal safety"
}
