package reliability_marshal_text

import (
	"fakesensitive"
	"fakesecrecy"
)

// Every configured safe type in this package fails TextMarshal safety
// (none implements encoding.TextMarshaler).
//
// Fields are EXPORTED to avoid field-walk diagnostic.

type CheckString struct {
	X fakesensitive.String // want "configured safe type fakesensitive.String does not guarantee text marshal safety"
}

type CheckSecret struct {
	X fakesecrecy.Secret[string] // want "configured safe type fakesecrecy.Secret does not guarantee text marshal safety"
}

type CheckRef struct {
	X fakesensitive.Ref[string] // want "configured safe type fakesensitive.Ref does not guarantee text marshal safety"
}
