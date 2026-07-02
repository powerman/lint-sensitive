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

type CheckSinglePtr struct {
	X fakesensitive.SinglePtr[struct{ a int }] // want "configured safe type fakesensitive.SinglePtr does not guarantee String-level safety"
}
