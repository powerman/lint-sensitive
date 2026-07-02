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
