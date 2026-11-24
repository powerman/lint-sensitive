package fields_off_require

import "fakesensitive"

// Without detect-fields the level diagnostics are still reported,
// while the unexported field gets no declaration diagnostic.
type holder struct {
	c fakesensitive.Credential // want "does not guarantee JSON marshal safety"
}
