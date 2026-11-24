package fields_off

import "fakesensitive"

// Without detect-fields no declaration diagnostic is reported:
// the field is reachable through an unexported field, but nothing prints it.
type holder struct {
	x fakesensitive.String
}
