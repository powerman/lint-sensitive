package skipgen

import "fakesensitive"

// NotGenerated is a struct in a regular file — always flagged.
type NotGenerated struct {
	x fakesensitive.String // want "sensitive value in unexported field \"x\" is leaked by fmt"
}
