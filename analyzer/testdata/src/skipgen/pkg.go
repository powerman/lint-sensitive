package skipgen

import "fakesensitive"

// NotGenerated is a struct in a regular file — always flagged.
type NotGenerated struct {
	x fakesensitive.String // want "is reachable behind a"
}
