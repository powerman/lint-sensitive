package skiptests

import "fakesensitive"

type NotTestFile struct {
	x fakesensitive.String // want "sensitive value in unexported field \"x\" is leaked by fmt"
}
