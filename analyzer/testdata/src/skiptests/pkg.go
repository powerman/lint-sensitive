package skiptests

import "fakesensitive"

type NotTestFile struct {
	x fakesensitive.String // want "is reachable behind a"
}
