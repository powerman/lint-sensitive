package skiptests_reliability

import "fakesecrecy"

// Shared uses a type that pkg_test.go uses too.
type Shared struct {
	X fakesecrecy.Secret[string] // want "configured safe type fakesecrecy.Secret does not guarantee JSON marshal safety"
}
