// Package fakecamo provides fake sensitive types for testing,
// emulating github.com/rbranson/camo.
package fakecamo

import "unsafe"

// Obscurable is the set of types which Secret can hold.
type Obscurable interface{ string | []byte }

// Secret keeps the content behind an unsafe pointer.
// The hash field is a fingerprint, which the linter knows to ignore.
type Secret[O Obscurable] struct {
	_    unsafe.Pointer
	hash uint64
}

// Obscure returns a Secret which keeps content.
func Obscure[O Obscurable](content O) Secret[O] {
	return Secret[O]{hash: uint64(len(content))}
}

// Reveal returns the content.
func (s Secret[O]) Reveal() O {
	var zero O
	return zero
}

// Unlisted has the same shape as Secret but is not in publicFields.
type Unlisted struct {
	_    unsafe.Pointer
	hash uint64
}
