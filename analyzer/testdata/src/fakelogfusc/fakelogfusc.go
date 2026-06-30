// Package fakelogfusc provides a fake sensitive type for testing,
// emulating github.com/AngusGMorrison/logfusc.
package fakelogfusc

// Secret is a generic wrapper that redacts values when printed.
type Secret[T any] struct {
	value T
}

func (s Secret[T]) String() string {
	return "[REDACTED]"
}

func (s Secret[T]) GoString() string {
	return "Secret{******}"
}
