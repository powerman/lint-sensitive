// Package fakesensitive provides a fake sensitive type for testing,
// emulating github.com/powerman/sensitive and github.com/go-playground/sensitive.
package fakesensitive

import "fmt"

// String is a fake sensitive string type.
type String string

func (s String) Format(f fmt.State, verb rune) {
	fmt.Fprint(f, "[redacted]")
}

// Ref wraps a value behind a double pointer,
// making it unreachable through fmt reflection.
type Ref[T any] struct {
	pp **T
}

// SinglePtr wraps a value behind a single pointer.
// It does NOT implement any fmt interface (safe types that do are e.g. Handle).
type SinglePtr[T any] struct {
	p *T
}

// FuncWrap calls a function to produce its value.
type FuncWrap[T any] struct {
	fn func() T
}

// ChanWrap wraps a value behind a channel.
type ChanWrap[T any] struct {
	ch chan T
}

// DoublePtrAndOther has a double-pointer field plus other fields.
// The double-pointer field is assumed to hold the secret,
// so the struct is safe even with non-pointer fields.
type DoublePtrAndOther[T any] struct {
	pp  **T
	aux int
}

// Handle wraps a value behind a single pointer, like sensitive.Handle.
// It implements fmt.Formatter to simulate real safe types.
type Handle[T any] struct {
	p *T
}

func (h Handle[T]) Format(f fmt.State, verb rune) {
	fmt.Fprint(f, "[redacted]")
}

// Secret is a SecretExposer interface, mirroring github.com/powerman/sensitive.Secret[T]
// and github.com/negrel/secrecy.SecretExposer[T].
type Secret[T any] interface {
	ExposeSecret() T
}
