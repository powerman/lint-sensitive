// Package fakesensitive provides a fake sensitive type for testing,
// emulating github.com/powerman/sensitive and github.com/go-playground/sensitive.
package fakesensitive

import "fmt"

// String is a fake sensitive string type.
type String string

func (s String) Format(f fmt.State, verb rune) {
	fmt.Fprint(f, "[redacted]")
}

// Boxed wraps a value behind a double pointer,
// making it unreachable through fmt reflection.
type Boxed[T any] struct {
	pp **T
}

// SinglePtr wraps a value behind a single pointer.
// Unlike Boxed, this IS reachable by fmt reflection.
type SinglePtr[T any] struct {
	p *T
}

// FuncWrap calls a function to produce its value.
type FuncWrap[T any] struct {
	fn func() T
}

// ChanWrap wraps a value behind a channel.
// Without a double-pointer field this struct is not safe.
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
