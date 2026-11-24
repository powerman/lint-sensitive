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

// NonCompound is a type constraint that only allows non-compound (basic) types.
// Used in tests for *TypeParam qualifier detection.
type NonCompound interface {
	~string | ~int | ~bool
}

// CompoundOrPrimitive is a type constraint that includes a compound type.
// Used in tests for *TypeParam qualifier detection.
type CompoundOrPrimitive interface {
	~string | SomeCompound
}

// SomeCompound is a compound type used in type constraints for tests.
type SomeCompound struct{ s string }

// Secret is a SecretExposer interface, mirroring github.com/powerman/sensitive.Secret[T]
// and github.com/negrel/secrecy.SecretExposer[T].
type Secret[T any] interface {
	ExposeSecret() T
}

// Label is a named non-compound type used as a pointee.
type Label string

// PtrToLabel holds a pointer to a named non-compound type.
// fmt prints it as an address, so it is structurally safe.
// It does NOT implement any fmt interface.
type PtrToLabel struct {
	p *Label
}

// PtrToCompound holds a pointer to a named struct.
// fmt dereferences it, so it is NOT structurally safe.
// It does NOT implement any fmt interface.
type PtrToCompound struct {
	p *SomeCompound
}

// Decoy has the method names of the fmt/encoding interfaces but with wrong signatures,
// so it implements none of them.
type Decoy string

func (Decoy) Format(x int)        {}
func (Decoy) String() int         { return 0 }
func (Decoy) GoString() int       { return 0 }
func (Decoy) MarshalJSON() string { return "" }
func (Decoy) MarshalText() string { return "" }

// PtrRecv declares the fmt/encoding interface methods on a pointer receiver only.
// fmt and encoding/json do not call them on a non-addressable T value.
type PtrRecv string

func (*PtrRecv) Format(f fmt.State, verb rune) {}
func (*PtrRecv) String() string                { return "" }
func (*PtrRecv) GoString() string              { return "" }
func (*PtrRecv) MarshalJSON() ([]byte, error)  { return nil, nil }
func (*PtrRecv) MarshalText() ([]byte, error)  { return nil, nil }

// FuncT is a named func type: fmt prints it as an address, like an unnamed func.
type FuncT func() string

// NamedFuncWrap holds its value behind a named func type.
// It does NOT implement any fmt interface.
type NamedFuncWrap struct{ fn FuncT }

// NestedRef holds a double pointer inside an anonymous struct.
// It does NOT implement any fmt interface.
type NestedRef struct{ v struct{ pp **string } }

// ArrayRef holds a double pointer inside an array.
// It does NOT implement any fmt interface.
type ArrayRef struct{ a [1]**string }

// NotComparable has the shape of gophers.dev/pkgs/secrets.Text:
// the zero-length array only makes it not comparable and protects nothing.
type NotComparable struct {
	_     [0]func()
	value string
}

func (NotComparable) String() string   { return "[redacted]" }
func (NotComparable) GoString() string { return "[redacted]" }

// FormatFuncWrap holds its value behind a named func type and implements fmt.Formatter.
type FormatFuncWrap struct{ fn FuncT }

func (FormatFuncWrap) Format(f fmt.State, verb rune) { fmt.Fprint(f, "[redacted]") }
