package reliability_generic

import "fakesensitive"

// Wrap is a configured safe type declared in the analyzed package.
// Each method receiver is an instance with its own type parameter,
// and it fails for the same reason as the declaration, so it is not reported again.
type Wrap[T any] struct { // want "configured safe type reliability_generic.Wrap does not guarantee format-level safety"
	p *T
}

func (w Wrap[T]) Get() T { return *w.p }

func (w Wrap[T]) Set(v T) { *w.p = v }

// Instances with type parameters of different generic declarations are reported once.
type Holder[T any] struct {
	X fakesensitive.SinglePtr[T] // want "configured safe type fakesensitive.SinglePtr does not guarantee format-level safety"
}

func Use[U any](x fakesensitive.SinglePtr[U]) {}

// A concrete instance which fails for the same reason is not reported again.
type CheckStruct struct {
	X fakesensitive.SinglePtr[struct{ a int }]
}

// The instance is classified with the constraint of its type parameter:
// a pointer to a non-compound type is structurally protected.
func UseNonCompound[T fakesensitive.NonCompound](x fakesensitive.SinglePtr[T]) {}
