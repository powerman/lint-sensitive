// Package fakesecrecy provides a fake sensitive type for testing,
// emulating github.com/negrel/secrecy.
package fakesecrecy

// Secret is a generic wrapper that redacts values when printed.
type Secret[T any] struct {
	value T
}

func (s Secret[T]) String() string {
	return "<!SECRET_LEAKED!>"
}

func (s Secret[T]) GoString() string {
	return "<!SECRET_LEAKED!>"
}

// SecretString is a specific secret-wrapping string type.
type SecretString struct {
	inner Secret[[]byte]
}
