// Package fakesensitive provides a fake sensitive type for testing,
// emulating github.com/powerman/sensitive and github.com/go-playground/sensitive.
package fakesensitive

import "fmt"

// String is a fake sensitive string type.
type String string

func (s String) Format(f fmt.State, verb rune) {
	fmt.Fprint(f, "[redacted]")
}
