// Package fakeconceal provides fake sensitive types for testing,
// emulating github.com/shoenig/go-conceal.
package fakeconceal

// Text conceals a string.
// Like the original, it is handed out as *Text and all its methods have a pointer receiver.
type Text struct {
	_     [0]func()
	value string
	hash  int
}

// New returns a Text which conceals s.
func New(s string) *Text {
	return &Text{value: s}
}

func (t *Text) String() string   { return "(redacted)" }
func (t *Text) GoString() string { return "(redacted)" }

// MarshalText outputs the secret, as the original does.
func (t *Text) MarshalText() ([]byte, error) { return []byte(t.value), nil }

// Bytes conceals a byte slice.
type Bytes struct {
	_     [0]func()
	value []byte
	hash  int
}

// NewBytes returns a Bytes which conceals b.
func NewBytes(b []byte) *Bytes {
	return &Bytes{value: b}
}

func (b *Bytes) String() string   { return "(redacted)" }
func (b *Bytes) GoString() string { return "(redacted)" }
