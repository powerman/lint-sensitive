// Package fakeplugin provides a fake safe type which is known only through plugin settings.
package fakeplugin

// Secret redacts itself in String but has no GoString.
type Secret struct {
	value string
}

func (Secret) String() string { return "<redacted>" }
