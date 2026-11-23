// Package fieldsdep holds types from a dependency package:
// the fields analyzer reports only on the analyzed package,
// so leaks inside these types must be found by walking from the analyzed package.
package fieldsdep

import "fakesensitive"

// Inner holds a safe type, which leaks only when reached under a disable factor.
type Inner struct{ Secret fakesensitive.String }

// MidCleanFirst reaches Inner via an exported field before an unexported one.
type MidCleanFirst struct {
	A Inner
	b Inner
}

// MidDirtyFirst reaches Inner via an unexported field before an exported one.
type MidDirtyFirst struct {
	b Inner
	A Inner
}
