package analyzer

import (
	"slices"
	"testing"
)

func TestLevelCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cls  typeClass
		want requires
	}{
		{
			name: "bare_type",
			cls:  typeClass{},
			want: requires{},
		},
		{
			name: "fmt_Formatter",
			cls:  typeClass{fmtFormatter: true},
			want: requires{
				formatSafe:   true,
				goStringSafe: true,
				stringSafe:   true,
			},
		},
		{
			name: "fmt_Stringer",
			cls:  typeClass{fmtStringer: true},
			want: requires{
				stringSafe: true,
			},
		},
		{
			name: "fmt_GoStringer",
			cls:  typeClass{fmtGoStringer: true},
			want: requires{
				goStringSafe: true,
			},
		},
		{
			name: "json_Marshaler",
			cls:  typeClass{jsonMarshaler: true},
			want: requires{
				marshalJSONSafe: true,
			},
		},
		{
			name: "text_Marshaler",
			cls:  typeClass{textMarshaler: true},
			want: requires{
				marshalJSONSafe: true,
				marshalTextSafe: true,
			},
		},
		{
			name: "structurally_safe",
			cls:  typeClass{structurallySafe: true},
			want: requires{
				formatSafe:   true,
				goStringSafe: true,
				stringSafe:   true,
			},
		},
		{
			name: "opaque",
			cls:  typeClass{opaque: true},
			want: requires{
				marshalJSONSafe: true,
			},
		},
		{
			name: "opaque_Stringer",
			cls:  typeClass{opaque: true, fmtStringer: true},
			want: requires{
				marshalJSONSafe: true,
				marshalTextSafe: true,
				stringSafe:      true,
			},
		},
		{
			name: "opaque_structurally_safe",
			cls:  typeClass{opaque: true, structurallySafe: true},
			want: requires{
				marshalJSONSafe: true,
				marshalTextSafe: true,
				formatSafe:      true,
				goStringSafe:    true,
				stringSafe:      true,
			},
		},
		{
			name: "opaque_GoStringer",
			cls:  typeClass{opaque: true, fmtGoStringer: true},
			want: requires{
				marshalJSONSafe: true,
				goStringSafe:    true,
			},
		},
		{
			name: "Stringer_and_GoStringer",
			cls: typeClass{
				fmtStringer:   true,
				fmtGoStringer: true,
			},
			want: requires{
				goStringSafe: true,
				stringSafe:   true,
			},
		},
		{
			name: "all_true",
			cls: typeClass{
				fmtFormatter:     true,
				fmtStringer:      true,
				fmtGoStringer:    true,
				jsonMarshaler:    true,
				textMarshaler:    true,
				structurallySafe: true,
			},
			want: requires{
				marshalJSONSafe: true,
				marshalTextSafe: true,
				formatSafe:      true,
				goStringSafe:    true,
				stringSafe:      true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := levelCheck(tt.cls, false)
			if got != tt.want {
				t.Errorf("levelCheck(%+v) =\n  %+v\nwant:\n  %+v", tt.cls, got, tt.want)
			}
		})
	}
}

// TestLevelCheckViaPointer verifies that methods which only *T has count
// for a type used only as *T, and do not count for a T value.
func TestLevelCheckViaPointer(t *testing.T) {
	t.Parallel()

	cls := typeClass{ptrOnly: map[string]bool{methodString: true, methodMarshalText: true}}

	if got := levelCheck(cls, false); got != (requires{}) {
		t.Errorf("levelCheck(%+v, false) = %+v, want nothing satisfied", cls, got)
	}
	want := requires{marshalJSONSafe: true, marshalTextSafe: true, stringSafe: true}
	if got := levelCheck(cls, true); got != want {
		t.Errorf("levelCheck(%+v, true) = %+v, want %+v", cls, got, want)
	}
}

// TestLevelCheckOpaqueViaPointer verifies that a pointer-only String
// makes an opaque struct text-marshal safe only for the pointer form.
func TestLevelCheckOpaqueViaPointer(t *testing.T) {
	t.Parallel()

	cls := typeClass{opaque: true, ptrOnly: map[string]bool{methodString: true}}

	want := requires{marshalJSONSafe: true}
	if got := levelCheck(cls, false); got != want {
		t.Errorf("levelCheck(%+v, false) = %+v, want %+v", cls, got, want)
	}
	want = requires{marshalJSONSafe: true, marshalTextSafe: true, stringSafe: true}
	if got := levelCheck(cls, true); got != want {
		t.Errorf("levelCheck(%+v, true) = %+v, want %+v", cls, got, want)
	}
}

// TestRevealingSurfaces verifies which surfaces a revealing method fails.
func TestRevealingSurfaces(t *testing.T) {
	t.Parallel()

	tests := []struct {
		method string
		want   []string // Names of the failed surfaces.
	}{
		{methodMarshalJSON, []string{"JSON marshal safety"}},
		{methodMarshalText, []string{"JSON marshal safety", "text marshal safety"}},
		{methodString, []string{"text marshal safety", "String-level safety"}},
		{methodGoString, []string{"GoString-level safety"}},
		{
			methodFormat,
			[]string{
				"text marshal safety", "format-level safety",
				"GoString-level safety", "String-level safety",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			t.Parallel()

			revealing := map[string]bool{tt.method: true}
			var got []string
			for _, d := range surfaces(requires{}, requires{}) {
				if revealingServing(revealing, d.servedBy) != "" {
					got = append(got, d.name)
				}
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("surfaces failed by %s = %v, want %v", tt.method, got, tt.want)
			}
		})
	}
}
