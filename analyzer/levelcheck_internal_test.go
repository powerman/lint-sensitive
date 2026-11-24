package analyzer

import (
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
