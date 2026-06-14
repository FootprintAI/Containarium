package credentials

import "testing"

func TestIsCloudToken(t *testing.T) {
	cases := []struct {
		tok  string
		want bool
	}{
		{"ctnr_abc.def", true},
		{"  ctnr_abc  ", true}, // surrounding whitespace trimmed
		{"eyJhbGciOiJIUzI1NiJ9.x.y", false}, // a JWT
		{"", false},
		{"ctnr", false},   // prefix must include the underscore
		{"xctnr_", false}, // prefix must be at the start
	}
	for _, c := range cases {
		if got := IsCloudToken(c.tok); got != c.want {
			t.Errorf("IsCloudToken(%q) = %v, want %v", c.tok, got, c.want)
		}
	}
}
