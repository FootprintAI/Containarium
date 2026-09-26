package tracker

import (
	"errors"
	"testing"
)

func TestNextPageURL(t *testing.T) {
	for _, tc := range []struct {
		name, header, want string
	}{
		{"empty", "", ""},
		{"github shape", `<https://api.example.com/repos/o/r/issues?page=2>; rel="next", <https://api.example.com/repos/o/r/issues?page=5>; rel="last"`, "https://api.example.com/repos/o/r/issues?page=2"},
		{"next not first", `<https://h/x?page=1>; rel="prev", <https://h/x?page=3>; rel="next"`, "https://h/x?page=3"},
		{"last page", `<https://h/x?page=1>; rel="first", <https://h/x?page=4>; rel="prev"`, ""},
		{"unquoted rel, extra params", `<https://h/x?page=2>; title="p2"; rel=next`, "https://h/x?page=2"},
		{"multi-valued rel", `<https://h/x?page=2>; rel="last next"`, "https://h/x?page=2"},
		{"malformed target", `https://h/x?page=2; rel="next"`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := NextPageURL(tc.header); got != tc.want {
				t.Errorf("NextPageURL(%q) = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}

func TestCheckSameOrigin(t *testing.T) {
	if err := CheckSameOrigin("https://api.example.com/a?page=1", "https://API.example.com/a?page=2"); err != nil {
		t.Errorf("same origin refused: %v", err)
	}
	if err := CheckSameOrigin("https://api.example.com/a", "https://other.example.com/a"); !errors.Is(err, ErrCrossOriginNextLink) {
		t.Errorf("cross-host link: err = %v, want ErrCrossOriginNextLink", err)
	}
	if err := CheckSameOrigin("https://api.example.com/a", "http://api.example.com/a"); !errors.Is(err, ErrCrossOriginNextLink) {
		t.Errorf("scheme downgrade: err = %v, want ErrCrossOriginNextLink", err)
	}
}
