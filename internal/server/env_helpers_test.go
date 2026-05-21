package server

import "testing"

func TestEnvBool(t *testing.T) {
	cases := map[string]bool{
		"":         false,
		"  ":       false,
		"0":        false,
		"false":    false,
		"no":       false,
		"off":      false,
		"maybe":    false,
		"true":     true,
		"TRUE":     true,
		"True":     true,
		"1":        true,
		"yes":      true,
		"YES":      true,
		"on":       true,
		"  true  ": true,
	}
	for val, want := range cases {
		t.Run(val, func(t *testing.T) {
			t.Setenv("CONTAINARIUM_ENV_BOOL_TEST", val)
			got := envBool("CONTAINARIUM_ENV_BOOL_TEST")
			if got != want {
				t.Fatalf("envBool(%q) = %v; want %v", val, got, want)
			}
		})
	}
}
