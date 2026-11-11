package hostport

import "testing"

func TestIsLoopback(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"localhost", true},
		{"LOCALHOST:8080", true},
		{"127.0.0.1", true},
		{"127.0.0.1:8080", true},
		{"[::1]:8080", true},
		{"::1", true},
		{"http://localhost:8080", true},
		{"http://127.0.0.1:8080/x", true},
		{"https://[::1]:8443", true},
		{"10.0.0.5:8080", false},
		{"example.com", false},
		{"localhost.example.com", false},
		{"http://203.0.113.7:8080", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsLoopback(tt.in); got != tt.want {
			t.Errorf("IsLoopback(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
