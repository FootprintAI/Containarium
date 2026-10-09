package sentinel

import (
	"testing"

	"github.com/footprintai/containarium/internal/gateway"
)

// #2415 — which backend a login's SSH session was routed to, by the same
// rule Apply uses to write sshpiper's routes: the first backend (sorted by
// id) that lists the user wins.
func TestKeyStore_BackendForLogin(t *testing.T) {
	ks := NewKeyStore()
	ks.backends["b-2"] = &backendKeys{backendID: "b-2", users: []gateway.UserKeys{{Username: "alice"}, {Username: "bob"}}}
	ks.backends["b-1"] = &backendKeys{backendID: "b-1", users: []gateway.UserKeys{{Username: "alice"}, {Username: "carol"}}}

	tests := []struct {
		login string
		want  string
		ok    bool
	}{
		{"alice", "b-1", true}, // claimed by both; sorted-first wins, as in Apply
		{"bob", "b-2", true},
		{"carol", "b-1", true},
		{"nobody", "", false},
		{"", "", false},
	}
	for _, tc := range tests {
		got, ok := ks.BackendForLogin(tc.login)
		if got != tc.want || ok != tc.ok {
			t.Errorf("BackendForLogin(%q) = %q,%v want %q,%v", tc.login, got, ok, tc.want, tc.ok)
		}
	}
}
