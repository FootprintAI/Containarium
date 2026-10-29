package gateway

import (
	"errors"
	"net/http"
	"testing"

	"github.com/footprintai/containarium/internal/toolaccess"
)

// TestResolveTerminalUser pins the as_run_user rule (#3275): the terminal opens
// as the run user only when the box has a tool-access level recorded AND the
// run user exists; every other case is a refusal, never a quiet fallback to the
// login user (which would sign in the wrong OS user).
func TestResolveTerminalUser(t *testing.T) {
	boom := errors.New("incus unavailable")
	tests := []struct {
		name       string
		asRunUser  bool
		level      string
		levelErr   error
		exists     bool
		existsErr  error
		wantUser   string
		wantStatus int // 0 = no refusal
	}{
		{name: "flag off keeps the login user", wantUser: "alice"},
		{name: "flag off ignores a recorded level", level: "none", exists: true, wantUser: "alice"},
		{name: "recorded level and run user opens as the run user", asRunUser: true, level: "build_tools", exists: true, wantUser: toolaccess.RunUser},
		{name: "none is a recorded level", asRunUser: true, level: "none", exists: true, wantUser: toolaccess.RunUser},
		{name: "no level recorded is refused", asRunUser: true, exists: true, wantStatus: http.StatusConflict},
		{name: "unrecognised level is refused", asRunUser: true, level: "root", exists: true, wantStatus: http.StatusConflict},
		{name: "run user missing is refused", asRunUser: true, level: "full_sudo", wantStatus: http.StatusConflict},
		{name: "level read error is refused", asRunUser: true, levelErr: boom, wantStatus: http.StatusServiceUnavailable},
		{name: "run user check error is refused", asRunUser: true, level: "full_sudo", existsErr: boom, wantStatus: http.StatusServiceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			th := &TerminalHandler{
				recordedToolAccess: func(string) (string, error) { return tt.level, tt.levelErr },
				runUserExists:      func(string) (bool, error) { return tt.exists, tt.existsErr },
			}
			user, refusal := th.resolveTerminalUser("alice-container", "alice", tt.asRunUser)
			if tt.wantStatus != 0 {
				if refusal == nil || refusal.status != tt.wantStatus {
					t.Fatalf("refusal = %+v, want status %d", refusal, tt.wantStatus)
				}
				if user != "" {
					t.Fatalf("a refused request must not name a user, got %q", user)
				}
				return
			}
			if refusal != nil {
				t.Fatalf("unexpected refusal: %+v", refusal)
			}
			if user != tt.wantUser {
				t.Fatalf("user = %q, want %q", user, tt.wantUser)
			}
		})
	}
}
