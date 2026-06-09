package gateway

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
)

// SSHWakeRequest is the JSON body for POST /ssh-wake. The sentinel's
// ssh-wake-proxy sends the box's username when an inbound SSH connection
// arrives for a box whose sshd isn't answering (i.e. it's auto-slept).
type SSHWakeRequest struct {
	Username string `json:"username"`
}

// SSHWakeResponse reports whether the box's sshd became dial-ready
// within the wake budget, plus the container IP the daemon observed.
type SSHWakeResponse struct {
	Ready bool   `json:"ready"`
	IP    string `json:"ip"`
}

// ServeSSHWake returns the handler for POST /ssh-wake (#539, wake-on-SSH).
// It is the SSH analogue of wake-on-HTTP's wake handler: the sentinel
// calls it to transparently start a slept box and block until the box's
// sshd (port 22) accepts, so the held SSH connection can then be spliced
// through. fn is wired to ContainerServer.WakeForSSH; a nil fn means the
// feature is not enabled on this daemon (503). This handler is mounted
// behind auth.SentinelHMACMiddleware — same HMAC channel as
// /authorized-keys — so only the sentinel can trigger a wake.
func ServeSSHWake(fn func(ctx context.Context, username string) (bool, string, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if fn == nil {
			http.Error(w, `{"error":"ssh wake not configured"}`, http.StatusServiceUnavailable)
			return
		}
		var req SSHWakeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
			http.Error(w, `{"error":"invalid request: username required"}`, http.StatusBadRequest)
			return
		}

		ready, ip, err := fn(r.Context(), req.Username)
		if err != nil {
			log.Printf("[ssh-wake] wake %s failed: %v", req.Username, err)
			http.Error(w, `{"error":"wake failed"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(SSHWakeResponse{Ready: ready, IP: ip}); err != nil {
			log.Printf("[ssh-wake] encode response for %s: %v", req.Username, err)
		}
	}
}
