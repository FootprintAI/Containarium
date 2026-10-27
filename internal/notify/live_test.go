package notify

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLiveNtfy publishes one push to a real ntfy server. Opt-in, skipped in
// CI: CONTAINARIUM_NTFY_E2E=<server>/<topic> (e.g. https://ntfy.example.com/my-test),
// with CONTAINARIUM_NTFY_E2E_TOKEN for a topic that needs one.
func TestLiveNtfy(t *testing.T) {
	target := os.Getenv("CONTAINARIUM_NTFY_E2E")
	if target == "" {
		t.Skip("set CONTAINARIUM_NTFY_E2E=<server>/<topic> to publish to a real ntfy server")
	}
	i := strings.LastIndex(target, "/")
	ch := Channel{Server: target[:i], Topic: target[i+1:]}
	token := os.Getenv("CONTAINARIUM_NTFY_E2E_TOKEN")
	if err := ValidateChannel(ch, token != ""); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	m := BuildMessage([]Request{{Box: "demo", Run: "e2e", RequestID: "req-1", Tool: "Bash", Prompt: "Bash: git push origin feature", ExpiresAt: now.Add(30 * time.Minute)}}, false, now)
	if err := NewSender().Send(context.Background(), ch, token, m); err != nil {
		t.Fatal(err)
	}
}
