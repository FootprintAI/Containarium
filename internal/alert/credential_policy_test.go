package alert

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/coderun/engine"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

type fileCredentialProber struct{ home string }

func (p fileCredentialProber) CredentialWatchTargets(context.Context) ([]CredentialWatchTarget, error) {
	return []CredentialWatchTarget{{SkillID: "s1", Box: "agent-s1-container", Engine: pb.AgentEngine_AGENT_ENGINE_CLAUDE}}, nil
}
func (p fileCredentialProber) ProbeCredential(ctx context.Context, _ CredentialWatchTarget) (pb.CodeCredentialSource, error) {
	script, _ := engine.CredentialAlertStatusScript(engine.NameClaude)
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script)
	cmd.Env = []string{"HOME=" + p.home, "PATH=" + os.Getenv("PATH")}
	out, err := cmd.Output()
	if err != nil {
		return srcNone, err
	}
	switch strings.TrimSpace(string(out)) {
	case "interactive":
		return srcInteractive, nil
	case "expired":
		return srcExpired, nil
	case "api-key":
		return pb.CodeCredentialSource_CODE_CREDENTIAL_SOURCE_API_KEY, nil
	case "none":
		return srcNone, nil
	}
	return srcNone, fmt.Errorf("unexpected source name")
}

func testCredentialPolicyTransitions(t *testing.T, store CredentialStateStore) {
	t.Helper()
	home := t.TempDir()
	credDir := filepath.Join(home, ".claude")
	markerDir := filepath.Join(home, ".local", "state", "containarium")
	for _, dir := range []string{credDir, markerDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(markerDir, "claude-auth-failed")
	writeExpiry := func(age time.Duration) {
		t.Helper()
		body := fmt.Sprintf(`{"accessToken":"FAKE_ACCESS_NEVER_OUTPUT","refreshToken":"FAKE_REFRESH_NEVER_OUTPUT","expiresAt":%d}`, time.Now().Add(-age).UnixMilli())
		if err := os.WriteFile(filepath.Join(credDir, ".credentials.json"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	notifier := &recordingNotifier{}
	prober := fileCredentialProber{home}
	watch := NewCredentialWatcher(prober, store, notifier)
	ctx := context.Background()
	sweep := func(want int) {
		t.Helper()
		watch.Sweep(ctx)
		if got := notifier.count(); got != want {
			t.Fatalf("alerts=%d want=%d", got, want)
		}
	}
	writeExpiry(time.Hour)
	sweep(0)
	sweep(0) // Idle, refreshable, multiple intervals.
	watch = NewCredentialWatcher(prober, store, notifier)
	sweep(0)
	if err := os.WriteFile(marker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	sweep(1)
	sweep(1) // An actual authentication failure is sufficient immediately.
	watch = NewCredentialWatcher(prober, store, notifier)
	sweep(1)
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	} // Successful authenticated run.
	writeExpiry(-time.Hour)
	sweep(1) // Recovery does not notify.
	writeExpiry(25 * time.Hour)
	sweep(2)
	sweep(2)
	watch = NewCredentialWatcher(prober, store, notifier)
	sweep(2)
	if err := os.Remove(filepath.Join(credDir, ".credentials.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(credDir, "settings.json"), []byte(`{"ANTHROPIC_API_KEY":"FAKE_SECRET_NEVER_OUTPUT"}`), 0600); err != nil {
		t.Fatal(err)
	}
	// API-key runs produce no OAuth episodes (source provenance tested in runtime).
	sweep(2) // A stale interactive failure does not change API-key behavior.
}

func TestCredentialWatcherPolicyFakeFiles(t *testing.T) {
	testCredentialPolicyTransitions(t, newMemStateStore())
}

func (p fileCredentialProber) CredentialEpisodes(context.Context, CredentialWatchTarget) (CredentialEpisodes, error) {
	_, err := os.Stat(filepath.Join(p.home, ".local", "state", "containarium", "claude-auth-failed"))
	if os.IsNotExist(err) {
		return CredentialEpisodes{Version: 1}, nil
	}
	if err != nil {
		return CredentialEpisodes{}, err
	}
	// Metadata fixture stands in for the separately tested, locked runtime CLI.
	return CredentialEpisodes{Version: 1, Active: true, Pending: []CredentialEpisode{{ID: "00000000-0000-0000-0000-000000000001"}}}, nil
}
func (p fileCredentialProber) AcknowledgeCredentialEpisodes(context.Context, CredentialWatchTarget, []string) error {
	return nil
}
