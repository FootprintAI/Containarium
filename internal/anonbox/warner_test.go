package anonbox

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// walls returns the wall messages the fake saw, in order.
func walls(f *fakeBoxes) []string {
	var out []string
	for _, cmd := range f.execs {
		if len(cmd) == 2 && cmd[0] == "wall" {
			out = append(out, cmd[1])
		}
	}
	return out
}

func ensureOne(t *testing.T, h *harness) string {
	t.Helper()
	key, fp := testKey(t)
	res, err := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp, PublicKey: key})
	if err != nil {
		t.Fatal(err)
	}
	h.boxes.execs = nil
	return res.BoxName
}

// TestWarn_Table: for a box expiring at T, Warn at each `now` fires exactly
// the thresholds that are due and not yet sent — and never twice.
func TestWarn_Table(t *testing.T) {
	ttl := DefaultLimits().TTL
	tests := []struct {
		name      string
		ticks     []time.Duration // offsets from creation at which Warn runs
		wantWalls []string        // threshold names, in order
	}{
		{"nothing due", []time.Duration{0, ttl - 11*time.Minute}, nil},
		{"10m then 1m", []time.Duration{ttl - 10*time.Minute, ttl - time.Minute}, []string{"10m", "1m"}},
		{"10m once across ticks", []time.Duration{ttl - 10*time.Minute, ttl - 9*time.Minute, ttl - 5*time.Minute}, []string{"10m"}},
		{"both due at once (missed 10m tick)", []time.Duration{ttl - 30*time.Second}, []string{"10m", "1m"}},
		{"after expiry: nothing", []time.Duration{ttl + time.Minute}, nil},
		{"1m then nothing more", []time.Duration{ttl - 50*time.Second, ttl - 10*time.Second}, []string{"10m", "1m"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, nil)
			start := h.now
			box := ensureOne(t, h)
			for _, off := range tt.ticks {
				h.now = start.Add(off)
				if err := h.m.Warn(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			got := walls(h.boxes)
			if len(got) != len(tt.wantWalls) {
				t.Fatalf("walls = %v, want thresholds %v", got, tt.wantWalls)
			}
			for i, th := range tt.wantWalls {
				if !strings.Contains(got[i], "about "+th+" ") || !strings.Contains(got[i], "containarium claim") {
					t.Errorf("wall[%d] = %q, want a %s warning with the claim hint", i, got[i], th)
				}
			}
			st, _ := h.m.findByName(context.Background(), box)
			wantLabel := formatWarned(parseWarned(strings.Join(tt.wantWalls, ",")))
			if st.Labels[LabelWarned] != wantLabel {
				t.Errorf("label %s = %q, want %q", LabelWarned, st.Labels[LabelWarned], wantLabel)
			}
		})
	}
}

// A restarted daemon (a fresh Manager over the same boxes) reads the label
// and does not re-send.
func TestWarn_RestartDoesNotResend(t *testing.T) {
	h := newHarness(t, nil)
	start := h.now
	ensureOne(t, h)
	h.now = start.Add(DefaultLimits().TTL - 10*time.Minute)
	if err := h.m.Warn(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(walls(h.boxes)) != 1 {
		t.Fatalf("first daemon: %v", walls(h.boxes))
	}

	restarted := New(h.boxes, h.acls, Config{Now: func() time.Time { return h.now }})
	h.boxes.execs = nil
	if err := restarted.Warn(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(walls(h.boxes)) != 0 {
		t.Errorf("restart re-sent: %v", walls(h.boxes))
	}
	h.now = start.Add(DefaultLimits().TTL - time.Minute)
	if err := restarted.Warn(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := walls(h.boxes); len(got) != 1 || !strings.Contains(got[0], "about 1m ") {
		t.Errorf("restart must still send the later threshold once: %v", got)
	}
}

// A failed wall is logged, marked as sent, and never retried.
func TestWarn_ExecFailureLoggedNotRetried(t *testing.T) {
	var logged []string
	h := newHarness(t, func(c *Config) {
		c.Logf = func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
	})
	start := h.now
	box := ensureOne(t, h)
	h.boxes.execErr = errors.New("agent not running")
	h.now = start.Add(DefaultLimits().TTL - 10*time.Minute)
	for i := 0; i < 3; i++ {
		if err := h.m.Warn(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(walls(h.boxes)); n != 1 {
		t.Errorf("wall attempted %d times, want exactly 1", n)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "not delivered") || !strings.Contains(logged[0], box) {
		t.Errorf("logged = %v", logged)
	}
	st, _ := h.m.findByName(context.Background(), box)
	if st.Labels[LabelWarned] != "10m" {
		t.Errorf("label = %q, want the attempt recorded", st.Labels[LabelWarned])
	}
}

// Claimed boxes and boxes without a TTL are left alone.
func TestWarn_SkipsClaimedAndUntimed(t *testing.T) {
	h := newHarness(t, nil)
	start := h.now
	box := ensureOne(t, h)
	content := strings.TrimSpace(fileNamed(t, h.boxes.files[box], ClaimURLPath).content)
	if _, err := h.m.Claim(context.Background(), ClaimRequest{Token: tokenFromClaimFile(t, content), Tenant: "qa"}); err != nil {
		t.Fatal(err)
	}
	h.boxes.execs = nil
	h.now = start.Add(DefaultLimits().TTL - time.Minute)
	if err := h.m.Warn(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(walls(h.boxes)) != 0 {
		t.Errorf("claimed box warned: %v", walls(h.boxes))
	}
}

func TestWarnedLabelRoundTrip(t *testing.T) {
	if got := formatWarned(parseWarned(" 1m, 10m ,,10m")); got != "10m,1m" {
		t.Errorf("got %q", got)
	}
	if len(parseWarned("")) != 0 {
		t.Error("empty label must parse to nothing")
	}
}
