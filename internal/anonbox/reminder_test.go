package anonbox

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type recReminder struct {
	sent []Reminder
	err  error
}

func (r *recReminder) Send(_ context.Context, rem Reminder) error {
	r.sent = append(r.sent, rem)
	return r.err
}

// reminderHarness: claims + reminders enabled, one box ensured, the
// opt-in file's content controlled through the fake's exec output.
func reminderHarness(t *testing.T) (*harness, *recReminder, *recFunnel, string, time.Time) {
	t.Helper()
	rem := &recReminder{}
	f := &recFunnel{}
	h := newHarness(t, func(c *Config) { c.Reminder = rem; c.Funnel = f })
	start := h.now
	key, fp := testKey(t)
	res, err := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp, PublicKey: key})
	if err != nil {
		t.Fatal(err)
	}
	// provision pre-created the empty opt-in file, world-writable
	rf := fileNamed(t, h.boxes.files[res.BoxName], RemindFilePath)
	if rf.mode != "0666" || rf.content != "" {
		t.Fatalf("remind-me file = %+v, want empty 0666", rf)
	}
	banner := fileNamed(t, h.boxes.files[res.BoxName], BannerPath)
	if !strings.Contains(banner.content, "containarium remind-me") {
		t.Errorf("banner lacks the remind-me hint")
	}
	h.boxes.execs = nil
	f.events = nil
	return h, rem, f, res.BoxName, start
}

func TestReminder_OptInInsideLast30MinSentOnce(t *testing.T) {
	h, rem, f, box, start := reminderHarness(t)
	h.boxes.catOutput = map[string]string{RemindFilePath: "  alice@example.com\n"}

	// Too early: the file is not even read.
	h.now = start.Add(DefaultLimits().TTL - 31*time.Minute)
	if err := h.m.Warn(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(rem.sent) != 0 || len(h.boxes.execs) != 0 {
		t.Fatalf("before T-30m: sent=%d execs=%v", len(rem.sent), h.boxes.execs)
	}

	// Inside the window: picked up, recorded, sent once with the claim link.
	h.now = start.Add(DefaultLimits().TTL - 29*time.Minute)
	for i := 0; i < 3; i++ {
		if err := h.m.Warn(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(rem.sent) != 1 {
		t.Fatalf("sent %d reminders, want exactly 1", len(rem.sent))
	}
	r := rem.sent[0]
	if r.Email != "alice@example.com" || r.BoxName != box || !r.ExpiresAt.Equal(start.Add(DefaultLimits().TTL)) {
		t.Errorf("reminder = %+v", r)
	}
	content := strings.TrimSpace(fileNamed(t, h.boxes.files[box], ClaimURLPath).content)
	if r.ClaimURL != content {
		t.Errorf("claim url in reminder %q != the one in the guest %q", r.ClaimURL, content)
	}
	if got := f.kinds(); got != "reminder_optin" {
		t.Errorf("funnel = %s, want one reminder_optin", got)
	}
	st, _ := h.m.findByName(context.Background(), box)
	if st.Labels[LabelReminded] == "" || st.Labels[LabelRemindEmail] != "" {
		t.Errorf("labels after send = reminded %q email %q, want attempt recorded and address cleared", st.Labels[LabelReminded], st.Labels[LabelRemindEmail])
	}
	// The regular walls still work alongside.
	h.now = start.Add(DefaultLimits().TTL - 10*time.Minute)
	if err := h.m.Warn(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(walls(h.boxes)) != 1 || len(rem.sent) != 1 {
		t.Errorf("walls=%d reminders=%d", len(walls(h.boxes)), len(rem.sent))
	}
}

func TestReminder_NoOptInNothingHappens(t *testing.T) {
	h, rem, f, box, start := reminderHarness(t)
	h.boxes.catOutput = map[string]string{RemindFilePath: "   \n"} // --clear leaves it empty
	h.now = start.Add(DefaultLimits().TTL - 20*time.Minute)
	for i := 0; i < 3; i++ {
		if err := h.m.Warn(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	st, _ := h.m.findByName(context.Background(), box)
	if len(rem.sent) != 0 || len(f.events) != 0 || st.Labels[LabelReminded] != "" || st.Labels[LabelRemindEmail] != "" {
		t.Errorf("no opt-in must change nothing: sent=%d events=%s labels=%v", len(rem.sent), f.kinds(), st.Labels)
	}
	// A late opt-in still works on a later tick.
	h.boxes.catOutput[RemindFilePath] = "late@example.com"
	if err := h.m.Warn(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(rem.sent) != 1 || rem.sent[0].Email != "late@example.com" {
		t.Errorf("late opt-in: %+v", rem.sent)
	}
}

func TestReminder_InvalidAddressIgnoredOnce(t *testing.T) {
	var logged []string
	rem := &recReminder{}
	h := newHarness(t, func(c *Config) {
		c.Reminder = rem
		c.Logf = func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
	})
	start := h.now
	key, fp := testKey(t)
	res, _ := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp, PublicKey: key})
	h.boxes.catOutput = map[string]string{RemindFilePath: "not an email"}
	h.now = start.Add(DefaultLimits().TTL - 20*time.Minute)
	for i := 0; i < 2; i++ {
		if err := h.m.Warn(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(rem.sent) != 0 {
		t.Errorf("invalid address must not be sent")
	}
	if n := len(logged); n != 1 || !strings.Contains(logged[0], "not valid") {
		t.Errorf("logged = %v, want exactly one 'not valid'", logged)
	}
	st, _ := h.m.findByName(context.Background(), res.BoxName)
	if st.Labels[LabelReminded] == "" {
		t.Errorf("an invalid opt-in must still count as the one attempt")
	}
}

func TestReminder_SendFailureLoggedNotRetried(t *testing.T) {
	var logged []string
	rem := &recReminder{err: errors.New("webhook 503")}
	h := newHarness(t, func(c *Config) {
		c.Reminder = rem
		c.Logf = func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
	})
	start := h.now
	key, fp := testKey(t)
	_, _ = h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp, PublicKey: key})
	h.boxes.catOutput = map[string]string{RemindFilePath: "bob@example.com"}
	h.now = start.Add(DefaultLimits().TTL - 20*time.Minute)
	for i := 0; i < 3; i++ {
		if err := h.m.Warn(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(rem.sent) != 1 {
		t.Errorf("attempted %d times, want 1", len(rem.sent))
	}
	joined := strings.Join(logged, "\n")
	if !strings.Contains(joined, "not delivered") || strings.Contains(joined, "bob@example.com") {
		t.Errorf("log must say not delivered and mask the address: %v", logged)
	}
}

func TestReminder_DisabledAndClaimedSkipped(t *testing.T) {
	// Reminder nil: file still pre-created, nothing read or sent.
	h := newHarness(t, nil)
	start := h.now
	key, fp := testKey(t)
	res, _ := h.m.Ensure(context.Background(), EnsureRequest{Fingerprint: fp, PublicKey: key})
	fileNamed(t, h.boxes.files[res.BoxName], RemindFilePath)
	h.boxes.execs = nil
	h.boxes.catOutput = map[string]string{RemindFilePath: "x@example.com"}
	h.now = start.Add(DefaultLimits().TTL - 20*time.Minute)
	if err := h.m.Warn(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, c := range h.boxes.execs {
		if c[0] == "cat" {
			t.Errorf("reminders disabled must not read the opt-in file")
		}
	}
}

func TestMaskEmail(t *testing.T) {
	for in, want := range map[string]string{"alice@example.com": "a***@example.com", "x": "***", "@bad": "***"} {
		if got := maskEmail(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}
