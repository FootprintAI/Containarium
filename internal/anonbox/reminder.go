package anonbox

import (
	"context"
	"net/mail"
	"strings"
	"time"

	"github.com/footprintai/containarium/pkg/core/box"
)

// Opt-in expiry reminder (#2206, decision on #2204: contact capture is
// opt-in only). A process inside the box has no daemon credential, so
// `containarium remind-me <email>` writes RemindFilePath — a file the
// daemon pre-creates world-writable at provision time — and the warner
// reads it on its tick inside the last ReminderBefore of the TTL. A
// non-empty, valid address is copied to LabelRemindEmail, a FunnelReminderOptIn
// is recorded, the reminder is handed to Config.Reminder exactly once, and
// the address label is cleared again: nothing about the user outlives the
// one delivery.
const (
	RemindFilePath   = "/etc/containarium/remind-me"
	LabelRemindEmail = "anon.remind_email" // set only between pickup and delivery
	LabelReminded    = "anon.reminded"     // RFC3339 of the one attempt; "" = not yet
	ReminderBefore   = 30 * time.Minute
)

// FunnelReminderOptIn is recorded once when an opt-in is picked up.
const FunnelReminderOptIn FunnelKind = "reminder_optin"

// Reminder is one delivery request.
type Reminder struct {
	Email     string
	BoxName   string
	ClaimURL  string // "<base>?token=…" or the bare token when no base is configured
	ExpiresAt time.Time
}

// ReminderSender delivers a Reminder. The daemon's implementation POSTs it
// to the control plane's webhook; nil = reminders disabled (the file is
// still pre-created so `remind-me` works, but nothing is ever sent).
type ReminderSender interface {
	Send(ctx context.Context, r Reminder) error
}

// remind runs on the warner tick for one unclaimed box: inside the last
// ReminderBefore, read the opt-in file and act on it once.
func (m *Manager) remind(ctx context.Context, name string, labels map[string]string, expiresAt time.Time, now time.Time) {
	if m.cfg.Reminder == nil || labels[LabelReminded] != "" {
		return
	}
	if expiresAt.Sub(now) > ReminderBefore {
		return
	}
	ref := boxRefFor(name)
	raw, stderr, err := m.boxes.Exec(ctx, ref, []string{"cat", RemindFilePath})
	if err != nil {
		// No file (or no agent): nothing to do this tick; the next one looks again.
		_ = stderr
		return
	}
	email := strings.TrimSpace(raw)
	if email == "" {
		return
	}
	if _, err := mail.ParseAddress(email); err != nil {
		m.cfg.Logf("[anonbox] %s: remind-me address %q is not valid; ignoring", name, email)
		m.markReminded(ctx, ref, now, "")
		return
	}

	// Pick up: label + funnel, then deliver once.
	if err := m.boxes.SetMeta(ctx, ref, map[string]string{LabelRemindEmail: email}); err != nil {
		m.cfg.Logf("[anonbox] %s: could not record remind-me opt-in: %v", name, err)
	}
	m.record(FunnelEvent{Kind: FunnelReminderOptIn, FPHash: labels[LabelFPHash], BoxName: name})

	claimURL := ""
	if m.cfg.ClaimSecret != nil {
		if u, err := m.claimURL(name, labels[LabelClaimTokenID], expiresAt); err == nil {
			claimURL = u
		} else {
			m.cfg.Logf("[anonbox] %s: could not re-mint the claim link for the reminder: %v", name, err)
		}
	}
	if err := m.cfg.Reminder.Send(ctx, Reminder{Email: email, BoxName: name, ClaimURL: claimURL, ExpiresAt: expiresAt}); err != nil {
		m.cfg.Logf("[anonbox] %s: expiry reminder to %s not delivered: %v", name, maskEmail(email), err)
	} else {
		m.cfg.Logf("[anonbox] %s: expiry reminder sent to %s", name, maskEmail(email))
	}
	// Used once either way: clear the address, record the attempt.
	m.markReminded(ctx, ref, now, email)
}

func (m *Manager) markReminded(ctx context.Context, ref box.BoxRef, now time.Time, email string) {
	meta := map[string]string{LabelReminded: now.UTC().Format(time.RFC3339)}
	if email != "" {
		meta[LabelRemindEmail] = ""
	}
	if err := m.boxes.SetMeta(ctx, ref, meta); err != nil {
		m.cfg.Logf("[anonbox] %s: could not record the reminder attempt: %v", ref.Name, err)
	}
}

// maskEmail keeps logs free of addresses: "a***@example.com".
func maskEmail(e string) string {
	at := strings.Index(e, "@")
	if at <= 0 {
		return "***"
	}
	return e[:1] + "***" + e[at:]
}

// reminderGuestFile is what provision pre-creates so an unprivileged user
// inside the box can opt in by writing to it.
func reminderGuestFile() (path, mode string, content []byte) {
	return RemindFilePath, "0666", []byte("")
}
