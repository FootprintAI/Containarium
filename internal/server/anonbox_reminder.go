package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/footprintai/containarium/internal/anonbox"
)

// anonReminderWebhook delivers the opt-in expiry reminder (#2206) as one
// POST to the control plane, which owns outbound email (it already sends
// signup mail). The daemon has no SMTP path — alerting is webhook-only —
// and this keeps it that way: no provider, no credentials on the anon host.
//
// Body: {"email","box_name","claim_url","expires_at"}; any 2xx is
// delivered. One attempt; the warner records it and never retries.
type anonReminderWebhook struct {
	url    string
	client *http.Client
}

func newAnonReminderWebhook(url string) *anonReminderWebhook {
	return &anonReminderWebhook{url: url, client: &http.Client{Timeout: 10 * time.Second}}
}

type anonReminderPayload struct {
	Email     string `json:"email"`
	BoxName   string `json:"box_name"`
	ClaimURL  string `json:"claim_url"`
	ExpiresAt string `json:"expires_at"`
}

// Send implements anonbox.ReminderSender.
func (w *anonReminderWebhook) Send(ctx context.Context, r anonbox.Reminder) error {
	body, err := json.Marshal(anonReminderPayload{Email: r.Email, BoxName: r.BoxName, ClaimURL: r.ClaimURL, ExpiresAt: r.ExpiresAt.UTC().Format(time.RFC3339)})
	if err != nil {
		return fmt.Errorf("encode reminder: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build reminder request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("reminder webhook: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("reminder webhook: HTTP %d", resp.StatusCode)
	}
	return nil
}
