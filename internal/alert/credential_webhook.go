package alert

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// WebhookURLConfigKey and WebhookSecretConfigKey are the DaemonConfigStore
// keys internal/server/alert_server.go persists the operator's webhook
// URL/secret under (and internal/threatdetect/notifier.go reads) — reused so
// an operator configures alerting once for every delivery path.
const (
	WebhookURLConfigKey    = "alert_webhook_url"
	WebhookSecretConfigKey = "alert_webhook_secret" // #nosec G101 -- a config key NAME, not a credential value
)

const (
	credentialWebhookMaxAttempts = 3
	credentialWebhookHTTPTimeout = 10 * time.Second
)

// WebhookConfigSource is the subset of app.DaemonConfigStore the notifier
// reads (structural, so this package does not import package app).
type WebhookConfigSource interface {
	Get(ctx context.Context, key string) (string, error)
}

// CredentialWebhookNotifier POSTs a CredentialExpiredAlert to the operator's
// configured webhook, signed with the same "sha256=<hex>" HMAC header the
// alert relay and the threat-detection notifier send, retried a bounded
// number of times, and recorded in webhook_deliveries when a DeliveryStore
// is wired. Delivery is synchronous: its only caller is the watcher's own
// background sweep.
type CredentialWebhookNotifier struct {
	config   WebhookConfigSource
	delivery *DeliveryStore // nil = attempts are logged, not persisted
	client   *http.Client
	backoff  func(attempt int) time.Duration
}

// NewCredentialWebhookNotifier builds the notifier. delivery may be nil.
func NewCredentialWebhookNotifier(config WebhookConfigSource, delivery *DeliveryStore) *CredentialWebhookNotifier {
	return &CredentialWebhookNotifier{
		config:   config,
		delivery: delivery,
		client:   &http.Client{Timeout: credentialWebhookHTTPTimeout},
		backoff:  func(attempt int) time.Duration { return time.Duration(attempt) * 500 * time.Millisecond },
	}
}

// NotifyCredentialExpired delivers a. No webhook configured is a no-op.
func (n *CredentialWebhookNotifier) NotifyCredentialExpired(ctx context.Context, a CredentialExpiredAlert) {
	url, err := n.config.Get(ctx, WebhookURLConfigKey)
	if err != nil || url == "" {
		log.Printf("[credential-watch] %s for %s: no operator webhook configured, not delivered", CredentialExpiredAlertName, a.Box)
		return
	}
	secret, _ := n.config.Get(ctx, WebhookSecretConfigKey) // optional: unsigned if absent

	body, merr := json.Marshal(a)
	if merr != nil {
		log.Printf("[credential-watch] marshal alert for %s: %v", a.Box, merr)
		return
	}

	var lastErr error
	var lastStatus int
	start := time.Now()
	for attempt := 0; attempt < credentialWebhookMaxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(n.backoff(attempt)):
			}
		}
		lastStatus, lastErr = n.postOnce(ctx, url, secret, body)
		if lastErr == nil {
			break
		}
	}

	errMsg := ""
	if lastErr != nil {
		errMsg = lastErr.Error()
		log.Printf("[credential-watch] webhook delivery failed for %s: %v", a.Box, lastErr)
	}
	if n.delivery == nil {
		return
	}
	if rerr := n.delivery.Record(ctx, &WebhookDelivery{
		AlertName:    CredentialExpiredAlertName,
		Source:       credentialWatchDeliverySource,
		WebhookURL:   maskWebhookURL(url),
		Success:      lastErr == nil,
		HTTPStatus:   lastStatus,
		ErrorMessage: errMsg,
		PayloadSize:  len(body),
		DurationMs:   int(time.Since(start).Milliseconds()),
	}); rerr != nil {
		log.Printf("[credential-watch] record webhook delivery for %s: %v", a.Box, rerr)
	}
}

func (n *CredentialWebhookNotifier) postOnce(ctx context.Context, url, secret string, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		req.Header.Set("X-Containarium-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

// maskWebhookURL keeps scheme+host and masks the path, which may embed a
// token — the same masking alert_server.go and threatdetect apply.
func maskWebhookURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	parts := strings.SplitN(rawURL, "//", 2)
	if len(parts) < 2 {
		return "***"
	}
	if idx := strings.Index(parts[1], "/"); idx > 0 {
		return parts[0] + "//" + parts[1][:idx] + "/***"
	}
	return rawURL
}
