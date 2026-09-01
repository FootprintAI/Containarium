package threatdetect

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

	"github.com/footprintai/containarium/internal/alert"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// webhookURLConfigKey and webhookSecretConfigKey are the exact
// DaemonConfigStore keys internal/server/alert_server.go already persists
// the operator's webhook URL/secret under — reused so operators configure
// alerting once, not once per delivery path.
const (
	webhookURLConfigKey    = "alert_webhook_url"
	webhookSecretConfigKey = "alert_webhook_secret" // #nosec G101 -- a DaemonConfigStore key NAME, not a credential value
)

const (
	notifierQueueCap    = 256
	notifierMaxAttempts = 3
	notifierHTTPTimeout = 10 * time.Second
)

// WebhookConfigSource is the subset of app.DaemonConfigStore the notifier
// needs. A structural interface (rather than depending on package app
// directly) keeps this package's dependency graph one-directional and the
// notifier table-testable with a fake.
type WebhookConfigSource interface {
	Get(ctx context.Context, key string) (string, error)
}

// Notifier is what FindingStore/MemFindingStore call after successfully
// persisting a finding. nil is valid on either store: no notifier means no
// webhook delivery (e.g. in tests that don't exercise it).
type Notifier interface {
	Notify(f *Finding)
}

// WebhookNotifier delivers MEDIUM+ findings straight to the operator's
// configured webhook — deliberately bypassing vmalert/alertmanager (design
// doc: that path needs the VictoriaMetrics container and is metrics-shaped;
// a direct POST works on any backend, including minimal BYOC hosts). It
// reuses the same webhook URL/secret config and HMAC-SHA256 signing scheme
// the existing alert-webhook relay uses, so operators configure alerting
// once.
//
// Delivery is asynchronous relative to the store write that triggers it:
// Notify enqueues onto a bounded channel and returns immediately. One
// worker goroutine drains it and does the actual HTTP POST with retry and
// backoff. A full queue or a dead webhook drops/fails deliveries (recorded
// as failed, when a DeliveryStore is wired) but never blocks the caller —
// the caller is the detection hot path, which must never stall behind a
// slow or unreachable webhook.
type WebhookNotifier struct {
	config   WebhookConfigSource
	delivery *alert.DeliveryStore // nil = attempts are logged, not persisted
	client   *http.Client
	queue    chan *Finding
}

// NewWebhookNotifier builds a notifier. config is required — without
// somewhere to read the webhook URL/secret from, the notifier can't do
// anything. delivery is optional (nil in degraded mode, when there's no
// Postgres pool to back a DeliveryStore).
func NewWebhookNotifier(config WebhookConfigSource, delivery *alert.DeliveryStore) *WebhookNotifier {
	return &WebhookNotifier{
		config:   config,
		delivery: delivery,
		client:   &http.Client{Timeout: notifierHTTPTimeout},
		queue:    make(chan *Finding, notifierQueueCap),
	}
}

// Start runs the delivery worker until ctx is done. Call once, before the
// first Notify.
func (n *WebhookNotifier) Start(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case f := <-n.queue:
				n.deliver(ctx, f)
			}
		}
	}()
}

// Notify enqueues f for delivery when its severity is MEDIUM or above.
// Non-blocking: if the queue is full the finding is dropped (and logged)
// rather than backing up the caller.
func (n *WebhookNotifier) Notify(f *Finding) {
	if f == nil || f.Severity < pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM {
		return
	}
	select {
	case n.queue <- f:
	default:
		log.Printf("threatdetect: webhook notify queue full (cap %d), dropping finding %d (rule=%s tenant=%s)",
			notifierQueueCap, f.ID, f.Rule, f.TenantID)
	}
}

func (n *WebhookNotifier) deliver(ctx context.Context, f *Finding) {
	url, err := n.config.Get(ctx, webhookURLConfigKey)
	if err != nil || url == "" {
		return // nothing configured — not an error, just nothing to do
	}
	secret, _ := n.config.Get(ctx, webhookSecretConfigKey) // optional: unsigned if absent

	body, merr := json.Marshal(f.ToProto())
	if merr != nil {
		log.Printf("threatdetect: marshal finding %d for webhook: %v", f.ID, merr)
		return
	}

	var lastErr error
	var lastStatus int
	start := time.Now()
	for attempt := 0; attempt < notifierMaxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff(attempt)):
			}
		}
		status, derr := n.postOnce(ctx, url, secret, body)
		lastStatus, lastErr = status, derr
		if derr == nil {
			break
		}
	}

	n.record(ctx, f, url, lastErr == nil, lastStatus, lastErr, len(body), time.Since(start))
}

func (n *WebhookNotifier) postOnce(ctx context.Context, url, secret string, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set("X-Containarium-Signature", signPayload(body, secret))
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

func (n *WebhookNotifier) record(ctx context.Context, f *Finding, url string, success bool, httpStatus int, deliverErr error, payloadSize int, dur time.Duration) {
	errMsg := ""
	if deliverErr != nil {
		errMsg = deliverErr.Error()
		log.Printf("threatdetect: webhook delivery failed for finding %d (rule=%s tenant=%s): %v", f.ID, f.Rule, f.TenantID, deliverErr)
	}
	if n.delivery == nil {
		return
	}
	if err := n.delivery.Record(ctx, &alert.WebhookDelivery{
		AlertName:    f.Rule.String(),
		Source:       "threatdetect",
		WebhookURL:   maskWebhookURL(url),
		Success:      success,
		HTTPStatus:   httpStatus,
		ErrorMessage: errMsg,
		PayloadSize:  payloadSize,
		DurationMs:   int(dur.Milliseconds()),
	}); err != nil {
		log.Printf("threatdetect: record webhook delivery for finding %d: %v", f.ID, err)
	}
}

// signPayload computes HMAC-SHA256 of payload using secret, in the same
// "sha256=<hex>" format internal/server/alert_server.go's signPayload uses,
// so an operator's existing signature-verification code works unmodified
// regardless of which path delivered the payload.
func signPayload(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// backoff is attempt-indexed linear backoff (attempt 1 -> 500ms, attempt 2
// -> 1s, ...) — simple and sufficient for a 3-attempt budget; no need for
// jittered exponential at this scale.
func backoff(attempt int) time.Duration {
	return time.Duration(attempt) * 500 * time.Millisecond
}

// maskWebhookURL mirrors alert_server.go's maskURL: show scheme+host, mask
// the path (which may embed a secret token). Reimplemented locally rather
// than imported — package server imports threatdetect, not the reverse.
func maskWebhookURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	parts := strings.SplitN(rawURL, "//", 2)
	if len(parts) < 2 {
		return "***"
	}
	hostPart := parts[1]
	if idx := strings.Index(hostPart, "/"); idx > 0 {
		return parts[0] + "//" + hostPart[:idx] + "/***"
	}
	return rawURL
}
