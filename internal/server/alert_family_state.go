package server

import (
	"context"
	"log"
	"sync/atomic"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/alert"
	"github.com/footprintai/containarium/internal/app"
)

// The ContainerServer side of the alert family (#3334): the atomically
// swapped backends the alert RPCs read, the pending/not-configured answers,
// and delivery recording with the #3335 Q15 log-and-count while pending.
// Untagged, like alert_server.go; the late-install wiring is in
// alert_store_recovery.go.

const (
	// alertStoreService is the alert family's grpc.health.v1 readiness entry.
	alertStoreService = "containarium.alerts"
	alertStoreDisplay = "alert rule and webhook delivery store"

	// credentialWatchService is the credential-expiry watch's readiness entry.
	credentialWatchService = "containarium.credential_watch"
	credentialWatchDisplay = "credential-expiry watch state"
)

// errAlertsNotConfigured is the answer when alerting is not configured at
// all (no Postgres, or no VictoriaMetrics). Unchanged from before #3334.
var errAlertsNotConfigured = status.Error(codes.Unavailable, "alerting is not configured")

// errAlertsNotInstalled is the answer while the alert family is pending.
var errAlertsNotInstalled = status.Error(codes.Unavailable,
	"alert store is not available yet (Postgres unavailable at startup); it installs in-process once Postgres answers — readiness "+alertStoreService)

// alertRuleStore is what the alert RPCs read and write rules through.
type alertRuleStore interface {
	Create(ctx context.Context, rule *alert.AlertRule) (*alert.AlertRule, error)
	Get(ctx context.Context, id string) (*alert.AlertRule, error)
	List(ctx context.Context) ([]*alert.AlertRule, error)
	Update(ctx context.Context, rule *alert.AlertRule) (*alert.AlertRule, error)
	Delete(ctx context.Context, id string) error
}

// alertRuleSyncer pushes the enabled rules into vmalert.
type alertRuleSyncer interface {
	SyncRules(ctx context.Context) error
}

// alertDeliveryLog records and lists webhook delivery attempts.
type alertDeliveryLog interface {
	Record(ctx context.Context, d *alert.WebhookDelivery) error
	List(ctx context.Context, limit, offset int) ([]alert.WebhookDelivery, int, error)
}

var (
	_ alertRuleStore   = (*alert.Store)(nil)
	_ alertRuleSyncer  = (*alert.Manager)(nil)
	_ alertDeliveryLog = (*alert.DeliveryStore)(nil)
)

// alertBackends is the installed alert family, swapped in as one value so a
// caller never sees the rule store without its manager or delivery store.
// Every field is required.
type alertBackends struct {
	rules      alertRuleStore
	syncer     alertRuleSyncer
	deliveries alertDeliveryLog
}

// alertFamilyState is the ContainerServer's view of the alert family. The zero
// value is "not configured".
type alertFamilyState struct {
	live    atomic.Pointer[alertBackends]
	pending atomic.Bool
	// unrecorded counts deliveries raised while the family was pending
	// (#3335 Q15).
	unrecorded atomic.Int64
}

// loadAlerts returns the installed alert family, or nil.
func (s *ContainerServer) loadAlerts() *alertBackends { return s.alerts.live.Load() }

// alertsUnavailable is the refusal for a store-backed alert RPC when
// loadAlerts is nil: pending and not configured answer differently.
func (s *ContainerServer) alertsUnavailable() error {
	if s.alerts.pending.Load() {
		return errAlertsNotInstalled
	}
	return errAlertsNotConfigured
}

// configureAlerting sets the alert family's configuration. Called once at
// startup, before serving, whenever the family is configured — installed or
// pending — so the late install swaps only the backends.
func (s *ContainerServer) configureAlerting(webhookURL, webhookSecret string, coreServices *CoreServices, daemonConfigStore *app.DaemonConfigStore) {
	s.alertWebhookURL = webhookURL
	s.alertWebhookSecret = webhookSecret
	s.coreServices = coreServices
	// Nil-guarded: the field is an interface (daemonConfigKV), and wrapping
	// a nil *app.DaemonConfigStore would defeat every `!= nil` check.
	if daemonConfigStore != nil {
		s.daemonConfigStore = daemonConfigStore
	}
}

// setAlertsPending marks the family configured but not installed.
func (s *ContainerServer) setAlertsPending() { s.alerts.pending.Store(true) }

// installAlerts swaps the family in. Safe while serving.
func (s *ContainerServer) installAlerts(b *alertBackends) {
	s.alerts.live.Store(b)
	s.alerts.pending.Store(false)
}

// unrecordedAlertDeliveries is the Q15 count.
func (s *ContainerServer) unrecordedAlertDeliveries() int64 { return s.alerts.unrecorded.Load() }

// recordAlertDelivery records d (best-effort). While the family is pending
// the delivery is not buffered: it is logged as one structured line and
// counted (#3335 Q15). With alerting not configured it is a no-op, as before.
func (s *ContainerServer) recordAlertDelivery(ctx context.Context, d *alert.WebhookDelivery) {
	b := s.loadAlerts()
	if b == nil {
		if !s.alerts.pending.Load() {
			return
		}
		n := s.alerts.unrecorded.Add(1)
		log.Printf("alert_delivery_unrecorded store=%s state=pending alert=%q source=%q success=%t http_status=%d unrecorded_total=%d",
			alertStoreService, d.AlertName, d.Source, d.Success, d.HTTPStatus, n)
		return
	}
	if err := b.deliveries.Record(ctx, d); err != nil {
		log.Printf("Warning: failed to record delivery: %v", err)
	}
}

// recordRelayDelivery is the gateway's relay-delivery callback. The gateway
// masks the URL itself. Wired whether or not the store is installed, so a
// relay delivery reaches the store once it is.
func (s *ContainerServer) recordRelayDelivery(ctx context.Context, alertName, source, webhookURL string, success bool, httpStatus int, errMsg string, payloadSize, durationMs int) {
	s.recordAlertDelivery(ctx, &alert.WebhookDelivery{
		AlertName:    alertName,
		Source:       source,
		WebhookURL:   webhookURL,
		Success:      success,
		HTTPStatus:   httpStatus,
		ErrorMessage: errMsg,
		PayloadSize:  payloadSize,
		DurationMs:   durationMs,
	})
}
