package autosleep

import (
	"context"
	"encoding/json"
	"log"

	"github.com/footprintai/containarium/internal/audit"
)

// AuditStoreAdapter wraps internal/audit.Store so the autosleep package
// can record sleep events without importing the wider audit graph
// (audit_logs schema, event subscriber, …) into its core. The fields
// map is JSON-marshaled into the audit_logs.detail column so future
// queries can `WHERE action='autosleep.stopped'` and parse the detail.
type AuditStoreAdapter struct {
	Store *audit.Store
}

// Log records one sleep. Best-effort: any error is logged and dropped
// so an audit-store outage never blocks the ticker. The username field
// of the audit row uses the well-known "_system" actor to match other
// daemon-initiated actions in the table.
func (a *AuditStoreAdapter) Log(event string, fields map[string]any) {
	if a == nil || a.Store == nil {
		return
	}
	detail, _ := json.Marshal(fields)
	username, _ := fields["username"].(string)
	entry := &audit.AuditEntry{
		Username:     "_system",
		Action:       event,
		ResourceType: "container",
		ResourceID:   username,
		Detail:       string(detail),
	}
	if err := a.Store.Log(context.Background(), entry); err != nil {
		log.Printf("[autosleep] audit log: %v", err)
	}
}
