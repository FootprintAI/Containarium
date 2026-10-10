package sentinel

import (
	_ "embed"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

//go:embed status.html
var statusPageHTML string

var statusTemplate = template.Must(template.New("status").Parse(statusPageHTML))

// StatusData holds the data rendered into the status page template.
type StatusData struct {
	State          string
	SpotIP         string
	ForwardedPorts string
	PreemptCount   int
	LastPreemption string
	OutageDuration string
	CertSyncCount  int
	CertLastSync   string
	CertSyncError  string
	KeySyncCount   int
	KeyLastSync    string
	KeySyncError   string

	// Tunnel sessions by transport (tunnel_sessions_tls /
	// tunnel_sessions_cleartext on /metrics).
	TunnelSessionsTLS       int
	TunnelSessionsCleartext int
}

// StatusHandler returns an HTTP handler that renders the sentinel status page.
func StatusHandler(m *Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := StatusData{
			State:          string(m.CurrentState()),
			SpotIP:         m.SpotIP(),
			ForwardedPorts: formatPorts(m.config.ForwardedPorts),
			PreemptCount:   m.PreemptCount(),
		}

		if lp := m.LastPreemption(); !lp.IsZero() {
			data.LastPreemption = lp.Format(time.RFC3339)
		}

		if od := m.OutageDuration(); od > 0 {
			data.OutageDuration = od.Round(time.Second).String()
		}

		if m.certStore != nil {
			data.CertSyncCount = m.certStore.SyncedCount()
			if ls := m.certStore.LastSync(); !ls.IsZero() {
				data.CertLastSync = ls.Format(time.RFC3339)
			}
			if err := m.certStore.LastSyncErr(); err != nil {
				data.CertSyncError = err.Error()
			}
		}

		if m.keyStore != nil {
			data.KeySyncCount = m.keyStore.SyncedCount()
			if ls := m.keyStore.LastSync(); !ls.IsZero() {
				data.KeyLastSync = ls.Format(time.RFC3339)
			}
			if err := m.keyStore.LastSyncErr(); err != nil {
				data.KeySyncError = err.Error()
			}
		}

		if m.tunnelRegistry != nil {
			stats := m.tunnelRegistry.SessionStats()
			data.TunnelSessionsTLS = stats.TLS
			data.TunnelSessionsCleartext = stats.Cleartext
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		if err := statusTemplate.Execute(w, data); err != nil {
			log.Printf("[sentinel] status page render error: %v", err)
		}
	}
}

func formatPorts(ports []int) string {
	if len(ports) == 0 {
		return "none"
	}
	strs := make([]string, len(ports))
	for i, p := range ports {
		strs[i] = strconv.Itoa(p)
	}
	return strings.Join(strs, ", ")
}
