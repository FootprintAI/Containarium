package server

import (
	"context"
	"fmt"

	otelmetric "go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/footprintai/containarium/internal/bridgedns"
)

// Bridge-DNS gauges (#2194). The OTel names use dots; VictoriaMetrics stores
// them with underscores (see the *Series constants), which is what the
// built-in alert rules query. Both spellings live here so the rules and the
// recorder cannot drift apart (bridge_dns_metrics_test.go pins that).
const (
	bridgeDNSInSyncName          = "bridge_dns.in_sync"
	bridgeDNSDriftRoundsName     = "bridge_dns.drift_passes"
	bridgeDNSLastRoundName       = "bridge_dns.last_pass_timestamp"
	bridgeDNSLastAppliedName     = "bridge_dns.last_applied_timestamp"
	bridgeDNSInSyncSeries        = "bridge_dns_in_sync"
	bridgeDNSDriftRoundsSeries   = "bridge_dns_drift_passes"
	bridgeDNSLastRoundSeries     = "bridge_dns_last_pass_timestamp"
	bridgeDNSLastAppliedSeries   = "bridge_dns_last_applied_timestamp"
	bridgeDNSOutOfSyncFor        = "10m"
	bridgeDNSStaleSeconds        = 300
	bridgeDNSStaleFor            = "5m"
	bridgeDNSDriftRepeatingLimit = 3
)

// bridgeDNSRecorder turns the reconciler's per-pass Status into gauges.
// Nothing is recorded before the first pass finishes, and a host that does
// not run the reconciler never builds one, so such hosts export no series
// and no alert can fire on them.
type bridgeDNSRecorder struct {
	inSync, driftPasses, lastPass, lastApplied otelmetric.Int64Gauge
}

func newBridgeDNSRecorder(provider *sdkmetric.MeterProvider) (*bridgeDNSRecorder, error) {
	meter := provider.Meter("containarium.bridgedns")
	r := &bridgeDNSRecorder{}
	for _, g := range []struct {
		dst  *otelmetric.Int64Gauge
		name string
		desc string
		unit string
	}{
		{&r.inSync, bridgeDNSInSyncName, "1 if the bridge held the desired DNS record at the end of the last reconcile pass, else 0", ""},
		{&r.driftPasses, bridgeDNSDriftRoundsName, "Reconcile passes that found the bridge DNS record drifted (monotonic per process)", ""},
		{&r.lastPass, bridgeDNSLastRoundName, "Unix time the last bridge DNS reconcile pass finished", "s"},
		{&r.lastApplied, bridgeDNSLastAppliedName, "Unix time of the last successful bridge DNS record rewrite", "s"},
	} {
		opts := []otelmetric.Int64GaugeOption{otelmetric.WithDescription(g.desc)}
		if g.unit != "" {
			opts = append(opts, otelmetric.WithUnit(g.unit))
		}
		gauge, err := meter.Int64Gauge(g.name, opts...)
		if err != nil {
			return nil, fmt.Errorf("bridgedns metrics: %s: %w", g.name, err)
		}
		*g.dst = gauge
	}
	return r, nil
}

// record is the reconciler's OnPass hook.
//
// in_sync is not recorded while the record is Absent: the operator has opted
// out of creating it (#2232), which is a state, not a fault, and a critical
// "out of sync" for it would page on every such host. The pass timestamp is
// still recorded, so a stopped loop is still caught.
func (r *bridgeDNSRecorder) record(st bridgedns.Status) {
	ctx := context.Background()
	if st.LastPass.IsZero() {
		return // nothing finished yet
	}
	if !st.Absent {
		v := int64(0)
		if st.InSync {
			v = 1
		}
		r.inSync.Record(ctx, v)
	}
	r.driftPasses.Record(ctx, int64(st.DriftCount))
	r.lastPass.Record(ctx, st.LastPass.Unix())
	if !st.LastApplied.IsZero() {
		r.lastApplied.Record(ctx, st.LastApplied.Unix())
	}
}

// attachBridgeDNSMetrics hooks the reconciler's passes to gauges on provider.
// No-op when either is nil (no reconciler on this host, or no metrics
// pipeline).
func attachBridgeDNSMetrics(rec *bridgedns.Reconciler, provider *sdkmetric.MeterProvider) error {
	if rec == nil || provider == nil {
		return nil
	}
	r, err := newBridgeDNSRecorder(provider)
	if err != nil {
		return err
	}
	rec.SetOnPass(r.record)
	return nil
}

// bridgeDNSAlertRules is the vmalert group for the bridge DNS record, built
// from the series constants above and appended to DefaultAlertRules.
func bridgeDNSAlertRules() string {
	return fmt.Sprintf(`
  - name: bridge_dns_alerts
    interval: 30s
    rules:
      - alert: BridgeDNSOutOfSync
        expr: %[1]s == 0
        for: %[2]s
        labels:
          severity: critical
          source: default
        annotations:
          summary: "Bridge DNS record is out of sync"
          description: "The Incus bridge's raw.dnsmasq record has not matched core-caddy's address for more than 10 minutes, so boxes on the bridge may resolve the base domain to an address that does not answer. Run 'containarium bridge-dns status' for the reason."

      - alert: BridgeDNSReconcilerStale
        expr: time() - %[3]s > %[4]d
        for: %[5]s
        labels:
          severity: warning
          source: default
        annotations:
          summary: "Bridge DNS reconciler has stopped"
          description: "No bridge DNS reconcile pass has finished for more than 5 minutes (passes run at least every minute). The loop has stopped or is wedged; a drifted record will not be repaired."

      - alert: BridgeDNSDriftRepeating
        expr: increase(%[6]s[1h]) > %[7]d
        labels:
          severity: warning
          source: default
        annotations:
          summary: "Bridge DNS record keeps drifting"
          description: "The bridge DNS record was found drifted more than %[7]d times in the last hour. Each drift is repaired, but something keeps changing it (a hand edit, a second daemon)."
`, bridgeDNSInSyncSeries, bridgeDNSOutOfSyncFor,
		bridgeDNSLastRoundSeries, bridgeDNSStaleSeconds, bridgeDNSStaleFor,
		bridgeDNSDriftRoundsSeries, bridgeDNSDriftRepeatingLimit)
}
