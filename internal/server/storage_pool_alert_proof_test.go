package server

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/poolcapacity"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// #3129: prove the pool-fill alert fires, with no live backend. There is no
// PromQL engine in the module, so these tests evaluate the one expression
// shape the rule uses ("<used> / <total> * 100 >= N") against a synthetic
// series and apply the rule's `for` window the way vmalert does. An
// expression that stops matching that shape fails the parse, so a rewritten
// rule cannot slip past unevaluated.

var poolFillExpr = regexp.MustCompile(`^\s*(\w+)\s*/\s*(\w+)\s*\*\s*100\s*>=\s*(\d+)\s*$`)

type poolRule struct {
	used, total string
	threshold   float64
	forWindow   time.Duration
	severity    string
}

func loadPoolRule(t *testing.T, name string) poolRule {
	t.Helper()
	rules, err := parseDefaultAlertRules()
	if err != nil {
		t.Fatalf("DefaultAlertRules does not parse: %v", err)
	}
	for _, r := range rules {
		if r.GetName() != name {
			continue
		}
		m := poolFillExpr.FindStringSubmatch(r.GetExpr())
		if m == nil {
			t.Fatalf("%s expr %q is not the evaluable shape 'used / total * 100 >= N'", name, r.GetExpr())
		}
		th, _ := strconv.ParseFloat(m[3], 64)
		d, err := time.ParseDuration(r.GetDuration())
		if err != nil {
			t.Fatalf("%s for=%q: %v", name, r.GetDuration(), err)
		}
		return poolRule{used: m[1], total: m[2], threshold: th, forWindow: d, severity: r.GetSeverity()}
	}
	t.Fatalf("rule %s not found in DefaultAlertRules", name)
	return poolRule{}
}

type alertState int

const (
	inactive alertState = iota
	pending
	firing
)

// eval walks one series (a sample per step) and returns the state after each
// sample, following Prometheus semantics: pending from the first sample that
// satisfies the condition, firing once it has held for the `for` window, reset
// by any sample that does not satisfy it.
func (r poolRule) eval(usedBytes []float64, total float64, step time.Duration) []alertState {
	out := make([]alertState, len(usedBytes))
	var since time.Duration
	active := false
	for i, u := range usedBytes {
		at := time.Duration(i) * step
		if u/total*100 >= r.threshold {
			if !active {
				active, since = true, at
			}
			if at-since >= r.forWindow {
				out[i] = firing
			} else {
				out[i] = pending
			}
		} else {
			active = false
			out[i] = inactive
		}
	}
	return out
}

func series(n int, f func(i int) float64) []float64 {
	s := make([]float64, n)
	for i := range s {
		s[i] = f(i)
	}
	return s
}

func TestStoragePoolFillWarning_FiresOnCrossingThreshold(t *testing.T) {
	r := loadPoolRule(t, "StoragePoolFillWarning")
	const total, step = 100.0, time.Minute

	// Climbs 80 -> 84 (below), then holds at 86 for 15 minutes.
	climb := series(20, func(i int) float64 {
		if i < 5 {
			return 80 + float64(i)
		}
		return 86
	})
	got := r.eval(climb, total, step)
	for i := 0; i < 5; i++ {
		if got[i] != inactive {
			t.Errorf("sample %d (%.0f%%) = %v, want inactive", i, climb[i], got[i])
		}
	}
	if got[5] != pending {
		t.Errorf("first sample over threshold = %v, want pending", got[5])
	}
	if got[5+9] != pending {
		t.Errorf("9m over threshold = %v, want still pending (for=%v)", got[5+9], r.forWindow)
	}
	if got[5+10] != firing || got[19] != firing {
		t.Errorf("10m over threshold = %v / end = %v, want firing", got[5+10], got[19])
	}
}

func TestStoragePoolFillWarning_Boundaries(t *testing.T) {
	r := loadPoolRule(t, "StoragePoolFillWarning")
	long := func(pct float64) []alertState {
		return r.eval(series(30, func(int) float64 { return pct }), 100, time.Minute)
	}
	if got := long(84.9)[29]; got != inactive {
		t.Errorf("84.9%% held 30m = %v, want inactive", got)
	}
	if got := long(85)[29]; got != firing {
		t.Errorf("exactly 85%% held 30m = %v, want firing (>=)", got)
	}
	// A dip below the threshold resets the `for` window.
	dip := series(30, func(i int) float64 {
		if i == 7 {
			return 50
		}
		return 90
	})
	got := r.eval(dip, 100, time.Minute)
	if got[6] != pending || got[7] != inactive || got[8] != pending {
		t.Errorf("around the dip: %v %v %v, want pending inactive pending", got[6], got[7], got[8])
	}
	if got[16] != pending || got[18] != firing {
		t.Errorf("after the dip: 9m = %v, 11m = %v; window should restart at the dip", got[16], got[18])
	}
}

// The alert threshold must be the one the host reports as WARNING (#3128's
// level), so the operator is never paged at a different point than the
// status line says.
func TestStoragePoolAlertThresholdsMatchHostLevels(t *testing.T) {
	warn := loadPoolRule(t, "StoragePoolFillWarning")
	crit := loadPoolRule(t, "StoragePoolNearlyFull")
	if warn.threshold != poolcapacity.WarnPercent || crit.threshold != poolcapacity.CritPercent {
		t.Fatalf("rule thresholds %v/%v != poolcapacity %d/%d", warn.threshold, crit.threshold,
			poolcapacity.WarnPercent, poolcapacity.CritPercent)
	}
	const total = 1000
	for used := int64(0); used <= total; used++ {
		pct := float64(used) / total * 100
		level := poolcapacity.Classify(used, total)
		if (pct >= warn.threshold) != (level == incus.StoragePoolLevelWarning || level == incus.StoragePoolLevelCritical) {
			t.Fatalf("used %d/%d: warn rule over=%v but Classify=%v", used, total, pct >= warn.threshold, level)
		}
		if (pct >= crit.threshold) != (level == incus.StoragePoolLevelCritical) {
			t.Fatalf("used %d/%d: crit rule over=%v but Classify=%v", used, total, pct >= crit.threshold, level)
		}
	}
}

// The warning must reach the operator channel: with a webhook configured the
// default Alertmanager route sends every severity there, and the critical
// route does too. With none configured it goes to a null receiver, which is
// the "no operator channel" state the runbook has the operator rule out.
func TestStoragePoolAlertRoutesToOperatorWebhook(t *testing.T) {
	cs := &CoreServices{}
	cfg := cs.generateAlertmanagerConfig("https://hooks.example.com/ops")
	if !strings.Contains(cfg, "route:\n  receiver: 'webhook'") {
		t.Errorf("default route is not the webhook receiver:\n%s", cfg)
	}
	if strings.Contains(cfg, "severity: warning") && !strings.Contains(cfg, "receiver: 'webhook'") {
		t.Error("a warning-specific route bypasses the webhook")
	}
	if !strings.Contains(cfg, fmt.Sprintf("- url: '%s'", "https://hooks.example.com/ops")) {
		t.Errorf("webhook receiver lacks the operator URL:\n%s", cfg)
	}
	if null := cs.generateAlertmanagerConfig(""); !strings.Contains(null, "receiver: 'null'") {
		t.Errorf("empty webhook should produce the null receiver:\n%s", null)
	}
}
