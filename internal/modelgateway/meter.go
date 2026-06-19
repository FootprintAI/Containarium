package modelgateway

import (
	"sort"
	"sync"
)

// meterKey attributes usage to a tenant/skill/provider/model.
type meterKey struct {
	tenant, skill, provider, model string
}

// MeterRow is a snapshot of one attribution bucket.
type MeterRow struct {
	Tenant       string `json:"tenant"`
	Skill        string `json:"skill,omitempty"`
	Provider     string `json:"provider"`
	Model        string `json:"model"`
	Calls        int64  `json:"calls"`
	InputTokens  int64  `json:"input_tokens"`
	OutputTokens int64  `json:"output_tokens"`
	CachedTokens int64  `json:"cached_tokens"`
}

// Meter is the in-memory per-tenant model-token writer the metering plane lacks
// today. Prototype: in-memory only; production writes the same shape into
// usage_rollups (see the design note's "metering/billing fit").
type Meter struct {
	mu   sync.Mutex
	rows map[meterKey]*MeterRow
}

// NewMeter returns an empty Meter.
func NewMeter() *Meter { return &Meter{rows: map[meterKey]*MeterRow{}} }

func (m *Meter) record(tenant, skill, provider string, u Usage) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := meterKey{tenant, skill, provider, u.Model}
	r := m.rows[k]
	if r == nil {
		r = &MeterRow{Tenant: tenant, Skill: skill, Provider: provider, Model: u.Model}
		m.rows[k] = r
	}
	r.Calls++
	r.InputTokens += u.InputTokens
	r.OutputTokens += u.OutputTokens
	r.CachedTokens += u.CachedTokens
}

// Snapshot returns the rollups in a stable order.
func (m *Meter) Snapshot() []MeterRow {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]MeterRow, 0, len(m.rows))
	for _, r := range m.rows {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Tenant != out[j].Tenant {
			return out[i].Tenant < out[j].Tenant
		}
		if out[i].Provider != out[j].Provider {
			return out[i].Provider < out[j].Provider
		}
		return out[i].Model < out[j].Model
	})
	return out
}
