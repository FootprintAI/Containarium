package cloud

import (
	"reflect"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/hostcheck"
)

func TestPopulateHostChecks_Posture(t *testing.T) {
	measuredAt := time.Date(2026, 1, 2, 3, 4, 5, 123, time.UTC)
	for _, tc := range []struct {
		name         string
		posture      []hostcheck.Check
		capabilityOK bool
	}{
		{"passing", []hostcheck.Check{{Name: "auditd running", OK: true, Detail: "running", Kind: hostcheck.KindPosture}}, true},
		{"failing", []hostcheck.Check{{Name: "auditd running", OK: false, Detail: "not running", Kind: hostcheck.KindPosture, Required: true}}, true},
		{"mixed", []hostcheck.Check{{Name: "auditd running", OK: true, Kind: hostcheck.KindPosture}, {Name: "Secure Boot", OK: false, Detail: "could not read", Kind: hostcheck.KindPosture}}, true},
		{"missing", nil, true},
		{"empty", []hostcheck.Check{}, true},
		{"capability failure", []hostcheck.Check{{Name: "auditd running", OK: true, Kind: hostcheck.KindPosture}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []hostcheck.Check{{Name: "useradd", OK: tc.capabilityOK, Required: true, Detail: "capability evidence"}}
			// Reusing the output must not retain a previous snapshot if the
			// next probe has no posture results.
			st := HostStatus{Posture: &HostSecurityPosture{MeasuredAt: measuredAt.Add(-time.Hour)}}
			populateHostChecks(&st, raw, tc.posture, measuredAt)
			if st.SelfCheckOK != tc.capabilityOK {
				t.Errorf("SelfCheckOK = %v, want capability result %v", st.SelfCheckOK, tc.capabilityOK)
			}
			wantLegacy := []HostCheck{{Name: "useradd", OK: tc.capabilityOK, Detail: "capability evidence"}}
			for _, c := range tc.posture {
				wantLegacy = append(wantLegacy, HostCheck{Name: "posture: " + c.Name, OK: c.OK, Detail: c.Detail})
			}
			if !reflect.DeepEqual(st.Checks, wantLegacy) {
				t.Errorf("legacy checks = %+v, want %+v", st.Checks, wantLegacy)
			}
			if len(tc.posture) == 0 {
				if st.Posture != nil {
					t.Fatalf("unmeasured posture = %+v, want nil", st.Posture)
				}
				return
			}
			if st.Posture == nil || !st.Posture.MeasuredAt.Equal(measuredAt) {
				t.Fatalf("posture measurement = %+v, want timestamp %v", st.Posture, measuredAt)
			}
			want := make([]HostCheck, 0, len(tc.posture))
			for _, c := range tc.posture {
				want = append(want, HostCheck{Name: c.Name, OK: c.OK, Detail: c.Detail})
			}
			if !reflect.DeepEqual(st.Posture.Checks, want) {
				t.Errorf("typed checks = %+v, want %+v", st.Posture.Checks, want)
			}
		})
	}
}
