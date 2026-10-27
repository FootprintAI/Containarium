package zap

import (
	"context"
	"errors"
	"testing"
)

// With ZAP missing, a scan request must fail before touching the store
// (store is nil: any CreateScanRun/EnqueueScanJob call would panic).
func TestRunScan_PreflightRejectsWhenZapNotInstalled(t *testing.T) {
	m := &Manager{zapInstalled: func() bool { return false }}
	id, err := m.RunScan(context.Background(), "manual", "")
	if !errors.Is(err, ErrZapNotInstalled) {
		t.Fatalf("err = %v, want ErrZapNotInstalled", err)
	}
	if id != "" {
		t.Fatalf("scan run id = %q, want empty", id)
	}
}

func TestRunScanCycle_SkipsWhenZapNotInstalled(t *testing.T) {
	m := &Manager{zapInstalled: func() bool { return false }}
	m.runScanCycle(context.Background()) // must not panic on nil store
}
