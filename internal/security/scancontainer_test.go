package security

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeReports struct {
	saved   []*Report
	saveErr error
}

func (f *fakeReports) SaveReport(_ context.Context, r *Report) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	cp := *r
	f.saved = append(f.saved, &cp)
	return nil
}

type hookCall struct{ container, username, status string }

func newTestScanner(rep *fakeReports, hook *[]hookCall) *Scanner {
	s := &Scanner{reports: rep}
	s.SetScanResultHook(func(c, u, st string) { *hook = append(*hook, hookCall{c, u, st}) })
	return s
}

// #2631: until the in-box runner exists, a requested scan records an honest
// `incomplete` report. It must never be persisted or handed to the quarantine
// hook as clean (#2496, #2589).
func TestScanContainer_RecordsIncompleteNeverClean(t *testing.T) {
	var hook []hookCall
	rep := &fakeReports{}
	s := newTestScanner(rep, &hook)

	if err := s.ScanContainer(context.Background(), "alice-container", "alice"); err != nil {
		t.Fatalf("ScanContainer: %v", err)
	}
	if len(rep.saved) != 1 {
		t.Fatalf("saved %d reports, want 1", len(rep.saved))
	}
	r := rep.saved[0]
	if r.Status != ScanStatusIncomplete || r.ContainerName != "alice-container" || r.Username != "alice" {
		t.Fatalf("report = %+v, want incomplete for alice-container", r)
	}
	if r.Status == ScanStatusClean || r.FindingsCount != 0 {
		t.Fatalf("must not look clean or carry findings: %+v", r)
	}
	if !strings.Contains(r.Findings, "#2631") {
		t.Errorf("reason should name #2631, got %q", r.Findings)
	}
	if len(hook) != 1 || hook[0].status != ScanStatusIncomplete {
		t.Fatalf("hook = %+v, want one incomplete call", hook)
	}
}

func TestScanContainer_SaveFailureIsAnError(t *testing.T) {
	var hook []hookCall
	rep := &fakeReports{saveErr: errors.New("db down")}
	s := newTestScanner(rep, &hook)

	if err := s.ScanContainer(context.Background(), "alice-container", "alice"); err == nil {
		t.Fatal("a report that could not be saved must fail the job")
	}
	if len(hook) != 0 {
		t.Fatalf("hook must not fire when nothing was recorded: %+v", hook)
	}
}

// The principle behind #2631: the platform must not mount a tenant's rootfs
// into any platform container to scan it. Guard it at the source level so a
// later change cannot quietly bring the disk-device path back.
func TestSecurityPackageNeverMountsTenantRootfs(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		for _, bad := range []string{`"device", "add"`, "storage-pools", "/rootfs", "readonly=true"} {
			if strings.Contains(src, bad) {
				t.Errorf("%s contains %q: tenant rootfs must not be mounted into a platform container (#2631)", f, bad)
			}
		}
	}
}
