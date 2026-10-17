package security

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeScanBox stands in for the security container: `ls` lists the mount and
// `clamdscan` returns the configured outcome.
type fakeScanBox struct {
	lsOut               string
	scanOut, scanErrOut string
	scanErr             error
	scanned             bool
}

func (f *fakeScanBox) ExecWithOutput(_ string, cmd []string) (string, string, error) {
	switch cmd[0] {
	case "ls":
		return f.lsOut, "", nil
	case "clamdscan":
		f.scanned = true
		return f.scanOut, f.scanErrOut, f.scanErr
	}
	return "", "", errors.New("unexpected command " + cmd[0])
}

// fakeScanDevices records mount/unmount calls.
type fakeScanDevices struct {
	added, removed []string
	addErr         error
}

func (f *fakeScanDevices) Remove(_ context.Context, device string) (string, error) {
	f.removed = append(f.removed, device)
	return "", nil
}

func (f *fakeScanDevices) Add(_ context.Context, device, _, _ string) (string, error) {
	f.added = append(f.added, device)
	return "boom", f.addErr
}

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

func newTestScanner(box *fakeScanBox, dev *fakeScanDevices, rep *fakeReports, hook *[]hookCall) *Scanner {
	zero := time.Duration(0)
	s := &Scanner{execer: box, devices: dev, reports: rep, settle: &zero, storagePool: "default"}
	s.SetScanResultHook(func(c, u, st string) { *hook = append(*hook, hookCall{c, u, st}) })
	return s
}

// #2589 / #2496: an incomplete clamdscan run must never be persisted or
// handed to the quarantine hook as clean, proven at the ScanContainer level
// (TestClassifyClamScan covers the classifier alone).
func TestScanContainer_PersistsAndReportsTheClassifiedStatus(t *testing.T) {
	exit1 := errors.New("command exited with code 1")
	exit2 := errors.New("command exited with code 2")
	found := "/mnt/scan-x/a: Eicar-Test-Signature FOUND\n"
	for _, tc := range []struct {
		name         string
		out, errOut  string
		err          error
		wantStatus   string
		wantCount    int
		wantFindings string // substring
	}{
		{"exit 0 is clean", "", "", nil, ScanStatusClean, 0, ""},
		{"exit 1 with FOUND is infected", found, "", exit1, ScanStatusInfected, 1, "Eicar-Test-Signature FOUND"},
		{"exit 2 without FOUND is incomplete", "", "ERROR: Can't access file", exit2, ScanStatusIncomplete, 0, "code 2"},
		{"exit 2 with FOUND is still infected", found, "WARNING: x", exit2, ScanStatusInfected, 1, "Eicar-Test-Signature FOUND"},
		{"exec failure is incomplete", "", "", errors.New("failed to execute command"), ScanStatusIncomplete, 0, "failed to execute command"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			box := &fakeScanBox{lsOut: "bin\netc\n", scanOut: tc.out, scanErrOut: tc.errOut, scanErr: tc.err}
			dev, rep := &fakeScanDevices{}, &fakeReports{}
			var hook []hookCall
			s := newTestScanner(box, dev, rep, &hook)

			if err := s.ScanContainer(context.Background(), "alice-container", "alice"); err != nil {
				t.Fatalf("ScanContainer: %v", err)
			}
			if len(rep.saved) != 1 {
				t.Fatalf("saved %d reports, want 1", len(rep.saved))
			}
			r := rep.saved[0]
			if r.Status != tc.wantStatus || r.FindingsCount != tc.wantCount {
				t.Errorf("saved status/count = %q/%d, want %q/%d", r.Status, r.FindingsCount, tc.wantStatus, tc.wantCount)
			}
			if !strings.Contains(r.Findings, tc.wantFindings) {
				t.Errorf("saved findings %q missing %q", r.Findings, tc.wantFindings)
			}
			if r.ContainerName != "alice-container" || r.Username != "alice" {
				t.Errorf("saved identity = %q/%q", r.ContainerName, r.Username)
			}
			want := hookCall{"alice-container", "alice", tc.wantStatus}
			if len(hook) != 1 || hook[0] != want {
				t.Errorf("hook calls = %+v, want exactly %+v", hook, want)
			}
			if tc.wantStatus == ScanStatusIncomplete && hook[0].status == ScanStatusClean {
				t.Error("an incomplete scan reached the quarantine hook as clean")
			}
			// The scan device is always removed again.
			if len(dev.added) != 1 || len(dev.removed) < 2 {
				t.Errorf("devices added=%v removed=%v, want one add and a stale + a cleanup remove", dev.added, dev.removed)
			}
		})
	}
}

// Failures before or after the scan must not produce a verdict at all.
func TestScanContainer_NoVerdictWhenTheScanCannotRun(t *testing.T) {
	t.Run("mount fails", func(t *testing.T) {
		box := &fakeScanBox{lsOut: "bin\n"}
		dev, rep := &fakeScanDevices{addErr: errors.New("exit status 1")}, &fakeReports{}
		var hook []hookCall
		err := newTestScanner(box, dev, rep, &hook).ScanContainer(context.Background(), "c", "u")
		if err == nil || !strings.Contains(err.Error(), "failed to mount rootfs") {
			t.Fatalf("err = %v, want a mount failure", err)
		}
		if box.scanned || len(rep.saved) != 0 || len(hook) != 0 {
			t.Errorf("scanned=%v saved=%d hook=%d, want nothing", box.scanned, len(rep.saved), len(hook))
		}
	})
	t.Run("empty mount is an error, not a clean scan", func(t *testing.T) {
		box := &fakeScanBox{lsOut: "  \n"}
		dev, rep := &fakeScanDevices{}, &fakeReports{}
		var hook []hookCall
		err := newTestScanner(box, dev, rep, &hook).ScanContainer(context.Background(), "c", "u")
		if err == nil || !strings.Contains(err.Error(), "is empty") {
			t.Fatalf("err = %v, want an empty-mount error", err)
		}
		if box.scanned || len(rep.saved) != 0 || len(hook) != 0 {
			t.Errorf("scanned=%v saved=%d hook=%d, want nothing", box.scanned, len(rep.saved), len(hook))
		}
		if len(dev.removed) < 2 {
			t.Errorf("device not cleaned up after an empty mount: removed=%v", dev.removed)
		}
	})
	t.Run("a report that cannot be saved is not announced", func(t *testing.T) {
		box := &fakeScanBox{lsOut: "bin\n"}
		dev, rep := &fakeScanDevices{}, &fakeReports{saveErr: errors.New("db down")}
		var hook []hookCall
		err := newTestScanner(box, dev, rep, &hook).ScanContainer(context.Background(), "c", "u")
		if err == nil || !strings.Contains(err.Error(), "failed to save report") {
			t.Fatalf("err = %v, want a save failure", err)
		}
		if len(hook) != 0 {
			t.Errorf("hook called %v although the verdict was not persisted", hook)
		}
	})
}
