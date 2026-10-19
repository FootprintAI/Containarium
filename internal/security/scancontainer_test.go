package security

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
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

// fakeTenantBox stands in for the tenant's container. Each scripted exec is keyed by
// a substring of the joined argv.
type fakeTenantBox struct {
	info    *incus.ContainerInfo
	infoErr error

	hasClamscan   bool
	hasSignatures bool
	version       string
	scanOut       string
	scanCode      int
	scanErr       error
	scanArgv      []string
	execs         [][]string
}

func (f *fakeTenantBox) GetContainer(string) (*incus.ContainerInfo, error) { return f.info, f.infoErr }

func (f *fakeTenantBox) ExecWithExitCode(_ string, cmd []string) (string, string, int, error) {
	f.execs = append(f.execs, cmd)
	j := strings.Join(cmd, " ")
	switch {
	case strings.Contains(j, "command -v clamscan"):
		if f.hasClamscan {
			return "/usr/bin/clamscan\n", "", 0, nil
		}
		return "", "", 1, nil
	case strings.Contains(j, "/var/lib/clamav"):
		if f.hasSignatures {
			return "", "", 0, nil
		}
		return "", "", 2, nil
	case strings.HasSuffix(j, "--version") && cmd[0] == "clamscan":
		return f.version + "\nsecond line\n", "", 0, nil
	case cmd[0] == "timeout":
		f.scanArgv = cmd
		return f.scanOut, "", f.scanCode, f.scanErr
	}
	return "", "", 0, errors.New("unexpected command " + j)
}

func readyTenantBox() *fakeTenantBox {
	return &fakeTenantBox{
		info:          &incus.ContainerInfo{Name: "alice-container", State: "Running", Memory: "4GB"},
		hasClamscan:   true,
		hasSignatures: true,
		version:       "ClamAV 1.0.7/27123/Sun Oct 18",
	}
}

func newTestScanner(box *fakeTenantBox, rep *fakeReports, hook *[]hookCall) *Scanner {
	s := &Scanner{box: box, reports: rep, timeout: time.Minute}
	s.SetScanResultHook(func(c, u, st string) { *hook = append(*hook, hookCall{c, u, st}) })
	return s
}

func runScan(t *testing.T, box *fakeTenantBox) (*Report, []hookCall) {
	t.Helper()
	var hook []hookCall
	rep := &fakeReports{}
	if err := newTestScanner(box, rep, &hook).ScanContainer(context.Background(), "alice-container", "alice"); err != nil {
		t.Fatalf("ScanContainer: %v", err)
	}
	if len(rep.saved) != 1 {
		t.Fatalf("saved %d reports, want 1", len(rep.saved))
	}
	return rep.saved[0], hook
}

func TestScanContainer_Outcomes(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*fakeTenantBox)
		wantStatus string
		wantInText string // substring expected in Findings (the reason / version / signatures)
		wantCount  int
		wantScan   bool // whether clamscan itself must have been run
	}{
		{"clean run records only the scanner version", func(b *fakeTenantBox) {}, ScanStatusClean, "ClamAV 1.0.7/27123/Sun Oct 18", 0, true},
		{"infected keeps signature names and counts, not paths", func(b *fakeTenantBox) {
			b.scanCode = 1
			b.scanOut = "/home/alice/secret plans/a.exe: Win.Test.EICAR_HDB-1 FOUND\n/home/alice/b.com: Win.Test.EICAR_HDB-1 FOUND\n/tmp/x: Eicar-Signature FOUND\n"
		}, ScanStatusInfected, "Win.Test.EICAR_HDB-1 (2)", 3, true},
		{"scan error is incomplete", func(b *fakeTenantBox) { b.scanCode = 2 }, ScanStatusIncomplete, "scan error", 0, true},
		{"killed (OOM) is incomplete", func(b *fakeTenantBox) { b.scanCode = 137 }, ScanStatusIncomplete, "out of memory", 0, true},
		{"timeout is incomplete", func(b *fakeTenantBox) { b.scanCode = 124 }, ScanStatusIncomplete, "timed out", 0, true},
		{"unknown exit code is incomplete", func(b *fakeTenantBox) { b.scanCode = 77 }, ScanStatusIncomplete, "77", 0, true},
		{"exec failure is incomplete", func(b *fakeTenantBox) { b.scanErr = errors.New("socket wedged") }, ScanStatusIncomplete, "socket wedged", 0, true},
		{"stopped box is incomplete and not scanned", func(b *fakeTenantBox) { b.info.State = "Stopped" }, ScanStatusIncomplete, "not running", 0, false},
		{"under 4 GB is unsupported_size and not scanned", func(b *fakeTenantBox) { b.info.Memory = "2GB" }, ScanStatusUnsupportedSize, "below the 4 GB", 0, false},
		{"clamscan missing is not_installed", func(b *fakeTenantBox) { b.hasClamscan = false }, ScanStatusNotInstalled, "not installed", 0, false},
		{"signatures missing is not_installed", func(b *fakeTenantBox) { b.hasSignatures = false }, ScanStatusNotInstalled, "signatures", 0, false},
		{"lookup failure is incomplete", func(b *fakeTenantBox) { b.infoErr = errors.New("no such box") }, ScanStatusIncomplete, "no such box", 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			box := readyTenantBox()
			tc.mutate(box)
			r, hook := runScan(t, box)
			if r.Status != tc.wantStatus {
				t.Fatalf("status = %q, want %q (findings %q)", r.Status, tc.wantStatus, r.Findings)
			}
			if !strings.Contains(r.Findings, tc.wantInText) {
				t.Errorf("findings %q should contain %q", r.Findings, tc.wantInText)
			}
			if r.FindingsCount != tc.wantCount {
				t.Errorf("findings count = %d, want %d", r.FindingsCount, tc.wantCount)
			}
			if (box.scanArgv != nil) != tc.wantScan {
				t.Errorf("clamscan ran = %v, want %v", box.scanArgv != nil, tc.wantScan)
			}
			if r.Status != ScanStatusClean && len(hook) == 1 && hook[0].status == ScanStatusClean {
				t.Fatalf("a %q outcome reached the hook as clean", r.Status)
			}
			if len(hook) != 1 || hook[0].status != r.Status {
				t.Fatalf("hook = %+v, want one call with %q", hook, r.Status)
			}
			if strings.Contains(r.Findings, "/home/") || strings.Contains(r.Findings, "secret plans") {
				t.Errorf("a file path leaked into the stored report: %q", r.Findings)
			}
		})
	}
}

func TestScanContainer_SaveFailureIsAnError(t *testing.T) {
	var hook []hookCall
	rep := &fakeReports{saveErr: errors.New("db down")}
	s := newTestScanner(readyTenantBox(), rep, &hook)
	if err := s.ScanContainer(context.Background(), "alice-container", "alice"); err == nil {
		t.Fatal("a report that could not be saved must fail the job")
	}
	if len(hook) != 0 {
		t.Fatalf("hook must not fire when nothing was recorded: %+v", hook)
	}
}

// The scan must run as the unprivileged nobody user with only the read-bypass
// capability, bounded by timeout, over the whole filesystem minus pseudo-fs —
// also for a privileged box, where it must never run as in-box root.
func TestInBoxScanCommand_DropsPrivilegeAndKeepsReadOnly(t *testing.T) {
	box := readyTenantBox()
	box.info.Memory = "8GiB"
	if _, _ = runScan(t, box); box.scanArgv == nil {
		t.Fatal("scan did not run")
	}
	j := strings.Join(box.scanArgv, " ")
	for _, want := range []string{
		"timeout 60 setpriv", "--reuid=65534", "--regid=65534", "--clear-groups",
		"--inh-caps=+dac_read_search", "--ambient-caps=+dac_read_search",
		"clamscan -r -i --no-summary --stdout", "--exclude-dir=^/proc", "--exclude-dir=^/sys", "--exclude-dir=^/dev", "--exclude-dir=^/run", " /",
	} {
		if !strings.Contains(j, want) {
			t.Errorf("scan argv %q is missing %q", j, want)
		}
	}
	for _, bad := range []string{"--reuid=0", "dac_override", "sys_admin", "--no-clear-groups", "--remove"} {
		if strings.Contains(j, bad) {
			t.Errorf("scan argv %q must not contain %q", j, bad)
		}
	}
}

func TestParseMemoryAndBoxTooSmall(t *testing.T) {
	small := []string{"2GB", "3500MB", "3GiB", "512MiB", "3999999999"}
	for _, v := range small {
		if !boxTooSmall(v) {
			t.Errorf("%q should be too small", v)
		}
	}
	ok := []string{"4GB", "4GiB", "8GB", "16GiB", "1TB", "", "50%", "unlimited", "garbage"}
	for _, v := range ok {
		if boxTooSmall(v) {
			t.Errorf("%q should be allowed (default box size is 4GB; unknown limits do not block)", v)
		}
	}
	if b, ok := parseMemoryBytes("4GiB"); !ok || b != 4<<30 {
		t.Errorf("4GiB = %d,%v", b, ok)
	}
}

func TestSummarizeFindings_DropsPathsKeepsSignatures(t *testing.T) {
	out := "/home/a b/c: d: Sig.One FOUND\n/x/y: Sig.One FOUND\n/z: Sig.Two FOUND\nnot a finding\n"
	count, sum := summarizeFindings(out)
	if count != 3 || sum != "Sig.One (2)\nSig.Two (1)" {
		t.Fatalf("count=%d summary=%q", count, sum)
	}
	if strings.Contains(sum, "/") {
		t.Fatalf("summary contains a path: %q", sum)
	}
}

func TestClassifyInBoxRun_NeverCleanOnError(t *testing.T) {
	for _, code := range []int{2, 3, 124, 126, 127, 137, 143, -1} {
		if st, _, _ := classifyInBoxRun(code, ""); st == ScanStatusClean {
			t.Errorf("exit %d classified clean", code)
		}
	}
	if st, _, _ := classifyInBoxRun(1, ""); st == ScanStatusClean || st == ScanStatusInfected {
		t.Errorf("exit 1 with no FOUND line must be incomplete, got %q", st)
	}
	if st, n, _ := classifyInBoxRun(2, "/a: Sig FOUND\n"); st != ScanStatusInfected || n != 1 {
		t.Errorf("infection found despite exit 2 must stay infected, got %q %d", st, n)
	}
	if st, _, _ := classifyInBoxRun(0, "/a: Sig FOUND\n"); st != ScanStatusInfected {
		t.Errorf("findings with exit 0 are never clean, got %q", st)
	}
}

func TestStatusEnumAndReason(t *testing.T) {
	if StatusEnum(ScanStatusNotInstalled).String() != "CLAMAV_SCAN_STATUS_NOT_INSTALLED" ||
		StatusEnum("never").String() != "CLAMAV_SCAN_STATUS_NEVER_SCANNED" ||
		StatusEnum("bogus").String() != "CLAMAV_SCAN_STATUS_UNSPECIFIED" {
		t.Error("status → enum mapping is wrong")
	}
	if ReasonFor(ScanStatusClean, "ClamAV 1.0") != "" || ReasonFor(ScanStatusInfected, "Sig (1)") != "" {
		t.Error("clean/infected must not carry a reason")
	}
	if ReasonFor(ScanStatusIncomplete, "timed out") != "timed out" {
		t.Error("incomplete should expose its reason")
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
