package security

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/threatdetect"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	"github.com/footprintai/containarium/pkg/core/sshdpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeBox is one box's filesystem + incus config as the reconciler sees it
// through the Backend: files by absolute path, drop-in dir entries derived
// from them, and every write/exec/config-set recorded.
type fakeBox struct {
	files  map[string]string
	config map[string]string

	writes   map[string]string
	execs    []string
	setCfg   map[string]string
	writeErr error
}

func newFakeBox(files map[string]string, marked bool) *fakeBox {
	b := &fakeBox{files: map[string]string{}, config: map[string]string{}, writes: map[string]string{}, setCfg: map[string]string{}}
	for k, v := range files {
		b.files[k] = v
	}
	if marked {
		b.config[sshdpolicy.MarkerKey] = sshdpolicy.MarkerValue
	}
	return b
}

func (b *fakeBox) backend() *incustest.MockBackend {
	m := incustest.NewMockBackend()
	m.ReadFileFunc = func(_, path string) ([]byte, error) {
		c, ok := b.files[path]
		if !ok {
			return nil, errors.New("not found")
		}
		return []byte(c), nil
	}
	m.ListDirFunc = func(_, path string) ([]string, error) {
		var out []string
		for p := range b.files {
			if strings.HasPrefix(p, path+"/") {
				out = append(out, strings.TrimPrefix(p, path+"/"))
			}
		}
		if len(out) == 0 {
			return nil, errors.New("no such directory")
		}
		return out, nil
	}
	m.WriteFileFunc = func(_, path string, content []byte, _ string) error {
		if b.writeErr != nil {
			return b.writeErr
		}
		b.writes[path] = string(content)
		b.files[path] = string(content)
		return nil
	}
	m.ExecFunc = func(_ string, cmd []string) error {
		b.execs = append(b.execs, strings.Join(cmd, " "))
		return nil
	}
	m.GetRawInstanceFunc = func(string) (map[string]string, string, error) { return b.config, "", nil }
	m.SetConfigFunc = func(_, k, v string) error {
		b.setCfg[k] = v
		b.config[k] = v
		return nil
	}
	return m
}

type fakeSink struct{ findings []*threatdetect.Finding }

func (s *fakeSink) Upsert(_ context.Context, f *threatdetect.Finding) (*threatdetect.Finding, error) {
	s.findings = append(s.findings, f)
	return f, nil
}

const imageDefaultMain = "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n"

var managed = string(sshdpolicy.DropInContent())

func TestReconcileBox_ImageDefaultIsBackfilledSilently(t *testing.T) {
	box := newFakeBox(map[string]string{sshdpolicy.MainConfigPath: imageDefaultMain}, false)
	sink := &fakeSink{}
	r := NewSSHDPostureReconciler(box.backend(), sink, 0)

	out, err := r.ReconcileBox(context.Background(), "alice-container")
	if err != nil {
		t.Fatal(err)
	}
	if !out.Backfilled || !out.Remediated || !out.Compliant || out.Finding != nil {
		t.Fatalf("want silent backfill, got %+v", out)
	}
	if box.writes[sshdpolicy.DropInPath] != managed {
		t.Errorf("managed drop-in not written: %q", box.writes)
	}
	if !containsPrefix(box.execs, "sh -c systemctl reload") {
		t.Errorf("sshd not reloaded after write: %v", box.execs)
	}
	if box.setCfg[sshdpolicy.MarkerKey] != sshdpolicy.MarkerValue {
		t.Errorf("marker not set: %v", box.setCfg)
	}
	if len(sink.findings) != 0 {
		t.Errorf("a never-managed box must not raise a finding on backfill: %+v", sink.findings)
	}
}

func TestReconcileBox_CompliantBoxIsUntouched(t *testing.T) {
	box := newFakeBox(map[string]string{
		sshdpolicy.MainConfigPath: imageDefaultMain,
		sshdpolicy.DropInPath:     managed,
	}, true)
	sink := &fakeSink{}
	out, err := NewSSHDPostureReconciler(box.backend(), sink, 0).ReconcileBox(context.Background(), "alice-container")
	if err != nil {
		t.Fatal(err)
	}
	if !out.Compliant || out.Remediated || out.Finding != nil {
		t.Fatalf("want untouched, got %+v", out)
	}
	if len(box.writes) != 0 || len(box.execs) != 0 || len(box.setCfg) != 0 {
		t.Errorf("compliant box must see no writes/execs/config: %v %v %v", box.writes, box.execs, box.setCfg)
	}
}

// A fresh create wrote the drop-in but no marker yet: the first pass only
// sets the marker.
func TestReconcileBox_FreshCreateGetsMarked(t *testing.T) {
	box := newFakeBox(map[string]string{
		sshdpolicy.MainConfigPath: imageDefaultMain,
		sshdpolicy.DropInPath:     managed,
	}, false)
	if _, err := NewSSHDPostureReconciler(box.backend(), nil, 0).ReconcileBox(context.Background(), "alice-container"); err != nil {
		t.Fatal(err)
	}
	if box.setCfg[sshdpolicy.MarkerKey] != sshdpolicy.MarkerValue || len(box.writes) != 0 {
		t.Errorf("want marker only, got writes=%v cfg=%v", box.writes, box.setCfg)
	}
}

func TestReconcileBox_DeletedDropInIsRewrittenAndRecorded(t *testing.T) {
	box := newFakeBox(map[string]string{sshdpolicy.MainConfigPath: imageDefaultMain}, true)
	sink := &fakeSink{}
	r := NewSSHDPostureReconciler(box.backend(), sink, 0)
	r.SetBackendID("backend-a")

	out, err := r.ReconcileBox(context.Background(), "alice-container")
	if err != nil {
		t.Fatal(err)
	}
	if !out.Remediated || !out.Compliant || out.Backfilled || out.Finding == nil {
		t.Fatalf("want remediate+finding, got %+v", out)
	}
	if box.writes[sshdpolicy.DropInPath] != managed {
		t.Errorf("drop-in not re-asserted")
	}
	if len(sink.findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(sink.findings))
	}
	f := sink.findings[0]
	if f.Rule != pb.ThreatRuleId_THREAT_RULE_ID_BOX_SSHD_PASSWORD_AUTH {
		t.Errorf("rule = %v", f.Rule)
	}
	if f.Severity != pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM {
		t.Errorf("closed-in-pass tampering should be MEDIUM, got %v", f.Severity)
	}
	if f.TenantID != "alice" || f.Container != "alice-container" || f.Subject != "alice-container" || f.BackendID != "backend-a" {
		t.Errorf("attribution: %+v", f)
	}
	var sawPassword, sawDropIn bool
	for _, c := range f.Evidence.Configs {
		switch c.Directive {
		case "PasswordAuthentication":
			sawPassword = true
			if c.Value != "yes" || !c.Remediated || !strings.Contains(c.Path, "sshd default") {
				t.Errorf("password evidence: %+v", c)
			}
		case "ManagedDropIn":
			sawDropIn = true
			if !c.Remediated || c.Note != "managed drop-in missing" {
				t.Errorf("drop-in evidence: %+v", c)
			}
		}
	}
	if !sawPassword || !sawDropIn {
		t.Errorf("evidence incomplete: %+v", f.Evidence.Configs)
	}
}

// The tenant cannot be beaten lexically: a drop-in sorting before ours wins
// under first-match. The pass cannot close that, so it is HIGH and the
// evidence names the tenant's file.
func TestReconcileBox_EarlierDropInOverridesIsHighAndAttributed(t *testing.T) {
	box := newFakeBox(map[string]string{
		sshdpolicy.MainConfigPath:           imageDefaultMain,
		sshdpolicy.DropInPath:               managed,
		sshdpolicy.DropInDir + "/00-0.conf": "PasswordAuthentication yes\n",
	}, true)
	sink := &fakeSink{}
	out, err := NewSSHDPostureReconciler(box.backend(), sink, 0).ReconcileBox(context.Background(), "alice-container")
	if err != nil {
		t.Fatal(err)
	}
	if out.Compliant || out.Remediated || out.Finding == nil {
		t.Fatalf("want open HIGH finding without rewrite (drop-in intact), got %+v", out)
	}
	f := sink.findings[0]
	if f.Severity != pb.ThreatSeverity_THREAT_SEVERITY_HIGH {
		t.Errorf("still-permissive box must be HIGH, got %v", f.Severity)
	}
	if len(f.Evidence.Configs) != 1 || f.Evidence.Configs[0].Path != sshdpolicy.DropInDir+"/00-0.conf" || f.Evidence.Configs[0].Remediated {
		t.Errorf("evidence must point at the tenant's file, unremediated: %+v", f.Evidence.Configs)
	}
}

func TestReconcileBox_AlteredDropInNoteAndMainFileAttribution(t *testing.T) {
	box := newFakeBox(map[string]string{
		sshdpolicy.MainConfigPath: imageDefaultMain + "PasswordAuthentication yes\n",
		sshdpolicy.DropInPath:     "# edited\nPasswordAuthentication yes\n",
	}, true)
	sink := &fakeSink{}
	if _, err := NewSSHDPostureReconciler(box.backend(), sink, 0).ReconcileBox(context.Background(), "bob-container"); err != nil {
		t.Fatal(err)
	}
	f := sink.findings[0]
	for _, c := range f.Evidence.Configs {
		if c.Directive == "ManagedDropIn" && c.Note != "managed drop-in altered" {
			t.Errorf("note = %q", c.Note)
		}
		if c.Directive == "PasswordAuthentication" && c.Path != sshdpolicy.DropInPath {
			t.Errorf("the altered drop-in sets it first; path = %q", c.Path)
		}
	}
	if box.files[sshdpolicy.DropInPath] != managed {
		t.Error("altered drop-in not restored")
	}
}

func TestReconcileBox_NoSSHDIsSkipped(t *testing.T) {
	box := newFakeBox(map[string]string{}, false)
	sink := &fakeSink{}
	out, err := NewSSHDPostureReconciler(box.backend(), sink, 0).ReconcileBox(context.Background(), "minimal-container")
	if err != nil {
		t.Fatal(err)
	}
	if out.Skipped == "" || len(box.writes) != 0 || len(box.setCfg) != 0 || len(sink.findings) != 0 {
		t.Errorf("box without sshd must be skipped untouched: %+v writes=%v cfg=%v", out, box.writes, box.setCfg)
	}
}

func TestReconcileBox_NilSinkStillRemediates(t *testing.T) {
	box := newFakeBox(map[string]string{sshdpolicy.MainConfigPath: imageDefaultMain}, true)
	out, err := NewSSHDPostureReconciler(box.backend(), nil, 0).ReconcileBox(context.Background(), "alice-container")
	if err != nil {
		t.Fatal(err)
	}
	if !out.Remediated || out.Finding == nil || box.writes[sshdpolicy.DropInPath] != managed {
		t.Errorf("remediation must not depend on a sink: %+v", out)
	}
}

func TestReconcileBox_WriteFailureIsAnError(t *testing.T) {
	box := newFakeBox(map[string]string{sshdpolicy.MainConfigPath: imageDefaultMain}, true)
	box.writeErr = errors.New("push failed")
	if _, err := NewSSHDPostureReconciler(box.backend(), &fakeSink{}, 0).ReconcileBox(context.Background(), "alice-container"); err == nil {
		t.Fatal("a failed re-assert must surface as an error, not a silent pass")
	}
}

func TestReconcileAll_OnlyRunningUserBoxes(t *testing.T) {
	box := newFakeBox(map[string]string{sshdpolicy.MainConfigPath: imageDefaultMain}, false)
	m := box.backend()
	m.ListContainersFunc = func() ([]incus.ContainerInfo, error) {
		return []incus.ContainerInfo{
			{Name: "alice-container", State: "Running"},
			{Name: "bob-container", State: "Stopped"},
			{Name: "containarium-core-postgres", State: "Running", Role: incus.RolePostgres},
		}, nil
	}
	s := NewSSHDPostureReconciler(m, &fakeSink{}, 0).ReconcileAll(context.Background())
	if s.Boxes != 1 || s.Backfilled != 1 || s.Errors != 0 {
		t.Errorf("summary = %s", s)
	}
}

func TestNewSSHDPostureReconciler_DefaultInterval(t *testing.T) {
	if r := NewSSHDPostureReconciler(incustest.NewMockBackend(), nil, 0); r.interval != DefaultSSHDPostureInterval {
		t.Errorf("interval = %v", r.interval)
	}
	if r := NewSSHDPostureReconciler(incustest.NewMockBackend(), nil, time.Minute); r.interval != time.Minute {
		t.Errorf("interval = %v", r.interval)
	}
}

func containsPrefix(list []string, prefix string) bool {
	for _, s := range list {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}
