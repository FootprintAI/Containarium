package security

import (
	"errors"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// installBox scripts a box: presence checks flip as install steps "succeed".
type installBox struct {
	info    *incus.ContainerInfo
	infoErr error

	bin, sigs bool
	debian    bool
	aptCode   int
	freshCode int
	freshGets bool // a successful freshclam produces signatures
	execErr   error

	ran []string
}

func (b *installBox) GetContainer(string) (*incus.ContainerInfo, error) { return b.info, b.infoErr }

func (b *installBox) ExecWithExitCode(_ string, cmd []string) (string, string, int, error) {
	if b.execErr != nil {
		return "", "", 0, b.execErr
	}
	j := strings.Join(cmd, " ")
	switch {
	case strings.Contains(j, "command -v clamscan"):
		return "", "", boolCode(b.bin), nil
	case strings.Contains(j, "/var/lib/clamav"):
		return "", "", boolCode(b.sigs), nil
	case strings.Contains(j, "command -v apt-get"):
		return "", "", boolCode(b.debian), nil
	case strings.Contains(j, "apt-get install"):
		b.ran = append(b.ran, "apt")
		if b.aptCode == 0 {
			b.bin = true
		}
		return "SECRET PACKAGE OUTPUT /home/alice/x", "", b.aptCode, nil
	case strings.Contains(j, "freshclam"):
		b.ran = append(b.ran, "freshclam")
		if b.freshCode == 0 && b.freshGets {
			b.sigs = true
		}
		return "", "", b.freshCode, nil
	}
	return "", "", 0, errors.New("unexpected command " + j)
}

func boolCode(ok bool) int {
	if ok {
		return 0
	}
	return 1
}

func newInstallBox() *installBox {
	return &installBox{
		info:      &incus.ContainerInfo{Name: "alice-container", State: "Running", Memory: "4GB"},
		debian:    true,
		freshGets: true,
	}
}

func TestInstallClamav(t *testing.T) {
	const (
		installed = pb.ClamavInstallOutcome_CLAMAV_INSTALL_OUTCOME_INSTALLED
		present   = pb.ClamavInstallOutcome_CLAMAV_INSTALL_OUTCOME_ALREADY_PRESENT
		family    = pb.ClamavInstallOutcome_CLAMAV_INSTALL_OUTCOME_UNSUPPORTED_FAMILY
		size      = pb.ClamavInstallOutcome_CLAMAV_INSTALL_OUTCOME_UNSUPPORTED_SIZE
		failed    = pb.ClamavInstallOutcome_CLAMAV_INSTALL_OUTCOME_FAILED
	)
	tests := []struct {
		name    string
		mutate  func(*installBox)
		want    pb.ClamavInstallOutcome
		wantRan string // "" = nothing may run; else the exact sequence joined by ,
	}{
		{"fresh box: package then signatures", func(b *installBox) {}, installed, "apt,freshclam"},
		{"already installed runs nothing", func(b *installBox) { b.bin, b.sigs = true, true }, present, ""},
		{"binary present, signatures missing: freshclam only", func(b *installBox) { b.bin = true }, installed, "freshclam"},
		{"RHEL-family is unsupported and runs nothing", func(b *installBox) { b.debian = false }, family, ""},
		{"under 4 GB is unsupported_size and runs nothing", func(b *installBox) { b.info.Memory = "2GB" }, size, ""},
		{"stopped box fails without running anything", func(b *installBox) { b.info.State = "Stopped" }, failed, ""},
		{"apt failure", func(b *installBox) { b.aptCode = 100 }, failed, "apt"},
		{"signature download fails", func(b *installBox) { b.freshCode = 1 }, failed, "apt,freshclam"},
		{"freshclam fails but the service already fetched signatures", func(b *installBox) { b.freshCode = 1; b.sigs = true }, installed, "apt,freshclam"},
		{"install ran but result is not verifiable", func(b *installBox) { b.freshGets = false }, failed, "apt,freshclam"},
		{"box unreachable", func(b *installBox) { b.execErr = errors.New("socket wedged") }, failed, ""},
		{"lookup failure", func(b *installBox) { b.infoErr = errors.New("no such box") }, failed, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := newInstallBox()
			tc.mutate(b)
			got, msg := InstallClamav(b, "alice-container")
			if got != tc.want {
				t.Fatalf("outcome = %v (%q), want %v", got, msg, tc.want)
			}
			if strings.Join(b.ran, ",") != tc.wantRan {
				t.Errorf("ran %v, want %q", b.ran, tc.wantRan)
			}
			if strings.Contains(msg, "SECRET PACKAGE OUTPUT") || strings.Contains(msg, "/home/") {
				t.Errorf("box output leaked into the message: %q", msg)
			}
		})
	}
}

// Idempotent: a second call after a successful install runs nothing.
func TestInstallClamav_SecondCallIsANoOp(t *testing.T) {
	b := newInstallBox()
	if got, _ := InstallClamav(b, "alice-container"); got != pb.ClamavInstallOutcome_CLAMAV_INSTALL_OUTCOME_INSTALLED {
		t.Fatalf("first call: %v", got)
	}
	b.ran = nil
	if got, _ := InstallClamav(b, "alice-container"); got != pb.ClamavInstallOutcome_CLAMAV_INSTALL_OUTCOME_ALREADY_PRESENT {
		t.Fatalf("second call: %v", got)
	}
	if len(b.ran) != 0 {
		t.Fatalf("second call ran %v", b.ran)
	}
}
