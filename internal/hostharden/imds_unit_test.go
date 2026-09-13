package hostharden

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallPersistentUnit(t *testing.T) {
	unitPath := filepath.Join(t.TempDir(), "containarium-imds-block.service")

	var calls []call
	run := fakeRunner(t, &calls, map[string]result{
		"systemctl daemon-reload":                                {},
		"systemctl enable --now containarium-imds-block.service": {},
	})

	if err := installPersistentUnit(run, unitPath, "/usr/local/bin/containariumd", "incusbr0"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(unitPath) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("unit file not written: %v", err)
	}
	unit := string(data)
	for _, want := range []string{
		"ExecStart=/usr/local/bin/containariumd hostharden block-metadata incusbr0",
		"[Install]",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit file missing %q:\n%s", want, unit)
		}
	}

	if len(calls) != 2 {
		t.Fatalf("expected 2 systemctl calls, got %d: %+v", len(calls), calls)
	}
}

func TestInstallPersistentUnit_DaemonReloadFails(t *testing.T) {
	unitPath := filepath.Join(t.TempDir(), "containarium-imds-block.service")

	var calls []call
	run := fakeRunner(t, &calls, map[string]result{
		"systemctl daemon-reload": {out: "permission denied", err: os.ErrPermission},
	})

	if err := installPersistentUnit(run, unitPath, "/usr/local/bin/containariumd", "incusbr0"); err == nil {
		t.Fatal("expected an error")
	}
}
