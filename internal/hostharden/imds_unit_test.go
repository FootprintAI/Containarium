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

// #2300: installing twice is a no-op — same file content, both runs succeed,
// and each run issues the same daemon-reload + enable --now pair (enabling an
// already-enabled unit is a systemctl no-op).
func TestInstallPersistentUnit_IdempotentSecondRun(t *testing.T) {
	unitPath := filepath.Join(t.TempDir(), "containarium-imds-block.service")
	var calls []call
	run := fakeRunner(t, &calls, map[string]result{
		"systemctl daemon-reload":                                {},
		"systemctl enable --now containarium-imds-block.service": {},
	})

	if err := installPersistentUnit(run, unitPath, "/usr/local/bin/containariumd", "incusbr0"); err != nil {
		t.Fatalf("first install: %v", err)
	}
	first, err := os.ReadFile(unitPath) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatal(err)
	}
	if err := installPersistentUnit(run, unitPath, "/usr/local/bin/containariumd", "incusbr0"); err != nil {
		t.Fatalf("second install: %v", err)
	}
	second, err := os.ReadFile(unitPath) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Errorf("second install changed the unit:\n--- first\n%s\n--- second\n%s", first, second)
	}
	if len(calls) != 4 {
		t.Errorf("want 2 systemctl calls per install (4 total), got %d: %+v", len(calls), calls)
	}
}
