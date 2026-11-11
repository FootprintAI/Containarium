package logverbcheck

import "testing"

// allowlist holds the tenant-named values that are deliberately left with
// %s, keyed "<path from the repo root>:<argument expression>". Keep it
// small: each entry needs a reason a reviewer can check. A key that no
// longer matches anything fails the test, so entries cannot go stale.
var allowlist = map[string]string{
	// Validated: isValidUsername has accepted the name before it reaches
	// this log line, so it cannot carry a control byte (#3473).
	"pkg/core/container/orphan_reaper.go:username": "validated by isValidUsername",

	// The daemon's own response: the anonymous user supplies only an SSH
	// key, and the box name and SSH user are derived by the daemon (#3473).
	"internal/sentinel/anondoor/plugin.go:res.GetBoxName()": "daemon-derived anonymous box name",
	"internal/sentinel/anondoor/plugin.go:res.GetSshUser()": "daemon-derived anonymous SSH user",

	// Operator values whose variable happens to share a tenant field name.
	"internal/cmd/sentinel.go:project":    "cloud project id from the operator's --project / --watch-spot-vm flag",
	"cmd/netpolicy-smoke/main.go:*tenant": "the operator's own -tenant flag in a manual smoke-test binary",
}

// TestRepo_TenantValuesAreEscaped is the CI gate for #3457. It runs in the
// repo-wide unit-test job and fails when a log call or an internal/cmd
// table row hands a tenant-controlled value (TenantFields) to %s or %v.
func TestRepo_TenantValuesAreEscaped(t *testing.T) {
	findings, scanned, unused, err := CheckTree("../..", "internal/cmd", allowlist)
	if err != nil {
		t.Fatal(err)
	}
	// The walker must actually see the tree: a wrong root would scan
	// nothing and pass.
	if scanned < 500 {
		t.Fatalf("scanned only %d Go files; is the repo root right?", scanned)
	}
	for _, f := range findings {
		t.Error(f)
	}
	for _, k := range unused {
		t.Errorf("allowlist entry %q matches nothing; remove it", k)
	}
}
