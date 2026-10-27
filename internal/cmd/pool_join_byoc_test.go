//go:build !windows && !containarium_client

package cmd

import (
	"reflect"
	"strings"
	"testing"
)

func TestSetBoolFlag(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		on   bool
		want []string
	}{
		{"adds when on", []string{"daemon", "--pool", "prod"}, true, []string{"daemon", "--pool", "prod", "--byoc-backend"}},
		{"no duplicate on re-run", []string{"daemon", "--byoc-backend", "--pool", "prod"}, true, []string{"daemon", "--pool", "prod", "--byoc-backend"}},
		{"removes when off", []string{"daemon", "--byoc-backend", "--pool", "prod"}, false, []string{"daemon", "--pool", "prod"}},
		{"removes =true and =false forms", []string{"daemon", "--byoc-backend=true", "--byoc-backend=false"}, false, []string{"daemon"}},
		// A bool flag takes no value token: the following token must survive.
		{"keeps the next token", []string{"daemon", "--byoc-backend", "--app-hosting"}, false, []string{"daemon", "--app-hosting"}},
		{"leaves look-alike flags alone", []string{"daemon", "--byoc-backend-x"}, false, []string{"daemon", "--byoc-backend-x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := setBoolFlag(tc.in, "--byoc-backend", tc.on); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("setBoolFlag(%v, %v) = %v, want %v", tc.in, tc.on, got, tc.want)
			}
		})
	}
}

func TestValidatePoolJoinBYOC(t *testing.T) {
	if err := validatePoolJoinBYOC(true, "cp.example.com"); err == nil || !strings.Contains(err.Error(), "--base-domain") {
		t.Errorf("--byoc with --base-domain: err = %v, want a refusal naming --base-domain", err)
	}
	for _, tc := range []struct {
		byoc bool
		base string
	}{{true, ""}, {false, "boxes.example.com"}, {false, ""}} {
		if err := validatePoolJoinBYOC(tc.byoc, tc.base); err != nil {
			t.Errorf("validatePoolJoinBYOC(%v, %q) = %v, want nil", tc.byoc, tc.base, err)
		}
	}
}

// The drop-in pool join writes carries the mark with --byoc, and re-running
// without --byoc takes it away again, like --base-domain.
func TestPoolDropIn_BYOCMark(t *testing.T) {
	marked := renderPoolDropIn(setBoolFlag(resolvePoolDaemonArgv(nil, false, "prod", "", nil), "--byoc-backend", true), "")
	if !strings.Contains(marked, "--byoc-backend") || strings.Contains(marked, "--base-domain") {
		t.Errorf("--byoc drop-in must carry --byoc-backend and no --base-domain:\n%s", marked)
	}

	current := []string{"/usr/local/bin/containariumd", "daemon", "--app-hosting", "--pool", "prod", "--byoc-backend"}
	rerun := renderPoolDropIn(setBoolFlag(resolvePoolDaemonArgv(current, true, "prod", "", nil), "--byoc-backend", false), "")
	if strings.Contains(rerun, "--byoc-backend") {
		t.Errorf("re-running without --byoc must drop the mark:\n%s", rerun)
	}
	if !strings.Contains(rerun, "--app-hosting") {
		t.Errorf("re-running must keep the host's other flags:\n%s", rerun)
	}
}
