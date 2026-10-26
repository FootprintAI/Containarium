package sshauthz

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// LoginGraceMargin is added to MaxApprovalWait to get the smallest
// sshpiperd --login-grace-time that is safe with device approval: the
// plugin may hold a login for the whole cap and then still has to finish
// the handshake.
const LoginGraceMargin = 10 * time.Second

// MinLoginGrace is the smallest --login-grace-time the check accepts.
const MinLoginGrace = MaxApprovalWait + LoginGraceMargin

// ParentCmdline returns the NUL-separated command line of this process's
// parent (sshpiperd when run as its plugin). It is Linux only; elsewhere or
// when /proc is unreadable it returns an error.
func ParentCmdline() ([]byte, error) {
	return os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", os.Getppid()))
}

// CheckParentLoginGrace logs a WARN through logf when the parent sshpiperd
// was started without a --login-grace-time of at least MinLoginGrace: the
// default 30s would drop a login while the user approves a device. A
// binary-only rollout leaves an old unit in place, so this is the runtime
// sign that the unit needs re-rendering (#3125). It never fails: an
// unreadable command line is only noted as a debug line, no alarm.
//
// A value of 0 or below is reported too: it is not a duration of at least
// MinLoginGrace (whether sshpiperd treats 0 as unlimited was not verified).
// The scan covers the whole parent command line, so a plugin argument
// literally named --login-grace-time would be misread (theoretical).
func CheckParentLoginGrace(read func() ([]byte, error), logf func(string, ...any)) {
	raw, err := read()
	if err != nil || len(raw) == 0 {
		logf("DEBUG ssh-authz: parent sshpiperd command line unreadable (%v); login-grace-time not checked", err)
		return
	}
	args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
	val, found := "", false
	for i := 1; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "-") {
			continue
		}
		a := strings.TrimLeft(args[i], "-")
		if a == "login-grace-time" {
			found = true
			if i+1 < len(args) {
				val = args[i+1]
			}
			break
		}
		if v, ok := strings.CutPrefix(a, "login-grace-time="); ok {
			found, val = true, v
			break
		}
	}
	const fix = "re-render the sshpiper unit (sshpiper.service.tmpl) or re-apply the sentinel startup script, then restart sshpiper; see docs/UPGRADE-AND-ROLLBACK.md"
	if !found {
		logf("WARN ssh-authz: parent sshpiperd has no --login-grace-time, so it uses the 30s default and drops a login while a device is being approved (approval cap %s, need at least %s); %s", MaxApprovalWait, MinLoginGrace, fix)
		return
	}
	d, perr := time.ParseDuration(val)
	if perr != nil || d < MinLoginGrace {
		logf("WARN ssh-authz: parent sshpiperd --login-grace-time=%q is not a duration of at least %s (approval cap %s plus %s margin); %s", val, MinLoginGrace, MaxApprovalWait, LoginGraceMargin, fix)
	}
}
