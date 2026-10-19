package container

import "os/exec"

// TerminateAccountSessions ends every live session and process account holds
// inside containerName, and changes nothing else: the account, its home,
// its sudoers entry and its authorized_keys all stay. Shared by collaborator
// removal (which then deletes the account) and TerminateUserSessions
// (#2522, which deletes nothing).
//
// Both steps are best-effort: loginctl exists only on systemd-based images,
// and pkill exits 1 when nothing matched, so neither status is an error —
// the KILL is what drops the shell. It reports whether pkill matched (exit
// 0), i.e. whether the account had anything running to end. An account name
// that is not a valid Linux login (pkill would read "-1" as a flag) is
// refused without touching the box.
func (m *Manager) TerminateAccountSessions(containerName, account string) bool {
	if !isValidUsername(account) {
		return false
	}
	_ = m.incus.Exec(containerName, []string{"loginctl", "terminate-user", account})
	_, _, code, err := m.incus.ExecWithExitCode(containerName, []string{"pkill", "-KILL", "-u", account})
	return err == nil && code == 0
}

// IsValidAccountName reports whether name is an acceptable Linux login for
// the box and jump accounts: letters, digits, '-' and '_', at most 32
// characters, not starting with a digit or '-'.
func IsValidAccountName(name string) bool { return isValidUsername(name) }

// hostPkill runs pkill on the host. A variable so tests record the argv
// instead of signalling real processes.
var hostPkill = func(args ...string) error {
	// #nosec G204 -- args are fixed flags plus an account checked by isValidUsername
	return exec.Command("pkill", args...).Run()
}

// TerminateJumpAccountSessions SIGKILLs every process the host jump account
// owns (its sshd session and the containarium-shell behind it). The account
// itself is untouched. It reports whether anything was running: pkill exits
// 1 when nothing matched and 2 for an unknown user, both "nothing ended".
func TerminateJumpAccountSessions(account string) bool {
	if !isValidUsername(account) {
		return false
	}
	return hostPkill("-KILL", "-u", account) == nil
}
