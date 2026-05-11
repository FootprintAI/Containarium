package server

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// DebugContainer inspects backend-local state for a container's SSH path and
// returns a structured diagnostic with a likely_cause and next_actions list.
// Catches the failure modes that previously hid behind opaque ssh client errors:
//
//   - Container missing / stopped
//   - Host user account missing (daemon should have created it but didn't)
//   - User's shell field in /etc/passwd points at a file that doesn't exist
//     (the containarium-shell wrapper, in particular)
//   - sshd journal lines explicitly showing why the most recent attempts
//     were rejected
//
// All inspections are read-only.
func (s *ContainerServer) DebugContainer(ctx context.Context, req *pb.DebugContainerRequest) (*pb.DebugContainerResponse, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}

	resp := &pb.DebugContainerResponse{}

	resp.ContainerState = s.debugContainerState(req.Username)

	exists, shell, _ := lookupHostUserShell(req.Username)
	resp.HostUserExists = exists
	resp.HostUserShell = shell
	if exists && shell != "" {
		resp.HostUserShellExists = isExecutableFile(shell)
	}

	resp.RecentSshdRejections = recentSshdLines(req.Username, 8)

	resp.LikelyCause, resp.NextActions = diagnose(req.Username, resp)

	return resp, nil
}

// debugContainerState returns a short string describing the container's state
// as the daemon sees it: "running", "stopped", "missing", or "error: <reason>".
func (s *ContainerServer) debugContainerState(username string) string {
	info, err := s.manager.Get(username)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			return "missing"
		}
		return "error: " + err.Error()
	}
	state := strings.ToLower(strings.TrimSpace(info.State))
	if state == "" {
		return "unknown"
	}
	return state
}

// lookupHostUserShell returns (exists, shell, homedir) for the host user with
// this username. Uses os/user first; falls back to scanning /etc/passwd because
// containarium creates users with NSS entries that some os/user implementations
// miss on glibc systems.
func lookupHostUserShell(username string) (bool, string, string) {
	if u, err := user.Lookup(username); err == nil {
		shell := readShellForUID(u.Uid)
		return true, shell, u.HomeDir
	}
	return scanPasswd(username)
}

func scanPasswd(username string) (bool, string, string) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return false, "", ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) >= 7 && parts[0] == username {
			return true, parts[6], parts[5]
		}
	}
	return false, "", ""
}

// readShellForUID reads /etc/passwd for the given uid and returns the shell
// field. Returns "" if not found.
func readShellForUID(uid string) string {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) >= 7 && parts[2] == uid {
			return parts[6]
		}
	}
	return ""
}

// isExecutableFile returns true if path resolves to a regular file with at
// least one executable bit set. Symlinks are followed.
func isExecutableFile(path string) bool {
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	if !st.Mode().IsRegular() {
		return false
	}
	return st.Mode().Perm()&0o111 != 0
}

// recentSshdLines pulls the last `limit` sshd journal lines mentioning the
// username. Empty slice if journalctl is not available or returns nothing.
// Best-effort — errors are swallowed because debug shouldn't fail on a missing
// systemd journal.
func recentSshdLines(username string, limit int) []string {
	if username == "" {
		return nil
	}
	cmd := exec.Command(
		"journalctl",
		"-u", "ssh.service",
		"-u", "sshd",
		"--since", "5 minutes ago",
		"--no-pager",
		"-q",
	)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var matches []string
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)
	target := " " + username + " " // exact username, not a prefix
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, target) {
			// Also accept "for <user>" pattern (Accepted publickey for X from ...)
			if !strings.Contains(line, "for "+username) && !strings.Contains(line, "User "+username+" ") {
				continue
			}
		}
		matches = append(matches, line)
	}
	if len(matches) > limit {
		matches = matches[len(matches)-limit:]
	}
	return matches
}

// diagnose looks at the collected facts and produces a one-line likely_cause
// plus an ordered list of next_actions for the caller. The ordering encodes
// what to try first.
func diagnose(username string, r *pb.DebugContainerResponse) (string, []string) {
	switch r.ContainerState {
	case "missing":
		return "container does not exist on this backend",
			[]string{
				fmt.Sprintf("create the container: containarium create %s --ssh-keys <pubkey>", username),
				"check that you're connecting to the right backend (the daemon may be on a different host)",
			}
	case "stopped":
		return "container exists but is stopped",
			[]string{
				fmt.Sprintf("start the container: containarium start %s", username),
				"if start fails, inspect with: containarium info " + username,
			}
	case "running":
		// keep going — runtime state is fine, may still be a host-level issue
	default:
		if strings.HasPrefix(r.ContainerState, "error:") {
			return "daemon failed to query container state: " + strings.TrimPrefix(r.ContainerState, "error:"),
				[]string{
					"check daemon logs: journalctl -u containarium -e --no-pager",
				}
		}
	}

	if !r.HostUserExists {
		return "host-level Linux user is missing — the daemon never created the account or it was deleted",
			[]string{
				fmt.Sprintf("recreate the container: containarium delete %s && containarium create %s --ssh-keys <pubkey>", username, username),
				fmt.Sprintf("sync host accounts from incus: containarium sync-accounts --user %s", username),
			}
	}

	if r.HostUserShell != "" && !r.HostUserShellExists {
		return fmt.Sprintf("host user's shell %q does not exist on this backend — sshd will reject every login", r.HostUserShell),
			[]string{
				"install the containarium-shell wrapper on the backend (see scripts/setup-ssh-container-proxy.sh)",
				"this is a deploy-time gap, not a per-container issue — fix the backend image/startup",
			}
	}

	// Walk sshd journal for known patterns the agent can act on.
	for _, line := range r.RecentSshdRejections {
		lower := strings.ToLower(line)
		switch {
		case strings.Contains(lower, "does not exist"):
			return "sshd refused login: " + extractReason(line),
				[]string{"see host_user_shell_exists in this report"}
		case strings.Contains(lower, "invalid user"):
			return "sshd reports the user as invalid (account exists but not allowed)",
				[]string{"check AllowUsers in /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/"}
		case strings.Contains(lower, "accepted publickey"):
			return "sshd accepted publickey for this user recently — the path through sshd works; if your client still fails, the problem is in the sshpiper hop or the client's own ssh options",
				[]string{
					"verify you used: ssh -i <key> -o IdentitiesOnly=yes <user>@<sentinel-host>",
					"check sshpiper sync on the sentinel (the user must appear in /etc/sshpiper/users/<user>/)",
				}
		}
	}

	return "no obvious host-side problem; check sentinel-side state (sshpiper sync, failtoban ban table) — these are not visible to the daemon yet",
		[]string{
			"verify the user appears in the sentinel's /etc/sshpiper/users/<user>/ (sshpiper sync is on a 2 min interval)",
			"verify your laptop IP is not in the sentinel's failtoban ban table",
			"retry with: ssh -i <key> -o IdentitiesOnly=yes <user>@<sentinel-host>",
		}
}

// extractReason pulls the part after the first ": " from an sshd log line.
func extractReason(line string) string {
	if i := strings.Index(line, ": "); i != -1 {
		return strings.TrimSpace(line[i+2:])
	}
	return line
}
