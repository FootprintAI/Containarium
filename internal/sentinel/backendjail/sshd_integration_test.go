//go:build integration && linux

// Package backendjail characterizes real backend SSH jail decisions without
// changing the host firewall or treating a TCP dial as an authentication failure.
package backendjail

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestIntegrationBackendJail separates actual sshd log matches, jail bans and
// source exemptions. A recording action deliberately leaves host packets alone.
func TestIntegrationBackendJail(t *testing.T) {
	for _, tc := range []struct {
		name, filter, ignore string
		invalid, refused     bool
		matches, failed      int
		banned               bool
	}{
		{name: "tcp_refusal", filter: "sshd", refused: true},
		{name: "valid_user_default", filter: "sshd"},
		{name: "valid_user_count_publickey", filter: "sshd[publickey=any]", matches: 7, failed: 7, banned: true},
		{name: "invalid_user_default", filter: "sshd", invalid: true, matches: 7, failed: 7, banned: true},
		{name: "exempt_source", filter: "sshd[publickey=any]", ignore: "127.0.0.1/32", matches: 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newJailFixture(t, tc.filter, tc.ignore)
			login := f.login
			if tc.invalid {
				login = "containarium-jail-no-such-user"
				if _, err := user.Lookup(login); err == nil {
					t.Fatal("synthetic invalid account unexpectedly exists")
				}
			}
			if tc.refused {
				f.controlFailure()
				f.stopSSHD()
			} else if err := f.connect(f.login, f.goodKey); err != nil {
				t.Fatalf("authorized baseline login: %v", err)
			}
			before := f.read("sshd-raw.log")
			for range 7 {
				err := f.connect(login, f.badKey)
				if err == nil {
					t.Fatal("rejected credential unexpectedly authenticated")
				}
				if tc.refused && !errors.Is(err, syscall.ECONNREFUSED) {
					t.Fatalf("expected TCP refusal, got %v", err)
				}
			}
			if !tc.refused {
				f.controlFailure()
			}
			f.stopSSHD()
			authLog := f.read("sshd-raw.log")
			if tc.refused {
				if authLog != before {
					t.Fatal("refused TCP connections unexpectedly created sshd records")
				}
			} else {
				record := "Failed publickey for " + login + " "
				if tc.invalid {
					record = "Invalid user " + login + " "
				}
				if got := strings.Count(authLog, record); got != 7 || !strings.Contains(authLog, "from 127.0.0.1 ") {
					t.Fatalf("expected seven real %q records from 127.0.0.1; got %d:\n%s", record, got, authLog)
				}
			}
			// Foreground -E lacks a syslog envelope. Replay with the current
			// timestamp/host/daemon prefix, retaining all original message bodies.
			var replay strings.Builder
			for _, line := range strings.Split(strings.TrimRight(authLog, "\r\n"), "\n") {
				fmt.Fprintf(&replay, "%s fixture sshd: %s\n", time.Now().Format("Jan _2 15:04:05"), strings.TrimSuffix(line, "\r"))
			}
			f.write("auth.log", replay.String())
			out := f.command("fail2ban-regex", "-c", f.conf, filepath.Join(f.dir, "auth.log"), tc.filter)
			f.write("filter.log", out)
			match := regexp.MustCompile(`Lines: \d+ lines, \d+ ignored, (\d+) matched,`).FindStringSubmatch(out)
			if len(match) != 2 || match[1] != strconv.Itoa(tc.matches+1) {
				t.Fatalf("expected %d filter matches:\n%s", tc.matches, out)
			}
			f.startJail()
			// A real invalid-user attempt from 127.0.0.2 supplies one additional
			// failure, proving even the negative cases consumed their input.
			status := f.waitStatus(tc.failed + 1)
			if tc.banned {
				f.waitAction("ban 127.0.0.1")
			}
			banned := strings.Fields(f.client("get", "sshd", "banip"))
			wantBanned := ""
			if tc.banned {
				wantBanned = "127.0.0.1"
			}
			if strings.Join(banned, " ") != wantBanned {
				t.Fatalf("want banned=%q; ban list=%v; %s", wantBanned, banned, status)
			}
			if tc.banned {
				f.client("set", "sshd", "unbanip", "127.0.0.1")
				f.waitAction("unban 127.0.0.1")
			}
			t.Logf("filter=%s ignoreip=%q source=127.0.0.1 dials=7 matches=%d failures=%d banned=%v; maxretry=3 findtime=600 bantime=3600; recording action only", tc.filter, tc.ignore, tc.matches, tc.failed, tc.banned)
		})
	}
}

// jailFixture owns private foreground services, synthetic keys and public evidence.
type jailFixture struct {
	t                  *testing.T
	dir, conf, login   string
	addr, goodKey      string
	badKey             string
	stopSSHD, stopJail func()
}

// jailTool resolves an explicit test prerequisite and fails rather than skipping.
func jailTool(t *testing.T, name string) string {
	t.Helper()
	if dir := os.Getenv("BACKEND_JAIL_BIN"); dir != "" {
		return filepath.Join(dir, name)
	}
	p, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("install openssh-server and fail2ban, or set BACKEND_JAIL_BIN: %v", err)
	}
	return p
}

// newJailFixture uses the installed upstream filter with an isolated configuration.
func newJailFixture(t *testing.T, filter, ignore string) *jailFixture {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	f := &jailFixture{t: t, dir: t.TempDir(), login: u.Username}
	f.conf = filepath.Join(f.dir, "fail2ban")
	config := os.Getenv("BACKEND_JAIL_CONFIG")
	if config == "" {
		config = "/etc/fail2ban"
	}
	f.command("cp", "-R", config, f.conf)
	// Replace jail.conf rather than inheriting enabled distro jails. The stock
	// filter and its common.conf includes remain byte-for-byte upstream files.
	f.write("fail2ban/jail.conf", fmt.Sprintf("[DEFAULT]\nbackend = polling\nusedns = no\nignoreself = false\nignoreip = %s\nmaxretry = 3\nfindtime = 600\nbantime = 3600\n[sshd]\nenabled = true\nfilter = %s\nlogpath = %s/auth.log\naction = record\n", ignore, filter, f.dir))
	if err := os.RemoveAll(filepath.Join(f.conf, "jail.d")); err != nil {
		t.Fatal(err)
	}
	f.write("fail2ban/fail2ban.local", "[DEFAULT]\ndbfile = None\n")
	f.write("fail2ban/action.d/record.conf", fmt.Sprintf("[Definition]\nactionstart =\nactionstop =\nactioncheck =\nactionban = echo ban <ip> >> %s/actions.log\nactionunban = echo unban <ip> >> %s/actions.log\n", f.dir, f.dir))
	for _, name := range []string{"host", "good", "bad"} {
		f.command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(f.dir, name))
	}
	f.goodKey, f.badKey = filepath.Join(f.dir, "good"), filepath.Join(f.dir, "bad")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.addr = l.Addr().String()
	_ = l.Close()
	_, port, _ := net.SplitHostPort(f.addr)
	f.write("sshd.conf", fmt.Sprintf("ListenAddress 127.0.0.1\nPort %s\nHostKey %s/host\nPidFile %s/sshd.pid\nAuthorizedKeysFile %s/good.pub\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin yes\nLogLevel VERBOSE\n", port, f.dir, f.dir, f.dir))
	f.stopSSHD = f.start("sshd", "-D", "-E", filepath.Join(f.dir, "sshd-raw.log"), "-f", filepath.Join(f.dir, "sshd.conf"))
	t.Cleanup(func() {
		if root := os.Getenv("BACKEND_JAIL_EVIDENCE"); root != "" {
			dest := filepath.Join(root, filepath.Base(t.Name()))
			if err := os.MkdirAll(dest, 0700); err != nil {
				t.Error(err)
				return
			}
			// Explicit allowlist: never copy the directory containing private keys.
			for _, name := range []string{"sshd-raw.log", "auth.log", "filter.log", "fail2ban.log", "actions.log", "status.log", "sshd.conf", "fail2ban/jail.conf", "fail2ban/filter.d/sshd.conf"} {
				data, err := os.ReadFile(filepath.Join(f.dir, name))
				if err == nil {
					if err := os.WriteFile(filepath.Join(dest, strings.ReplaceAll(name, "/", "-")), data, 0600); err != nil {
						t.Error(err)
					}
				}
			}
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", f.addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sshd readiness: %v; %s", err, f.read("sshd-raw.log"))
		}
		time.Sleep(20 * time.Millisecond)
	}
	return f
}

// write persists private fixture configuration or public evidence.
func (f *jailFixture) write(name, data string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, name), []byte(data), 0600); err != nil {
		f.t.Fatal(err)
	}
}

// read reports missing evidence rather than hiding a failed foreground service.
func (f *jailFixture) read(name string) string {
	f.t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, name))
	if err != nil {
		f.t.Fatal(err)
	}
	return string(b)
}

// command runs only locally configured test binaries with a finite deadline.
func (f *jailFixture) command(name string, args ...string) string {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, jailTool(f.t, name), args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		f.t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

// start reaps a process group on every exit path, including failed assertions.
func (f *jailFixture) start(name string, args ...string) func() {
	f.t.Helper()
	cmd := exec.Command(jailTool(f.t, name), args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	log, err := os.Create(filepath.Join(f.dir, name+"-process.log"))
	if err != nil {
		f.t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		_ = log.Close()
		f.t.Fatal(err)
	}
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
			done := make(chan struct{})
			go func() { _ = cmd.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				<-done
			}
			_ = log.Close()
		}
	}
	f.t.Cleanup(stop)
	return stop
}

// connect uses a real SSH handshake and verifies the fixture's host key.
func (f *jailFixture) connect(login, key string, source ...string) error {
	data, err := os.ReadFile(key)
	if err != nil {
		return err
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return err
	}
	host, _, _, _, err := ssh.ParseAuthorizedKey([]byte(f.read("host.pub")))
	if err != nil {
		return err
	}
	dialer := net.Dialer{Timeout: time.Second}
	if len(source) != 0 {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(source[0])}
	}
	c, err := dialer.Dial("tcp", f.addr)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	conn, _, _, err := ssh.NewClientConn(c, f.addr, &ssh.ClientConfig{User: login, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(host)})
	if err == nil {
		_ = conn.Close()
	}
	return err
}

// controlFailure supplies a real, nonexempt failure as a log-consumption marker.
func (f *jailFixture) controlFailure() {
	if err := f.connect("containarium-jail-control-invalid", f.badKey, "127.0.0.2"); err == nil {
		f.t.Fatal("control account unexpectedly authenticated")
	}
}

// client addresses only this fixture's private fail2ban Unix socket.
func (f *jailFixture) client(args ...string) string {
	return f.command("fail2ban-client", append([]string{"-c", f.conf, "-s", filepath.Join(f.dir, "f2b.sock")}, args...)...)
}

// startJail starts the real polling filter after sshd has finished writing logs.
func (f *jailFixture) startJail() {
	f.stopJail = f.start("fail2ban-server", "-xf", "-c", f.conf, "-s", filepath.Join(f.dir, "f2b.sock"), "-p", filepath.Join(f.dir, "f2b.pid"), "--logtarget", filepath.Join(f.dir, "fail2ban.log"), "start")
	deadline := time.Now().Add(5 * time.Second)
	for {
		log, _ := os.ReadFile(filepath.Join(f.dir, "fail2ban.log"))
		if strings.Contains(string(log), "Jail 'sshd' started") {
			break
		}
		if time.Now().After(deadline) {
			f.t.Fatalf("fail2ban readiness: %s", f.read("fail2ban-server-process.log"))
		}
		time.Sleep(20 * time.Millisecond)
	}
	f.client("ping")
}

// waitStatus polls the real reader's counters and captures its final snapshot.
func (f *jailFixture) waitStatus(expected int) string {
	deadline := time.Now().Add(10 * time.Second)
	for {
		out := f.client("status", "sshd")
		match := regexp.MustCompile(`Total failed:\s+(\d+)`).FindStringSubmatch(out)
		if len(match) == 2 && match[1] == strconv.Itoa(expected) {
			f.write("status.log", out)
			return out
		}
		if time.Now().After(deadline) {
			f.t.Fatalf("expected %d failures; %s\n%s", expected, out, f.read("fail2ban.log"))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// waitAction proves the jail executed its configured ban or unban action.
func (f *jailFixture) waitAction(want string) {
	deadline := time.Now().Add(5 * time.Second)
	for {
		b, _ := os.ReadFile(filepath.Join(f.dir, "actions.log"))
		if strings.Contains("\n"+string(b), "\n"+want+"\n") {
			return
		}
		if time.Now().After(deadline) {
			f.t.Fatalf("missing action %q: %s", want, b)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
