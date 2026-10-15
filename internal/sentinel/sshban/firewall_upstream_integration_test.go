//go:build integration && linux && sshfirewall

package sshban

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"golang.org/x/crypto/ssh"
)

// firewallFixture runs actual sshd and fail2ban only inside a fresh net namespace.
type firewallFixture struct {
	t                     *testing.T
	dir, conf, addr, port string
	bridgeStop            chan struct{}
	bridgeDone            chan struct{}
}

// firewallCommand runs fixed fixture tools with bounded execution and real output.
func (f *firewallFixture) command(name string, args ...string) string {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(f.t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		f.t.Fatalf("%s: %v\n%s", name, err, out)
	}
	return string(out)
}

// write stores only the selected fixture file in its private directory.
func (f *firewallFixture) write(name, body string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, name), []byte(body), 0600); err != nil {
		f.t.Fatal(err)
	}
}

// start reaps the actual server process on success and every failed assertion.
func (f *firewallFixture) start(name string, args ...string) {
	f.t.Helper()
	log, err := os.Create(filepath.Join(f.dir, filepath.Base(name)+".process.log"))
	if err != nil {
		f.t.Fatal(err)
	}
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		_ = log.Close()
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); _ = log.Close() })
}

// newFirewallFixture refuses host-network execution before invoking any firewall tool.
func newFirewallFixture(t *testing.T) *firewallFixture {
	t.Helper()
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	host, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 || self == host || os.Getenv("SSH_UPSTREAM_ISOLATED_NETNS") != "1" {
		t.Fatal("run with sudo unshare --net; host firewall execution is forbidden")
	}
	f := &firewallFixture{t: t, dir: t.TempDir(), addr: retryUnusedAddress(t), bridgeStop: make(chan struct{}), bridgeDone: make(chan struct{})}
	// Activate connection tracking before creating baseline flows. Installing
	// the first conntrack rule only after a handshake misclassifies that
	// previously untracked flow as NEW and invalidates session-survival proof.
	f.command("iptables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	_, f.port, _ = net.SplitHostPort(f.addr)
	f.conf = filepath.Join(f.dir, "fail2ban")
	f.command("cp", "-R", "/etc/fail2ban", f.conf)
	if err := os.RemoveAll(filepath.Join(f.conf, "jail.d")); err != nil {
		t.Fatal(err)
	}
	f.write("auth.log", "")
	f.write("sshd-raw.log", "")
	f.write("authorized_keys", "")
	f.command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(f.dir, "host"))
	f.write("sshd.conf", fmt.Sprintf("ListenAddress 127.0.0.1\nPort %s\nHostKey %s/host\nPidFile %s/sshd.pid\nAuthorizedKeysFile %s/authorized_keys\nStrictModes no\nUsePAM yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin yes\nLogLevel VERBOSE\n", f.port, f.dir, f.dir, f.dir))
	f.write("fail2ban/fail2ban.local", "[DEFAULT]\ndbfile = None\n")
	f.write("fail2ban/jail.conf", fmt.Sprintf("[DEFAULT]\nbackend = polling\nusedns = no\nignoreself = false\nignoreip =\nmaxretry = 3\nfindtime = 600\nbantime = 3600\n[sshd]\nenabled = true\nfilter = sshd[publickey=any]\nlogpath = %s/auth.log\naction = iptables-multiport[name=guard-proof, port=%s, protocol=tcp]\n", f.dir, f.port))
	go f.bridgeLogs()
	t.Cleanup(func() { close(f.bridgeStop); <-f.bridgeDone })
	f.start("/usr/sbin/sshd", "-D", "-E", filepath.Join(f.dir, "sshd-raw.log"), "-f", filepath.Join(f.dir, "sshd.conf"))
	f.wait(func() bool {
		c, err := net.DialTimeout("tcp", f.addr, 100*time.Millisecond)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	}, "sshd readiness")
	f.start("fail2ban-server", "-xf", "-c", f.conf, "-s", filepath.Join(f.dir, "f2b.sock"), "-p", filepath.Join(f.dir, "f2b.pid"), "--logtarget", filepath.Join(f.dir, "fail2ban.log"), "start")
	f.wait(func() bool {
		data, _ := os.ReadFile(filepath.Join(f.dir, "fail2ban.log"))
		return strings.Contains(string(data), "Jail 'sshd' started")
	}, "live jail readiness")
	t.Cleanup(func() {
		if root := os.Getenv("SSH_UPSTREAM_EVIDENCE_DIR"); root != "" {
			if err := os.MkdirAll(root, 0755); err != nil {
				t.Error(err)
				return
			}
			for _, name := range []string{"auth.log", "sshd-raw.log", "fail2ban.log", "sshd.conf", "fail2ban/jail.conf", "status.log", "iptables.log", "iptables-banned.log"} {
				data, err := os.ReadFile(filepath.Join(f.dir, name))
				if err == nil {
					if err := os.WriteFile(filepath.Join(root, strings.ReplaceAll(name, "/", "-")), data, 0644); err != nil {
						t.Error(err)
					}
				}
			}
		}
	})
	return f
}

// bridgeLogs adds only the syslog envelope missing from foreground sshd -E.
func (f *firewallFixture) bridgeLogs() {
	defer close(f.bridgeDone)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	offset := 0
	for {
		select {
		case <-f.bridgeStop:
			return
		case <-ticker.C:
		}
		data, err := os.ReadFile(filepath.Join(f.dir, "sshd-raw.log"))
		if err != nil {
			f.t.Error(err)
			return
		}
		if len(data) <= offset {
			continue
		}
		end := strings.LastIndexByte(string(data), '\n') + 1
		if end <= offset {
			continue
		}
		out, err := os.OpenFile(filepath.Join(f.dir, "auth.log"), os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			f.t.Error(err)
			return
		}
		for _, line := range strings.Split(strings.TrimRight(string(data[offset:end]), "\r\n"), "\n") {
			if _, err := fmt.Fprintf(out, "%s fixture sshd: %s\n", time.Now().Format("Jan _2 15:04:05"), strings.TrimSuffix(line, "\r")); err != nil {
				f.t.Error(err)
			}
		}
		_ = out.Close()
		offset = end
	}
}

// wait polls explicit observable state instead of sleeping through readiness.
func (f *firewallFixture) wait(ready func() bool, what string) {
	f.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			data, _ := os.ReadFile(filepath.Join(f.dir, "fail2ban.log"))
			raw, _ := os.ReadFile(filepath.Join(f.dir, "sshd-raw.log"))
			f.t.Fatalf("%s timed out:\n%s\n%s", what, data, raw)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// jail addresses only this namespace fixture's private fail2ban socket.
func (f *firewallFixture) jail(args ...string) string {
	return f.command("fail2ban-client", append([]string{"-c", f.conf, "-s", filepath.Join(f.dir, "f2b.sock")}, args...)...)
}

// direct tests real packet reachability and credential acceptance independently.
func (f *firewallFixture) direct(source string, key ssh.Signer) error {
	d := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
	c, err := d.Dial("tcp", f.addr)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	s, _, _, err := ssh.NewClientConn(c, f.addr, &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.PublicKeys(key)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	if err == nil {
		_ = s.Close()
	}
	return err
}

// TestIntegrationGuardedSSHLiveFirewall measures a multi-minute real outage.
func TestIntegrationGuardedSSHLiveFirewall(t *testing.T) {
	f := newFirewallFixture(t)
	healthyAddr := retryUnusedAddress(t)
	controller, socket := guardedControl(t, f.addr, 10*time.Minute, healthyAddr)
	main := newConfiguredRetryFixture(t, 3, 1, retryMode{routed: true, controlSocket: socket, backend: f.addr, backendUser: "root"})
	anon := newConfiguredRetryFixture(t, 3, 1, retryMode{routed: true, anonymous: true, controlSocket: socket, backend: f.addr, backendUser: "root"})
	healthy := newConfiguredRetryFixture(t, 3, 1, retryMode{routed: true, controlSocket: socket, backend: healthyAddr})
	healthy.retryBackend(t)
	keys := string(ssh.MarshalAuthorizedKey(main.upstream.PublicKey())) + string(ssh.MarshalAuthorizedKey(anon.upstream.PublicKey()))
	f.write("authorized_keys", keys)
	if err := f.direct("127.0.0.9", main.upstream); err != nil {
		t.Fatalf("real sshd authorized baseline: %v", err)
	}
	_, bad := integrationKey(t, t.TempDir(), "firewall-control-bad")
	for range 3 {
		if err := f.direct("127.0.0.9", bad); err == nil {
			t.Fatal("negative control authenticated")
		}
	}
	f.wait(func() bool { return strings.Contains(f.jail("get", "sshd", "banip"), "127.0.0.9") }, "actual negative-control ban")
	if err := f.direct("127.0.0.9", main.upstream); err == nil {
		t.Fatal("jail announced a ban without blocking authorized packets")
	}
	f.write("iptables-banned.log", f.command("iptables-save"))
	f.jail("set", "sshd", "unbanip", "127.0.0.9")
	f.wait(func() bool { return f.direct("127.0.0.9", main.upstream) == nil }, "packet recovery after unban")

	// A live connection and its authenticated SSH transport must survive a
	// NEW-only outage rule. The real sshd process and existing flows stay up.
	raw, err := net.DialTimeout("tcp", main.addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.SetDeadline(time.Now().Add(4 * time.Second))
	established, chans, requests, err := ssh.NewClientConn(raw, main.addr, &ssh.ClientConfig{User: "fixture", Auth: []ssh.AuthMethod{ssh.PublicKeys(main.keys[0])}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	if err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	defer established.Close()
	go ssh.DiscardRequests(requests)
	go func() {
		for c := range chans {
			_ = c.Reject(ssh.Prohibited, "no server-initiated channels")
		}
	}()
	_ = raw.SetDeadline(time.Time{})
	f.command("iptables", "-I", "INPUT", "1", "-s", "127.0.0.1", "-p", "tcp", "--dport", f.port, "-m", "conntrack", "--ctstate", "NEW", "-j", "REJECT", "--reject-with", "tcp-reset")
	start := time.Now()
	clients := 0
	for time.Since(start) < 125*time.Second {
		var wg sync.WaitGroup
		for _, entry := range []*retryFixture{main, anon} {
			wg.Go(func() {
				if err := retryHandshake(entry.addr, "127.0.0.2", entry.keys[0]); err == nil {
					t.Error("outage admitted a backend SSH setup")
				}
			})
		}
		wg.Wait()
		clients += 2
		if err := retryHandshake(healthy.addr, "127.0.0.2", healthy.keys[0]); err != nil {
			t.Fatalf("outage blocked an unrelated healthy backend: %v", err)
		}
		if _, _, err := established.SendRequest("keepalive@openssh.com", true, nil); err != nil {
			t.Fatalf("established session interrupted by setup gate: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	outageAttempts := len(main.attempts(t)) + len(anon.attempts(t)) - 1
	if outageAttempts > 22 {
		t.Fatalf("unbounded aggregate retry rate: %d attempts/125s", outageAttempts)
	}
	f.command("iptables", "-D", "INPUT", "-s", "127.0.0.1", "-p", "tcp", "--dport", f.port, "-m", "conntrack", "--ctstate", "NEW", "-j", "REJECT", "--reject-with", "tcp-reset")
	if _, err := controller.HintSSHUpstreamRecovery(t.Context(), &pb.HintSSHUpstreamRecoveryRequest{BackendId: "backend"}); err != nil {
		t.Fatal(err)
	}
	restored := time.Now()
	if err := retryHandshake(main.addr, "127.0.0.2", main.keys[0]); err != nil {
		t.Fatalf("hinted SSH-ready recovery: %v", err)
	}
	if err := retryHandshake(anon.addr, "127.0.0.2", anon.keys[0]); err != nil {
		t.Fatalf("anonymous recovery: %v", err)
	}
	if time.Since(restored) > 3*time.Second {
		t.Fatal("safe-budget recovery exceeded three seconds")
	}
	for _, entry := range []*retryFixture{main, anon} {
		if got := entry.status(t, "127.0.0.2").Status.GetFailures(); got != 0 {
			t.Fatalf("backend outage charged source %d", got)
		}
	}
	if strings.Contains(f.jail("get", "sshd", "banip"), "127.0.0.1") {
		t.Fatal("backend banned sentinel during guarded outage")
	}
	f.write("status.log", f.jail("status", "sshd"))
	t.Logf("outage=%s clients=%d backend_connects=%d source=127.0.0.1 maxretry=3 findtime=600s filter=publickey=any ignoreip=empty; sentinel unbanned; recovery=%s; actual firewall negative control passed", time.Since(start), clients, outageAttempts, time.Since(restored))

	// Reachable rejection consumes two real jail matches, then recovery waits
	// out the actual 600-second window even after the proxy keys are repaired.
	f.write("authorized_keys", "")
	for i := range 2 {
		if err := retryHandshake(main.addr, "127.0.0.2", main.keys[0]); err == nil {
			t.Fatal("rejected proxy key authenticated")
		}
		if i == 0 {
			time.Sleep(1300 * time.Millisecond)
		}
	}
	f.wait(func() bool {
		data, _ := os.ReadFile(filepath.Join(f.dir, "auth.log"))
		return strings.Count(string(data), "Failed publickey for root from 127.0.0.1 ") >= 2
	}, "two measured proxy-key failures")
	f.write("authorized_keys", keys)
	before := len(main.attempts(t)) + len(anon.attempts(t))
	blockedAt := time.Now()
	for time.Since(blockedAt) < 601*time.Second {
		for _, entry := range []*retryFixture{main, anon} {
			if err := retryHandshake(entry.addr, "127.0.0.2", entry.keys[0]); err == nil {
				t.Fatal("exhausted risk budget reopened before full findtime")
			}
		}
		if got := len(main.attempts(t)) + len(anon.attempts(t)); got != before {
			t.Fatal("exhausted budget sent a backend packet")
		}
		if strings.Contains(f.jail("get", "sshd", "banip"), "127.0.0.1") {
			t.Fatal("sentinel was banned")
		}
		// Stop just before the retained last failure expires; recover below by
		// polling a fresh client once the full window has actually elapsed.
		if time.Since(blockedAt) > 595*time.Second {
			break
		}
		time.Sleep(time.Second)
	}
	f.wait(func() bool { return retryHandshake(main.addr, "127.0.0.2", main.keys[0]) == nil }, "safe recovery after real findtime")
	f.write("status.log", f.jail("status", "sshd"))
	f.write("iptables.log", f.command("iptables-save"))
	t.Logf("exhausted real 600s budget retained; aggregate backend attempts stayed at %d during suppression; recovery waited=%s", before, time.Since(blockedAt))
}
