package guardraildropin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TODO(#3761): the two values below belong to the hook handler. They are
// restated here because the handler is not merged yet; replace them with its
// exported constants once it is.
const (
	// stampSubdir is under the box user's $XDG_STATE_HOME (~/.local/state).
	stampSubdir = "containarium-guardrail/stamps"
	// clientProcessName is the comm of a Claude Code process.
	clientProcessName = "claude"
)

// DefaultEngineUnit is the systemd unit of the engine service the hook
// calls. Installing that unit, and putting the box user in the group that
// may open its socket, is the engine installer's job, not this package's.
const DefaultEngineUnit = "containarium-engine.service"

// DefaultStampGrace is how long a client process may run before a missing
// stamp counts. SessionStart fires within seconds; the slack is for a slow
// start.
const DefaultStampGrace = 3 * time.Minute

// stampSlack absorbs the rounding of ps's whole-second elapsed time.
const stampSlack = 5 * time.Second

// Box is the daemon's root path into a box: exec and file push as root.
// *incus.Client satisfies it.
type Box interface {
	ExecWithExitCode(container string, command []string) (stdout, stderr string, exitCode int, err error)
	WriteFile(container, path string, content []byte, mode string) error
	PushFile(container, path string, content io.ReadSeeker, mode string) error
}

// openBinary opens the pinned hook binary on the daemon's host.
type openBinary func() (io.ReadSeekCloser, error)

// Result is one coverage check's outcome.
type Result struct {
	Coverage      pb.GuardrailHookCoverage
	Detail        string
	ClientVersion string
	CheckedAt     time.Time
	// repair: the daemon's own files are missing or changed, so the next
	// step is to install them again.
	repair bool
}

type clientVersion struct{ fingerprint, version string }

// checker installs, removes and checks the drop-in in one box at a time.
type checker struct {
	box    Box
	opts   Options
	dropIn []byte
	// socket is the engine's unix socket path in the box; "" when the
	// engine address is not a unix socket.
	socket string
	open   openBinary
	clock  func() time.Time

	mu       sync.Mutex
	binSHA   string
	versions map[string]clientVersion // container -> last read
}

func newChecker(box Box, opts Options, open openBinary) (*checker, error) {
	socket, err := engineSocket(opts.EngineAddr)
	if err != nil {
		return nil, err
	}
	dropIn, err := Render(opts.HookTimeout, opts.EngineAddr)
	if err != nil {
		return nil, err
	}
	if _, err := versionAtLeast(opts.MinClientVersion, "0"); err != nil {
		return nil, fmt.Errorf("minimum client version: %w", err)
	}
	return &checker{box: box, opts: opts, dropIn: dropIn, socket: socket, open: open, clock: time.Now, versions: map[string]clientVersion{}}, nil
}

// binarySHA is the SHA-256 of the pinned binary, hashed once.
func (c *checker) binarySHA() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.binSHA != "" {
		return c.binSHA, nil
	}
	f, err := c.open()
	if err != nil {
		return "", fmt.Errorf("open hook binary: %w", err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash hook binary: %w", err)
	}
	c.binSHA = hex.EncodeToString(h.Sum(nil))
	return c.binSHA, nil
}

// engineSocket validates an engine address the way the hook does and
// returns its unix socket path, or "" for a loopback host:port or no engine.
// The path ends up inside a single-quoted shell word, so a quote is refused.
func engineSocket(addr string) (string, error) {
	p := strings.TrimPrefix(addr, "unix://")
	switch {
	case addr == "":
		return "", nil
	case strings.HasPrefix(p, "/"):
		if strings.ContainsAny(p, "'\n") {
			return "", fmt.Errorf("engine address %q: the socket path must not contain a quote or a newline", addr)
		}
		return p, nil
	case strings.HasPrefix(addr, "unix:"):
		return "", fmt.Errorf("engine address %q: want unix://<absolute path>", addr)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("engine address %q: want a unix socket path or a loopback host:port", addr)
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return "", fmt.Errorf("engine address %q is not inside the box: use a unix socket or a loopback address", addr)
	}
	return "", nil
}

// run executes argv as root in the box. A non-zero exit is not an error.
func (c *checker) run(container string, argv ...string) (string, int, error) {
	out, _, code, err := c.box.ExecWithExitCode(container, argv)
	if err != nil {
		return "", code, fmt.Errorf("%s in %q: %w", argv[0], container, err)
	}
	return out, code, nil
}

// mustRun is run for a command whose non-zero exit is a failure.
func (c *checker) mustRun(container string, argv ...string) error {
	_, code, err := c.run(container, argv...)
	if err == nil && code != 0 {
		err = fmt.Errorf("%s in %q: exit %d", argv[0], container, code)
	}
	return err
}

// boxSHA is the SHA-256 of a file in the box; "" when it is not there.
func (c *checker) boxSHA(container, p string) (string, error) {
	out, code, err := c.run(container, "sha256sum", "--", p)
	if err != nil || code != 0 {
		return "", err
	}
	return strings.Fields(out + " x")[0], nil
}

// install puts the pinned binary and then the drop-in into a running box.
// Binary first: the drop-in must never name a command that is not there.
func (c *checker) install(container string) error {
	want, err := c.binarySHA()
	if err != nil {
		return err
	}
	if err := c.mustRun(container, "mkdir", "-p", "-m", "0755", HookBinaryDir, DropInDir); err != nil {
		return err
	}
	have, err := c.boxSHA(container, HookBinaryPath)
	if err != nil {
		return err
	}
	if have != want {
		f, err := c.open()
		if err != nil {
			return fmt.Errorf("open hook binary: %w", err)
		}
		defer func() { _ = f.Close() }()
		if err := c.box.PushFile(container, HookBinaryPath, f, "0755"); err != nil {
			return fmt.Errorf("install hook binary in %q: %w", container, err)
		}
	}
	if err := c.box.WriteFile(container, DropInPath, c.dropIn, "0644"); err != nil {
		return fmt.Errorf("install drop-in in %q: %w", container, err)
	}
	return nil
}

// remove takes the drop-in out first, then the binary. It is the
// break-glass, so it must work whatever state the binary is in.
func (c *checker) remove(container string) error {
	if err := c.mustRun(container, "rm", "-f", "--", DropInPath); err != nil {
		return err
	}
	if err := c.mustRun(container, "rm", "-rf", "--", HookBinaryDir); err != nil {
		return err
	}
	c.mu.Lock()
	delete(c.versions, container)
	c.mu.Unlock()
	return nil
}

// check runs the coverage check on a running box whose switch is on. user is
// the box's Linux user. It reads; it never writes into the box.
func (c *checker) check(container, user string) Result {
	r := c.evaluate(container, user)
	r.CheckedAt = c.clock()
	return r
}

func unknown(err error) Result {
	return Result{Coverage: pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_UNKNOWN, Detail: "the check could not run: " + err.Error()}
}

func (c *checker) evaluate(container, user string) Result {
	// 1. Our own files: present, then unchanged.
	dropIn, code, err := c.run(container, "cat", "--", DropInPath)
	if err != nil {
		return unknown(err)
	}
	if code != 0 {
		return Result{Coverage: pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_NOT_INSTALLED, Detail: "the drop-in is missing", repair: true}
	}
	want, err := c.binarySHA()
	if err != nil {
		return unknown(err)
	}
	have, err := c.boxSHA(container, HookBinaryPath)
	if err != nil {
		return unknown(err)
	}
	if have == "" {
		return Result{Coverage: pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_NOT_INSTALLED, Detail: "the hook binary is missing", repair: true}
	}
	if !bytes.Equal([]byte(dropIn), c.dropIn) {
		return Result{Coverage: pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_TAMPERED, Detail: "the drop-in differs from what the daemon installed", repair: true}
	}
	if have != want {
		return Result{Coverage: pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_TAMPERED, Detail: "the hook binary differs from the pinned one", repair: true}
	}

	// 2. Any other managed file that turns hooks off. A second managed file
	// with disableAllHooks does disable ours, whichever sorts first.
	list, _, err := c.run(container, "find", ManagedSettingsDir, "-maxdepth", "2", "-name", "*.json")
	if err != nil {
		return unknown(err)
	}
	for _, p := range strings.Split(strings.TrimSpace(list), "\n") {
		if p == DropInPath || (path.Dir(p) != DropInDir && p != ManagedSettingsDir+"/managed-settings.json") {
			continue
		}
		raw, code, err := c.run(container, "cat", "--", p)
		if err != nil {
			return unknown(err)
		}
		if code == 0 && disablesHooks([]byte(raw)) {
			return Result{Coverage: pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_TAMPERED,
				Detail: fmt.Sprintf("another managed settings file sets disableAllHooks: %q", p)}
		}
	}

	// 3. The client version, as the box user, only when the binary changed.
	version, res := c.clientVersion(container, user)
	if res != nil {
		return *res
	}

	// 4. The detector engine.
	if c.opts.EngineUnit != "" {
		_, code, err := c.run(container, "systemctl", "is-active", "--quiet", c.opts.EngineUnit)
		if err != nil {
			return unknown(err)
		}
		if code != 0 {
			return Result{Coverage: pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_ENGINE_NOT_RUNNING,
				Detail: "the engine service " + c.opts.EngineUnit + " is not active", ClientVersion: version}
		}
	}
	// The hook runs as the box user, so a running engine whose socket that
	// user cannot open is the same outcome: no scan. A fresh login is
	// tested; a session started before the user joined the socket's group
	// keeps its old groups until it is restarted.
	if c.socket != "" {
		_, code, err := c.run(container, "su", "-", user, "-c", "test -S '"+c.socket+"' -a -r '"+c.socket+"' -a -w '"+c.socket+"'")
		if err != nil {
			return unknown(err)
		}
		if code != 0 {
			return Result{Coverage: pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_ENGINE_NOT_RUNNING,
				Detail:        "the engine socket " + c.socket + " is missing or the box user may not open it (is the user in the socket's group?)",
				ClientVersion: version}
		}
	}

	// 5. Are the hooks firing? Every hook invocation touches a stamp named
	// after its client process; a client that has run past the grace period
	// with no stamp since it started is running without our hooks.
	ps, _, err := c.run(container, "ps", "-eo", "pid=,etimes=,comm=")
	if err != nil {
		return unknown(err)
	}
	now := c.clock()
	for _, line := range strings.Split(ps, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[2] != clientProcessName {
			continue
		}
		pid, perr := strconv.Atoi(f[0])
		secs, serr := strconv.ParseInt(f[1], 10, 64)
		if perr != nil || serr != nil {
			continue
		}
		age := time.Duration(secs) * time.Second
		if age < c.opts.StampGrace {
			continue
		}
		out, code, err := c.run(container, "sh", "-c", stampMTimeScript, "sh", strconv.Itoa(pid))
		if err != nil {
			return unknown(err)
		}
		mtime, perr := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
		if code != 0 || perr != nil || time.Unix(mtime, 0).Before(now.Add(-age-stampSlack)) {
			return Result{Coverage: pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_HOOKS_NOT_FIRING,
				Detail:        fmt.Sprintf("client process %d has run for %s with no hook stamp since it started", pid, age.Round(time.Second)),
				ClientVersion: version}
		}
	}

	detail := "the drop-in and hook binary are in place and hooks are firing"
	if version == "" {
		detail = "the drop-in and hook binary are in place; no client is installed for the box user"
	}
	return Result{Coverage: pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_COVERED, Detail: detail, ClientVersion: version}
}

// stampMTimeScript prints the mtime of the stamp for the client process $1.
// It resolves the stamp directory from that process's own HOME and
// XDG_STATE_HOME and prints nothing else: no other variable of the process's
// environment leaves the box.
const stampMTimeScript = `e=/proc/$1/environ
h=$(tr '\0' '\n' <"$e" | sed -n 's/^HOME=//p' | head -n 1)
x=$(tr '\0' '\n' <"$e" | sed -n 's/^XDG_STATE_HOME=//p' | head -n 1)
exec stat -c %Y -- "${x:-$h/.local/state}/` + stampSubdir + `/$1"`

// clientVersion returns the box user's Claude Code version, "" when none is
// installed, or a non-nil Result when the version fails the check.
func (c *checker) clientVersion(container, user string) (string, *Result) {
	fp, code, err := c.run(container, "stat", "-L", "-c", "%i:%Y:%s", "/home/"+user+"/.local/bin/claude")
	if err != nil {
		r := unknown(err)
		return "", &r
	}
	if code != 0 {
		return "", nil
	}
	fp = strings.TrimSpace(fp)
	c.mu.Lock()
	cached := c.versions[container]
	c.mu.Unlock()
	if cached.fingerprint != fp {
		// As the box user, never root: the client must not create
		// root-owned state in the user's home.
		out, _, err := c.run(container, "su", "-", user, "-c", `"$HOME/.local/bin/claude" --version`)
		if err != nil {
			r := unknown(err)
			return "", &r
		}
		cached = clientVersion{fingerprint: fp, version: versionRE.FindString(strings.TrimSpace(out))}
		if cached.version != "" {
			c.mu.Lock()
			c.versions[container] = cached
			c.mu.Unlock()
		}
	}
	ok, err := versionAtLeast(cached.version, c.opts.MinClientVersion)
	if err != nil {
		r := unknown(fmt.Errorf("read the client version: %w", err))
		return "", &r
	}
	if !ok {
		return cached.version, &Result{Coverage: pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_CLIENT_TOO_OLD,
			Detail:        "client " + cached.version + " is older than the minimum " + c.opts.MinClientVersion,
			ClientVersion: cached.version}
	}
	return cached.version, nil
}

var versionRE = regexp.MustCompile(`^\d+(\.\d+)*`)

// versionAtLeast compares dotted numeric versions; a missing part is 0.
func versionAtLeast(have, min string) (bool, error) {
	h, err := versionParts(have)
	if err != nil {
		return false, err
	}
	m, err := versionParts(min)
	if err != nil {
		return false, err
	}
	for i := 0; i < len(h) || i < len(m); i++ {
		var a, b int
		if i < len(h) {
			a = h[i]
		}
		if i < len(m) {
			b = m[i]
		}
		if a != b {
			return a > b, nil
		}
	}
	return true, nil
}

func versionParts(v string) ([]int, error) {
	if v == "" || versionRE.FindString(v) != v {
		return nil, fmt.Errorf("version %q is not dotted numbers", v)
	}
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("version %q: %w", v, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// disablesHooks reports whether a managed settings file turns hooks off. A
// file that does not parse but names the key counts: the check errs toward
// reporting.
func disablesHooks(raw []byte) bool {
	var s struct {
		DisableAllHooks bool `json:"disableAllHooks"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return bytes.Contains(raw, []byte("disableAllHooks"))
	}
	return s.DisableAllHooks
}
