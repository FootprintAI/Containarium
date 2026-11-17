package guardraildropin

import (
	"bytes"
	"encoding/json"
	"errors"
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
// restated here because this package must not import it before it merges;
// replace them with its constants afterwards.
const (
	// stampSubdir is under the box user's state directory.
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

// maxManagedFileBytes caps what the check reads from one managed settings
// file. A real one is a few kilobytes.
const maxManagedFileBytes = 1 << 20

// openBinary opens the pinned hook binary on the daemon's host.
type openBinary func() (io.ReadSeekCloser, error)

// Result is one coverage check's outcome.
type Result struct {
	Coverage      pb.GuardrailHookCoverage
	Detail        string
	ClientVersion string
	// ClientInstalled is whether a client was found for the box user. A
	// box that is COVERED with none installed has nothing running without
	// the hooks; it has not shown that hooks fire.
	ClientInstalled bool
	CheckedAt       time.Time
	// repair: the daemon's own files are missing or changed, so the next
	// step is to install them again.
	repair bool
	// stale: the files are the ones an earlier daemon version or earlier
	// flags installed. Not tampering; repaired without being reported.
	stale bool
}

type clientVersion struct{ fingerprint, version string }

// checker installs, removes and checks the drop-in in one box at a time.
type checker struct {
	box    Box
	run    runner
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
	if opts.ExecTimeout < time.Second {
		return nil, fmt.Errorf("guardrail hook exec timeout %s is under one second", opts.ExecTimeout)
	}
	return &checker{box: box, run: runner{box: box, timeout: opts.ExecTimeout, grace: execGrace}, opts: opts,
		dropIn: dropIn, socket: socket, open: open, clock: time.Now, versions: map[string]clientVersion{}}, nil
}

// engineSocket validates an engine address the way the hook does and
// returns its unix socket path, or "" for a loopback host:port or no engine.
func engineSocket(addr string) (string, error) {
	p := strings.TrimPrefix(addr, "unix://")
	switch {
	case addr == "":
		return "", nil
	case strings.HasPrefix(p, "/"):
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

// node is what `stat` says about one path, without following a link.
type node struct {
	missing bool
	kind    string // stat's %F: "regular file", "directory", "symbolic link", "fifo", ...
	uid     int
	mode    int64
}

// closed: owned by root and not writable by group or others.
func (n node) closed() bool { return !n.missing && n.uid == 0 && n.mode&0o022 == 0 }

func (n node) rootDir() bool { return n.kind == "directory" && n.closed() }

func (n node) rootFile() bool { return strings.HasPrefix(n.kind, "regular") && n.closed() }

const statScript = `for p in "$@"; do stat -c '%F|%u|%a' -- "$p" 2>/dev/null || echo missing; done`

// stat reports each path's type, owner and mode. It never opens the path.
func (c *checker) stat(container string, paths ...string) ([]node, error) {
	out, _, err := c.run.script(container, statScript, paths...)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != len(paths) {
		return nil, fmt.Errorf("stat in %q: %d answers for %d paths", container, len(lines), len(paths))
	}
	nodes := make([]node, len(paths))
	for i, l := range lines {
		f := strings.Split(l, "|")
		if len(f) != 3 {
			nodes[i].missing = true
			continue
		}
		uid, uerr := strconv.Atoi(f[1])
		mode, merr := strconv.ParseInt(f[2], 8, 64)
		if uerr != nil || merr != nil {
			return nil, fmt.Errorf("stat in %q: unreadable answer for %s", container, paths[i])
		}
		nodes[i] = node{kind: f[0], uid: uid, mode: mode}
	}
	return nodes, nil
}

// check runs the coverage check on a running box whose switch is on. user is
// the box's Linux user; prev is what the daemon last installed there. It
// reads; it never writes into the box.
func (c *checker) check(container, user string, prev installed) Result {
	r := c.evaluate(container, user, prev)
	r.CheckedAt = c.clock()
	return r
}

func unknown(err error) Result {
	detail := "the check could not run: " + err.Error()
	if errors.Is(err, errExecTimeout) {
		detail = "the check timed out inside the box: " + err.Error()
	}
	return Result{Coverage: pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_UNKNOWN, Detail: detail}
}

func notInstalled(detail string) Result {
	return Result{Coverage: pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_NOT_INSTALLED, Detail: detail, repair: true}
}

func tampered(detail string, repair bool) Result {
	return Result{Coverage: pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_TAMPERED, Detail: detail, repair: repair}
}

func (c *checker) evaluate(container, user string, prev installed) Result {
	// 1. Our own files and their directories: what they are, whose they
	// are, then what is in them. Nothing is opened before stat says it is
	// a regular file.
	paths := []string{ManagedSettingsDir, DropInDir, HookBinaryDir, DropInPath, HookBinaryPath}
	nodes, err := c.stat(container, paths...)
	if err != nil {
		return unknown(err)
	}
	for i, n := range nodes[:3] {
		switch {
		case n.missing:
			return notInstalled(paths[i] + " is missing")
		case !n.rootDir():
			// Not repaired: the install refuses such a directory too.
			return tampered(paths[i]+" is not a root-owned directory closed to group and others", false)
		}
	}
	for i, n := range nodes[3:] {
		switch p := paths[3+i]; {
		case n.missing:
			return notInstalled(p + " is missing")
		case !n.rootFile():
			return tampered(p+" is not a regular root-owned file closed to group and others", true)
		}
	}
	want, err := c.current()
	if err != nil {
		return unknown(err)
	}
	dropIn, _, err := c.run.run(container, "head", "-c", strconv.Itoa(maxManagedFileBytes), "--", DropInPath)
	if err != nil {
		return unknown(err)
	}
	haveBin, err := c.boxSHA(container, HookBinaryPath)
	if err != nil {
		return unknown(err)
	}
	if have := sha256Hex([]byte(dropIn)); have != want.dropIn {
		if have == prev.dropIn {
			return Result{repair: true, stale: true, Detail: "the drop-in is from an earlier daemon configuration"}
		}
		return tampered("the drop-in differs from what the daemon installed", true)
	}
	if haveBin != want.binary {
		if haveBin == prev.binary {
			return Result{repair: true, stale: true, Detail: "the hook binary is from an earlier daemon version"}
		}
		return tampered("the hook binary differs from the pinned one", true)
	}

	// 2. Any other managed file that turns hooks off. A second managed file
	// with disableAllHooks does disable ours, whichever sorts first. Names
	// are NUL-separated (a name may hold a newline), and only a regular
	// file under the size cap is opened: a link or a FIFO is reported, not
	// read.
	list, _, err := c.run.run(container, "find", ManagedSettingsDir, "-maxdepth", "2", "-name", "*.json", "-printf", `%y\t%s\t%p\0`)
	if err != nil {
		return unknown(err)
	}
	for _, entry := range strings.Split(list, "\x00") {
		f := strings.SplitN(entry, "\t", 3)
		if len(f) != 3 {
			continue
		}
		kind, p := f[0], f[2]
		if p == DropInPath || kind == "d" || (path.Dir(p) != DropInDir && p != ManagedSettingsDir+"/managed-settings.json") {
			continue
		}
		if size, serr := strconv.ParseInt(f[1], 10, 64); kind != "f" || serr != nil || size > maxManagedFileBytes {
			return tampered(fmt.Sprintf("another managed settings file cannot be checked (not a regular file, or too large): %q", p), false)
		}
		raw, code, err := c.run.run(container, "head", "-c", strconv.Itoa(maxManagedFileBytes), "--", p)
		if err != nil {
			return unknown(err)
		}
		if code == 0 && disablesHooks([]byte(raw)) {
			return tampered(fmt.Sprintf("another managed settings file sets disableAllHooks: %q", p), false)
		}
	}

	// 3. The client and its version.
	res := Result{}
	if stop := c.client(container, user, &res); stop {
		return res
	}

	// 4. The engine service, then its socket as the box user: the hook
	// runs as that user, so a running engine whose socket the user cannot
	// open is the same outcome, no scan. A fresh process is tested; a
	// session started before the user joined the socket's group keeps its
	// old groups until it is restarted.
	if c.opts.EngineUnit != "" {
		_, code, err := c.run.run(container, "systemctl", "is-active", "--quiet", c.opts.EngineUnit)
		if err != nil {
			return unknown(err)
		}
		if code != 0 {
			res.Coverage = pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_ENGINE_NOT_RUNNING
			res.Detail = "the engine service " + c.opts.EngineUnit + " is not active"
			return res
		}
	}
	if c.socket != "" {
		_, code, err := c.run.run(container, "runuser", "-u", user, "--", "test", "-S", c.socket, "-a", "-r", c.socket, "-a", "-w", c.socket)
		if err != nil {
			return unknown(err)
		}
		if code != 0 {
			res.Coverage = pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_ENGINE_NOT_RUNNING
			res.Detail = "the engine socket " + c.socket + " is missing or the box user may not open it (is the user in the socket's group?)"
			return res
		}
	}

	// 5. Are the hooks firing? Every hook invocation touches a stamp named
	// after its client process; a client that has run past the grace period
	// with no stamp since it started is running without our hooks.
	ps, _, err := c.run.run(container, "ps", "-eo", "pid=,etimes=,comm=")
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
		out, code, err := c.run.script(container, stampMTimeScript, strconv.Itoa(pid))
		if err != nil {
			return unknown(err)
		}
		mtime, perr := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
		if code != 0 || perr != nil || time.Unix(mtime, 0).Before(now.Add(-age-stampSlack)) {
			res.Coverage = pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_HOOKS_NOT_FIRING
			res.Detail = fmt.Sprintf("client process %d has run for %s with no hook stamp since it started", pid, age.Round(time.Second))
			return res
		}
	}

	res.Coverage = pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_COVERED
	res.Detail = "the drop-in and hook binary are in place and hooks are firing"
	if !res.ClientInstalled {
		res.Detail = "the drop-in and hook binary are in place; no client is installed for the box user"
	}
	return res
}

// stampMTimeScript prints the mtime of the stamp for the client process $1.
// It resolves the state directory the way the hook does, from that
// process's own environment: XDG_STATE_HOME when it is an absolute path,
// else HOME/.local/state. Nothing else of the environment leaves the box.
const stampMTimeScript = `e=/proc/$1/environ
h=$(tr '\0' '\n' <"$e" | sed -n 's/^HOME=//p' | head -n 1)
x=$(tr '\0' '\n' <"$e" | sed -n 's/^XDG_STATE_HOME=//p' | head -n 1)
case "$x" in /*) ;; *) x="$h/.local/state" ;; esac
exec stat -c %Y -- "$x/` + stampSubdir + `/$1"`

// findClientScript prints the client binary for the box user $1 as three
// lines: an identity of the file (inode, mtime, size), its path, and the
// user's home. It looks where the installers put it and on a default PATH,
// then at the executable of any running client process. It runs as root
// and executes nothing of the user's: no profile, no client. Exit 1 means
// no client was found.
const findClientScript = `h=$(getent passwd "$1" | cut -d: -f6)
[ -n "$h" ] || exit 2
p=$(PATH="$h/.local/bin:$h/.claude/local:$h/.npm-global/bin:$h/bin:/usr/local/bin:/usr/bin:/bin"; command -v ` + clientProcessName + ` 2>/dev/null)
if [ -z "$p" ]; then
  for d in /proc/[0-9]*; do
    [ "$(cat "$d/comm" 2>/dev/null)" = ` + clientProcessName + ` ] || continue
    t=$(readlink "$d/exe" 2>/dev/null)
    case "$t" in ''|*/node|*/bun|*' (deleted)') continue ;; esac
    p=$t
    break
  done
fi
[ -n "$p" ] || exit 1
stat -L -c '%i:%Y:%s' -- "$p" || exit 1
printf '%s\n%s\n' "$p" "$h"`

// client fills the client fields of res. It returns true when res is final:
// the version fails the check, or the check could not run.
func (c *checker) client(container, user string, res *Result) bool {
	out, code, err := c.run.script(container, findClientScript, user)
	if err != nil {
		*res = unknown(err)
		return true
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if code != 0 || len(lines) != 3 {
		return false // no client for this user
	}
	res.ClientInstalled = true
	fp, bin, home := lines[0], lines[1], lines[2]
	c.mu.Lock()
	cached := c.versions[container]
	c.mu.Unlock()
	if cached.fingerprint != fp {
		// Read only when the binary changed, and as the box user, never
		// root: the client must not create root-owned state in the user's
		// home. No login shell, so the user's profile neither runs nor
		// prints ahead of the version.
		out, _, err := c.run.run(container, "runuser", "-u", user, "--",
			"env", "-i", "HOME="+home, "PATH=/usr/local/bin:/usr/bin:/bin", bin, "--version")
		if err != nil {
			*res = unknown(err)
			res.ClientInstalled = true
			return true
		}
		cached = clientVersion{fingerprint: fp, version: versionRE.FindString(out)}
		if cached.version != "" {
			c.mu.Lock()
			c.versions[container] = cached
			c.mu.Unlock()
		}
	}
	res.ClientVersion = cached.version
	ok, err := versionAtLeast(cached.version, c.opts.MinClientVersion)
	switch {
	case err != nil:
		*res = unknown(fmt.Errorf("read the client version: %w", err))
		res.ClientInstalled = true
		return true
	case !ok:
		res.Coverage = pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_CLIENT_TOO_OLD
		res.Detail = "client " + cached.version + " is older than the minimum " + c.opts.MinClientVersion
		return true
	}
	return false
}

// versionRE finds the first dotted version anywhere in a command's output.
var versionRE = regexp.MustCompile(`\d+(?:\.\d+)+`)

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
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("version %q is not dotted numbers", v)
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
