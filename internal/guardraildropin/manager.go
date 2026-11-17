package guardraildropin

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// DefaultCheckInterval is the period of the coverage check.
const DefaultCheckInterval = 5 * time.Minute

// ErrBoxNotFound is returned for a username with no box on this daemon.
var ErrBoxNotFound = errors.New("box not found")

// Options are the daemon's knobs; zero values take the defaults.
type Options struct {
	CheckInterval    time.Duration
	MinClientVersion string
	HookTimeout      time.Duration
	StampGrace       time.Duration
	// ExecTimeout bounds each command the daemon runs inside a box.
	ExecTimeout time.Duration
	// EngineUnit is the systemd unit of the detector engine in the box.
	// Empty or EngineBuiltin: the daemon installs the reference engine as
	// ReferenceEngineUnit and runs it. Any other name is a unit the
	// operator provides; the daemon installs none and only checks it.
	// EngineNone skips the unit check too.
	EngineUnit string
	// EngineAddr is the engine's address inside the box, passed to every
	// hook as --engine: unix://<absolute path>, an absolute socket path, or
	// a loopback host:port. Empty follows EngineUnit: the built-in
	// engine's socket, or DefaultEngineAddr for an operator's unit.
	// EngineNone passes none, and the hook scans with its in-process
	// reference rules.
	EngineAddr string
	// HookBinary is the host path of the CLI binary copied into boxes.
	// Empty means the daemon's own executable, which carries the same
	// command tree and is by construction the daemon's version. Either way
	// the file must be a statically linked Linux binary: a box has its own
	// libc, which need not be the host's.
	HookBinary string
}

// EngineNone as Options.EngineUnit or Options.EngineAddr means "no engine
// service": no unit to check, no address to pass.
const EngineNone = "none"

func (o Options) withDefaults() Options {
	if o.CheckInterval <= 0 {
		o.CheckInterval = DefaultCheckInterval
	}
	if o.MinClientVersion == "" {
		o.MinClientVersion = DefaultMinClientVersion
	}
	if o.HookTimeout <= 0 {
		o.HookTimeout = DefaultHookTimeout
	}
	if o.ExecTimeout <= 0 {
		o.ExecTimeout = DefaultExecTimeout
	}
	if o.StampGrace <= 0 {
		o.StampGrace = DefaultStampGrace
	}
	switch o.EngineUnit {
	case "":
		o.EngineUnit = EngineBuiltin
	case EngineNone:
		o.EngineUnit = ""
	}
	switch o.EngineAddr {
	case "":
		o.EngineAddr = DefaultEngineAddr
		if o.EngineUnit == EngineBuiltin {
			o.EngineAddr = ReferenceEngineAddr
		}
	case EngineNone:
		o.EngineAddr = ""
	}
	return o
}

// Instances is the slice of the Incus client the manager needs besides Box.
type Instances interface {
	ListContainers() ([]incus.ContainerInfo, error)
	GetRawInstance(name string) (map[string]string, string, error)
	SetConfig(containerName, key, value string) error
	UnsetConfig(containerName, key string) error
}

// BoxCoverage is one box's switch and last check.
type BoxCoverage struct {
	Username string
	Enabled  bool
	Result
}

// Manager owns the per-box switch, the install and removal of the drop-in,
// and the periodic coverage check. The switch is the box's
// incus.GuardrailHookKey, so it survives a daemon restart and moves with
// the box; results are in memory and rebuilt by the next check.
//
// The check execs as root and reads. It writes nothing into the box, and
// nothing into the box's config unless it had to install again. Auto-sleep
// reads the last-start stamp and recorded network traffic only, so a check
// is not activity and never wakes a box.
type Manager struct {
	inst     Instances
	checker  *checker
	interval time.Duration

	// boxMu holds one lock per box: enable, start and the periodic check
	// of one box run one at a time, and a slow box holds up no other.
	// Switching off takes no lock at all (see SetEnabled).
	boxMu sync.Map // container name -> *sync.Mutex

	mu      sync.Mutex
	results map[string]Result // container name -> last check

	stopCh   chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

// NewManager builds a manager over the daemon's Incus client.
func NewManager(inst Instances, box Box, opts Options) (*Manager, error) {
	return newManager(inst, box, opts, func() (io.ReadSeekCloser, error) { return openHookBinary(opts.HookBinary) })
}

// openHookBinary opens the binary to pin and refuses one that is not a
// static Linux executable. The daemon's own executable is opened through
// /proc/self/exe, which is the running file even after the path on disk was
// replaced by an upgrade that has not restarted the daemon yet.
func openHookBinary(path string) (io.ReadSeekCloser, error) {
	if path == "" {
		path = "/proc/self/exe"
		if _, err := os.Stat(path); err != nil {
			if path, err = os.Executable(); err != nil {
				return nil, err
			}
		}
	}
	f, err := os.Open(path) // #nosec G304 -- operator-configured path or the daemon's own executable
	if err != nil {
		return nil, err
	}
	if err := requireStaticELF(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("hook binary %s: %w; build the daemon with CGO_ENABLED=0 or name a static containarium binary with --guardrail-hook-binary", path, err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// requireStaticELF accepts only an ELF executable with no program
// interpreter, which is what CGO_ENABLED=0 produces. A dynamically linked
// binary needs the loader and libc of the machine it was built for.
func requireStaticELF(r io.ReaderAt) error {
	f, err := elf.NewFile(r)
	if err != nil {
		return errors.New("not a Linux ELF executable")
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return errors.New("dynamically linked, so it may not start on a box's libc")
		}
	}
	return nil
}

func newManager(inst Instances, box Box, opts Options, open openBinary) (*Manager, error) {
	opts = opts.withDefaults()
	c, err := newChecker(box, opts, open)
	if err != nil {
		return nil, err
	}
	return &Manager{inst: inst, checker: c, interval: opts.CheckInterval, results: map[string]Result{},
		stopCh: make(chan struct{}), done: make(chan struct{})}, nil
}

// Start runs the periodic check until ctx is done or Stop is called.
func (m *Manager) Start(ctx context.Context) {
	go func() {
		defer close(m.done)
		t := time.NewTicker(m.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-m.stopCh:
				return
			case <-t.C:
				m.tick()
			}
		}
	}()
}

// Stop ends the loop and waits for a check in flight.
func (m *Manager) Stop() {
	m.stopOnce.Do(func() { close(m.stopCh) })
	<-m.done
}

func containerName(username string) string { return username + "-container" }

func usernameOf(container string) string { return strings.TrimSuffix(container, "-container") }

const stateRunning = "Running"

// tick checks every running box whose switch is set. Boxes that never had
// the feature on are not touched at all.
func (m *Manager) tick() {
	boxes, err := m.inst.ListContainers()
	if err != nil {
		log.Printf("[guardrail-hook] list boxes: %v", err)
		return
	}
	for _, b := range boxes {
		if b.Role.IsCoreRole() || b.GuardrailHook == incus.GuardrailHookOff || b.State != stateRunning {
			continue
		}
		m.reconcile(b.Name, false)
	}
}

// BoxStarted applies the switch to a box that has just started: install
// while it is on, or finish a removal owed from when the box was stopped.
func (m *Manager) BoxStarted(username string) {
	m.reconcile(containerName(username), true)
}

func (m *Manager) lockBox(container string) func() {
	mu, _ := m.boxMu.LoadOrStore(container, &sync.Mutex{})
	mu.(*sync.Mutex).Lock()
	return mu.(*sync.Mutex).Unlock
}

// state reads a box's switch and what the daemon last installed there.
func (m *Manager) state(container string) (incus.GuardrailHookSwitch, installed, error) {
	cfg, _, err := m.inst.GetRawInstance(container)
	if err != nil {
		return "", installed{}, err
	}
	return incus.GuardrailHookSwitch(cfg[incus.GuardrailHookKey]), parseInstalled(cfg[incus.GuardrailHookInstalledKey]), nil
}

// reconcile brings one running box in line with its switch. installFirst is
// for moments the daemon expects to write (enable, start): install, then
// check. Without it (the periodic check) the order is check, then repair:
//
//   - files an earlier daemon version or earlier flags installed are
//     replaced and checked again, and only that second result is kept. An
//     upgrade is not tampering;
//   - anything else that is missing or changed is recorded as found, then
//     put back, so the report is not lost to the repair.
func (m *Manager) reconcile(container string, installFirst bool) {
	defer m.lockBox(container)()
	// Read the switch again under the lock; the list may be stale.
	sw, prev, err := m.state(container)
	if err != nil {
		log.Printf("[guardrail-hook] read %q: %v", container, err)
		return
	}
	user := usernameOf(container)
	switch sw {
	case incus.GuardrailHookOn:
		if installFirst {
			if !m.install(container, user, prev) {
				return
			}
			if _, prev, err = m.state(container); err != nil {
				return
			}
		}
		r := m.checker.check(container, user, prev)
		switch {
		case r.stale:
			log.Printf("[guardrail-hook] %q: %s; updating", container, r.Detail)
			if !m.install(container, user, prev) {
				return
			}
			if _, prev, err = m.state(container); err != nil {
				return
			}
			m.setResult(container, m.checker.check(container, user, prev))
		case r.repair && !installFirst:
			m.setResult(container, r)
			log.Printf("[guardrail-hook] %q: %s; installing again", container, r.Detail)
			m.install(container, user, prev)
		default:
			m.setResult(container, r)
		}
	case incus.GuardrailHookRemoving:
		if err := m.finishRemoval(container); err != nil {
			log.Printf("[guardrail-hook] %v (will retry)", err)
		}
	}
}

// install installs into a box and records what it installed on the box's
// config. On failure the stored result says why, as not installed. It
// reports whether the box now has the drop-in.
func (m *Manager) install(container, user string, prev installed) bool {
	err := m.checker.install(container, user)
	if err != nil {
		log.Printf("[guardrail-hook] install: %v", err)
		m.setResult(container, Result{Coverage: pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_NOT_INSTALLED,
			Detail: "the daemon could not install the drop-in: " + err.Error(), CheckedAt: m.checker.clock()})
		return false
	}
	if cur, cerr := m.checker.current(); cerr == nil && cur != prev {
		if err := m.inst.SetConfig(container, incus.GuardrailHookInstalledKey, cur.String()); err != nil {
			log.Printf("[guardrail-hook] record install on %q: %v", container, err)
		}
	}
	// Switching off does not wait for this lock. If it happened while the
	// files were being written, take them out again: its own removal may
	// have run before the write.
	if sw, _, err := m.state(container); err == nil && sw != incus.GuardrailHookOn {
		if err := m.checker.remove(container); err != nil {
			log.Printf("[guardrail-hook] %v (will retry)", err)
		}
		return false
	}
	return true
}

// finishRemoval removes the files from a running box and clears the switch.
func (m *Manager) finishRemoval(container string) error {
	if err := m.checker.remove(container); err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.results, container)
	m.mu.Unlock()
	if err := m.inst.UnsetConfig(container, incus.GuardrailHookInstalledKey); err != nil {
		return err
	}
	return m.inst.UnsetConfig(container, incus.GuardrailHookKey)
}

func (m *Manager) setResult(container string, r Result) {
	m.mu.Lock()
	m.results[container] = r
	m.mu.Unlock()
}

func (m *Manager) find(username string) (*incus.ContainerInfo, error) {
	boxes, err := m.inst.ListContainers()
	if err != nil {
		return nil, err
	}
	for i := range boxes {
		if boxes[i].Name == containerName(username) && !boxes[i].Role.IsCoreRole() {
			return &boxes[i], nil
		}
	}
	return nil, ErrBoxNotFound
}

// SetEnabled turns the feature on or off for one box and applies it now if
// the box is running. Off on a stopped box records the removal as owed; it
// is done when the box next starts.
//
// Off is the break-glass and takes no lock: it must not wait behind a
// coverage check of this box or any other. A check or install in flight
// re-reads the switch after it writes and undoes its own write (install).
func (m *Manager) SetEnabled(username string, enabled bool) (BoxCoverage, error) {
	b, err := m.find(username)
	if err != nil {
		return BoxCoverage{}, err
	}
	running := b.State == stateRunning
	if enabled {
		// Fail before flipping the switch if there is no binary to pin.
		if _, err := m.checker.binarySHA(); err != nil {
			return BoxCoverage{}, err
		}
		if err := m.inst.SetConfig(b.Name, incus.GuardrailHookKey, string(incus.GuardrailHookOn)); err != nil {
			return BoxCoverage{}, err
		}
		if running {
			m.reconcile(b.Name, true)
		}
		return m.Coverage(username)
	}
	if b.GuardrailHook == incus.GuardrailHookOff {
		return m.Coverage(username)
	}
	// Mark first: if the removal below fails, the periodic check retries it.
	if err := m.inst.SetConfig(b.Name, incus.GuardrailHookKey, string(incus.GuardrailHookRemoving)); err != nil {
		return BoxCoverage{}, err
	}
	if running {
		if err := m.finishRemoval(b.Name); err != nil {
			return BoxCoverage{}, err
		}
	}
	return m.Coverage(username)
}

// Coverage is one box's switch and last result.
func (m *Manager) Coverage(username string) (BoxCoverage, error) {
	b, err := m.find(username)
	if err != nil {
		return BoxCoverage{}, err
	}
	return m.coverageOf(b), nil
}

func (m *Manager) coverageOf(b *incus.ContainerInfo) BoxCoverage {
	out := BoxCoverage{Username: usernameOf(b.Name), Enabled: b.GuardrailHook == incus.GuardrailHookOn}
	m.mu.Lock()
	last, checked := m.results[b.Name]
	m.mu.Unlock()
	switch {
	case b.GuardrailHook == incus.GuardrailHookRemoving:
		out.Result = Result{Coverage: pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_FEATURE_OFF,
			Detail: "the feature is off; the drop-in is removed when the box next runs"}
	case !out.Enabled:
		out.Result = Result{Coverage: pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_NOT_COVERED_FEATURE_OFF, Detail: "the feature is off for this box"}
	case b.State != stateRunning:
		out.Result = Result{Coverage: pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_UNKNOWN, Detail: "the box is not running; stopped boxes are not checked"}
	case !checked:
		out.Result = Result{Coverage: pb.GuardrailHookCoverage_GUARDRAIL_HOOK_COVERAGE_UNKNOWN, Detail: "not checked yet"}
	default:
		out.Result = last
	}
	return out
}

// List is every box whose switch is on, by username.
func (m *Manager) List() ([]BoxCoverage, error) {
	boxes, err := m.inst.ListContainers()
	if err != nil {
		return nil, err
	}
	var out []BoxCoverage
	for i := range boxes {
		if boxes[i].Role.IsCoreRole() || boxes[i].GuardrailHook != incus.GuardrailHookOn {
			continue
		}
		out = append(out, m.coverageOf(&boxes[i]))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}
