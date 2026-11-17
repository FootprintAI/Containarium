package guardraildropin

import (
	"context"
	"errors"
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
	// EngineUnit is the systemd unit of the detector engine in the box.
	// EngineNone skips the unit check.
	EngineUnit string
	// EngineAddr is the engine's address inside the box, passed to every
	// hook as --engine: unix://<absolute path>, an absolute socket path, or
	// a loopback host:port. EngineNone passes none, and the hook scans with
	// its in-process reference rules.
	EngineAddr string
	// HookBinary is the host path of the CLI binary copied into boxes.
	// Empty means the daemon's own executable, which carries the same
	// command tree and is by construction the daemon's version.
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
	if o.StampGrace <= 0 {
		o.StampGrace = DefaultStampGrace
	}
	switch o.EngineUnit {
	case "":
		o.EngineUnit = DefaultEngineUnit
	case EngineNone:
		o.EngineUnit = ""
	}
	switch o.EngineAddr {
	case "":
		o.EngineAddr = DefaultEngineAddr
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
// The check execs as root and writes nothing: not into the box, and not
// into the box's config. Auto-sleep reads the last-start stamp and recorded
// network traffic only, so a check is not activity and never wakes a box.
type Manager struct {
	inst     Instances
	checker  *checker
	interval time.Duration

	// opMu serializes work on boxes, so a periodic repair cannot put a
	// drop-in back after a concurrent switch-off removed it.
	opMu sync.Mutex

	mu      sync.Mutex
	results map[string]Result // container name -> last check

	stopCh   chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

// NewManager builds a manager over the daemon's Incus client.
func NewManager(inst Instances, box Box, opts Options) (*Manager, error) {
	p := opts.HookBinary
	return newManager(inst, box, opts, func() (io.ReadSeekCloser, error) {
		if p == "" {
			var err error
			if p, err = os.Executable(); err != nil {
				return nil, err
			}
		}
		return os.Open(p)
	})
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

// reconcile brings one running box in line with its switch. installFirst is
// for moments the daemon expects to write (enable, start): install, then
// check. Without it (the periodic check) the order is check, record, then
// repair, so a tampered file is reported before it is put back.
func (m *Manager) reconcile(container string, installFirst bool) {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	// Read the switch again under the lock; the list may be stale.
	cfg, _, err := m.inst.GetRawInstance(container)
	if err != nil {
		log.Printf("[guardrail-hook] read %q: %v", container, err)
		return
	}
	switch incus.GuardrailHookSwitch(cfg[incus.GuardrailHookKey]) {
	case incus.GuardrailHookOn:
		if installFirst {
			if err := m.checker.install(container); err != nil {
				log.Printf("[guardrail-hook] install: %v", err)
			}
		}
		r := m.checker.check(container, usernameOf(container))
		m.setResult(container, r)
		if r.repair && !installFirst {
			log.Printf("[guardrail-hook] %q: %s; installing again", container, r.Detail)
			if err := m.checker.install(container); err != nil {
				log.Printf("[guardrail-hook] repair: %v", err)
			}
		}
	case incus.GuardrailHookRemoving:
		if err := m.finishRemoval(container); err != nil {
			log.Printf("[guardrail-hook] %v (will retry)", err)
		}
	}
}

// finishRemoval removes the files from a running box and clears the switch.
func (m *Manager) finishRemoval(container string) error {
	if err := m.checker.remove(container); err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.results, container)
	m.mu.Unlock()
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
	m.opMu.Lock()
	defer m.opMu.Unlock()
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
