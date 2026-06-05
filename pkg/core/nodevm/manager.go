package nodevm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// guestBinaryPath is where the containarium binary lands inside the node VM.
const guestBinaryPath = "/usr/local/bin/containarium"

// guestTokenPath is the perm-tight file the in-guest tunnel reads its
// token from (never passed on argv / kernel cmdline).
const guestTokenPath = "/etc/containarium/tunnel.token"

// Manager orchestrates node-VM lifecycle over the incus CLI.
type Manager struct {
	run Runner
	// BinaryPath is the local containarium binary pushed into each node VM
	// (so the node matches the operator's version exactly).
	BinaryPath string
	// waitAttempts / waitSleep bound the agent-readiness poll. A VM takes
	// tens of seconds to boot its incus-agent, so we must sleep between
	// probes — without it the retries burn out in milliseconds. Small/zero
	// in tests (success on the first probe never reaches the sleep).
	waitAttempts int
	waitSleep    time.Duration
}

// NewManager builds a Manager. binaryPath is the local containarium binary
// to push into node VMs (empty = skip the push, e.g. for a dry run).
func NewManager(r Runner, binaryPath string) *Manager {
	return &Manager{run: r, BinaryPath: binaryPath, waitAttempts: 60, waitSleep: 4 * time.Second}
}

// Node is one node VM as listed on the host.
type Node struct {
	Name  string
	State string
}

// Provision creates the VM, (for GPU) attaches the card, pushes the
// binary + token, and runs the in-guest bootstrap. Idempotent intent:
// if the VM already exists it reconciles the bootstrap rather than
// failing (full reconcile of partial state is a follow-up).
func (m *Manager) Provision(s Spec) (*Node, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}

	exists, err := m.vmExists(s.Name)
	if err != nil {
		return nil, err
	}
	if !exists {
		if _, err := m.run.Run(launchArgs(s)...); err != nil {
			return nil, fmt.Errorf("launch VM: %w", err)
		}
		if s.Kind == KindGPU {
			if _, err := m.run.Run(gpuDeviceArgs(s.Name, s.GPUPCI)...); err != nil {
				return nil, fmt.Errorf("attach GPU: %w", err)
			}
		}
	}

	if err := m.waitAgent(s.Name); err != nil {
		return nil, err
	}

	// Deliver the binary (so the node matches the operator's version).
	if m.BinaryPath != "" {
		if _, err := m.run.Run("file", "push", m.BinaryPath, s.Name+guestBinaryPath, "--mode", "0755"); err != nil {
			return nil, fmt.Errorf("push binary: %w", err)
		}
	}

	// Deliver the tunnel token as a 0600 file — never on argv.
	if s.TunnelToken != "" {
		if err := m.pushToken(s.Name, s.TunnelToken); err != nil {
			return nil, err
		}
	}

	// Run the in-guest bootstrap (nested Incus + daemon + tunnel).
	script := RenderBootstrap(s, guestTokenPath)
	if _, err := m.run.Run("exec", s.Name, "--", "bash", "-c", script); err != nil {
		return nil, fmt.Errorf("bootstrap guest: %w", err)
	}

	return &Node{Name: s.Name, State: "provisioned"}, nil
}

// pushToken writes the token to a local 0600 temp file and `incus file
// push`es it to the guest at 0600, then removes the temp. Keeps the token
// off every command line.
func (m *Manager) pushToken(name, token string) error {
	tmp, err := os.CreateTemp("", "ctnr-tunnel-token-")
	if err != nil {
		return fmt.Errorf("stage token: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return fmt.Errorf("chmod token tmp: %w", err)
	}
	if _, err := tmp.WriteString(token); err != nil {
		return fmt.Errorf("write token tmp: %w", err)
	}
	_ = tmp.Close()
	// Ensure the parent dir exists in the guest, then push 0600.
	if _, err := m.run.Run("exec", name, "--", "mkdir", "-p", filepath.Dir(guestTokenPath)); err != nil {
		return fmt.Errorf("mkdir token dir: %w", err)
	}
	if _, err := m.run.Run("file", "push", tmp.Name(), name+guestTokenPath, "--mode", "0600"); err != nil {
		return fmt.Errorf("push token: %w", err)
	}
	return nil
}

func (m *Manager) waitAgent(name string) error {
	attempts := m.waitAttempts
	if attempts <= 0 {
		attempts = 30
	}
	for i := 0; i < attempts; i++ {
		if _, err := m.run.Run("exec", name, "--", "true"); err == nil {
			return nil
		}
		if i < attempts-1 && m.waitSleep > 0 {
			time.Sleep(m.waitSleep)
		}
	}
	return fmt.Errorf("VM %s agent did not become ready after %d attempts", name, attempts)
}

func (m *Manager) vmExists(name string) (bool, error) {
	nodes, err := m.List()
	if err != nil {
		return false, err
	}
	for _, n := range nodes {
		if n.Name == name {
			return true, nil
		}
	}
	return false, nil
}

// List returns the node VMs on this host.
func (m *Manager) List() ([]Node, error) {
	out, err := m.run.Run(listArgs()...)
	if err != nil {
		return nil, fmt.Errorf("list VMs: %w", err)
	}
	var nodes []Node
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.SplitN(line, ",", 2)
		n := Node{Name: strings.TrimSpace(f[0])}
		if len(f) > 1 {
			n.State = strings.TrimSpace(f[1])
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}

// Destroy tears a node VM down.
func (m *Manager) Destroy(name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if _, err := m.run.Run(destroyArgs(name)...); err != nil {
		return fmt.Errorf("destroy VM: %w", err)
	}
	return nil
}

// CLIRunner is the production Runner: it shells out to `incus`.
type CLIRunner struct{ bin string }

// NewCLIRunner locates `incus` on PATH.
func NewCLIRunner() (*CLIRunner, error) {
	bin, err := exec.LookPath("incus")
	if err != nil {
		return nil, fmt.Errorf("incus not found on PATH (required for node-VM provisioning): %w", err)
	}
	return &CLIRunner{bin: bin}, nil
}

// Run executes `incus <args...>`.
func (r *CLIRunner) Run(args ...string) (string, error) {
	// #nosec G204 -- bin is resolved via exec.LookPath("incus"); args are
	// fixed verbs plus validated VM/pool names, PCI addrs, and paths.
	out, err := exec.Command(r.bin, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("incus %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
