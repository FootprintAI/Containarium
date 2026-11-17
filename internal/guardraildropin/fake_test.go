package guardraildropin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// fakeBox is an in-memory box: a file map plus canned answers for the
// handful of argv-form commands the package runs as root. No real host.
type fakeBox struct {
	mu           sync.Mutex
	files        map[string][]byte
	engineActive bool
	ps           string
	stamps       map[string]string // pid -> stamp mtime (epoch seconds)
	claudeStat   string            // "" = no client installed
	version      string
	versionCalls int
	execErr      error
	log          []string // "exec cat", "write <path>", ...
}

func newFakeBox() *fakeBox {
	return &fakeBox{files: map[string][]byte{}, stamps: map[string]string{}, engineActive: true,
		claudeStat: "11:1700000000:200", version: "2.1.326 (Claude Code)"}
}

func (f *fakeBox) ExecWithExitCode(_ string, c []string) (string, string, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, "exec "+c[0])
	if f.execErr != nil {
		return "", "", -1, f.execErr
	}
	last := c[len(c)-1]
	switch c[0] {
	case "cat":
		b, ok := f.files[last]
		if !ok {
			return "", "No such file", 1, nil
		}
		return string(b), "", 0, nil
	case "find":
		var out []string
		for p := range f.files {
			if strings.HasPrefix(p, c[1]+"/") && strings.HasSuffix(p, ".json") {
				out = append(out, p)
			}
		}
		sort.Strings(out)
		return strings.Join(out, "\n"), "", 0, nil
	case "sha256sum":
		b, ok := f.files[last]
		if !ok {
			return "", "No such file", 1, nil
		}
		sum := sha256.Sum256(b)
		return hex.EncodeToString(sum[:]) + "  " + last + "\n", "", 0, nil
	case "systemctl":
		if f.engineActive {
			return "", "", 0, nil
		}
		return "", "", 3, nil
	case "stat":
		if f.claudeStat == "" {
			return "", "No such file", 1, nil
		}
		return f.claudeStat + "\n", "", 0, nil
	case "su":
		f.versionCalls++
		return f.version + "\n", "", 0, nil
	case "ps":
		return f.ps, "", 0, nil
	case "sh":
		if m, ok := f.stamps[last]; ok {
			return m + "\n", "", 0, nil
		}
		return "", "No such file", 1, nil
	case "mkdir":
		return "", "", 0, nil
	case "rm":
		for p := range f.files {
			if p == last || strings.HasPrefix(p, last+"/") {
				delete(f.files, p)
			}
		}
		return "", "", 0, nil
	}
	return "", "unexpected command " + c[0], 127, nil
}

func (f *fakeBox) WriteFile(_ string, path string, content []byte, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, "write "+path)
	f.files[path] = append([]byte(nil), content...)
	return nil
}

func (f *fakeBox) PushFile(c, path string, content io.ReadSeeker, mode string) error {
	b, err := io.ReadAll(content)
	if err != nil {
		return err
	}
	return f.WriteFile(c, path, b, mode)
}

func (f *fakeBox) execCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, l := range f.log {
		if strings.HasPrefix(l, "exec ") {
			n++
		}
	}
	return n
}

// fakeInstances is the daemon's instance list and config writes.
type fakeInstances struct {
	mu     sync.Mutex
	boxes  map[string]*incus.ContainerInfo
	writes []string // every config write, "set <name> <key>=<v>" / "unset <name> <key>"
}

func (f *fakeInstances) ListContainers() ([]incus.ContainerInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []incus.ContainerInfo
	for _, b := range f.boxes {
		out = append(out, *b)
	}
	return out, nil
}

func (f *fakeInstances) GetRawInstance(name string) (map[string]string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.boxes[name]
	if !ok {
		return nil, "", errors.New("not found")
	}
	return map[string]string{incus.GuardrailHookKey: string(b.GuardrailHook)}, "", nil
}

func (f *fakeInstances) SetConfig(name, key, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, "set "+name+" "+key+"="+value)
	if key == incus.GuardrailHookKey {
		f.boxes[name].GuardrailHook = incus.GuardrailHookSwitch(value)
	}
	return nil
}

func (f *fakeInstances) UnsetConfig(name, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, "unset "+name+" "+key)
	if key == incus.GuardrailHookKey {
		f.boxes[name].GuardrailHook = incus.GuardrailHookOff
	}
	return nil
}

type nopSeekCloser struct{ io.ReadSeeker }

func (nopSeekCloser) Close() error { return nil }

// bytesBinary is a hook binary held in memory, standing in for the file on
// the daemon's host.
func bytesBinary(b []byte) openBinary {
	return func() (io.ReadSeekCloser, error) { return nopSeekCloser{strings.NewReader(string(b))}, nil }
}
