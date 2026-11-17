package guardraildropin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/footprintai/containarium/pkg/core/incus"
)

const fakeClientPath = "/home/alice/.local/bin/claude"

// operatorUnit is an engine unit the operator provides; the daemon installs
// none. The tests written for #3762 run in this mode.
const operatorUnit = "containarium-engine.service"

var operatorEngine = Options{EngineUnit: operatorUnit}

// fakeBox is an in-memory box: a file map plus answers for the commands the
// package runs as root. It models just enough of a filesystem (file type,
// owner, mode, the three directories) to drive the checks. No real host.
type fakeBox struct {
	mu    sync.Mutex
	files map[string][]byte
	// meta overrides what stat says about a path ("symbolic link|0|777").
	meta map[string]string
	// kinds overrides find's type letter for a managed file ("l", "p").
	kinds        map[string]string
	dirs         map[string]bool
	engineActive bool
	socketDenied bool // the box user cannot reach the engine socket
	smokeBroken  bool // the hook binary does not run in this box
	// The built-in reference engine: whether its unit is running, whether
	// the box user is in the socket's group, and whether a start fails.
	refRunning       bool
	inGroup          bool
	engineStartFails bool
	ps               string
	stamps           map[string]string // pid -> stamp mtime (epoch seconds)
	claudeStat       string            // "" = no client installed
	version          string
	versionCalls     int
	execErr          error
	exitCode         int // when non-zero, every command exits with it
	// hang blocks the managed-file listing for a container until closed;
	// entered is closed when the first such call arrives.
	hang    map[string]chan struct{}
	entered chan struct{}
	once    sync.Once
	// onWrite runs before a file write lands.
	onWrite func(path string)
	log     []string // "exec cat", "write <path>", "mv <dst>", ...
}

func newFakeBox() *fakeBox {
	return &fakeBox{files: map[string][]byte{}, meta: map[string]string{}, kinds: map[string]string{}, dirs: map[string]bool{},
		stamps: map[string]string{}, hang: map[string]chan struct{}{}, entered: make(chan struct{}),
		engineActive: true, claudeStat: "11:1700000000:200", version: "2.1.326 (Claude Code)"}
}

func (f *fakeBox) ExecWithExitCode(container string, c []string) (string, string, int, error) {
	if len(c) < 5 || c[0] != "timeout" || c[1] != "-k" {
		return "", "", 127, fmt.Errorf("command not run under timeout: %v", c)
	}
	c = c[4:]
	if c[0] == "find" {
		f.mu.Lock()
		ch := f.hang[container]
		f.mu.Unlock()
		if ch != nil {
			f.once.Do(func() { close(f.entered) })
			<-ch
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	last := c[len(c)-1]
	f.log = append(f.log, "exec "+c[0]+" "+last)
	if f.execErr != nil {
		return "", "", -1, f.execErr
	}
	if f.exitCode != 0 {
		return "", "", f.exitCode, nil
	}
	if c[0] == "sh" {
		return f.script(c[2], c[4:])
	}
	switch c[0] {
	case "head":
		b, ok := f.files[last]
		if !ok {
			return "", "No such file", 1, nil
		}
		n, err := strconv.Atoi(c[2])
		if err != nil {
			return "", "bad byte count", 1, nil
		}
		if len(b) > n {
			b = b[:n]
		}
		return string(b), "", 0, nil
	case "find":
		var paths []string
		for p := range f.files {
			if strings.HasPrefix(p, c[1]+"/") && strings.HasSuffix(p, ".json") {
				paths = append(paths, p)
			}
		}
		sort.Strings(paths)
		var out strings.Builder
		for _, p := range paths {
			kind := f.kinds[p]
			if kind == "" {
				kind = "f"
			}
			fmt.Fprintf(&out, "%s\t%d\t%s\x00", kind, len(f.files[p]), p)
		}
		return out.String(), "", 0, nil
	case "sha256sum":
		b, ok := f.files[last]
		if !ok {
			return "", "No such file", 1, nil
		}
		sum := sha256.Sum256(b)
		return hex.EncodeToString(sum[:]) + "  " + last + "\n", "", 0, nil
	case "systemctl":
		f.log = append(f.log, "systemctl "+c[1])
		switch c[1] {
		case "is-active":
			active := f.engineActive
			if last == ReferenceEngineUnit {
				active = f.refRunning
			}
			if active {
				return "", "", 0, nil
			}
			return "", "", 3, nil
		case "start", "restart":
			_, unit := f.files[EngineUnitPath]
			_, bin := f.files[HookBinaryPath]
			if !unit || !bin || f.engineStartFails {
				return "", "", 1, nil
			}
			f.refRunning = true
		}
		return "", "", 0, nil
	case "runuser":
		return f.asUser(c[4:])
	case "ps":
		return f.ps, "", 0, nil
	case "mv":
		src, dst := c[len(c)-2], last
		b, ok := f.files[src]
		if !ok {
			return "", "No such file", 1, nil
		}
		f.files[dst] = b
		delete(f.files, src)
		delete(f.meta, dst) // a rename replaces a link, it does not follow it
		f.log = append(f.log, "mv "+dst)
		return "", "", 0, nil
	case "rm":
		targets := c[1:]
		for i, a := range c {
			if a == "--" {
				targets = c[i+1:]
			}
		}
		for _, target := range targets {
			for p := range f.files {
				if p == target || strings.HasPrefix(p, target+"/") {
					delete(f.files, p)
				}
			}
			delete(f.dirs, target)
		}
		return "", "", 0, nil
	}
	return "", "unexpected command " + c[0], 127, nil
}

// asUser answers a command run as the box user: c is what follows "--".
func (f *fakeBox) asUser(c []string) (string, string, int, error) {
	if c[0] == "test" {
		if c[2] == ReferenceEngineSocket && (!f.refRunning || !f.inGroup) {
			return "", "", 1, nil
		}
		if f.socketDenied {
			return "", "", 1, nil
		}
		return "", "", 0, nil
	}
	// env -i VAR=... <binary> args...
	i := 2
	for i < len(c) && strings.Contains(c[i], "=") {
		i++
	}
	bin, args := c[i], strings.Join(c[i+1:], " ")
	switch args {
	case "guardrail hook --help":
		if _, ok := f.files[bin]; !ok || f.smokeBroken {
			return "", "cannot execute", 126, nil
		}
		return "Usage:\n  containarium guardrail hook <event> [flags]\n", "", 0, nil
	case "--version":
		f.versionCalls++
		return f.version + "\n", "", 0, nil
	}
	return "", "unexpected user command", 127, nil
}

func (f *fakeBox) script(script string, args []string) (string, string, int, error) {
	switch script {
	case statScript:
		var out strings.Builder
		for _, p := range args {
			switch _, isFile := f.files[p]; {
			case f.meta[p] != "":
				out.WriteString(f.meta[p] + "\n")
			case isFile:
				out.WriteString("regular file|0|644\n")
			case f.dirs[p]:
				out.WriteString("directory|0|755\n")
			default:
				out.WriteString("missing\n")
			}
		}
		return out.String(), "", 0, nil
	case prepareDirsScript:
		for _, d := range args {
			if m := f.meta[d]; m != "" && m != "directory|0|755" {
				return d + " is a symlink\n", "", 3, nil
			}
			f.dirs[d] = true
		}
		return "", "", 0, nil
	case engineAccountsScript:
		f.log = append(f.log, "accounts "+strings.Join(args, " "))
		f.inGroup = true
		return "", "", 0, nil
	case removeEngineScript:
		f.log = append(f.log, "remove-engine")
		delete(f.files, EngineUnitPath)
		delete(f.files, tmpUnitPath)
		f.refRunning = false
		return "", "", 0, nil
	case findClientScript:
		if f.claudeStat == "" {
			return "", "", 1, nil
		}
		return f.claudeStat + "\n" + fakeClientPath + "\n/home/alice\n", "", 0, nil
	case stampMTimeScript:
		if m, ok := f.stamps[args[0]]; ok {
			return m + "\n", "", 0, nil
		}
		return "", "No such file", 1, nil
	}
	return "", "unexpected script", 127, nil
}

func (f *fakeBox) WriteFile(_ string, path string, content []byte, _ string) error {
	if f.onWrite != nil {
		f.onWrite(path)
	}
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

func (f *fakeBox) has(path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.files[path]
	return ok
}

func (f *fakeBox) fileCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.files)
}

func (f *fakeBox) logged(prefix string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, l := range f.log {
		if strings.HasPrefix(l, prefix) {
			out = append(out, l)
		}
	}
	return out
}

// fakeInstances is the daemon's instance list and config writes.
type fakeInstances struct {
	mu     sync.Mutex
	boxes  map[string]*incus.ContainerInfo
	config map[string]string // container -> installed marker
	writes []string          // every config write, "set <name> <key>=<v>" / "unset <name> <key>"
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
	return map[string]string{incus.GuardrailHookKey: string(b.GuardrailHook), incus.GuardrailHookInstalledKey: f.config[name]}, "", nil
}

func (f *fakeInstances) SetConfig(name, key, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, "set "+name+" "+key+"="+value)
	switch key {
	case incus.GuardrailHookKey:
		f.boxes[name].GuardrailHook = incus.GuardrailHookSwitch(value)
	case incus.GuardrailHookInstalledKey:
		if f.config == nil {
			f.config = map[string]string{}
		}
		f.config[name] = value
	}
	return nil
}

func (f *fakeInstances) UnsetConfig(name, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, "unset "+name+" "+key)
	switch key {
	case incus.GuardrailHookKey:
		f.boxes[name].GuardrailHook = incus.GuardrailHookOff
	case incus.GuardrailHookInstalledKey:
		delete(f.config, name)
	}
	return nil
}

func (f *fakeInstances) sw(name string) incus.GuardrailHookSwitch {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.boxes[name].GuardrailHook
}

func (f *fakeInstances) set(name string, fn func(*incus.ContainerInfo)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f.boxes[name])
}

type nopSeekCloser struct{ io.ReadSeeker }

func (nopSeekCloser) Close() error { return nil }

// bytesBinary is a hook binary held in memory, standing in for the file on
// the daemon's host.
func bytesBinary(b []byte) openBinary {
	return func() (io.ReadSeekCloser, error) { return nopSeekCloser{strings.NewReader(string(b))}, nil }
}
