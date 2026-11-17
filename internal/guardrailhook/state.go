package guardrailhook

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/guardrail"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Files under the state directory. Every one is 0600 in a 0700 directory.
const (
	stateDirName = "containarium-guardrail"
	keyFile      = "marker.key"     // 32 random bytes, hex
	markersFile  = "markers.jsonl"  // one markerRow per line, append-only
	spoolFile    = "findings.jsonl" // one GuardrailHookRecord per line
	stampsDir    = "stamps"         // one empty file per agent pid
	blockedDir   = "blocked-sessions"
)

// DefaultStateDir is $XDG_STATE_HOME/containarium-guardrail, falling back to
// ~/.local/state/containarium-guardrail.
func DefaultStateDir() (string, error) {
	if x := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(x) {
		return filepath.Join(x, stateDirName), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("guardrail state directory: %w", err)
	}
	return filepath.Join(home, ".local", "state", stateDirName), nil
}

// markerRow is one line of the marker map. A personal-data marker carries
// its value, which is the only way back. A secret marker is listed with no
// value, so an edit that uses one can be told apart from a marker this box
// never issued; a secret itself is never written anywhere.
type markerRow struct {
	Token string `json:"token"`
	guardrail.VaultEntry
}

type state struct {
	dir      string
	key      []byte
	markers  map[string]guardrail.VaultEntry
	spoolMax int64
	now      func() time.Time
}

func openState(cfg Config) (*state, error) {
	if cfg.StateDir == "" {
		return nil, errors.New("guardrail state directory is not set")
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("guardrail state directory: %w", err)
	}
	s := &state{dir: cfg.StateDir, markers: map[string]guardrail.VaultEntry{}, spoolMax: cfg.SpoolMaxBytes, now: cfg.Now}
	var err error
	if s.key, err = loadOrCreateKey(filepath.Join(s.dir, keyFile)); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(s.dir, markersFile)) // #nosec G304 -- a fixed name under the state directory
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("guardrail marker map: %w", err)
	}
	for _, line := range bytes.Split(b, []byte("\n")) {
		var row markerRow
		// A torn last line (two hooks appending at once) is skipped: the
		// marker it was for is then unknown, and an unknown marker is denied.
		if json.Unmarshal(line, &row) == nil && row.Token != "" {
			s.markers[row.Token] = row.VaultEntry
		}
	}
	return s, nil
}

// loadOrCreateKey returns the marker key, creating it on first use. Two
// hooks starting at once must agree on one key, so the new key is linked
// into place (which fails if another got there first) and then read back.
func loadOrCreateKey(path string) ([]byte, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("guardrail marker key: %w", err)
		}
		tmp, err := os.CreateTemp(filepath.Dir(path), keyFile+".*")
		if err != nil {
			return nil, fmt.Errorf("guardrail marker key: %w", err)
		}
		_, werr := tmp.WriteString(hex.EncodeToString(key))
		cerr := tmp.Close()
		lerr := os.Link(tmp.Name(), path)
		_ = os.Remove(tmp.Name())
		if err := errors.Join(werr, cerr); err != nil {
			return nil, fmt.Errorf("guardrail marker key: %w", err)
		}
		if lerr != nil && !errors.Is(lerr, os.ErrExist) {
			return nil, fmt.Errorf("guardrail marker key: %w", lerr)
		}
	}
	b, err := os.ReadFile(path) // #nosec G304 -- a fixed name under the state directory
	if err != nil {
		return nil, fmt.Errorf("guardrail marker key: %w", err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("guardrail marker key %s is damaged; remove it to start a new one (existing markers stop resolving)", path)
	}
	return key, nil
}

// remember adds a marker to the map. Best effort: if the row cannot be
// written the marker is simply unknown later, and an unknown marker is
// denied, which is the safe way to fail.
func (s *state) remember(token string, e guardrail.VaultEntry) {
	if _, ok := s.markers[token]; ok {
		return
	}
	s.markers[token] = e
	line, err := marshalJSON(markerRow{Token: token, VaultEntry: e})
	if err != nil {
		return
	}
	appendLine(filepath.Join(s.dir, markersFile), line, 0)
}

// appendRecord adds one row to the findings spool, or drops it when the
// spool is full.
func (s *state) appendRecord(r *pb.GuardrailHookRecord) {
	r.ObservedAt = timestamppb.New(s.now())
	line, err := protojson.Marshal(r)
	if err != nil {
		return
	}
	appendLine(filepath.Join(s.dir, spoolFile), line, s.spoolMax)
}

// appendLine appends line and a newline in one write. With max > 0 the line
// is dropped if the file would grow past max bytes.
func appendLine(path string, line []byte, max int64) {
	line = append(line, '\n')
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- a fixed name under the state directory
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	if max > 0 {
		if info, err := f.Stat(); err != nil || info.Size()+int64(len(line)) > max {
			return
		}
	}
	_, _ = f.Write(line)
}

// touchStamp marks that a hook fired for the agent process pid, so an
// operator can tell from outside whether hooks are firing at all.
func (s *state) touchStamp(pid int) {
	dir := filepath.Join(s.dir, stampsDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	p := filepath.Join(dir, strconv.Itoa(pid))
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- a pid under the state directory
	if err != nil {
		return
	}
	_ = f.Close()
	now := s.now()
	_ = os.Chtimes(p, now, now)
}

func (s *state) blockedPath(session string) string {
	sum := sha256.Sum256([]byte(session))
	return filepath.Join(s.dir, blockedDir, hex.EncodeToString(sum[:16]))
}

func (s *state) blockSession(session string) error {
	p := s.blockedPath(session)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, nil, 0o600)
}

func (s *state) sessionBlocked(session string) bool {
	_, err := os.Stat(s.blockedPath(session))
	return err == nil
}

func (s *state) unblockSession(session string) { _ = os.Remove(s.blockedPath(session)) }

// ProcTable reads the process table, to find the agent process a hook runs
// under.
type ProcTable interface {
	Comm(pid int) (string, error)
	Parent(pid int) (int, error)
}

// agentComm is the agent's process name.
const agentComm = "claude"

// stampPID picks the pid the stamp is keyed by. A hook configured in exec
// form is started by the agent directly, so its parent is the agent. A
// shell-form hook has a shell in between, so walk up to the first agent
// ancestor. With none (or no readable process table) it is the parent.
func stampPID(ppid int, proc ProcTable) int {
	pid := ppid
	for i := 0; i < 32 && pid > 1; i++ {
		comm, err := proc.Comm(pid)
		if err != nil {
			break
		}
		if comm == agentComm {
			return pid
		}
		next, err := proc.Parent(pid)
		if err != nil || next == pid {
			break
		}
		pid = next
	}
	return ppid
}

// procFS is ProcTable over /proc. Where there is no /proc every read fails
// and the stamp falls back to the parent pid.
type procFS struct{}

func (procFS) Comm(pid int) (string, error) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm")) // #nosec G304 -- /proc/<pid>/comm
	return strings.TrimSpace(string(b)), err
}

func (procFS) Parent(pid int) (int, error) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat")) // #nosec G304 -- /proc/<pid>/stat
	if err != nil {
		return 0, err
	}
	// "pid (comm) state ppid ...": comm may hold spaces and parentheses, so
	// read from the last ')'.
	s := string(b)
	fields := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
	if len(fields) < 2 {
		return 0, fmt.Errorf("unexpected /proc/%d/stat", pid)
	}
	return strconv.Atoi(fields[1])
}

// marshalJSON encodes v on one line without HTML escaping, so a redacted
// result differs from the original only where it was redacted.
func marshalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
