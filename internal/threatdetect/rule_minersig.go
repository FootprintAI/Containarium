package threatdetect

import (
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/netbpf"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// embeddedMinerSigYAML is the baseline miner-signature list (#2638): binary
// names and command-line markers of the common miners. Versioned like the
// bad-destination list; extended without a rebuild via AddSignature /
// `containarium security miner-signatures add`. It carries no sha256
// entries (decided on #2711 Q2); the hash matcher serves operator entries.
//
//go:embed rule_minersig_list.yaml
var embeddedMinerSigYAML []byte

// minerSigConfigKey is the DaemonConfigStore key operator-added entries are
// persisted under, JSON-encoded.
const minerSigConfigKey = "threatdetect.miner_signatures.operator"

// ErrMinerSignatureNotFound reports a remove of an entry that is not among
// the operator-added ones.
var ErrMinerSignatureNotFound = errors.New("miner signature not found among operator-added entries")

// ErrMinerSignatureBuiltin reports a remove of a baseline entry.
var ErrMinerSignatureBuiltin = errors.New("miner signature is a baseline entry and cannot be removed")

// ErrMinerSignatureCatchAll reports a pattern that would match (nearly)
// every exec: a name glob with no literal character ("*", "?*", "[a-z]*")
// or an argv marker too short to single anything out. With kill_process on,
// such an entry — a typo for "*miner*", say — would SIGKILL every process in
// every box, so it is refused at insert (#2638 review).
var ErrMinerSignatureCatchAll = errors.New("miner signature matches every process")

// minMinerSigArgvLen is the fewest literal characters an argv marker must
// carry — "-o *" or "ab" tell a miner from nothing. Baseline entries are
// held to it too (TestMinerSignatureBaselineParses).
const minMinerSigArgvLen = 4

// MinerSignatureEntry is one entry of the miner-signature list, mirroring
// pb.MinerSignature. Pattern is stored normalized (see
// NormalizeMinerSignature).
type MinerSignatureEntry struct {
	Kind    pb.MinerSignatureKind
	Pattern string
	Label   string
	// Builtin marks a baseline entry shipped with the daemon.
	Builtin bool
}

// ToProto renders the entry as the wire message.
func (e MinerSignatureEntry) ToProto() *pb.MinerSignature {
	return &pb.MinerSignature{Kind: e.Kind, Pattern: e.Pattern, Label: e.Label, Builtin: e.Builtin}
}

// Subject is the finding subject of a hit on this entry: "<kind>:<pattern>".
func (e MinerSignatureEntry) Subject() string {
	return MinerSignatureKindName(e.Kind) + ":" + e.Pattern
}

// minerSigJSON is the persisted shape of one operator entry. Kind is the
// short name ("name", "argv", "sha256"), not the enum number, so the stored
// value stays readable and survives enum renumbering.
type minerSigJSON struct {
	Kind    string `json:"kind" yaml:"kind"`
	Pattern string `json:"pattern" yaml:"pattern"`
	Label   string `json:"label" yaml:"label"`
}

type minerSigYAMLFile struct {
	Version int            `yaml:"version"`
	Entries []minerSigJSON `yaml:"entries"`
}

var minerSigKindNames = map[pb.MinerSignatureKind]string{
	pb.MinerSignatureKind_MINER_SIGNATURE_KIND_NAME:   "name",
	pb.MinerSignatureKind_MINER_SIGNATURE_KIND_ARGV:   "argv",
	pb.MinerSignatureKind_MINER_SIGNATURE_KIND_SHA256: "sha256",
}

// MinerSignatureKindName is the short lowercase name of k ("name", "argv",
// "sha256"); "" for UNSPECIFIED or an unknown value.
func MinerSignatureKindName(k pb.MinerSignatureKind) string { return minerSigKindNames[k] }

// ParseMinerSignatureKind reads a short name or the full enum name.
func ParseMinerSignatureKind(s string) (pb.MinerSignatureKind, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "miner_signature_kind_")
	for k, n := range minerSigKindNames {
		if n == s {
			return k, nil
		}
	}
	return pb.MinerSignatureKind_MINER_SIGNATURE_KIND_UNSPECIFIED, fmt.Errorf("unknown miner-signature kind %q: want name, argv or sha256", s)
}

// hasGlob reports whether s holds a path.Match metacharacter.
func hasGlob(s string) bool { return strings.ContainsAny(s, "*?[") }

// globLiteralLen counts the characters of a path.Match pattern that must
// match literally: everything outside '*', '?' and a "[...]" class (an
// escaped character counts as one literal). Zero means the pattern
// constrains nothing but length. p has already passed path.Match.
func globLiteralLen(p string) int {
	n := 0
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '*', '?':
		case '[':
			// Skip the class up to its closing ']' (path.Match refuses ']'
			// as a first member, so the first ']' is the closing one).
			if k := strings.IndexByte(p[i+1:], ']'); k >= 0 {
				i += k + 1
			} else {
				i = len(p)
			}
		case '\\':
			if i+1 < len(p) {
				i++
			}
			n++
		default:
			n++
		}
	}
	return n
}

// NormalizeMinerSignature validates pattern for kind and returns it in the
// form it is stored and matched in: lowercased (matching is
// case-insensitive) except for an argv glob, whose option tokens match
// case-sensitively; surrounding whitespace trimmed except for an argv
// literal, whose trailing space is significant ("--coin ").
func NormalizeMinerSignature(kind pb.MinerSignatureKind, pattern string) (string, error) {
	switch kind {
	case pb.MinerSignatureKind_MINER_SIGNATURE_KIND_NAME:
		p := strings.ToLower(strings.TrimSpace(pattern))
		if p == "" {
			return "", errors.New("name pattern is empty")
		}
		if strings.Contains(p, "/") {
			return "", fmt.Errorf("name pattern %q: matches a basename, must not contain '/'", pattern)
		}
		if _, err := path.Match(p, ""); err != nil {
			return "", fmt.Errorf("name pattern %q: %w", pattern, err)
		}
		if globLiteralLen(p) == 0 {
			return "", fmt.Errorf("name pattern %q has no literal character and matches every basename: %w", pattern, ErrMinerSignatureCatchAll)
		}
		return p, nil
	case pb.MinerSignatureKind_MINER_SIGNATURE_KIND_ARGV:
		if strings.TrimSpace(pattern) == "" {
			return "", errors.New("argv pattern is empty")
		}
		// A literal is lowercased (case-insensitive substring). A glob keeps
		// its case: option tokens ("-o") match case-sensitively, since "-O"
		// is a different flag (gcc's optimisation level); see matchToken.
		p := strings.ToLower(pattern)
		literal := len(strings.TrimSpace(p))
		if hasGlob(pattern) {
			p = strings.Join(strings.Fields(pattern), " ")
			literal = 0
			for _, tok := range strings.Fields(p) {
				if _, err := path.Match(tok, ""); err != nil {
					return "", fmt.Errorf("argv pattern %q: %w", pattern, err)
				}
				literal += globLiteralLen(tok)
			}
			if literal == 0 {
				return "", fmt.Errorf("argv pattern %q has no literal character and matches every command line: %w", pattern, ErrMinerSignatureCatchAll)
			}
		}
		if literal < minMinerSigArgvLen {
			return "", fmt.Errorf("argv pattern %q is too short to be a signature (want at least %d literal characters): %w", pattern, minMinerSigArgvLen, ErrMinerSignatureCatchAll)
		}
		return p, nil
	case pb.MinerSignatureKind_MINER_SIGNATURE_KIND_SHA256:
		p := strings.ToLower(strings.TrimSpace(pattern))
		if len(p) != 64 {
			return "", fmt.Errorf("sha256 pattern %q: want 64 hex characters", pattern)
		}
		if _, err := hex.DecodeString(p); err != nil {
			return "", fmt.Errorf("sha256 pattern %q: not hex", pattern)
		}
		return p, nil
	default:
		return "", fmt.Errorf("miner-signature kind %d is not name, argv or sha256", int32(kind))
	}
}

func entryFromJSON(j minerSigJSON, builtin bool) (MinerSignatureEntry, error) {
	kind, err := ParseMinerSignatureKind(j.Kind)
	if err != nil {
		return MinerSignatureEntry{}, err
	}
	p, err := NormalizeMinerSignature(kind, j.Pattern)
	if err != nil {
		return MinerSignatureEntry{}, err
	}
	return MinerSignatureEntry{Kind: kind, Pattern: p, Label: j.Label, Builtin: builtin}, nil
}

// parseBaselineMinerSigYAML parses the embedded list. A malformed list is
// an error (and TestMinerSignatureBaselineParses fails the build on it).
func parseBaselineMinerSigYAML(raw []byte) (version string, entries []MinerSignatureEntry, err error) {
	var f minerSigYAMLFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return "", nil, fmt.Errorf("threatdetect: parse baseline miner-signature list: %w", err)
	}
	if f.Version <= 0 {
		return "", nil, errors.New("threatdetect: baseline miner-signature list: missing version")
	}
	for _, j := range f.Entries {
		e, err := entryFromJSON(j, true)
		if err != nil {
			return "", nil, fmt.Errorf("threatdetect: baseline miner-signature list: %w", err)
		}
		entries = append(entries, e)
	}
	return strconv.Itoa(f.Version), entries, nil
}

// minerSigMatcher is an immutable compiled snapshot of baseline + operator
// entries, rebuilt (not mutated) on every add/remove.
type minerSigMatcher struct {
	names     []MinerSignatureEntry
	argvLits  []MinerSignatureEntry
	argvGlobs []minerSigArgvGlob
	hashes    map[string]MinerSignatureEntry
}

type minerSigArgvGlob struct {
	entry  MinerSignatureEntry
	tokens []string
}

func newMinerSigMatcher(all []MinerSignatureEntry) *minerSigMatcher {
	m := &minerSigMatcher{hashes: make(map[string]MinerSignatureEntry)}
	for _, e := range all {
		switch e.Kind {
		case pb.MinerSignatureKind_MINER_SIGNATURE_KIND_NAME:
			m.names = append(m.names, e)
		case pb.MinerSignatureKind_MINER_SIGNATURE_KIND_ARGV:
			if hasGlob(e.Pattern) {
				m.argvGlobs = append(m.argvGlobs, minerSigArgvGlob{entry: e, tokens: strings.Fields(e.Pattern)})
			} else {
				m.argvLits = append(m.argvLits, e)
			}
		case pb.MinerSignatureKind_MINER_SIGNATURE_KIND_SHA256:
			m.hashes[e.Pattern] = e
		}
	}
	return m
}

// matchCheap runs the hot-path matchers: name (basename of filename, then
// comm), then argv. Patterns were validated at insert, so path.Match cannot
// return ErrBadPattern here.
func (m *minerSigMatcher) matchCheap(ev ExecEvent) (MinerSignatureEntry, bool) {
	base := strings.ToLower(path.Base(ev.Filename))
	comm := strings.ToLower(ev.Comm)
	for _, e := range m.names {
		for _, cand := range []string{base, comm} {
			if cand == "" || cand == "." || cand == "/" {
				continue
			}
			if ok, _ := path.Match(e.Pattern, cand); ok {
				return e, true
			}
		}
	}
	argv := strings.ToLower(ev.Argv)
	for _, e := range m.argvLits {
		if strings.Contains(argv, e.Pattern) {
			return e, true
		}
	}
	if len(m.argvGlobs) > 0 {
		args := strings.Fields(ev.Argv) // original case; matchToken folds where it should
		for _, g := range m.argvGlobs {
			if matchTokenRun(g.tokens, args) {
				return g.entry, true
			}
		}
	}
	return MinerSignatureEntry{}, false
}

// matchTokenRun reports whether consecutive args match every glob token in
// order ("-o *:3333" against [... "-o" "pool.example:3333" ...]).
func matchTokenRun(tokens, args []string) bool {
	for i := 0; i+len(tokens) <= len(args); i++ {
		hit := true
		for j, tok := range tokens {
			if !matchToken(tok, args[i+j]) {
				hit = false
				break
			}
		}
		if hit {
			return true
		}
	}
	return false
}

// matchToken matches one glob token against one argument. A token without
// '=' never matches a "key=value" argument: path.Match's '*' crosses '=', so
// "-o *:4444" would otherwise hit ssh's "-o ProxyJump=bastion:4444" (a
// HIGH finding, and a kill with kill_process). A token that spells '=' out
// ("--coin=*") matches the key=value form on purpose.
//
// An option token (leading '-') matches case-sensitively, so "-o *:3333"
// does not hit "-O ..."; any other token is case-insensitive like the rest
// of the rule.
func matchToken(tok, arg string) bool {
	if !strings.Contains(tok, "=") && strings.Contains(arg, "=") {
		return false
	}
	if !strings.HasPrefix(tok, "-") {
		tok, arg = strings.ToLower(tok), strings.ToLower(arg)
	}
	ok, _ := path.Match(tok, arg)
	return ok
}

func (m *minerSigMatcher) matchHash(sum string) (MinerSignatureEntry, bool) {
	e, ok := m.hashes[strings.ToLower(sum)]
	return e, ok
}

// MinerSignatureRule implements Rule and ExecConsumer for
// THREAT_RULE_ID_MINER_SIGNATURE (#2638; design component 5): an exec whose
// binary name, argv or executable hash matches the signature list raises a
// HIGH finding with the exec attached. Name and argv match on the engine's
// exec path; the hash matcher runs only when the list has hash entries and
// nothing cheaper hit, by asking RuleContext.HashExec to hash
// /proc/<pid>/exe off that path and redeliver the event with SHA256 set.
type MinerSignatureRule struct {
	mu       sync.RWMutex
	version  string
	baseline []MinerSignatureEntry
	operator []MinerSignatureEntry
	matcher  *minerSigMatcher
	store    ConfigKV // nil = operator entries live for this process only
}

// NewMinerSignatureRule loads the embedded baseline and, when store is
// non-nil, the persisted operator entries.
func NewMinerSignatureRule(ctx context.Context, store ConfigKV) (*MinerSignatureRule, error) {
	return newMinerSignatureRule(ctx, store, embeddedMinerSigYAML)
}

func newMinerSignatureRule(ctx context.Context, store ConfigKV, baselineYAML []byte) (*MinerSignatureRule, error) {
	version, baseline, err := parseBaselineMinerSigYAML(baselineYAML)
	if err != nil {
		return nil, err
	}
	r := &MinerSignatureRule{version: version, baseline: baseline, store: store}
	if r.operator, err = r.loadOperator(ctx); err != nil {
		return nil, err
	}
	r.rebuildLocked()
	return r, nil
}

func (r *MinerSignatureRule) loadOperator(ctx context.Context) ([]MinerSignatureEntry, error) {
	if r.store == nil {
		return nil, nil
	}
	val, err := r.store.Get(ctx, minerSigConfigKey)
	if err != nil {
		if errors.Is(err, app.ErrDaemonConfigNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("threatdetect: load operator miner signatures: %w", err)
	}
	if val == "" {
		return nil, nil
	}
	var raw []minerSigJSON
	if err := json.Unmarshal([]byte(val), &raw); err != nil {
		return nil, fmt.Errorf("threatdetect: unmarshal operator miner signatures: %w", err)
	}
	out := make([]MinerSignatureEntry, 0, len(raw))
	for _, j := range raw {
		e, err := entryFromJSON(j, false)
		if err != nil {
			return nil, fmt.Errorf("threatdetect: operator miner signature: %w", err)
		}
		out = append(out, e)
	}
	return out, nil
}

func (r *MinerSignatureRule) persistLocked(ctx context.Context, operator []MinerSignatureEntry) error {
	if r.store == nil {
		return nil
	}
	raw := make([]minerSigJSON, 0, len(operator))
	for _, e := range operator {
		raw = append(raw, minerSigJSON{Kind: MinerSignatureKindName(e.Kind), Pattern: e.Pattern, Label: e.Label})
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("threatdetect: marshal operator miner signatures: %w", err)
	}
	return r.store.Set(ctx, minerSigConfigKey, string(data))
}

func (r *MinerSignatureRule) rebuildLocked() {
	all := make([]MinerSignatureEntry, 0, len(r.baseline)+len(r.operator))
	all = append(all, r.baseline...)
	all = append(all, r.operator...)
	r.matcher = newMinerSigMatcher(all)
}

// ID identifies this rule for findings, status, and rule config.
func (r *MinerSignatureRule) ID() pb.ThreatRuleId {
	return pb.ThreatRuleId_THREAT_RULE_ID_MINER_SIGNATURE
}

// OnFlows is a no-op — this rule evaluates execs only.
func (r *MinerSignatureRule) OnFlows(RuleContext, []netbpf.FlowRecord) []RawFinding { return nil }

// OnDeny is a no-op — this rule evaluates execs only.
func (r *MinerSignatureRule) OnDeny(RuleContext, netbpf.DenyEvent) []RawFinding { return nil }

// Sweep is a no-op — this rule has no time-window state.
func (r *MinerSignatureRule) Sweep(RuleContext, time.Time) []RawFinding { return nil }

// OnExec matches one exec. First delivery (SHA256 empty): name and argv; on
// a miss, and only if the list holds hash entries, the event is handed to
// ctx.HashExec for the off-path hash. Second delivery (SHA256 set): the hash
// matcher only, since the cheaper matchers already missed.
func (r *MinerSignatureRule) OnExec(ctx RuleContext, ev ExecEvent) []RawFinding {
	r.mu.RLock()
	m := r.matcher
	r.mu.RUnlock()

	var hit MinerSignatureEntry
	var ok bool
	if ev.SHA256 == "" {
		hit, ok = m.matchCheap(ev)
		if !ok {
			if len(m.hashes) > 0 && ctx.HashExec != nil {
				ctx.HashExec(ev)
			}
			return nil
		}
	} else if hit, ok = m.matchHash(ev.SHA256); !ok {
		return nil
	}
	return []RawFinding{{
		Rule:      pb.ThreatRuleId_THREAT_RULE_ID_MINER_SIGNATURE,
		Severity:  pb.ThreatSeverity_THREAT_SEVERITY_HIGH,
		TenantID:  ev.TenantID,
		Container: ev.Container,
		Subject:   hit.Subject(),
		Evidence: Evidence{Execs: []ExecEvidence{{
			PID:           ev.PID,
			PPID:          ev.PPID,
			UID:           ev.UID,
			Comm:          ev.Comm,
			Filename:      ev.Filename,
			Argv:          ev.Argv,
			ArgvTruncated: ev.ArgvTruncated,
			SHA256:        ev.SHA256,
			Matched:       hit.Subject(),
		}}},
	}}
}

// BaselineVersion is the version of the embedded list this build ships.
func (r *MinerSignatureRule) BaselineVersion() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.version
}

// HasHashEntries reports whether any sha256 entry is configured, i.e.
// whether the host needs to hash executables at all.
func (r *MinerSignatureRule) HasHashEntries() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.matcher.hashes) > 0
}

// ListSignatures returns baseline then operator entries.
func (r *MinerSignatureRule) ListSignatures() []MinerSignatureEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]MinerSignatureEntry, 0, len(r.baseline)+len(r.operator))
	out = append(out, r.baseline...)
	return append(out, r.operator...)
}

// AddSignature adds (or relabels) an operator entry, effective immediately
// and persisted when a store is configured. Adding a pattern the baseline
// already carries is rejected: it would be a duplicate that can never be
// removed separately.
func (r *MinerSignatureRule) AddSignature(ctx context.Context, kind pb.MinerSignatureKind, pattern, label string) (MinerSignatureEntry, error) {
	p, err := NormalizeMinerSignature(kind, pattern)
	if err != nil {
		return MinerSignatureEntry{}, err
	}
	entry := MinerSignatureEntry{Kind: kind, Pattern: p, Label: label}

	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.baseline {
		if e.Kind == kind && e.Pattern == p {
			return MinerSignatureEntry{}, fmt.Errorf("%s: already in the baseline: %w", entry.Subject(), ErrMinerSignatureBuiltin)
		}
	}
	next := append([]MinerSignatureEntry(nil), r.operator...)
	replaced := false
	for i, e := range next {
		if e.Kind == kind && e.Pattern == p {
			next[i], replaced = entry, true
			break
		}
	}
	if !replaced {
		next = append(next, entry)
	}
	if err := r.persistLocked(ctx, next); err != nil {
		return MinerSignatureEntry{}, err
	}
	r.operator = next
	r.rebuildLocked()
	return entry, nil
}

// RemoveSignature removes an operator entry. ErrMinerSignatureBuiltin for a
// baseline entry, ErrMinerSignatureNotFound when no operator entry matches.
func (r *MinerSignatureRule) RemoveSignature(ctx context.Context, kind pb.MinerSignatureKind, pattern string) error {
	p, err := NormalizeMinerSignature(kind, pattern)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.baseline {
		if e.Kind == kind && e.Pattern == p {
			return fmt.Errorf("%s: %w", e.Subject(), ErrMinerSignatureBuiltin)
		}
	}
	idx := -1
	for i, e := range r.operator {
		if e.Kind == kind && e.Pattern == p {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("%s:%s: %w", MinerSignatureKindName(kind), p, ErrMinerSignatureNotFound)
	}
	next := append(append([]MinerSignatureEntry(nil), r.operator[:idx]...), r.operator[idx+1:]...)
	if err := r.persistLocked(ctx, next); err != nil {
		return err
	}
	r.operator = next
	r.rebuildLocked()
	return nil
}
