package threatdetect

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func newTestMinerSigRule(t *testing.T, store ConfigKV) *MinerSignatureRule {
	t.Helper()
	r, err := NewMinerSignatureRule(context.Background(), store)
	if err != nil {
		t.Fatalf("NewMinerSignatureRule: %v", err)
	}
	return r
}

func execEv(filename, comm, argv string) ExecEvent {
	return ExecEvent{Container: "box-1", TenantID: "t1", At: time.Unix(100, 0), PID: 4242, PPID: 1, UID: 1000,
		Comm: comm, Filename: filename, Argv: argv}
}

// TestNormalizeMinerSignature_RejectsCatchAll (#2638 review): a pattern that
// would match every exec is refused at insert — with kill_process on it
// would SIGKILL every process in every box. Name globs need a literal
// character; argv markers need minMinerSigArgvLen of them.
func TestNormalizeMinerSignature_RejectsCatchAll(t *testing.T) {
	name, argv := pb.MinerSignatureKind_MINER_SIGNATURE_KIND_NAME, pb.MinerSignatureKind_MINER_SIGNATURE_KIND_ARGV
	tests := []struct {
		kind    pb.MinerSignatureKind
		pattern string
		want    string // normalized form, or "" when refused
		wantErr string // substring of the error when refused
	}{
		// name: anything-goes globs
		{name, "*", "", "matches every basename"},
		{name, "?*", "", "matches every basename"},
		{name, "**", "", "matches every basename"},
		{name, "?", "", "matches every basename"},
		{name, "???", "", "matches every basename"},
		{name, "[a-z]*", "", "matches every basename"},
		{name, "[^.]*", "", "matches every basename"},
		{name, " * ", "", "matches every basename"},
		{name, "   ", "", "is empty"},
		// name: one literal character is a choice, not a typo
		{name, "*m*", "*m*", ""},
		{name, "x*", "x*", ""},
		{name, "\\*", "\\*", ""},
		{name, "cpuminer*", "cpuminer*", ""},
		{name, "XMRig", "xmrig", ""},
		// argv literal: too short to single a miner out
		{argv, "a", "", "too short to be a signature"},
		{argv, "-o", "", "too short to be a signature"},
		{argv, "abc", "", "too short to be a signature"},
		{argv, " ab ", "", "too short to be a signature"},
		{argv, "   ", "", "is empty"},
		{argv, "abcd", "abcd", ""},
		{argv, "--coin ", "--coin ", ""},
		{argv, "stratum+tcp://", "stratum+tcp://", ""},
		// argv glob: tokens must carry literal characters, enough of them
		{argv, "*", "", "matches every command line"},
		{argv, "* *", "", "matches every command line"},
		{argv, "? *", "", "matches every command line"},
		{argv, "[a-z]*", "", "matches every command line"},
		{argv, "-o *", "", "too short to be a signature"},
		{argv, "-o *:3333", "-o *:3333", ""},
		{argv, "--coin=*", "--coin=*", ""},
		{argv, "-o[^/]*:3333", "-o[^/]*:3333", ""},
	}
	for _, tt := range tests {
		t.Run(MinerSignatureKindName(tt.kind)+":"+tt.pattern, func(t *testing.T) {
			got, err := NormalizeMinerSignature(tt.kind, tt.pattern)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("accepted %q as %q, want an error containing %q", tt.pattern, got, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
				}
				if !errors.Is(err, ErrMinerSignatureInvalid) {
					t.Fatalf("error = %v, want ErrMinerSignatureInvalid so the server maps it to InvalidArgument", err)
				}
				if tt.wantErr != "is empty" && !errors.Is(err, ErrMinerSignatureCatchAll) {
					t.Fatalf("error = %v, want ErrMinerSignatureCatchAll so the server maps it to InvalidArgument", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused %q: %v", tt.pattern, err)
			}
			if got != tt.want {
				t.Fatalf("normalized = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestNormalizeMinerSignature_InvalidSentinel (#2768 item 5): every refusal,
// whatever the kind, wraps ErrMinerSignatureInvalid, the one sentinel the
// server maps to InvalidArgument; AddSignature and RemoveSignature return it
// unchanged, so the server need not normalize first.
func TestNormalizeMinerSignature_InvalidSentinel(t *testing.T) {
	r := newTestMinerSigRule(t, nil)
	for _, c := range []struct {
		kind    pb.MinerSignatureKind
		pattern string
	}{
		{pb.MinerSignatureKind_MINER_SIGNATURE_KIND_NAME, "/tmp/xmrig"},
		{pb.MinerSignatureKind_MINER_SIGNATURE_KIND_NAME, "xm[rig"},
		{pb.MinerSignatureKind_MINER_SIGNATURE_KIND_ARGV, "-o [a-"},
		{pb.MinerSignatureKind_MINER_SIGNATURE_KIND_SHA256, "abcd"},
		{pb.MinerSignatureKind_MINER_SIGNATURE_KIND_SHA256, strings.Repeat("z", 64)},
		{pb.MinerSignatureKind_MINER_SIGNATURE_KIND_UNSPECIFIED, "xmrig"},
	} {
		if _, err := NormalizeMinerSignature(c.kind, c.pattern); !errors.Is(err, ErrMinerSignatureInvalid) {
			t.Errorf("Normalize(%v, %q) = %v, want ErrMinerSignatureInvalid", c.kind, c.pattern, err)
		}
		if _, err := r.AddSignature(context.Background(), c.kind, c.pattern, ""); !errors.Is(err, ErrMinerSignatureInvalid) {
			t.Errorf("AddSignature(%v, %q) = %v, want ErrMinerSignatureInvalid", c.kind, c.pattern, err)
		}
		if err := r.RemoveSignature(context.Background(), c.kind, c.pattern); !errors.Is(err, ErrMinerSignatureInvalid) {
			t.Errorf("RemoveSignature(%v, %q) = %v, want ErrMinerSignatureInvalid", c.kind, c.pattern, err)
		}
	}
}

// TestMinerSignatureRule_AddRefusesCatchAll: the guard holds on the insert
// path too, and a refused add leaves the list untouched.
func TestMinerSignatureRule_AddRefusesCatchAll(t *testing.T) {
	r := newTestMinerSigRule(t, nil)
	before := len(r.ListSignatures())
	for _, c := range []struct {
		kind    pb.MinerSignatureKind
		pattern string
	}{
		{pb.MinerSignatureKind_MINER_SIGNATURE_KIND_NAME, "*"},
		{pb.MinerSignatureKind_MINER_SIGNATURE_KIND_ARGV, "-o"},
	} {
		if _, err := r.AddSignature(context.Background(), c.kind, c.pattern, "typo"); !errors.Is(err, ErrMinerSignatureCatchAll) {
			t.Fatalf("AddSignature(%s, %q) = %v, want ErrMinerSignatureCatchAll", MinerSignatureKindName(c.kind), c.pattern, err)
		}
	}
	if n := len(r.ListSignatures()); n != before {
		t.Fatalf("list grew from %d to %d on refused adds", before, n)
	}
	if got := r.OnExec(RuleContext{}, execEv("/usr/sbin/sshd", "sshd", "sshd -D")); len(got) != 0 {
		t.Fatalf("sshd matched after refused adds: %+v", got)
	}
}

// TestMinerSignatureBaselineParses fails the build on a malformed embedded
// list, and pins the #2711 Q2 decision: the shipped baseline carries name
// and argv entries only — no sha256.
func TestMinerSignatureBaselineParses(t *testing.T) {
	version, entries, err := parseBaselineMinerSigYAML(embeddedMinerSigYAML)
	if err != nil {
		t.Fatalf("embedded baseline: %v", err)
	}
	if version == "" || len(entries) == 0 {
		t.Fatalf("version=%q entries=%d, want a versioned, non-empty list", version, len(entries))
	}
	kinds := map[pb.MinerSignatureKind]int{}
	for _, e := range entries {
		kinds[e.Kind]++
		if !e.Builtin {
			t.Errorf("%s: baseline entry not marked builtin", e.Subject())
		}
	}
	if kinds[pb.MinerSignatureKind_MINER_SIGNATURE_KIND_SHA256] != 0 {
		t.Errorf("baseline carries %d sha256 entries; the shipped list is name and argv only (#2711 Q2)", kinds[pb.MinerSignatureKind_MINER_SIGNATURE_KIND_SHA256])
	}
	for _, name := range []string{"xmrig", "minerd", "cpuminer*", "nanominer", "t-rex", "lolminer", "nbminer", "gminer"} {
		if !hasEntry(entries, pb.MinerSignatureKind_MINER_SIGNATURE_KIND_NAME, name) {
			t.Errorf("baseline missing name %q", name)
		}
	}
	for _, marker := range []string{"--donate-level", "stratum+tcp://", "stratum+ssl://", "--coin ", "--coin=*", "-o *:3333", "-o *:14444", "--url=*:3333", "--url *:14433", "-o[^/]*:7777"} {
		if !hasEntry(entries, pb.MinerSignatureKind_MINER_SIGNATURE_KIND_ARGV, marker) {
			t.Errorf("baseline missing argv marker %q", marker)
		}
	}
}

func hasEntry(entries []MinerSignatureEntry, kind pb.MinerSignatureKind, pattern string) bool {
	for _, e := range entries {
		if e.Kind == kind && e.Pattern == pattern {
			return true
		}
	}
	return false
}

func TestMinerSignatureBaseline_MalformedRejected(t *testing.T) {
	for name, raw := range map[string]string{
		"not yaml":       "version: [",
		"no version":     "entries:\n  - {kind: name, pattern: xmrig}\n",
		"unknown kind":   "version: 1\nentries:\n  - {kind: md5, pattern: abc}\n",
		"bad glob":       "version: 1\nentries:\n  - {kind: name, pattern: \"xm[rig\"}\n",
		"short sha256":   "version: 1\nentries:\n  - {kind: sha256, pattern: abcd}\n",
		"name with path": "version: 1\nentries:\n  - {kind: name, pattern: /tmp/xmrig}\n",
		"empty argv":     "version: 1\nentries:\n  - {kind: argv, pattern: \"  \"}\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := newMinerSignatureRule(context.Background(), nil, []byte(raw)); err == nil {
				t.Fatal("malformed baseline accepted")
			}
		})
	}
}

// TestMinerSignatureRule_Matchers is the matcher table over the baseline
// (name glob, argv literal, argv token glob incl. -o host:<stratum port>).
func TestMinerSignatureRule_Matchers(t *testing.T) {
	r := newTestMinerSigRule(t, nil)
	tests := []struct {
		name        string
		ev          ExecEvent
		wantSubject string // "" = no finding
	}{
		{"bare name", execEv("/usr/local/bin/xmrig", "xmrig", "xmrig"), "name:xmrig"},
		{"hidden dir", execEv("/tmp/.x/xmrig", "xmrig", "./xmrig"), "name:xmrig"},
		{"case-insensitive", execEv("/opt/XMRig", "XMRig", "./XMRig"), "name:xmrig"},
		{"glob cpuminer-multi", execEv("/opt/cpuminer-multi", "cpuminer-multi", "./cpuminer-multi"), "name:cpuminer*"},
		{"comm only (renamed path)", execEv("/usr/bin/.cache", "t-rex", "/usr/bin/.cache"), "name:t-rex"},
		{"argv despite benign name", execEv("/usr/bin/gcc", "gcc", "gcc --donate-level 1"), "argv:--donate-level"},
		{"stratum url in node", execEv("/usr/bin/node", "node", "node pool.js stratum+tcp://pool.example:443"), "argv:stratum+tcp://"},
		{"stratum tls url", execEv("/usr/bin/python3", "python3", "python3 m.py --url=stratum+ssl://pool.example:443"), "argv:stratum+ssl://"},
		{"argv uppercase", execEv("/usr/bin/svc", "svc", "svc STRATUM+TCP://pool.example:443"), "argv:stratum+tcp://"},
		{"coin flag", execEv("/usr/bin/svc", "svc", "svc --coin monero"), "argv:--coin "},
		{"-o host:3333", execEv("/usr/bin/svc", "svc", "./svc -o pool.example:3333 -u wallet"), "argv:-o *:3333"},
		{"-o host:14444", execEv("/usr/bin/svc", "svc", "./svc -a rx -o 198.51.100.7:14444"), "argv:-o *:14444"},
		{"xmrig -o pool:3333", execEv("/opt/x", "x", "xmrig -o pool.example.com:3333"), "argv:-o *:3333"},
		{"-o stratum url still caught by the literal", execEv("/opt/x", "x", "./x -o stratum+tcp://pool:3333"), "argv:stratum+tcp://"},
		{"--coin=monero", execEv("/usr/bin/svc", "svc", "svc --coin=monero"), "argv:--coin=*"},
		{"ssh -o ProxyJump=host:4444", execEv("/usr/bin/ssh", "ssh", "ssh -o ProxyJump=bastion:4444 host"), ""},
		{"ssh -o Port=3333", execEv("/usr/bin/ssh", "ssh", "ssh -o Port=3333 host"), ""},
		{"ssh -o key=value with stratum port", execEv("/usr/bin/ssh", "ssh", "ssh -o ProxyCommand=nc:3333 host"), ""},
		{"--url=host:3333", execEv("/opt/x", "x", "./x --url=pool.example:3333"), "argv:--url=*:3333"},
		{"--url host:4444", execEv("/opt/x", "x", "./x --url pool.example:4444"), "argv:--url *:4444"},
		{"-ohost:5555 attached", execEv("/opt/x", "x", "./x -opool.example:5555"), "argv:-o[^/]*:5555"},
		{"host part is case-insensitive", execEv("/opt/x", "x", "./x -o POOL.Example:3333"), "argv:-o *:3333"},
		{"-O is not -o", execEv("/usr/bin/cc", "cc", "cc -O pool:3333"), ""},
		{"-O attached is not -o", execEv("/usr/bin/cc", "cc", "cc -Opool:3333"), ""},
		{"--url with a scheme is not host:port", execEv("/usr/bin/curl", "curl", "curl --url=http://h:3333/x"), ""},
		{"-o attached path", execEv("/usr/bin/ld", "ld", "ld -o/out/a:3333"), ""},
		{"gcc -O2", execEv("/usr/bin/gcc", "gcc", "gcc -O2 -o main main.c"), ""},
		{"-o on a non-stratum port", execEv("/usr/bin/svc", "svc", "./svc -o pool.example:443"), ""},
		{"-o output file named like a port", execEv("/usr/bin/ld", "ld", "ld -o out/a:3333.o"), ""},
		{"--coins is not --coin ", execEv("/usr/bin/app", "app", "app --coins=3"), ""},
		{"empty event", ExecEvent{Container: "box-1"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.OnExec(RuleContext{}, tt.ev)
			if tt.wantSubject == "" {
				if len(got) != 0 {
					t.Fatalf("finding %+v, want none", got)
				}
				return
			}
			if len(got) != 1 || got[0].Subject != tt.wantSubject {
				t.Fatalf("findings %+v, want one with subject %q", got, tt.wantSubject)
			}
		})
	}
}

// TestMinerSignatureRule_FindingCarriesExec: a hit is one HIGH
// MINER_SIGNATURE finding for the event's container and tenant with the
// exec attached as evidence and `matched` set.
func TestMinerSignatureRule_FindingCarriesExec(t *testing.T) {
	r := newTestMinerSigRule(t, nil)
	ev := execEv("/tmp/xmrig", "xmrig", "./xmrig --donate-level 1")
	ev.ArgvTruncated = true
	ev.StartTime = 987654 // #2765: the kill compares it against the pid's
	got := r.OnExec(RuleContext{}, ev)
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	f := got[0]
	if f.Rule != pb.ThreatRuleId_THREAT_RULE_ID_MINER_SIGNATURE || f.Severity != pb.ThreatSeverity_THREAT_SEVERITY_HIGH ||
		f.Container != "box-1" || f.TenantID != "t1" || f.Subject != "name:xmrig" {
		t.Fatalf("finding = %+v", f)
	}
	want := ExecEvidence{PID: 4242, StartTime: 987654, PPID: 1, UID: 1000, Comm: "xmrig", Filename: "/tmp/xmrig",
		Argv: "./xmrig --donate-level 1", ArgvTruncated: true, Matched: "name:xmrig"}
	if len(f.Evidence.Execs) != 1 || f.Evidence.Execs[0] != want {
		t.Fatalf("evidence = %+v, want %+v", f.Evidence.Execs, want)
	}
}

// TestMinerSignatureRule_SHA256Path: with a hash entry, an exec no cheaper
// entry matches is handed to HashExec (and only then); the redelivery with
// SHA256 set raises the finding. Without hash entries nothing is hashed.
func TestMinerSignatureRule_SHA256Path(t *testing.T) {
	ctx := context.Background()
	r := newTestMinerSigRule(t, nil)
	var asked []ExecEvent
	rc := RuleContext{HashExec: func(ev ExecEvent) { asked = append(asked, ev) }}

	clean := execEv("/opt/app/worker", "worker", "./worker --threads 4")
	if got := r.OnExec(rc, clean); len(got) != 0 || len(asked) != 0 {
		t.Fatalf("no hash entries: findings=%v hash requests=%d, want none", got, len(asked))
	}

	sum := strings.Repeat("0a", 32)
	if _, err := r.AddSignature(ctx, pb.MinerSignatureKind_MINER_SIGNATURE_KIND_SHA256, strings.ToUpper(sum), "renamed xmrig 6.x"); err != nil {
		t.Fatal(err)
	}
	if !r.HasHashEntries() {
		t.Fatal("HasHashEntries = false after adding one")
	}
	if got := r.OnExec(rc, clean); len(got) != 0 || len(asked) != 1 || asked[0].PID != clean.PID {
		t.Fatalf("first delivery: findings=%v hash requests=%v, want none and one request", got, asked)
	}
	// A cheap hit never costs a hash.
	if got := r.OnExec(rc, execEv("/tmp/xmrig", "xmrig", "xmrig")); len(got) != 1 || len(asked) != 1 {
		t.Fatalf("cheap hit: findings=%d hash requests=%d, want 1 and still 1", len(got), len(asked))
	}

	hashed := clean
	hashed.SHA256 = sum
	got := r.OnExec(rc, hashed)
	if len(got) != 1 || got[0].Subject != "sha256:"+sum || got[0].Evidence.Execs[0].SHA256 != sum {
		t.Fatalf("hashed delivery: %+v, want a sha256 finding carrying the hash", got)
	}
	if len(asked) != 1 {
		t.Fatalf("a hashed delivery must not ask for another hash (requests=%d)", len(asked))
	}
	other := clean
	other.SHA256 = strings.Repeat("ff", 32)
	if got := r.OnExec(rc, other); len(got) != 0 {
		t.Fatalf("non-matching hash raised %+v", got)
	}
}

// TestMinerSignatureRule_OperatorRoundTrip: add/remove persist through the
// config store and survive a reload; baseline entries cannot be removed or
// shadowed.
func TestMinerSignatureRule_OperatorRoundTrip(t *testing.T) {
	ctx := context.Background()
	store := &fakeConfigStore{}
	r := newTestMinerSigRule(t, store)
	base := len(r.ListSignatures())

	if _, err := r.AddSignature(ctx, pb.MinerSignatureKind_MINER_SIGNATURE_KIND_NAME, "SRBMiner*", "SRBMiner"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.AddSignature(ctx, pb.MinerSignatureKind_MINER_SIGNATURE_KIND_ARGV, "--algo randomx", ""); err != nil {
		t.Fatal(err)
	}
	if got := r.OnExec(RuleContext{}, execEv("/tmp/SRBMiner-MULTI", "SRBMiner-MULTI", "x")); len(got) != 1 || got[0].Subject != "name:srbminer*" {
		t.Fatalf("operator name entry did not take effect: %+v", got)
	}

	reloaded := newTestMinerSigRule(t, store)
	if n := len(reloaded.ListSignatures()); n != base+2 {
		t.Fatalf("after reload: %d entries, want %d", n, base+2)
	}
	if got := reloaded.OnExec(RuleContext{}, execEv("/usr/bin/svc", "svc", "svc --ALGO randomx")); len(got) != 1 {
		t.Fatal("persisted argv entry not matched after reload")
	}

	if err := reloaded.RemoveSignature(ctx, pb.MinerSignatureKind_MINER_SIGNATURE_KIND_NAME, "srbminer*"); err != nil {
		t.Fatal(err)
	}
	if err := reloaded.RemoveSignature(ctx, pb.MinerSignatureKind_MINER_SIGNATURE_KIND_NAME, "srbminer*"); !errors.Is(err, ErrMinerSignatureNotFound) {
		t.Fatalf("second remove err = %v, want ErrMinerSignatureNotFound", err)
	}
	if err := reloaded.RemoveSignature(ctx, pb.MinerSignatureKind_MINER_SIGNATURE_KIND_NAME, "xmrig"); !errors.Is(err, ErrMinerSignatureBuiltin) {
		t.Fatalf("baseline remove err = %v, want ErrMinerSignatureBuiltin", err)
	}
	if _, err := reloaded.AddSignature(ctx, pb.MinerSignatureKind_MINER_SIGNATURE_KIND_NAME, "XMRIG", ""); !errors.Is(err, ErrMinerSignatureBuiltin) {
		t.Fatalf("baseline duplicate add err = %v, want ErrMinerSignatureBuiltin", err)
	}
	if got := newTestMinerSigRule(t, store).ListSignatures(); len(got) != base+1 {
		t.Fatalf("after remove + reload: %d entries, want %d", len(got), base+1)
	}
}

func TestMinerSignatureRule_AddPersistFailureLeavesListUnchanged(t *testing.T) {
	store := &fakeConfigStore{}
	r := newTestMinerSigRule(t, store)
	before := len(r.ListSignatures())
	store.err = errors.New("db down")
	if _, err := r.AddSignature(context.Background(), pb.MinerSignatureKind_MINER_SIGNATURE_KIND_NAME, "foo", ""); err == nil {
		t.Fatal("add succeeded with a failing store")
	}
	if len(r.ListSignatures()) != before {
		t.Fatal("a failed persist still changed the live list")
	}
}

// TestEngine_MinerSignatureRule_HashRedelivery wires the rule into a real
// engine: the engine's hasher hook receives the miss, and redelivering
// through Engine.OnExec upserts the finding with container and tenant.
func TestEngine_MinerSignatureRule_HashRedelivery(t *testing.T) {
	sink := &fakeSink{}
	e := NewEngine(sink, "b1", false, nil, fixedClock(time.Unix(0, 0)))
	r := newTestMinerSigRule(t, nil)
	sum := strings.Repeat("1b", 32)
	if _, err := r.AddSignature(context.Background(), pb.MinerSignatureKind_MINER_SIGNATURE_KIND_SHA256, sum, ""); err != nil {
		t.Fatal(err)
	}
	e.Register(r)
	var pending []ExecEvent
	e.SetExecHasher(func(ev ExecEvent) { pending = append(pending, ev) })

	e.OnExec(execEv("/opt/w", "w", "./w"))
	if len(sink.calls()) != 0 || len(pending) != 1 {
		t.Fatalf("upserts=%d pending=%d, want 0 and 1", len(sink.calls()), len(pending))
	}
	ev := pending[0]
	ev.SHA256 = sum
	e.OnExec(ev)
	calls := sink.calls()
	if len(calls) != 1 || calls[0].Container != "box-1" || calls[0].TenantID != "t1" || calls[0].BackendID != "b1" ||
		calls[0].Rule != pb.ThreatRuleId_THREAT_RULE_ID_MINER_SIGNATURE {
		t.Fatalf("upserts = %+v", calls)
	}
}
