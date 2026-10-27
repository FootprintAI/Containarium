package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/internal/notify"
	"github.com/footprintai/containarium/internal/secrets"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeNotifySecrets is an in-memory secrets store with the real store's
// broker-only rules: Get hides a broker value, BrokerCredential reads only one.
type fakeNotifySecrets struct {
	mu   sync.Mutex
	rows map[string]struct{ value, delivery string }
}

func newFakeNotifySecrets() *fakeNotifySecrets {
	return &fakeNotifySecrets{rows: map[string]struct{ value, delivery string }{}}
}

func (f *fakeNotifySecrets) Get(_ context.Context, u, n string) (*secrets.SecretMetadata, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.rows[u+"/"+n]
	if !ok {
		return nil, "", secrets.ErrNotFound
	}
	if r.delivery == secrets.DeliveryBroker {
		return &secrets.SecretMetadata{}, "", secrets.ErrBrokerOnly
	}
	return &secrets.SecretMetadata{}, r.value, nil
}

func (f *fakeNotifySecrets) Set(_ context.Context, u, n, v, d string) (*secrets.SecretMetadata, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows[u+"/"+n] = struct{ value, delivery string }{v, d}
	return &secrets.SecretMetadata{}, nil
}

func (f *fakeNotifySecrets) Delete(_ context.Context, u, n string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.rows[u+"/"+n]; !ok {
		return secrets.ErrNotFound
	}
	delete(f.rows, u+"/"+n)
	return nil
}

func (f *fakeNotifySecrets) BrokerCredential(_ context.Context, u, n string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.rows[u+"/"+n]
	if !ok {
		return "", secrets.ErrNotFound
	}
	if r.delivery != secrets.DeliveryBroker {
		return "", secrets.ErrNotBrokerOnly
	}
	return r.value, nil
}

type sentPush struct {
	ch    notify.Channel
	token string
	msg   notify.Message
}

type fakeSender struct {
	mu   sync.Mutex
	sent []sentPush
	err  error
}

func (f *fakeSender) Send(_ context.Context, ch notify.Channel, token string, m notify.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, sentPush{ch, token, m})
	return nil
}

func notifyCtx(user string) context.Context {
	return auth.ContextWithTestSubject(context.Background(), user, "user")
}

func newTestNotifyServer(t *testing.T) (*NotifyServer, *fakeNotifySecrets, *fakeSender, *shBox, string) {
	t.Helper()
	b := &shBox{}
	dir := t.TempDir()
	sec := newFakeNotifySecrets()
	snd := &fakeSender{}
	s := NewNotifyServer(notify.NewMemStore(), sec, func() boxScriptFunc { return b.exec }, dir)
	s.sender = snd
	return s, sec, snd, b, dir
}

func TestSetNotifyChannel_TokenStoredBrokerOnlyNeverReturned(t *testing.T) {
	s, sec, _, _, _ := newTestNotifyServer(t)
	resp, err := s.SetNotifyChannel(notifyCtx("alice"), &pb.SetNotifyChannelRequest{
		Kind: pb.NotifyChannelKind_NOTIFY_CHANNEL_KIND_NTFY, Server: "https://ntfy.example.com", Topic: "alice-runs", Token: "tk_123",
	})
	if err != nil {
		t.Fatal(err)
	}
	ch := resp.GetChannel()
	if ch.GetUsername() != "alice" || !ch.GetHasToken() {
		t.Fatalf("channel = %v", ch)
	}
	if strings.Contains(ch.String(), "tk_123") {
		t.Fatal("response carries the token")
	}
	row := sec.rows["alice/"+notify.TokenSecretName]
	if row.value != "tk_123" || row.delivery != secrets.DeliveryBroker {
		t.Fatalf("stored secret = %+v, want the token in broker-only delivery", row)
	}

	// Updating without a token keeps it; clear_token removes it.
	resp, err = s.SetNotifyChannel(notifyCtx("alice"), &pb.SetNotifyChannelRequest{
		Kind: pb.NotifyChannelKind_NOTIFY_CHANNEL_KIND_NTFY, Server: "https://ntfy.example.com", Topic: "alice-2",
	})
	if err != nil || !resp.GetChannel().GetHasToken() {
		t.Fatalf("update without token: %v %v", resp, err)
	}
	resp, err = s.SetNotifyChannel(notifyCtx("alice"), &pb.SetNotifyChannelRequest{
		Kind: pb.NotifyChannelKind_NOTIFY_CHANNEL_KIND_NTFY, Server: "https://ntfy.example.com", Topic: "alice-2", ClearToken: true,
	})
	if err != nil || resp.GetChannel().GetHasToken() {
		t.Fatalf("clear_token: %v %v", resp, err)
	}
	if _, ok := sec.rows["alice/"+notify.TokenSecretName]; ok {
		t.Fatal("clear_token left the secret")
	}
}

func TestSetNotifyChannel_Refusals(t *testing.T) {
	s, sec, _, _, _ := newTestNotifyServer(t)
	ntfy := pb.NotifyChannelKind_NOTIFY_CHANNEL_KIND_NTFY
	cases := []struct {
		name string
		ctx  context.Context
		req  *pb.SetNotifyChannelRequest
		code codes.Code
	}{
		{"other tenant", notifyCtx("alice"), &pb.SetNotifyChannelRequest{Username: "bob", Kind: ntfy, Server: "https://n.example.com", Topic: "t"}, codes.PermissionDenied},
		{"no kind", notifyCtx("alice"), &pb.SetNotifyChannelRequest{Server: "https://n.example.com", Topic: "t"}, codes.InvalidArgument},
		{"token over http", notifyCtx("alice"), &pb.SetNotifyChannelRequest{Kind: ntfy, Server: "http://n.example.com", Topic: "t", Token: "x"}, codes.InvalidArgument},
		{"token and clear", notifyCtx("alice"), &pb.SetNotifyChannelRequest{Kind: ntfy, Server: "https://n.example.com", Topic: "t", Token: "x", ClearToken: true}, codes.InvalidArgument},
		{"bad topic", notifyCtx("alice"), &pb.SetNotifyChannelRequest{Kind: ntfy, Server: "https://n.example.com", Topic: "a/b"}, codes.InvalidArgument},
		{"wrong scope", ctxWithScopes("alice", false, auth.ScopeSecretsRead), &pb.SetNotifyChannelRequest{Kind: ntfy, Server: "https://n.example.com", Topic: "t"}, codes.PermissionDenied},
	}
	for _, c := range cases {
		if _, err := s.SetNotifyChannel(c.ctx, c.req); status.Code(err) != c.code {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.code)
		}
	}
	// A same-named secret the box receives is not overwritten.
	sec.rows["alice/"+notify.TokenSecretName] = struct{ value, delivery string }{"old", secrets.DeliveryEnv}
	_, err := s.SetNotifyChannel(notifyCtx("alice"), &pb.SetNotifyChannelRequest{Kind: ntfy, Server: "https://n.example.com", Topic: "t", Token: "new"})
	if status.Code(err) != codes.FailedPrecondition || sec.rows["alice/"+notify.TokenSecretName].value != "old" {
		t.Fatalf("delivering secret overwritten: err=%v row=%+v", err, sec.rows["alice/"+notify.TokenSecretName])
	}
}

func TestDeleteNotifyChannel_RemovesToken(t *testing.T) {
	s, sec, _, _, _ := newTestNotifyServer(t)
	ctx := notifyCtx("alice")
	if _, err := s.SetNotifyChannel(ctx, &pb.SetNotifyChannelRequest{Kind: pb.NotifyChannelKind_NOTIFY_CHANNEL_KIND_NTFY, Server: "https://n.example.com", Topic: "t", Token: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteNotifyChannel(ctx, &pb.DeleteNotifyChannelRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := sec.rows["alice/"+notify.TokenSecretName]; ok {
		t.Fatal("token secret left behind")
	}
	if _, err := s.GetNotifyChannel(ctx, &pb.GetNotifyChannelRequest{}); status.Code(err) != codes.NotFound {
		t.Fatalf("get after delete: %v", err)
	}
}

func TestTestNotifyChannel_SendsWithToken(t *testing.T) {
	s, _, snd, _, _ := newTestNotifyServer(t)
	ctx := notifyCtx("alice")
	if _, err := s.TestNotifyChannel(ctx, &pb.TestNotifyChannelRequest{}); status.Code(err) != codes.NotFound {
		t.Fatalf("test without channel: %v", err)
	}
	if _, err := s.SetNotifyChannel(ctx, &pb.SetNotifyChannelRequest{Kind: pb.NotifyChannelKind_NOTIFY_CHANNEL_KIND_NTFY, Server: "https://n.example.com", Topic: "t", Token: "tk"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TestNotifyChannel(ctx, &pb.TestNotifyChannelRequest{}); err != nil {
		t.Fatal(err)
	}
	if len(snd.sent) != 1 || snd.sent[0].token != "tk" || snd.sent[0].ch.Topic != "t" {
		t.Fatalf("sent = %+v", snd.sent)
	}
	snd.err = errors.New("HTTP 403")
	if _, err := s.TestNotifyChannel(ctx, &pb.TestNotifyChannelRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("failed send: %v", err)
	}
}

// writeJournal writes a run's input journal next to its record.
func writeJournal(t *testing.T, dir, run string, events ...coderun.InputEvent) {
	t.Helper()
	var b []byte
	for _, e := range events {
		line, err := e.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, line...)
	}
	if err := os.WriteFile(filepath.Join(dir, run+".input.jsonl"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func openReq(id, prompt string, at time.Time) coderun.InputEvent {
	tool, _, _ := strings.Cut(prompt, ":")
	return coderun.InputEvent{Kind: coderun.KindInputRequest, T: at, RequestID: id, RequestKind: coderun.RequestKindPermission,
		Tool: tool, Prompt: prompt, Options: []coderun.Answer{coderun.AnswerAllow, coderun.AnswerDeny}, Default: coderun.AnswerDeny,
		ExpiresAt: at.Add(30 * time.Minute)}
}

func TestNotifyWatcher_PushesOpenRequestsOfLiveRuns(t *testing.T) {
	boot := hostBootID(t)
	s, _, snd, b, dir := newTestNotifyServer(t)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	ctx := notifyCtx("alice")
	if _, err := s.SetNotifyChannel(ctx, &pb.SetNotifyChannelRequest{Kind: pb.NotifyChannelKind_NOTIFY_CHANNEL_KIND_NTFY, Server: "https://n.example.com", Topic: "t", Token: "tk"}); err != nil {
		t.Fatal(err)
	}
	exit0 := 0
	// live run with one open and one answered request
	writeRecord(t, dir, recordSpec{name: "live", pid: os.Getpid(), boot: boot, started: now})
	writeJournal(t, dir, "live",
		openReq("r1", "Bash: git push origin feat", now),
		openReq("r0", "Bash: ls", now),
		coderun.InputEvent{Kind: coderun.KindInputResponse, T: now, RequestID: "r0", Answer: coderun.AnswerAllow, Reason: coderun.ReasonAnswered},
	)
	// exited run with an open request: nobody is waiting
	writeRecord(t, dir, recordSpec{name: "done", pid: os.Getpid(), boot: boot, started: now, exitCode: &exit0})
	writeJournal(t, dir, "done", openReq("r9", "Bash: rm x", now))
	// live run without approvals: no journal, no push
	writeRecord(t, dir, recordSpec{name: "plain", pid: os.Getpid(), boot: boot, started: now})

	s.pollOnce(context.Background())
	if len(snd.sent) != 1 {
		t.Fatalf("pushes = %d (%+v), want 1", len(snd.sent), snd.sent)
	}
	p := snd.sent[0]
	if p.token != "tk" || !strings.Contains(p.msg.Title, "alice/live") || !strings.Contains(p.msg.Body, "git push origin feat") {
		t.Fatalf("push = %+v", p)
	}
	if strings.Contains(p.msg.Body, "rm x") {
		t.Fatal("pushed an exited run's request")
	}
	if b.boxes[len(b.boxes)-1] != "alice-container" {
		t.Fatalf("read box %q", b.boxes[len(b.boxes)-1])
	}

	// Next poll: same open request, no second push.
	s.pollOnce(context.Background())
	if len(snd.sent) != 1 {
		t.Fatalf("re-pushed an already pushed request: %d", len(snd.sent))
	}
}

func TestNotifyWatcher_FailedSendRetried(t *testing.T) {
	boot := hostBootID(t)
	s, _, snd, _, dir := newTestNotifyServer(t)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	if _, err := s.SetNotifyChannel(notifyCtx("alice"), &pb.SetNotifyChannelRequest{Kind: pb.NotifyChannelKind_NOTIFY_CHANNEL_KIND_NTFY, Server: "http://ntfy.lan.example", Topic: "t"}); err != nil {
		t.Fatal(err)
	}
	writeRecord(t, dir, recordSpec{name: "live", pid: os.Getpid(), boot: boot, started: now})
	writeJournal(t, dir, "live", openReq("r1", "Bash: make deploy", now))
	snd.err = errors.New("connection refused")
	s.pollOnce(context.Background())
	snd.err = nil
	s.pollOnce(context.Background())
	if len(snd.sent) != 1 || snd.sent[0].token != "" {
		t.Fatalf("after a failed send: %+v", snd.sent)
	}
}

func TestNotifyWatcher_NoChannelNoBoxRead(t *testing.T) {
	s, _, _, b, _ := newTestNotifyServer(t)
	s.pollOnce(context.Background())
	if b.calls() != 0 {
		t.Fatalf("watcher read %d boxes with no channel configured", b.calls())
	}
}

func TestNotifyJournalScript_RefusesSymlinkedJournal(t *testing.T) {
	boot := hostBootID(t)
	s, _, _, b, dir := newTestNotifyServer(t)
	now := time.Now().UTC()
	writeRecord(t, dir, recordSpec{name: "live", pid: os.Getpid(), boot: boot, started: now})
	secret := filepath.Join(t.TempDir(), "other")
	writeJournal(t, filepath.Dir(secret), "other", openReq("r1", "Bash: from another file", now))
	if err := os.Symlink(secret+".input.jsonl", filepath.Join(dir, "live.input.jsonl")); err != nil {
		t.Fatal(err)
	}
	out, err := b.exec("alice-container", notifyJournalScript(dir))
	if err != nil {
		t.Fatal(err)
	}
	if got := parseNotifyJournals("alice", out); len(got["live"]) != 0 {
		t.Fatalf("read a symlinked journal: %+v", got)
	}
	_ = s
}

func TestNotifyWatcher_CapsPushesPerPoll(t *testing.T) {
	boot := hostBootID(t)
	s, _, snd, _, dir := newTestNotifyServer(t)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	if _, err := s.SetNotifyChannel(notifyCtx("alice"), &pb.SetNotifyChannelRequest{Kind: pb.NotifyChannelKind_NOTIFY_CHANNEL_KIND_NTFY, Server: "https://n.example.com", Topic: "t"}); err != nil {
		t.Fatal(err)
	}
	for _, run := range []string{"a", "b", "c", "d", "e"} {
		writeRecord(t, dir, recordSpec{name: run, pid: os.Getpid(), boot: boot, started: now})
		writeJournal(t, dir, run, openReq("r1", "Bash: x", now))
	}
	s.pollOnce(context.Background())
	if len(snd.sent) != notifyMaxPushesPerPoll {
		t.Fatalf("first poll: %d pushes, want %d", len(snd.sent), notifyMaxPushesPerPoll)
	}
	s.pollOnce(context.Background())
	if len(snd.sent) != 5 {
		t.Fatalf("after second poll: %d pushes, want 5 (none dropped)", len(snd.sent))
	}
}
