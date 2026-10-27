//go:build !containarium_client

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
	mu         sync.Mutex
	rows       map[string]struct{ value, delivery string }
	failSet    bool
	failDelete int // fail this many Delete calls
}

func (f *fakeNotifySecrets) List(_ context.Context, u string) ([]secrets.SecretMetadata, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []secrets.SecretMetadata
	for k, r := range f.rows {
		if owner, name, _ := strings.Cut(k, "/"); owner == u {
			out = append(out, secrets.SecretMetadata{Username: u, Name: name, Delivery: r.delivery})
		}
	}
	return out, nil
}

// tokenRows returns u's channel-token secrets, by name.
func (f *fakeNotifySecrets) tokenRows(u string) map[string]struct{ value, delivery string } {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]struct{ value, delivery string }{}
	for k, r := range f.rows {
		if owner, name, _ := strings.Cut(k, "/"); owner == u && strings.HasPrefix(name, notify.TokenSecretPrefix) {
			out[name] = r
		}
	}
	return out
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
	if f.failSet {
		return nil, errors.New("secrets store down")
	}
	f.rows[u+"/"+n] = struct{ value, delivery string }{v, d}
	return &secrets.SecretMetadata{}, nil
}

func (f *fakeNotifySecrets) Delete(_ context.Context, u, n string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failDelete > 0 {
		f.failDelete--
		return errors.New("secrets store down")
	}
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
	// block, when set, is called before a send and may wait.
	block func(ch notify.Channel)
}

func (f *fakeSender) Send(_ context.Context, ch notify.Channel, token string, m notify.Message) error {
	if f.block != nil {
		f.block(ch)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, sentPush{ch, token, m})
	return nil
}

func (f *fakeSender) all() []sentPush {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sentPush(nil), f.sent...)
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
	rows := sec.tokenRows("alice")
	if len(rows) != 1 {
		t.Fatalf("token secrets = %v, want one", rows)
	}
	for _, row := range rows {
		if row.value != "tk_123" || row.delivery != secrets.DeliveryBroker {
			t.Fatalf("stored secret = %+v, want the token in broker-only delivery", row)
		}
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
	if rows := sec.tokenRows("alice"); len(rows) != 0 {
		t.Fatalf("clear_token left %v", rows)
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
	// A same-prefixed secret the box receives was not written here: setting
	// and clearing tokens never touches it.
	name := notify.TokenSecretPrefix + "MINE"
	sec.rows["alice/"+name] = struct{ value, delivery string }{"old", secrets.DeliveryEnv}
	for _, req := range []*pb.SetNotifyChannelRequest{
		{Kind: ntfy, Server: "https://n.example.com", Topic: "t", Token: "new"},
		{Kind: ntfy, Server: "https://n.example.com", Topic: "t", ClearToken: true},
	} {
		if _, err := s.SetNotifyChannel(notifyCtx("alice"), req); err != nil {
			t.Fatal(err)
		}
	}
	if r := sec.rows["alice/"+name]; r.value != "old" || r.delivery != secrets.DeliveryEnv {
		t.Fatalf("delivering secret changed: %+v", r)
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
	if rows := sec.tokenRows("alice"); len(rows) != 0 {
		t.Fatalf("token secrets left behind: %v", rows)
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
	s.wg.Wait()
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
	s.wg.Wait()
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
	s.wg.Wait()
	snd.err = nil
	s.pollOnce(context.Background())
	s.wg.Wait()
	if len(snd.sent) != 1 || snd.sent[0].token != "" {
		t.Fatalf("after a failed send: %+v", snd.sent)
	}
}

func TestNotifyWatcher_NoChannelNoBoxRead(t *testing.T) {
	s, _, _, b, _ := newTestNotifyServer(t)
	s.pollOnce(context.Background())
	s.wg.Wait()
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
	if got := parseNotifyJournals("alice", out, time.Now()); len(got["live"]) != 0 {
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
	s.wg.Wait()
	if len(snd.sent) != notifyMaxPushesPerPoll {
		t.Fatalf("first poll: %d pushes, want %d", len(snd.sent), notifyMaxPushesPerPoll)
	}
	s.pollOnce(context.Background())
	s.wg.Wait()
	if len(snd.sent) != 5 {
		t.Fatalf("after second poll: %d pushes, want 5 (none dropped)", len(snd.sent))
	}
}

// gatedChannelStore is a ChannelStore whose Set can be held or failed.
type gatedChannelStore struct {
	*notify.MemStore
	mu      sync.Mutex
	holdSet chan struct{} // when non-nil, Set waits for it to close
	entered chan struct{}
	failSet bool
}

func (g *gatedChannelStore) Set(ctx context.Context, ch notify.Channel) (notify.Channel, error) {
	g.mu.Lock()
	hold, entered, fail := g.holdSet, g.entered, g.failSet
	g.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if hold != nil {
		<-hold
	}
	if fail {
		return notify.Channel{}, errors.New("store down")
	}
	return g.MemStore.Set(ctx, ch)
}

// TestSetNotifyChannel_NewTokenNeverSentToOldServer: while a channel moves
// from server A with token A to server B with token B, no push pairs server
// A with token B, and a failed store write leaves A with token A.
func TestSetNotifyChannel_NewTokenNeverSentToOldServer(t *testing.T) {
	boot := hostBootID(t)
	s, _, snd, _, dir := newTestNotifyServer(t)
	g := &gatedChannelStore{MemStore: notify.NewMemStore()}
	s.store = g
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	ntfy := pb.NotifyChannelKind_NOTIFY_CHANNEL_KIND_NTFY
	ctx := notifyCtx("alice")
	if _, err := s.SetNotifyChannel(ctx, &pb.SetNotifyChannelRequest{Kind: ntfy, Server: "https://a.example.com", Topic: "t", Token: "tokA"}); err != nil {
		t.Fatal(err)
	}
	writeRecord(t, dir, recordSpec{name: "live", pid: os.Getpid(), boot: boot, started: now})

	// A failed move keeps A paired with token A.
	g.failSet = true
	if _, err := s.SetNotifyChannel(ctx, &pb.SetNotifyChannelRequest{Kind: ntfy, Server: "https://b.example.com", Topic: "t", Token: "tokB"}); err == nil {
		t.Fatal("Set with a failing store succeeded")
	}
	g.failSet = false
	writeJournal(t, dir, "live", openReq("r1", "Bash: x", now))
	s.pollOnce(context.Background())
	s.wg.Wait()

	// A move that is held mid-way while the watcher polls.
	g.mu.Lock()
	g.holdSet, g.entered = make(chan struct{}), make(chan struct{}, 1)
	g.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		_, err := s.SetNotifyChannel(ctx, &pb.SetNotifyChannelRequest{Kind: ntfy, Server: "https://b.example.com", Topic: "t", Token: "tokB"})
		done <- err
	}()
	<-g.entered
	writeJournal(t, dir, "live", openReq("r2", "Bash: y", now))
	now = now.Add(time.Minute)
	polled := make(chan struct{})
	go func() { s.pollOnce(context.Background()); s.wg.Wait(); close(polled) }()
	time.Sleep(50 * time.Millisecond)
	g.mu.Lock()
	close(g.holdSet)
	g.holdSet = nil
	g.mu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	<-polled
	for _, p := range snd.all() {
		want := map[string]string{"https://a.example.com": "tokA", "https://b.example.com": "tokB"}[p.ch.Server]
		if p.token != "" && p.token != want {
			t.Fatalf("push to %s carried %q", p.ch.Server, p.token)
		}
	}
	if len(snd.all()) == 0 {
		t.Fatal("no push sent")
	}
}

// TestNotifyWatcher_SlowServerDoesNotDelayOtherUsers: one user's stalled
// ntfy server does not hold back another user's first push.
func TestNotifyWatcher_SlowServerDoesNotDelayOtherUsers(t *testing.T) {
	boot := hostBootID(t)
	s, _, snd, b, _ := newTestNotifyServer(t)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	// One temp dir per user's "box".
	dirs := map[string]string{"alice-container": t.TempDir(), "bob-container": t.TempDir()}
	s.exec = func() boxScriptFunc {
		return func(box, script string) (string, error) {
			return b.exec(box, strings.ReplaceAll(script, shellSingleQuote(s.dir), shellSingleQuote(dirs[box])))
		}
	}
	for _, u := range []string{"alice", "bob"} {
		if _, err := s.SetNotifyChannel(notifyCtx(u), &pb.SetNotifyChannelRequest{Kind: pb.NotifyChannelKind_NOTIFY_CHANNEL_KIND_NTFY, Server: "https://" + u + ".example.com", Topic: "t"}); err != nil {
			t.Fatal(err)
		}
		d := dirs[u+"-container"]
		writeRecord(t, d, recordSpec{name: "live", pid: os.Getpid(), boot: boot, started: now})
		writeJournal(t, d, "live", openReq("r1", "Bash: x", now))
	}
	release := make(chan struct{})
	snd.block = func(ch notify.Channel) {
		if ch.Server == "https://alice.example.com" {
			<-release
		}
	}
	s.pollOnce(context.Background())
	deadline := time.After(2 * time.Second)
	for {
		var bob bool
		for _, p := range snd.all() {
			bob = bob || p.ch.Server == "https://bob.example.com"
		}
		if bob {
			break
		}
		select {
		case <-deadline:
			close(release)
			t.Fatal("bob's push waited for alice's stalled server")
		case <-time.After(10 * time.Millisecond):
		}
	}
	// A poll while alice's send is still stuck does not start a second one.
	s.pollOnce(context.Background())
	close(release)
	s.wg.Wait()
	n := 0
	for _, p := range snd.all() {
		if p.ch.Server == "https://alice.example.com" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("alice pushes = %d, want 1", n)
	}
}

// TestNotifyWatcher_OldOpenRequestBehindLargeJournal: an open request stays
// visible after more than the read limit of other journal lines.
func TestNotifyWatcher_OldOpenRequestBehindLargeJournal(t *testing.T) {
	boot := hostBootID(t)
	s, _, snd, _, dir := newTestNotifyServer(t)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	if _, err := s.SetNotifyChannel(notifyCtx("alice"), &pb.SetNotifyChannelRequest{Kind: pb.NotifyChannelKind_NOTIFY_CHANNEL_KIND_NTFY, Server: "https://n.example.com", Topic: "t"}); err != nil {
		t.Fatal(err)
	}
	writeRecord(t, dir, recordSpec{name: "live", pid: os.Getpid(), boot: boot, started: now})
	events := []coderun.InputEvent{openReq("r-old", "Bash: make release", now)}
	note := strings.Repeat("n", 1000)
	for i := 0; i < 2*notifyJournalReadLimit/1000; i++ {
		events = append(events, coderun.InputEvent{Kind: coderun.KindInputStatus, T: now, Text: note})
	}
	writeJournal(t, dir, "live", events...)
	s.pollOnce(context.Background())
	s.wg.Wait()
	if got := snd.all(); len(got) != 1 || !strings.Contains(got[0].msg.Body, "make release") {
		t.Fatalf("pushes = %+v, want the old open request", got)
	}
}

// TestSetNotifyChannel_TokenWriteFailurePreservesOldChannel: when the new
// token cannot be stored, the RPC fails and the previous channel and token
// stay in effect.
func TestSetNotifyChannel_TokenWriteFailurePreservesOldChannel(t *testing.T) {
	s, sec, _, _, _ := newTestNotifyServer(t)
	ctx := notifyCtx("alice")
	ntfy := pb.NotifyChannelKind_NOTIFY_CHANNEL_KIND_NTFY
	if _, err := s.SetNotifyChannel(ctx, &pb.SetNotifyChannelRequest{Kind: ntfy, Server: "https://a.example.com", Topic: "t", Token: "tokA"}); err != nil {
		t.Fatal(err)
	}
	sec.failSet = true
	if _, err := s.SetNotifyChannel(ctx, &pb.SetNotifyChannelRequest{Kind: ntfy, Server: "https://b.example.com", Topic: "t2", Token: "tokB"}); err == nil {
		t.Fatal("Set with a failing secrets store succeeded")
	}
	sec.failSet = false
	ch, token, err := s.channelAndToken(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Server != "https://a.example.com" || ch.Topic != "t" || !ch.HasToken() || token != "tokA" {
		t.Fatalf("after a failed update: channel %+v token %q, want A with tokA", ch, token)
	}
}

// TestSetNotifyChannel_ConcurrentSetsKeepTokenWithItsServer: many concurrent
// updates, some failing their token write, always leave the stored channel
// paired with the token it was set with.
func TestSetNotifyChannel_ConcurrentSetsKeepTokenWithItsServer(t *testing.T) {
	s, sec, _, _, _ := newTestNotifyServer(t)
	ntfy := pb.NotifyChannelKind_NOTIFY_CHANNEL_KIND_NTFY
	ctx := notifyCtx("alice")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			host := []string{"a", "b", "c"}[i%3]
			sec.mu.Lock()
			sec.failSet = i%4 == 0
			sec.mu.Unlock()
			_, _ = s.SetNotifyChannel(ctx, &pb.SetNotifyChannelRequest{Kind: ntfy, Server: "https://" + host + ".example.com", Topic: "t", Token: "tok-" + host})
		}(i)
	}
	wg.Wait()
	sec.failSet = false
	ch, token, err := s.channelAndToken(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if ch.HasToken() && "https://"+strings.TrimPrefix(token, "tok-")+".example.com" != ch.Server {
		t.Fatalf("channel %s stored with token %q", ch.Server, token)
	}
}

// TestSetNotifyChannel_ChannelWriteFailurePreservesOldChannel: when the row
// that would point at the new token cannot be written, the previous channel
// and token stay in effect and the new token secret is removed.
func TestSetNotifyChannel_ChannelWriteFailurePreservesOldChannel(t *testing.T) {
	s, sec, _, _, _ := newTestNotifyServer(t)
	g := &gatedChannelStore{MemStore: notify.NewMemStore()}
	s.store = g
	ctx := notifyCtx("alice")
	ntfy := pb.NotifyChannelKind_NOTIFY_CHANNEL_KIND_NTFY
	if _, err := s.SetNotifyChannel(ctx, &pb.SetNotifyChannelRequest{Kind: ntfy, Server: "https://a.example.com", Topic: "t", Token: "tokA"}); err != nil {
		t.Fatal(err)
	}
	g.failSet = true
	if _, err := s.SetNotifyChannel(ctx, &pb.SetNotifyChannelRequest{Kind: ntfy, Server: "https://b.example.com", Topic: "t2", Token: "tokB"}); err == nil {
		t.Fatal("Set with a failing channel store succeeded")
	}
	g.failSet = false
	ch, token, err := s.channelAndToken(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Server != "https://a.example.com" || token != "tokA" {
		t.Fatalf("after a failed update: channel %+v token %q, want A with tokA", ch, token)
	}
	if rows := sec.tokenRows("alice"); len(rows) != 1 {
		t.Fatalf("token secrets = %v, want only A's", rows)
	}
}

// TestDeleteNotifyChannel_RetryAfterTokenDeleteFailure: a delete whose token
// removal fails can be retried, and the retry removes channel and token.
func TestDeleteNotifyChannel_RetryAfterTokenDeleteFailure(t *testing.T) {
	s, sec, _, _, _ := newTestNotifyServer(t)
	ctx := notifyCtx("alice")
	if _, err := s.SetNotifyChannel(ctx, &pb.SetNotifyChannelRequest{Kind: pb.NotifyChannelKind_NOTIFY_CHANNEL_KIND_NTFY, Server: "https://n.example.com", Topic: "t", Token: "x"}); err != nil {
		t.Fatal(err)
	}
	sec.failDelete = 1
	if _, err := s.DeleteNotifyChannel(ctx, &pb.DeleteNotifyChannelRequest{}); err == nil {
		t.Fatal("delete with a failing secrets store succeeded")
	}
	if _, err := s.DeleteNotifyChannel(ctx, &pb.DeleteNotifyChannelRequest{}); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if rows := sec.tokenRows("alice"); len(rows) != 0 {
		t.Fatalf("token secrets left after the retry: %v", rows)
	}
	if _, err := s.GetNotifyChannel(ctx, &pb.GetNotifyChannelRequest{}); status.Code(err) != codes.NotFound {
		t.Fatalf("channel left after the retry: %v", err)
	}
}

// TestNotifyWatcher_ChannelRemovedBeforeSendIsRetried: a request whose push
// found the channel gone is pushed once a channel is set again.
func TestNotifyWatcher_ChannelRemovedBeforeSendIsRetried(t *testing.T) {
	boot := hostBootID(t)
	s, _, snd, _, dir := newTestNotifyServer(t)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	ctx := notifyCtx("alice")
	set := &pb.SetNotifyChannelRequest{Kind: pb.NotifyChannelKind_NOTIFY_CHANNEL_KIND_NTFY, Server: "https://n.example.com", Topic: "t"}
	if _, err := s.SetNotifyChannel(ctx, set); err != nil {
		t.Fatal(err)
	}
	writeRecord(t, dir, recordSpec{name: "live", pid: os.Getpid(), boot: boot, started: now})
	writeJournal(t, dir, "live", openReq("r1", "Bash: make deploy", now))
	// The channel disappears between the poll's selection and its send.
	snd.block = func(notify.Channel) {}
	exec := s.exec
	s.exec = func() boxScriptFunc {
		inner := exec()
		return func(box, script string) (string, error) {
			out, err := inner(box, script)
			_, _ = s.DeleteNotifyChannel(ctx, &pb.DeleteNotifyChannelRequest{})
			return out, err
		}
	}
	s.pollOnce(context.Background())
	s.wg.Wait()
	if n := len(snd.all()); n != 0 {
		t.Fatalf("pushed %d with no channel", n)
	}
	s.exec = exec
	if _, err := s.SetNotifyChannel(ctx, set); err != nil {
		t.Fatal(err)
	}
	s.pollOnce(context.Background())
	s.wg.Wait()
	if got := snd.all(); len(got) != 1 || !strings.Contains(got[0].msg.Body, "make deploy") {
		t.Fatalf("pushes after the channel came back = %+v", got)
	}
}

// TestNotifyChannel_LeavesOtherSecretsWithThePrefix: a broker-only secret
// whose name only shares the token prefix is not this service's, and no set
// or delete removes it.
func TestNotifyChannel_LeavesOtherSecretsWithThePrefix(t *testing.T) {
	s, sec, _, _, _ := newTestNotifyServer(t)
	ctx := notifyCtx("alice")
	ntfy := pb.NotifyChannelKind_NOTIFY_CHANNEL_KIND_NTFY
	other := notify.TokenSecretPrefix + "BACKUP"
	sec.rows["alice/"+other] = struct{ value, delivery string }{"keep", secrets.DeliveryBroker}
	for _, req := range []*pb.SetNotifyChannelRequest{
		{Kind: ntfy, Server: "https://a.example.com", Topic: "t"},
		{Kind: ntfy, Server: "https://a.example.com", Topic: "t", Token: "tokA"},
		{Kind: ntfy, Server: "https://b.example.com", Topic: "t", Token: "tokB"},
		{Kind: ntfy, Server: "https://b.example.com", Topic: "t", ClearToken: true},
		{Kind: ntfy, Server: "https://b.example.com", Topic: "t", Token: "tokC"},
	} {
		if _, err := s.SetNotifyChannel(ctx, req); err != nil {
			t.Fatal(err)
		}
	}
	if rows := sec.tokenRows("alice"); len(rows) != 2 {
		t.Fatalf("token secrets = %v, want the other one and tokC's", rows)
	}
	if _, err := s.DeleteNotifyChannel(ctx, &pb.DeleteNotifyChannelRequest{}); err != nil {
		t.Fatal(err)
	}
	if r, ok := sec.rows["alice/"+other]; !ok || r.value != "keep" {
		t.Fatalf("unrelated secret removed: %+v %v", r, ok)
	}
	if rows := sec.tokenRows("alice"); len(rows) != 1 {
		t.Fatalf("token secrets after delete = %v, want only the other one", rows)
	}
}

// TestNotifyWatcher_UsesTheBoxsOwnRequestLine: a later line the agent appends
// with the same request id is the same request, and does not change what is
// pushed; a request past its expiry is not pushed.
func TestNotifyWatcher_UsesTheBoxsOwnRequestLine(t *testing.T) {
	boot := hostBootID(t)
	s, _, snd, _, dir := newTestNotifyServer(t)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	if _, err := s.SetNotifyChannel(notifyCtx("alice"), &pb.SetNotifyChannelRequest{Kind: pb.NotifyChannelKind_NOTIFY_CHANNEL_KIND_NTFY, Server: "https://n.example.com", Topic: "t"}); err != nil {
		t.Fatal(err)
	}
	writeRecord(t, dir, recordSpec{name: "live", pid: os.Getpid(), boot: boot, started: now})
	expired := openReq("r0", "Bash: old", now.Add(-time.Hour))
	writeJournal(t, dir, "live", expired, openReq("r1", "Bash: make test", now), openReq("r1", "Bash: forged", now))
	s.pollOnce(context.Background())
	s.wg.Wait()
	got := snd.all()
	if len(got) != 1 {
		t.Fatalf("pushes = %+v, want 1", got)
	}
	if b := got[0].msg.Body; !strings.Contains(b, "make test") || strings.Contains(b, "forged") || strings.Contains(b, "more waiting") {
		t.Fatalf("push body %q, want only the box's own line of r1", b)
	}
}
