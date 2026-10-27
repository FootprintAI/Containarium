package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/agentbox"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/internal/notify"
	"github.com/footprintai/containarium/internal/secrets"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// NotifyService (#2185): a user's ntfy channel, and the watcher that pushes
// each `code run --approvals ask` request waiting on them.
//
// The watcher reads the input journal of every live run on the box of each
// user with a channel, through the same root exec and file guard ListBoxRuns
// uses, and publishes what notify.Coalescer says is due. The channel's token
// is a broker-only tenant secret, read here with BrokerCredential and never
// delivered to a box.

// notifySecretStore is the slice of secrets.Store the notify service uses.
type notifySecretStore interface {
	Get(ctx context.Context, username, name string) (*secrets.SecretMetadata, string, error)
	Set(ctx context.Context, username, name, value, delivery string) (*secrets.SecretMetadata, error)
	Delete(ctx context.Context, username, name string) error
	BrokerCredential(ctx context.Context, username, name string) (string, error)
}

// notifySender is notify.Sender, behind an interface for tests.
type notifySender interface {
	Send(ctx context.Context, ch notify.Channel, token string, m notify.Message) error
}

// NotifyServer implements pb.NotifyServiceServer.
type NotifyServer struct {
	pb.UnimplementedNotifyServiceServer

	store   notify.ChannelStore
	secrets notifySecretStore
	sender  notifySender
	// exec runs a script in a box (ContainerServer.boxRunExecFn); dir is
	// agent-box's log dir.
	exec func() boxScriptFunc
	dir  string

	coalescer *notify.Coalescer
	now       func() time.Time

	// cfgMu makes a channel change and the token it carries one step for the
	// watcher: a push reads the channel and its token under it, so it never
	// pairs a new token with the old server.
	cfgMu sync.Mutex

	// Each user is polled on its own goroutine, so one slow box or ntfy
	// server delays only that user; inflight keeps one poll per user at a
	// time, and sem bounds how many run at once.
	mu       sync.Mutex
	inflight map[string]bool
	sem      chan struct{}
	wg       sync.WaitGroup
}

// NewNotifyServer wires the service. secretStore may be nil on a daemon
// without one; a channel can then not hold a token.
func NewNotifyServer(store notify.ChannelStore, secretStore notifySecretStore, exec func() boxScriptFunc, dir string) *NotifyServer {
	return &NotifyServer{
		store:     store,
		secrets:   secretStore,
		sender:    notify.NewSender(),
		exec:      exec,
		dir:       dir,
		coalescer: notify.NewCoalescer(notify.DefaultWindow),
		now:       time.Now,
		inflight:  map[string]bool{},
		sem:       make(chan struct{}, notifyMaxConcurrentUsers),
	}
}

// notifyUser resolves the request's user: its username, or the caller when
// empty. A non-admin may only name themselves.
func notifyUser(ctx context.Context, username string) (string, error) {
	if username == "" {
		subject, _, ok := auth.SubjectFromGRPCContext(ctx)
		if !ok || subject == "" {
			return "", status.Error(codes.Unauthenticated, "no authenticated user; pass username")
		}
		username = subject
	}
	if !validRunPathID(username) {
		return "", status.Errorf(codes.InvalidArgument, "username must match %s", runIDPattern.String())
	}
	if err := auth.AuthorizeTenant(ctx, username); err != nil {
		return "", err
	}
	return username, nil
}

func notifyChannelProto(ch notify.Channel) *pb.NotifyChannel {
	out := &pb.NotifyChannel{
		Username:      ch.Username,
		Kind:          pb.NotifyChannelKind_NOTIFY_CHANNEL_KIND_NTFY,
		Server:        ch.Server,
		Topic:         ch.Topic,
		HasToken:      ch.HasToken,
		RedactCommand: ch.RedactCommand,
	}
	if !ch.UpdatedAt.IsZero() {
		out.UpdatedAt = timestamppb.New(ch.UpdatedAt)
	}
	return out
}

// storeNotifyToken writes the token as the user's broker-only secret. It
// refuses to overwrite a same-named secret that a box receives: that value
// is already the box's to read, and turning it broker-only would not undo it.
func (s *NotifyServer) storeNotifyToken(ctx context.Context, username, token string) error {
	if s.secrets == nil {
		return status.Error(codes.FailedPrecondition, "secrets store not configured on this daemon; a channel cannot hold a token")
	}
	_, _, err := s.secrets.Get(ctx, username, notify.TokenSecretName)
	switch {
	case err == nil:
		return status.Errorf(codes.FailedPrecondition,
			"secret %s exists in a mode delivered to the box; delete it with `containarium secrets delete %s %s` first",
			notify.TokenSecretName, username, notify.TokenSecretName)
	case errors.Is(err, secrets.ErrBrokerOnly), errors.Is(err, secrets.ErrNotFound):
	default:
		return status.Errorf(codes.Internal, "check %s: %v", notify.TokenSecretName, err)
	}
	if _, err := s.secrets.Set(ctx, username, notify.TokenSecretName, token, secrets.DeliveryBroker); err != nil {
		return status.Errorf(codes.Internal, "store token: %v", err)
	}
	return nil
}

func (s *NotifyServer) deleteNotifyToken(ctx context.Context, username string) error {
	if s.secrets == nil {
		return nil
	}
	_, _, err := s.secrets.Get(ctx, username, notify.TokenSecretName)
	if !errors.Is(err, secrets.ErrBrokerOnly) {
		// Absent, or a delivering secret this service did not write: leave it.
		return nil
	}
	if err := s.secrets.Delete(ctx, username, notify.TokenSecretName); err != nil && !errors.Is(err, secrets.ErrNotFound) {
		return status.Errorf(codes.Internal, "delete token: %v", err)
	}
	return nil
}

// SetNotifyChannel creates or replaces the user's channel.
func (s *NotifyServer) SetNotifyChannel(ctx context.Context, req *pb.SetNotifyChannelRequest) (*pb.SetNotifyChannelResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSecretsWrite); err != nil {
		return nil, err
	}
	username, err := notifyUser(ctx, req.GetUsername())
	if err != nil {
		return nil, err
	}
	if req.GetKind() != pb.NotifyChannelKind_NOTIFY_CHANNEL_KIND_NTFY {
		return nil, status.Error(codes.InvalidArgument, "kind must be NOTIFY_CHANNEL_KIND_NTFY")
	}
	if req.GetToken() != "" && req.GetClearToken() {
		return nil, status.Error(codes.InvalidArgument, "token and clear_token are mutually exclusive")
	}
	if strings.ContainsAny(req.GetToken(), "\r\n") {
		return nil, status.Error(codes.InvalidArgument, "token must be a single line")
	}
	prev, err := s.store.Get(ctx, username)
	if err != nil && !errors.Is(err, notify.ErrNotFound) {
		return nil, status.Errorf(codes.Internal, "read channel: %v", err)
	}
	prevFound := err == nil
	hasToken := req.GetToken() != "" || (prev.HasToken && !req.GetClearToken())
	ch := notify.Channel{
		Username:      username,
		Server:        strings.TrimSpace(req.GetServer()),
		Topic:         req.GetTopic(),
		HasToken:      hasToken,
		RedactCommand: req.GetRedactCommand(),
	}
	if err := notify.ValidateChannel(ch, hasToken); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	stored, err := s.setChannel(ctx, ch, prev, prevFound, req.GetToken(), req.GetClearToken())
	if err != nil {
		return nil, err
	}
	log.Printf("[notify] channel set for %s: ntfy %s (token %v, redact %v)", username, ch.Server, ch.HasToken, ch.RedactCommand)
	return &pb.SetNotifyChannelResponse{Channel: notifyChannelProto(stored)}, nil
}

// setChannel stores ch and, when given, its new token, under cfgMu. A new or
// cleared token is written while the stored channel says it has none, so the
// watcher never pairs a token with a server it was not given for. If the
// token cannot be written, the previous channel (prev, when found) is put
// back, leaving the old channel and token in effect; if the last channel
// write fails, the channel stays without a token.
func (s *NotifyServer) setChannel(ctx context.Context, ch, prev notify.Channel, prevFound bool, token string, clearToken bool) (notify.Channel, error) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	if token != "" || clearToken {
		tokenless := ch
		tokenless.HasToken = false
		if _, err := s.store.Set(ctx, tokenless); err != nil {
			return notify.Channel{}, status.Errorf(codes.Internal, "store channel: %v", err)
		}
		var err error
		if clearToken {
			err = s.deleteNotifyToken(ctx, ch.Username)
		} else {
			err = s.storeNotifyToken(ctx, ch.Username, token)
		}
		if err != nil {
			s.restoreChannel(ctx, ch.Username, prev, prevFound)
			return notify.Channel{}, err
		}
	}
	stored, err := s.store.Set(ctx, ch)
	if err != nil {
		return notify.Channel{}, status.Errorf(codes.Internal, "store channel: %v", err)
	}
	return stored, nil
}

// restoreChannel puts back the channel a failed setChannel replaced. The
// token was not changed (its write failed), so prev and the stored token
// still belong together. Called with cfgMu held.
func (s *NotifyServer) restoreChannel(ctx context.Context, username string, prev notify.Channel, prevFound bool) {
	var err error
	if prevFound {
		_, err = s.store.Set(ctx, prev)
	} else {
		err = s.store.Delete(ctx, username)
	}
	if err != nil && !errors.Is(err, notify.ErrNotFound) {
		log.Printf("[notify] restore channel of %s after a failed token write: %v (left without a token)", username, err)
	}
}

// GetNotifyChannel returns the user's channel, without its token.
func (s *NotifyServer) GetNotifyChannel(ctx context.Context, req *pb.GetNotifyChannelRequest) (*pb.GetNotifyChannelResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSecretsRead); err != nil {
		return nil, err
	}
	username, err := notifyUser(ctx, req.GetUsername())
	if err != nil {
		return nil, err
	}
	ch, err := s.store.Get(ctx, username)
	if errors.Is(err, notify.ErrNotFound) {
		return nil, status.Errorf(codes.NotFound, "no notification channel for %s", username)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read channel: %v", err)
	}
	return &pb.GetNotifyChannelResponse{Channel: notifyChannelProto(ch)}, nil
}

// DeleteNotifyChannel removes the user's channel and its token.
func (s *NotifyServer) DeleteNotifyChannel(ctx context.Context, req *pb.DeleteNotifyChannelRequest) (*pb.DeleteNotifyChannelResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSecretsWrite); err != nil {
		return nil, err
	}
	username, err := notifyUser(ctx, req.GetUsername())
	if err != nil {
		return nil, err
	}
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	if err := s.store.Delete(ctx, username); err != nil {
		if errors.Is(err, notify.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "no notification channel for %s", username)
		}
		return nil, status.Errorf(codes.Internal, "delete channel: %v", err)
	}
	if err := s.deleteNotifyToken(ctx, username); err != nil {
		return nil, err
	}
	return &pb.DeleteNotifyChannelResponse{}, nil
}

// TestNotifyChannel sends one test push.
func (s *NotifyServer) TestNotifyChannel(ctx context.Context, req *pb.TestNotifyChannelRequest) (*pb.TestNotifyChannelResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSecretsRead); err != nil {
		return nil, err
	}
	username, err := notifyUser(ctx, req.GetUsername())
	if err != nil {
		return nil, err
	}
	ch, token, err := s.channelAndToken(ctx, username)
	if errors.Is(err, notify.ErrNotFound) {
		return nil, status.Errorf(codes.NotFound, "no notification channel for %s; run `containarium notify set ntfy` first", username)
	}
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	msg := notify.Message{
		Title: "Containarium test notification",
		Body:  "Pushes for permission requests from " + username + "'s code runs arrive here.",
		Tags:  []string{"white_check_mark"},
	}
	if err := s.sender.Send(ctx, ch, token, msg); err != nil {
		return nil, status.Errorf(codes.Unavailable, "%v", err)
	}
	return &pb.TestNotifyChannelResponse{Message: "test push accepted by " + ch.Server}, nil
}

// channelAndToken reads a user's channel and its token as one consistent
// pair (see cfgMu).
func (s *NotifyServer) channelAndToken(ctx context.Context, username string) (notify.Channel, string, error) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	ch, err := s.store.Get(ctx, username)
	if err != nil {
		return notify.Channel{}, "", err
	}
	token, err := s.channelToken(ctx, ch)
	if err != nil {
		return notify.Channel{}, "", fmt.Errorf("read token: %w", err)
	}
	return ch, token, nil
}

func (s *NotifyServer) channelToken(ctx context.Context, ch notify.Channel) (string, error) {
	if !ch.HasToken {
		return "", nil
	}
	if s.secrets == nil {
		return "", errors.New("secrets store not configured on this daemon")
	}
	return s.secrets.BrokerCredential(ctx, ch.Username, notify.TokenSecretName)
}

// NotifyPollInterval is how often the watcher reads the journals: well under
// the 10 s a first request may take to reach the phone (#2185).
const NotifyPollInterval = 5 * time.Second

// notifyMaxConcurrentUsers bounds how many users are polled at once.
const notifyMaxConcurrentUsers = 16

// notifyMaxPushesPerPoll caps the pushes one user gets per poll.
const notifyMaxPushesPerPoll = 3

// notifyJournalReadLimit caps how much of a journal is read per poll: the
// tail of its request and response lines (status notes, which can be large
// and many, are left out on the box). An open request older than this many
// bytes of later requests and responses is not seen; a request expires after
// --approval-timeout anyway. A torn first line is skipped by
// coderun.ParseInputJournal.
const notifyJournalReadLimit = 256 << 10

// notifyJournalScript prints "B <boot-id>", "P <live pids>", then for every
// run record with an input journal
// "R <file> <base64 record> <base64 exit sidecar | -> <base64 journal tail>",
// the tail holding only input_request and input_response lines (the kind is
// the first key MarshalLine writes).
// Every file goes through open3's regular-file and resolved-path guard.
func notifyJournalScript(dir string) string {
	return fmt.Sprintf(`d=%s
%s[ -d "$d" ] || exit 0
echo "B $(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
echo "P $(ls /proc | grep -E '^[0-9]+$' | tr '\n' ' ')"
for f in "$d"/*.json; do
  b="${f%%.json}"
  [ -e "$b.input.jsonl" ] || continue
  open3 "$f" || continue
  r=$(b64_3)
  x=-
  if open3 "$b.exit"; then x=$(b64_3); fi
  open3 "$b.input.jsonl" || continue
  j=$(grep -E '^\{"kind":"input_(request|response)"' <&3 | tail -c %d | base64 | tr -d '\n'); exec 3<&-
  echo "R ${f##*/} ${r:--} ${x:--} ${j:--}"
done
`, shellSingleQuote(dir), boxRunOpenFn, notifyJournalReadLimit)
}

// parseNotifyJournals turns the script's output into the open requests of
// each live run, keyed by run name. A run that is not running is left out.
func parseNotifyJournals(box, out string) map[string][]notify.Request {
	var boot string
	alive := map[int]bool{}
	open := map[string][]notify.Request{}
	type rec struct {
		name    string
		record  agentbox.RunRecord
		journal []byte
	}
	var recs []rec
	for _, line := range strings.Split(out, "\n") {
		kind, rest, _ := strings.Cut(line, " ")
		switch kind {
		case "B":
			boot = strings.TrimSpace(rest)
		case "P":
			for _, f := range strings.Fields(rest) {
				var pid int
				if _, err := fmt.Sscan(f, &pid); err == nil {
					alive[pid] = true
				}
			}
		case "R":
			fields := strings.Fields(rest)
			if len(fields) != 4 || !agentbox.IsCurrentRecordFile(fields[0]) {
				continue
			}
			name := strings.TrimSuffix(fields[0], ".json")
			if !validRunPathID(name) {
				continue
			}
			recData, err := decodeB64Field(fields[1])
			if err != nil {
				continue
			}
			record, err := agentbox.DecodeRunRecord(recData)
			if err != nil {
				continue
			}
			sidecar, _ := decodeB64Field(fields[2])
			journal, err := decodeB64Field(fields[3])
			if err != nil {
				continue
			}
			recs = append(recs, rec{name, agentbox.FoldExitSidecar(record, sidecar), journal})
		}
	}
	for _, r := range recs {
		if agentbox.ResolveOutcome(r.record, boot, func(pid int) bool { return pid > 0 && alive[pid] }) != agentbox.RunOutcomeRunning {
			continue
		}
		summary := coderun.SummarizeApprovals(coderun.ParseInputJournal(r.journal))
		reqs := make([]notify.Request, 0, len(summary.Open))
		for _, e := range summary.Open {
			reqs = append(reqs, notify.Request{
				Box: box, Run: r.name, RequestID: e.RequestID, Tool: e.Tool, Prompt: e.Prompt, ExpiresAt: e.ExpiresAt,
			})
		}
		open[r.name] = reqs
	}
	return open
}

// RunNotifyWatcher polls until ctx is done.
func (s *NotifyServer) RunNotifyWatcher(ctx context.Context) {
	t := time.NewTicker(NotifyPollInterval)
	defer t.Stop()
	for {
		s.pollOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// pollOnce starts one poll for every channel user that has none running,
// each on its own goroutine (bounded by sem). Tests wait on s.wg.
func (s *NotifyServer) pollOnce(ctx context.Context) {
	exec := s.exec()
	if exec == nil {
		return
	}
	channels, err := s.store.List(ctx)
	if err != nil {
		log.Printf("[notify] list channels: %v", err)
		return
	}
	for _, ch := range channels {
		s.mu.Lock()
		busy := s.inflight[ch.Username]
		if !busy {
			s.inflight[ch.Username] = true
		}
		s.mu.Unlock()
		if busy {
			continue
		}
		s.wg.Add(1)
		go func(user string) {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.inflight, user)
				s.mu.Unlock()
			}()
			select {
			case s.sem <- struct{}{}:
				defer func() { <-s.sem }()
			case <-ctx.Done():
				return
			}
			s.pollUser(ctx, exec, user)
		}(ch.Username)
	}
}

// pollUser reads one user's journals and sends what is due. A box that
// cannot be read is skipped this round, keeping its state.
func (s *NotifyServer) pollUser(ctx context.Context, exec boxScriptFunc, user string) {
	out, err := exec(user+"-container", notifyJournalScript(s.dir))
	if err != nil {
		return
	}
	pushes := s.coalescer.Step(user, parseNotifyJournals(user, out), s.now())
	sort.Slice(pushes, func(i, j int) bool { return pushes[i].Run < pushes[j].Run })
	// The box's user can write run records and journals, so a flood of
	// fake runs must not become a flood of pushes: the rest wait.
	for _, p := range pushes[min(len(pushes), notifyMaxPushesPerPoll):] {
		s.coalescer.Requeue(p)
	}
	pushes = pushes[:min(len(pushes), notifyMaxPushesPerPoll)]
	for _, p := range pushes {
		if ctx.Err() != nil {
			s.coalescer.Requeue(p)
			continue
		}
		if err := s.deliver(ctx, user, p); err != nil {
			log.Printf("[notify] push for %s/%s: %v", user, p.Run, err)
			s.coalescer.Requeue(p)
			continue
		}
		s.coalescer.Sent(p, s.now())
	}
}

// deliver sends one push with the channel and token read together, at send
// time: a channel changed or removed since the poll began is honoured.
func (s *NotifyServer) deliver(ctx context.Context, user string, p notify.Push) error {
	ch, token, err := s.channelAndToken(ctx, user)
	if errors.Is(err, notify.ErrNotFound) {
		return nil // channel removed: nothing to send to
	}
	if err != nil {
		return err
	}
	return s.sender.Send(ctx, ch, token, notify.BuildMessage(p.Requests, ch.RedactCommand, s.now()))
}
