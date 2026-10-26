package sshauthz

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/tg123/sshpiper/libplugin"
	"google.golang.org/protobuf/proto"
)

// Device approval (#2526, design component 3). An APPROVAL_PENDING answer in
// enforce mode keeps sshpiperd's chain cursor on this plugin with a retry;
// sshpiperd turns it into publickey partial success once the key has signed,
// and keyboard-interactive shows the URL and code, waits for Enter, and polls.
const (
	approvalPrompt      = "press Enter once approved: "
	defaultApprovalPoll = 2 * time.Second
	minApprovalPoll     = 250 * time.Millisecond
	// Caps on connections in the approval stage at once (#3084): a key that
	// signed can hold at most this many polls per login and per source IP.
	// Beyond them the login is refused at once; nothing waits for a slot.
	maxApprovalsPerLogin = 3
	maxApprovalsPerIP    = 10
)

// pendingApproval is kept in the plugin by connection id, never in sshpiperd
// metadata: sshpiperd stores a retry's metadata even for an unsigned publickey
// query, so state there would let a client that queried someone else's public
// key reach the prompt after signing with another key. Every publickey offer
// clears its connection's approval first, so the approval present at
// keyboard-interactive belongs to the key that signed.
type pendingApproval struct {
	id, url, code string
	host          string // the URL's host, the only part of it that is logged
	poll          time.Duration
	deadline      time.Time // min(expires_at, first PENDING + MaxApprovalWait)
	backend, fp   string
	// session, login and addr identify the connection in the denied record of
	// a prompt never answered; user is the daemon's user_id with the PENDING.
	session, login, addr, user string
	wire          []byte
	req           *pb.AuthorizeSSHRequest
}

// newApproval returns the approval to prompt for, or false when the daemon's
// answer cannot be shown safely; the caller then denies as before.
func newApproval(res *pb.AuthorizeSSHResponse, now time.Time) (pendingApproval, bool) {
	a := res.GetApproval()
	if res.GetDenyReason() != pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING || a == nil ||
		!printable(a.GetApprovalId(), 256) || !printable(a.GetCode(), 64) || !printable(a.GetUrl(), 2048) {
		return pendingApproval{}, false
	}
	// The URL and code reach the user's terminal: https only, no control
	// characters (printable), nothing that could pass for a different site.
	u, err := url.Parse(a.GetUrl())
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return pendingApproval{}, false
	}
	if err := a.GetExpiresAt().CheckValid(); err != nil {
		return pendingApproval{}, false
	}
	poll := defaultApprovalPoll
	if d := a.GetPollAfter(); d != nil {
		if d.CheckValid() != nil {
			return pendingApproval{}, false
		}
		if d.AsDuration() > 0 {
			poll = max(d.AsDuration(), minApprovalPoll)
		}
	}
	deadline := a.GetExpiresAt().AsTime()
	if capped := now.Add(MaxApprovalWait); capped.Before(deadline) {
		deadline = capped
	}
	if !now.Before(deadline) {
		return pendingApproval{}, false
	}
	return pendingApproval{id: a.GetApprovalId(), url: a.GetUrl(), code: a.GetCode(), host: u.Host, poll: poll, deadline: deadline, user: res.GetUserId()}, true
}

// printable is 1..limit bytes of visible ASCII: no space, no control bytes.
func printable(s string, limit int) bool {
	if s == "" || len(s) > limit {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// unanswered is the refusal of an approval whose prompt was never answered.
func unanswered(user string) *pb.AuthorizeSSHResponse {
	return &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, DenyReason: pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING, UserId: user}
}

// putApproval reports false when the bounded store is full. Approvals past
// their deadline are swept first; a swept one was never consumed by
// keyboard-interactive, so it is audited as a prompt never answered.
func (p *Plugin) putApproval(id string, a pendingApproval) bool {
	now := p.cfg.Now()
	p.mu.Lock()
	var expired []pendingApproval
	for k, v := range p.approvals {
		if !now.Before(v.deadline) {
			delete(p.approvals, k)
			expired = append(expired, v)
		}
	}
	full := len(p.approvals) >= maxPending
	if !full {
		p.approvals[id] = a
	}
	p.mu.Unlock()
	p.recordUnanswered(expired, "expired")
	return !full
}

// recordUnanswered writes the denied record of each approval that left the
// store without keyboard-interactive consuming it: the key was offered, the
// client ended the connection or let the approval expire, and the prompt was
// never answered. Neither the approval id nor the code is logged.
func (p *Plugin) recordUnanswered(orphans []pendingApproval, cause string) {
	for _, a := range orphans {
		p.cfg.Logf("[ssh-authz] login=%q backend=%q: connection %s before the device approval prompt was answered; recorded as denied", a.login, a.backend, cause)
		p.recordDeniedFor(a.session, a.addr, a.login, a.fp, unanswered(a.user))
	}
}

// takeApproval removes and returns the connection's approval.
func (p *Plugin) takeApproval(id string) (pendingApproval, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	a, ok := p.approvals[id]
	delete(p.approvals, id)
	return a, ok
}

func (p *Plugin) hasApproval(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.approvals[id]
	return ok
}

func (p *Plugin) nextAuthMethods(conn libplugin.ConnMetadata) ([]string, error) {
	if p.hasApproval(conn.UniqueID()) {
		return []string{"keyboard-interactive"}, nil
	}
	return []string{"publickey"}, nil
}

// pipeCreateError is sshpiperd's notice that a connection ended without a
// pipe, which is how a dropped client surfaces: sshpiperd reads nothing from
// the client while this plugin is in a callback, so the drop shows only when
// the connection is next used (the liveness probe in keyboardInteractive)
// or when the login grace runs out. The notice carries the client address
// only. A poll running for that address stops, and an approval still stored
// for it is audited as a prompt never answered.
func (p *Plugin) pipeCreateError(remote string, _ error) {
	p.mu.Lock()
	if cancel, ok := p.polls[remote]; ok {
		cancel()
	}
	var orphans []pendingApproval
	for id, a := range p.approvals {
		if a.addr == remote {
			delete(p.approvals, id)
			orphans = append(orphans, a)
		}
	}
	p.mu.Unlock()
	p.recordUnanswered(orphans, "ended")
}

// acquireSlot admits a connection to the approval stage under the per-login
// and per-source-IP caps, returning the release, or the reason it was
// refused. It never waits for a slot.
func (p *Plugin) acquireSlot(login, ip string) (release func(), refused string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n := p.slotsByLogin[login]; n >= maxApprovalsPerLogin {
		return nil, fmt.Sprintf("%d device approvals already in progress for this login (cap %d)", n, maxApprovalsPerLogin)
	}
	if n := p.slotsByIP[ip]; n >= maxApprovalsPerIP {
		return nil, fmt.Sprintf("%d device approvals already in progress from this address (cap %d)", n, maxApprovalsPerIP)
	}
	p.slotsByLogin[login]++
	p.slotsByIP[ip]++
	return func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.slotsByLogin[login]--; p.slotsByLogin[login] <= 0 {
			delete(p.slotsByLogin, login)
		}
		if p.slotsByIP[ip]--; p.slotsByIP[ip] <= 0 {
			delete(p.slotsByIP, ip)
		}
	}, ""
}

// watchPoll registers the running poll of a connection by client address so
// pipeCreateError can stop it; the returned func unregisters it.
func (p *Plugin) watchPoll(remote string, cancel context.CancelFunc) func() {
	if remote == "" {
		return func() {}
	}
	p.mu.Lock()
	p.polls[remote] = cancel
	p.mu.Unlock()
	return func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		delete(p.polls, remote)
	}
}

// sleep waits for the poll interval or until the poll is cancelled. Config
// .Sleep replaces the wait in tests, where cancellation arrives from inside it.
func (p *Plugin) sleep(ctx context.Context, d time.Duration) {
	if p.cfg.Sleep != nil {
		p.cfg.Sleep(d)
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// clientIP is the host part of a client address, or the address itself.
func clientIP(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// keyboardInteractive runs the approval for the key that just signed. It
// consumes the approval whatever the outcome and waits at most until its
// deadline, so no connection holds the plugin past MaxApprovalWait after its
// first PENDING. The poll stops early when sshpiperd reports the client gone
// (pipeCreateError), and before each re-poll a zero-prompt keyboard-interactive
// request is sent so that sshpiperd uses the connection and notices a dropped
// client; the client answers it with no responses and shows nothing.
// Neither the approval id nor the code is logged.
func (p *Plugin) keyboardInteractive(conn libplugin.ConnMetadata, challenge libplugin.KeyboardInteractiveChallenge) (*libplugin.Upstream, error) {
	a, ok := p.takeApproval(conn.UniqueID())
	if !ok {
		return nil, errPublicKeyOnly
	}
	meta := map[string]string{sshsession.MetaUserID: "", sshsession.MetaAuthzDecision: "", sshsession.MetaDenyReason: "", sshsession.MetaEnforced: ""}
	gaveUp := unanswered(a.user)
	release, refused := p.acquireSlot(conn.User(), clientIP(conn.RemoteAddr()))
	if refused != "" {
		p.cfg.Logf("[ssh-authz] login=%q backend=%q: device approval refused: %s", conn.User(), a.backend, refused)
		return p.stash(meta, conn, a.wire, a.backend, a.fp, gaveUp)
	}
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer p.watchPoll(conn.RemoteAddr(), cancel)()
	instruction := fmt.Sprintf("Approve this device at %s, code %s", a.url, a.code)
	if _, err := challenge(conn.User(), instruction, approvalPrompt, false); err != nil {
		p.cfg.Logf("[ssh-authz] login=%q backend=%q: approval prompt not answered: %v", conn.User(), a.backend, err)
		return p.stash(meta, conn, a.wire, a.backend, a.fp, gaveUp)
	}
	req, _ := proto.Clone(a.req).(*pb.AuthorizeSSHRequest)
	req.ApprovalId = a.id
	ck := CacheKey{Backend: a.backend, Login: conn.User(), Fingerprint: a.fp}
	gone := func() (*libplugin.Upstream, error) {
		p.cfg.Logf("[ssh-authz] login=%q backend=%q: client gone during device approval, polling stopped", conn.User(), a.backend)
		return p.stash(meta, conn, a.wire, a.backend, a.fp, gaveUp)
	}
	for {
		if ctx.Err() != nil {
			return gone()
		}
		remaining := a.deadline.Sub(p.cfg.Now())
		if remaining <= 0 {
			p.cfg.Logf("[ssh-authz] login=%q backend=%q: device not approved before the deadline", conn.User(), a.backend)
			return p.stash(meta, conn, a.wire, a.backend, a.fp, gaveUp)
		}
		actx, acancel := context.WithTimeout(ctx, min(p.cfg.Timeout, remaining))
		res, err := p.cfg.Authorizer.Authorize(actx, a.backend, req)
		acancel()
		if ctx.Err() != nil {
			return gone()
		}
		if err != nil || validateResponse(res) != nil {
			// Fail closed: no grace during approval, there was no positive.
			return p.stash(meta, conn, a.wire, a.backend, a.fp, unavailable())
		}
		if res.GetDecision() == pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW {
			p.cfg.Cache.Put(ck, res.GetUserId(), res.GetCacheTtl().AsDuration())
			return p.stash(meta, conn, a.wire, a.backend, a.fp, res)
		}
		if res.GetDenyReason() != pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING {
			return p.stash(meta, conn, a.wire, a.backend, a.fp, res)
		}
		gaveUp.UserId = res.GetUserId()
		p.sleep(ctx, min(a.poll, remaining))
		// The liveness probe: an empty name and instruction with no prompt.
		if _, err := challenge("", "", "", false); err != nil {
			return gone()
		}
	}
}

// beginApproval stores the approval for this connection and asks sshpiperd to
// retry this plugin, which keeps the chain cursor here. A full store denies.
func (p *Plugin) beginApproval(meta map[string]string, conn libplugin.ConnMetadata, a pendingApproval, res *pb.AuthorizeSSHResponse) (*libplugin.Upstream, error) {
	a.session, a.login, a.addr = conn.UniqueID(), conn.User(), conn.RemoteAddr()
	if !p.putApproval(conn.UniqueID(), a) {
		p.cfg.Logf("[ssh-authz] login=%q: too many pending device approvals", conn.User())
		return p.stash(meta, conn, a.wire, a.backend, a.fp, res)
	}
	p.cfg.Logf("[ssh-authz] login=%q backend=%q: device approval pending at approval_host=%q, prompting with keyboard-interactive", conn.User(), a.backend, a.host)
	return &libplugin.Upstream{Auth: libplugin.CreateRetryCurrentPluginAuth(nil)}, nil
}
