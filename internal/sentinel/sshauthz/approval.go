package sshauthz

import (
	"context"
	"fmt"
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
)

// pendingApproval is kept in the plugin by connection id, never in sshpiperd
// metadata: sshpiperd stores a retry's metadata even for an unsigned publickey
// query, so state there would let a client that queried someone else's public
// key reach the prompt after signing with another key. Every publickey offer
// clears its connection's approval first, so the approval present at
// keyboard-interactive belongs to the key that signed.
type pendingApproval struct {
	id, url, code string
	poll          time.Duration
	deadline      time.Time // min(expires_at, first PENDING + MaxApprovalWait)
	backend, fp   string
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
	return pendingApproval{id: a.GetApprovalId(), url: a.GetUrl(), code: a.GetCode(), poll: poll, deadline: deadline}, true
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

// putApproval reports false when the bounded store is full.
func (p *Plugin) putApproval(id string, a pendingApproval) bool {
	now := p.cfg.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, v := range p.approvals {
		if !now.Before(v.deadline) {
			delete(p.approvals, k)
		}
	}
	if len(p.approvals) >= maxPending {
		return false
	}
	p.approvals[id] = a
	return true
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

// keyboardInteractive runs the approval for the key that just signed. It
// consumes the approval whatever the outcome and waits at most until its
// deadline, so no connection holds the plugin past MaxApprovalWait after its
// first PENDING. Neither the approval id nor the code is logged.
func (p *Plugin) keyboardInteractive(conn libplugin.ConnMetadata, challenge libplugin.KeyboardInteractiveChallenge) (*libplugin.Upstream, error) {
	a, ok := p.takeApproval(conn.UniqueID())
	if !ok {
		return nil, errPublicKeyOnly
	}
	meta := map[string]string{sshsession.MetaUserID: "", sshsession.MetaAuthzDecision: "", sshsession.MetaDenyReason: "", sshsession.MetaEnforced: ""}
	gaveUp := &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, DenyReason: pb.SSHDenyReason_SSH_DENY_REASON_APPROVAL_PENDING}
	instruction := fmt.Sprintf("Approve this device at %s, code %s", a.url, a.code)
	if _, err := challenge(conn.User(), instruction, approvalPrompt, false); err != nil {
		p.cfg.Logf("[ssh-authz] login=%q backend=%q: approval prompt not answered: %v", conn.User(), a.backend, err)
		return p.stash(meta, conn, a.wire, a.backend, a.fp, gaveUp)
	}
	req, _ := proto.Clone(a.req).(*pb.AuthorizeSSHRequest)
	req.ApprovalId = a.id
	ck := CacheKey{Backend: a.backend, Login: conn.User(), Fingerprint: a.fp}
	for {
		remaining := a.deadline.Sub(p.cfg.Now())
		if remaining <= 0 {
			p.cfg.Logf("[ssh-authz] login=%q backend=%q: device not approved before the deadline", conn.User(), a.backend)
			return p.stash(meta, conn, a.wire, a.backend, a.fp, gaveUp)
		}
		ctx, cancel := context.WithTimeout(context.Background(), min(p.cfg.Timeout, remaining))
		res, err := p.cfg.Authorizer.Authorize(ctx, a.backend, req)
		cancel()
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
		p.cfg.Sleep(min(a.poll, remaining))
	}
}

// beginApproval stores the approval for this connection and asks sshpiperd to
// retry this plugin, which keeps the chain cursor here. A full store denies.
func (p *Plugin) beginApproval(meta map[string]string, conn libplugin.ConnMetadata, a pendingApproval, res *pb.AuthorizeSSHResponse) (*libplugin.Upstream, error) {
	if !p.putApproval(conn.UniqueID(), a) {
		p.cfg.Logf("[ssh-authz] login=%q: too many pending device approvals", conn.User())
		return p.stash(meta, conn, a.wire, a.backend, a.fp, res)
	}
	p.cfg.Logf("[ssh-authz] login=%q backend=%q: device approval pending, prompting with keyboard-interactive", conn.User(), a.backend)
	return &libplugin.Upstream{Auth: libplugin.CreateRetryCurrentPluginAuth(nil)}, nil
}
