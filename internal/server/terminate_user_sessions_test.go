package server

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/cloud"
	"github.com/footprintai/containarium/internal/collaborator"
	"github.com/footprintai/containarium/internal/sshauthz"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// sessionRecorder is a fake Incus exec plus a fake host pkill writing one
// ordered command log, so a test can assert the exact sequence across the
// box and the host (#2522). Every other incus.Backend method panics (nil
// embed), so a stray delete or file write fails the test loudly.
type sessionRecorder struct {
	incus.Backend
	mu      sync.Mutex
	boxes   map[string]string // container name -> state
	log     []string
	tenants map[string]string // container name -> incus.TenantLabelKey value (optional)
	killed  map[string]bool   // account -> pkill matched (box and host)
	collabs []*collaborator.Collaborator
	listErr error
}

func (r *sessionRecorder) GetContainer(name string) (*incus.ContainerInfo, error) {
	state, ok := r.boxes[name]
	if !ok {
		return nil, errors.New("not found")
	}
	return &incus.ContainerInfo{Name: name, State: state, Tenant: r.tenants[name]}, nil
}

func (r *sessionRecorder) Exec(name string, cmd []string) error {
	r.record("box " + name + ": " + strings.Join(cmd, " "))
	return nil
}

func (r *sessionRecorder) ExecWithExitCode(name string, cmd []string) (string, string, int, error) {
	r.record("box " + name + ": " + strings.Join(cmd, " "))
	if r.killed[cmd[len(cmd)-1]] {
		return "", "", 0, nil
	}
	return "", "", 1, nil
}

func (r *sessionRecorder) hostKill(account string) bool {
	r.record("host: pkill -KILL -u " + account)
	return r.killed[account]
}

func (r *sessionRecorder) ListByCollaborator(_ context.Context, user string) ([]*collaborator.Collaborator, error) {
	var out []*collaborator.Collaborator
	for _, c := range r.collabs {
		if c.CollaboratorUsername == user {
			out = append(out, c)
		}
	}
	return out, r.listErr
}

func (r *sessionRecorder) record(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.log = append(r.log, s)
}

func newSessionServer(r *sessionRecorder) *ContainerServer {
	return &ContainerServer{
		manager:         container.NewWithBackend(r),
		collabAccess:    r,
		hostSessionKill: r.hostKill,
	}
}

func collab(owner, user string) *collaborator.Collaborator {
	return &collaborator.Collaborator{
		ContainerName:        owner + "-container",
		OwnerUsername:        owner,
		CollaboratorUsername: user,
		AccountName:          owner + "-container-" + user,
	}
}

func TestEndUserSessions_Walk(t *testing.T) {
	cases := []struct {
		name           string
		rec            *sessionRecorder
		want           []string
		wantTerminated int32
		wantBoxes      int32
	}{
		{
			name: "owner box only",
			rec: &sessionRecorder{
				boxes:  map[string]string{"alice-container": "Running", "bob-container": "Running"},
				killed: map[string]bool{"alice": true},
			},
			want: []string{
				"box alice-container: loginctl terminate-user alice",
				"box alice-container: pkill -KILL -u alice",
				"host: pkill -KILL -u alice",
			},
			// alice had processes in her box and on her jump account.
			wantTerminated: 2, wantBoxes: 1,
		},
		{
			name: "collaborator on two boxes",
			rec: &sessionRecorder{
				boxes: map[string]string{"bob-container": "Running", "carol-container": "Running"},
				collabs: []*collaborator.Collaborator{
					collab("bob", "alice"), collab("carol", "alice"), collab("carol", "dave"),
				},
				killed: map[string]bool{"bob-container-alice": true},
			},
			want: []string{
				"box bob-container: loginctl terminate-user bob-container-alice",
				"box bob-container: pkill -KILL -u bob-container-alice",
				"host: pkill -KILL -u bob-container-alice",
				"box carol-container: loginctl terminate-user carol-container-alice",
				"box carol-container: pkill -KILL -u carol-container-alice",
				"host: pkill -KILL -u carol-container-alice",
			},
			wantTerminated: 2, wantBoxes: 2,
		},
		{
			name: "user with no boxes",
			rec: &sessionRecorder{
				boxes:   map[string]string{"bob-container": "Running"},
				collabs: []*collaborator.Collaborator{collab("bob", "dave")},
			},
			want: nil, wantTerminated: 0, wantBoxes: 0,
		},
		{
			name: "stopped box: host account only",
			rec: &sessionRecorder{
				boxes: map[string]string{"alice-container": "Stopped"},
			},
			want:           []string{"host: pkill -KILL -u alice"},
			wantTerminated: 0, wantBoxes: 1,
		},
		{
			name: "collaborator row whose box is gone is skipped",
			rec: &sessionRecorder{
				boxes:   map[string]string{},
				collabs: []*collaborator.Collaborator{collab("bob", "alice")},
			},
			want: nil, wantTerminated: 0, wantBoxes: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := newSessionServer(tc.rec).EndUserSessions(context.Background(), "alice", "")
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(tc.rec.log, "\n") != strings.Join(tc.want, "\n") {
				t.Errorf("commands:\n%s\nwant:\n%s", strings.Join(tc.rec.log, "\n"), strings.Join(tc.want, "\n"))
			}
			for _, line := range tc.rec.log {
				for _, banned := range []string{"userdel", "rm ", "deluser", "authorized_keys", "sudoers"} {
					if strings.Contains(line, banned) {
						t.Errorf("terminate must not delete or edit anything: %q", line)
					}
				}
			}
			if resp.GetTerminatedSessions() != tc.wantTerminated || resp.GetBoxesTouched() != tc.wantBoxes {
				t.Errorf("response = %d terminated / %d boxes, want %d / %d",
					resp.GetTerminatedSessions(), resp.GetBoxesTouched(), tc.wantTerminated, tc.wantBoxes)
			}
		})
	}
}

// A failing collaborator lookup still ends the owner-box sessions it can
// reach, then reports the error so the caller (or assignment replay) retries.
func TestEndUserSessions_CollaboratorLookupErrorStillKillsOwnerBox(t *testing.T) {
	rec := &sessionRecorder{
		boxes:   map[string]string{"alice-container": "Running"},
		listErr: errors.New("db down"),
	}
	_, err := newSessionServer(rec).EndUserSessions(context.Background(), "alice", "")
	if err == nil {
		t.Fatal("expected the lookup error")
	}
	if len(rec.log) != 3 {
		t.Errorf("owner box sessions should still be ended: %v", rec.log)
	}
}

func TestEndUserSessions_RejectsInvalidUsername(t *testing.T) {
	for _, u := range []string{"", "-1", "a b", "../x", "alice-container-bob/../x"} {
		rec := &sessionRecorder{boxes: map[string]string{}}
		_, err := newSessionServer(rec).EndUserSessions(context.Background(), u, "")
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%q: code = %v, want InvalidArgument", u, status.Code(err))
		}
		if len(rec.log) != 0 {
			t.Errorf("%q reached a command: %v", u, rec.log)
		}
	}
}

// TestTerminateUserSessions_Authorization pins the decision recorded on
// #2522: the admin role, or a service token (admin role) carrying ssh:write,
// may name any user; a tenant token only itself; another user is
// PermissionDenied.
func TestTerminateUserSessions_Authorization(t *testing.T) {
	cases := []struct {
		name     string
		ctx      context.Context
		target   string
		wantCode codes.Code
	}{
		{
			name:   "admin role terminates another user",
			ctx:    auth.ContextWithTestSubject(context.Background(), "operator", auth.RoleAdmin),
			target: "alice", wantCode: codes.OK,
		},
		{
			name: "service token with ssh:write terminates another user",
			ctx: auth.ContextWithTestSubjectScopes(context.Background(), auth.SystemSubject,
				[]string{auth.RoleAdmin}, []string{auth.ScopeSSHWrite}),
			target: "alice", wantCode: codes.OK,
		},
		{
			name:   "tenant token terminates its own sessions",
			ctx:    auth.ContextWithTestSubjectScopes(context.Background(), "alice", nil, []string{auth.ScopeSSHWrite}),
			target: "alice", wantCode: codes.OK,
		},
		{
			name:   "tenant token naming another user is denied",
			ctx:    auth.ContextWithTestSubjectScopes(context.Background(), "bob", nil, []string{auth.ScopeSSHWrite}),
			target: "alice", wantCode: codes.PermissionDenied,
		},
		{
			name: "service token without ssh:write is denied",
			ctx: auth.ContextWithTestSubjectScopes(context.Background(), auth.SystemSubject,
				[]string{auth.RoleAdmin}, []string{auth.ScopeContainersRead}),
			target: "alice", wantCode: codes.PermissionDenied,
		},
		{
			name:   "no subject is unauthenticated",
			ctx:    context.Background(),
			target: "alice", wantCode: codes.Unauthenticated,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &sessionRecorder{
				boxes:  map[string]string{"alice-container": "Running"},
				killed: map[string]bool{"alice": true},
			}
			resp, err := newSessionServer(rec).TerminateUserSessions(tc.ctx, &pb.TerminateUserSessionsRequest{Username: tc.target})
			if status.Code(err) != tc.wantCode {
				t.Fatalf("code = %v (%v), want %v", status.Code(err), err, tc.wantCode)
			}
			if tc.wantCode != codes.OK {
				if len(rec.log) != 0 {
					t.Errorf("a denied call ran commands: %v", rec.log)
				}
				return
			}
			if resp.GetBoxesTouched() != 1 || resp.GetTerminatedSessions() != 2 {
				t.Errorf("response = %+v", resp)
			}
		})
	}
}

// The cloud assignment handler reaches the same server function.
func TestCloudSessionTerminator_UsesEndUserSessions(t *testing.T) {
	rec := &sessionRecorder{boxes: map[string]string{"alice-container": "Running"}}
	if err := (cloudSessionTerminator{s: newSessionServer(rec)}).TerminateUserSessions(context.Background(), "alice", ""); err != nil {
		t.Fatal(err)
	}
	if len(rec.log) != 3 {
		t.Errorf("commands = %v, want the owner-box sequence", rec.log)
	}
}

// Managed mode (#2602): the assignment's user_id is the control plane's id.
// The terminator resolves it through the logins recorded on earlier managed
// AuthorizeSSH decisions; a self-host id with no record still works; an id
// it cannot map is ErrUserNotMapped, not a zero-session success.
func TestCloudSessionTerminator_ManagedUserID(t *testing.T) {
	const cpUser = "0b9c1f7e-3d2a-4c55-9a61-7f0e2d4b8c10"
	ids := sshauthz.NewManagedIdentities()
	allowAs := func(login string) {
		t.Helper()
		d := &sshauthz.Decider{
			Local: sshauthz.LocalFactsFunc(func(context.Context, *pb.AuthorizeSSHRequest) (string, bool, error) {
				return login, true, nil
			}),
			Cloud:      fakeSSHCloud{resp: &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW, UserId: cpUser}},
			Managed:    true,
			Identities: ids,
		}
		req := &pb.AuthorizeSSHRequest{Login: login, Credential: &pb.SSHCredential{Kind: &pb.SSHCredential_PublicKey{
			PublicKey: &pb.SSHPublicKeyCredential{FingerprintSha256: "SHA256:alicekey"},
		}}}
		if _, err := d.Decide(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("control-plane id seen in an earlier decision", func(t *testing.T) {
		rec := &sessionRecorder{
			boxes:   map[string]string{"alice-container": "Running", "bob-container": "Running"},
			collabs: []*collaborator.Collaborator{collab("bob", "alice")},
			killed:  map[string]bool{"alice": true},
		}
		allowAs("alice")
		allowAs("bob-container-alice") // same user also logs in as a collaborator
		if err := (cloudSessionTerminator{s: newSessionServer(rec), ids: ids}).TerminateUserSessions(context.Background(), cpUser, ""); err != nil {
			t.Fatal(err)
		}
		want := []string{
			"box alice-container: loginctl terminate-user alice",
			"box alice-container: pkill -KILL -u alice",
			"host: pkill -KILL -u alice",
			"box bob-container: loginctl terminate-user bob-container-alice",
			"box bob-container: pkill -KILL -u bob-container-alice",
			"host: pkill -KILL -u bob-container-alice",
		}
		if strings.Join(rec.log, "\n") != strings.Join(want, "\n") {
			t.Errorf("commands:\n%s\nwant (alice walked once):\n%s", strings.Join(rec.log, "\n"), strings.Join(want, "\n"))
		}
	})

	t.Run("id never seen is not mapped", func(t *testing.T) {
		rec := &sessionRecorder{boxes: map[string]string{"alice-container": "Running"}}
		err := (cloudSessionTerminator{s: newSessionServer(rec), ids: ids}).TerminateUserSessions(context.Background(), "5f1e2d3c-0000-4000-8000-000000000000", "")
		if !errors.Is(err, cloud.ErrUserNotMapped) {
			t.Fatalf("err = %v, want ErrUserNotMapped", err)
		}
		if len(rec.log) != 0 {
			t.Errorf("an unmapped id ran commands: %v", rec.log)
		}
	})

	t.Run("not a local name at all is not mapped", func(t *testing.T) {
		rec := &sessionRecorder{}
		err := (cloudSessionTerminator{s: newSessionServer(rec), ids: ids}).TerminateUserSessions(context.Background(), "Not A Login", "")
		if !errors.Is(err, cloud.ErrUserNotMapped) {
			t.Fatalf("err = %v, want ErrUserNotMapped", err)
		}
	})

	t.Run("known local id falls back to the self-host rule", func(t *testing.T) {
		rec := &sessionRecorder{boxes: map[string]string{"carol-container": "Running"}}
		if err := (cloudSessionTerminator{s: newSessionServer(rec), ids: ids}).TerminateUserSessions(context.Background(), "carol", ""); err != nil {
			t.Fatal(err)
		}
		if len(rec.log) != 3 {
			t.Errorf("commands = %v, want carol's owner-box sequence", rec.log)
		}
	})
}

type fakeSSHCloud struct{ resp *pb.AuthorizeSSHResponse }

func (f fakeSSHCloud) AuthorizeSSH(context.Context, *pb.AuthorizeSSHRequest, ...grpc.CallOption) (*pb.AuthorizeSSHResponse, error) {
	return f.resp, nil
}

// #2546: on a host shared by two orgs, an org-scoped order ends only that
// org's sessions; unscoped ends both (the original behaviour).
func TestEndUserSessions_OrgScope(t *testing.T) {
	newRec := func() *sessionRecorder {
		return &sessionRecorder{
			boxes:   map[string]string{"alice-container": "Running", "bob-container": "Running"},
			tenants: map[string]string{"alice-container": "org-a", "bob-container": "org-b"},
			// alice is a collaborator on bob's box, which belongs to the other org.
			collabs: []*collaborator.Collaborator{collab("bob", "alice")},
			killed:  map[string]bool{"alice": true, "bob-container-alice": true},
		}
	}
	for _, tc := range []struct {
		name, org string
		wantBoxes int32
		want      []string
		notWant   []string
	}{
		{"org-a order leaves org-b alone", "org-a", 1,
			[]string{"box alice-container: pkill -KILL -u alice", "host: pkill -KILL -u alice"},
			[]string{"bob-container"}},
		{"org-b order leaves org-a alone", "org-b", 1,
			[]string{"box bob-container: pkill -KILL -u bob-container-alice", "host: pkill -KILL -u bob-container-alice"},
			[]string{"alice-container", "u alice\n"}},
		{"unscoped ends both", "", 2,
			[]string{"box alice-container: pkill -KILL -u alice", "box bob-container: pkill -KILL -u bob-container-alice"},
			nil},
		{"unknown org touches nothing", "org-z", 0, nil, []string{"box", "host"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := newRec()
			resp, err := newSessionServer(rec).EndUserSessions(context.Background(), "alice", tc.org)
			if err != nil {
				t.Fatal(err)
			}
			if resp.GetBoxesTouched() != tc.wantBoxes {
				t.Errorf("boxes touched = %d, want %d (log: %v)", resp.GetBoxesTouched(), tc.wantBoxes, rec.log)
			}
			joined := strings.Join(rec.log, "\n") + "\n"
			for _, w := range tc.want {
				if !strings.Contains(joined, w) {
					t.Errorf("missing %q in:\n%s", w, joined)
				}
			}
			for _, n := range tc.notWant {
				if strings.Contains(joined, n) {
					t.Errorf("unexpected %q in:\n%s", n, joined)
				}
			}
		})
	}
}

// The cloud terminator forwards the order's org to every walk it makes.
func TestCloudSessionTerminator_ForwardsOrg(t *testing.T) {
	rec := &sessionRecorder{
		boxes:   map[string]string{"alice-container": "Running"},
		tenants: map[string]string{"alice-container": "org-a"},
		killed:  map[string]bool{"alice": true},
	}
	if err := (cloudSessionTerminator{s: newSessionServer(rec)}).TerminateUserSessions(context.Background(), "alice", "org-other"); !errors.Is(err, cloud.ErrUserNotMapped) {
		t.Fatalf("err = %v, want ErrUserNotMapped (no box in that org)", err)
	}
	if len(rec.log) != 0 {
		t.Errorf("other org's box was touched: %v", rec.log)
	}
}
