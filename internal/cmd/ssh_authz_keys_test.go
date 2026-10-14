//go:build !windows && !containarium_client

package cmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// sshdArgs returns what sshd passes for %f %t %k on a fresh ed25519 key.
func sshdArgs(t *testing.T) (fingerprint, keyType, key string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(ssh.MarshalAuthorizedKey(pk)))
	return ssh.FingerprintSHA256(pk), fields[0], fields[1]
}

func allowResp() *pb.AuthorizeSSHResponse {
	return &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_ALLOW, UserId: "alice"}
}

func denyResp(r pb.SSHDenyReason) *pb.AuthorizeSSHResponse {
	return &pb.AuthorizeSSHResponse{Decision: pb.SSHAuthzDecision_SSH_AUTHZ_DECISION_DENY, DenyReason: r}
}

func runKeys(t *testing.T, o sshAuthzKeysOptions) (stdout string, code int) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = runSSHAuthzKeys(context.Background(), o, &out, &errOut)
	return out.String(), code
}

func TestSSHAuthzKeys_AllowPrintsExactlyTheKeyLine(t *testing.T) {
	fp, kt, k := sshdArgs(t)
	var got *pb.AuthorizeSSHRequest
	out, code := runKeys(t, sshAuthzKeysOptions{
		Login: "alice", Fingerprint: fp, KeyType: kt, Key: k,
		Authorize: func(_ context.Context, req *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
			got = req
			return allowResp(), nil
		},
	})
	if code != 0 || out != kt+" "+k+"\n" {
		t.Fatalf("code = %d stdout = %q, want 0 and exactly the key line", code, out)
	}
	pk := got.GetCredential().GetPublicKey()
	if got.GetLogin() != "alice" || pk.GetFingerprintSha256() != fp || pk.GetKeyType() != pb.SSHKeyType_SSH_KEY_TYPE_ED25519 {
		t.Fatalf("request = %v, want login, sshd's fingerprint and the parsed key type", got)
	}
}

// Every deny prints nothing and exits 0 in both modes: a decision was made.
func TestSSHAuthzKeys_DenyPrintsNothing(t *testing.T) {
	fp, kt, k := sshdArgs(t)
	for reason := range pb.SSHDenyReason_name {
		for _, enforce := range []bool{false, true} {
			r := pb.SSHDenyReason(reason)
			out, code := runKeys(t, sshAuthzKeysOptions{
				Login: "alice", Fingerprint: fp, KeyType: kt, Key: k, Enforce: enforce,
				Authorize: func(context.Context, *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
					return denyResp(r), nil
				},
			})
			if code != 0 || out != "" {
				t.Errorf("%s enforce=%v: code = %d stdout = %q, want 0 and nothing", r, enforce, code, out)
			}
		}
	}
}

// No decision (daemon unreachable): nothing printed; exit 0 audit-only, 1 enforce.
func TestSSHAuthzKeys_UnreachableDaemonExitCodeFollowsMode(t *testing.T) {
	fp, kt, k := sshdArgs(t)
	for _, tt := range []struct {
		enforce bool
		want    int
	}{{false, 0}, {true, 1}} {
		out, code := runKeys(t, sshAuthzKeysOptions{
			Login: "alice", Fingerprint: fp, KeyType: kt, Key: k, Enforce: tt.enforce,
			Authorize: func(context.Context, *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
				return nil, errors.New("connection refused")
			},
		})
		if code != tt.want || out != "" {
			t.Errorf("enforce=%v: code = %d stdout = %q, want %d and nothing", tt.enforce, code, out, tt.want)
		}
	}
}

func TestSSHAuthzKeys_RefusesBadInputWithoutAskingTheDaemon(t *testing.T) {
	fp, kt, k := sshdArgs(t)
	otherFP, _, _ := sshdArgs(t)
	for _, tt := range []struct {
		name, fp, kt, k string
	}{
		{"fingerprint of another key", otherFP, kt, k},
		{"unparseable key", fp, kt, "not-base64!"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			asked := false
			out, code := runKeys(t, sshAuthzKeysOptions{
				Login: "alice", Fingerprint: tt.fp, KeyType: tt.kt, Key: tt.k,
				Authorize: func(context.Context, *pb.AuthorizeSSHRequest) (*pb.AuthorizeSSHResponse, error) {
					asked = true
					return allowResp(), nil
				},
			})
			if code != 1 || out != "" || asked {
				t.Fatalf("code = %d stdout = %q asked = %v, want 1, nothing, not asked", code, out, asked)
			}
		})
	}
}

// The real authorizer: POST /v1/ssh/authorize with the token file's JWT.
func TestSSHAuthzKeys_HTTPAuthorizerSendsTokenToDaemon(t *testing.T) {
	var gotAuth, gotPath string
	var gotReq pb.AuthorizeSSHRequest
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.Path
		body, _ := io.ReadAll(r.Body)
		if err := protojson.Unmarshal(body, &gotReq); err != nil {
			t.Errorf("decode request: %v", err)
		}
		b, _ := protojson.Marshal(allowResp())
		_, _ = w.Write(b)
	}))
	defer daemon.Close()

	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("jwt-value\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	fp, kt, k := sshdArgs(t)
	out, code := runKeys(t, sshAuthzKeysOptions{
		Login: "alice", Fingerprint: fp, KeyType: kt, Key: k,
		Authorize: httpSSHAuthorizer(daemon.URL, tokenFile),
	})
	if code != 0 || out != kt+" "+k+"\n" {
		t.Fatalf("code = %d stdout = %q, want the key line", code, out)
	}
	if gotPath != "/v1/ssh/authorize" || gotAuth != "Bearer jwt-value" || gotReq.GetLogin() != "alice" {
		t.Fatalf("path = %q auth = %q login = %q", gotPath, gotAuth, gotReq.GetLogin())
	}
}

// A refused token or a missing token file is "no decision", not a deny.
func TestSSHAuthzKeys_HTTPAuthorizerFailuresAreNoDecision(t *testing.T) {
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"sentinel auth failed","code":401}`, http.StatusUnauthorized)
	}))
	defer refusing.Close()
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("jwt-value"), 0o400); err != nil {
		t.Fatal(err)
	}
	fp, kt, k := sshdArgs(t)
	for name, authz := range map[string]sshAuthorizer{
		"401 from daemon":    httpSSHAuthorizer(refusing.URL, tokenFile),
		"missing token file": httpSSHAuthorizer(refusing.URL, filepath.Join(t.TempDir(), "absent")),
	} {
		out, code := runKeys(t, sshAuthzKeysOptions{
			Login: "alice", Fingerprint: fp, KeyType: kt, Key: k, Enforce: true, Authorize: authz,
		})
		if code != 1 || out != "" {
			t.Errorf("%s: code = %d stdout = %q, want 1 (enforce, no decision) and nothing", name, code, out)
		}
	}
}
