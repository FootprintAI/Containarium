package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `containarium gateway` flag validation (#1726). The request builders are pure,
// so every "the flags must not produce this request" rule is a table row rather
// than a manual CLI run.

func TestBuildSetTenantProviderKeyRequest(t *testing.T) {
	tests := []struct {
		name     string
		keyOwner string
		provider string
		key      string
		wantErr  bool
		want     *pb.SetTenantProviderKeyRequest
	}{
		{
			name: "user owner", keyOwner: "user:alice", provider: "kafeido", key: "sk-1",
			want: &pb.SetTenantProviderKeyRequest{KeyOwner: "user:alice", Provider: pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO, ApiKey: "sk-1"},
		},
		{
			name: "org owner", keyOwner: "org:0b1c", provider: "gemini-openai", key: "sk-2",
			want: &pb.SetTenantProviderKeyRequest{KeyOwner: "org:0b1c", Provider: pb.GatewayProvider_GATEWAY_PROVIDER_GEMINI_OPENAI, ApiKey: "sk-2"},
		},
		{name: "missing provider", keyOwner: "user:alice", key: "sk-1", wantErr: true},
		{name: "unknown provider", keyOwner: "user:alice", provider: "nope", key: "sk-1", wantErr: true},
		{name: "missing key owner", provider: "kafeido", key: "sk-1", wantErr: true},
		{name: "blank key owner", keyOwner: "   ", provider: "kafeido", key: "sk-1", wantErr: true},
		{name: "missing key", keyOwner: "user:alice", provider: "kafeido", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildSetTenantProviderKeyRequest(tt.keyOwner, tt.provider, tt.key)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want an error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.GetKeyOwner() != tt.want.GetKeyOwner() || got.GetProvider() != tt.want.GetProvider() || got.GetApiKey() != tt.want.GetApiKey() {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestBuildMintGatewayTokenRequest(t *testing.T) {
	tests := []struct {
		name     string
		box      string
		provider string
		runID    string
		ttl      string
		models   []string
		dryRun   bool
		wantErr  bool
		wantTTL  time.Duration
	}{
		{name: "minimal", box: "alice", provider: "kafeido"},
		{name: "full", box: "alice", provider: "kafeido", runID: "run-42", ttl: "2h", models: []string{"m-small"}, wantTTL: 2 * time.Hour},
		{name: "dry run", box: "alice", provider: "kafeido", dryRun: true},
		{name: "ttl whitespace is ignored", box: "alice", provider: "kafeido", ttl: "   "},
		{name: "missing box", provider: "kafeido", wantErr: true},
		{name: "missing provider", box: "alice", wantErr: true},
		{name: "unknown provider", box: "alice", provider: "nope", wantErr: true},
		{name: "ttl is not a duration", box: "alice", provider: "kafeido", ttl: "24", wantErr: true},
		{name: "ttl in an unsupported unit", box: "alice", provider: "kafeido", ttl: "2 days", wantErr: true},
		{name: "zero ttl", box: "alice", provider: "kafeido", ttl: "0s", wantErr: true},
		{name: "negative ttl", box: "alice", provider: "kafeido", ttl: "-1h", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildMintGatewayTokenRequest(tt.box, tt.provider, tt.runID, tt.ttl, tt.models, tt.dryRun)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want an error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.GetBox() != tt.box || got.GetRunId() != tt.runID || got.GetDryRun() != tt.dryRun {
				t.Errorf("got %+v", got)
			}
			if tt.wantTTL == 0 {
				if got.GetTtl() != nil {
					t.Errorf("ttl = %v, want unset so the server applies its default", got.GetTtl().AsDuration())
				}
			} else if got.GetTtl().AsDuration() != tt.wantTTL {
				t.Errorf("ttl = %v, want %v", got.GetTtl().AsDuration(), tt.wantTTL)
			}
		})
	}
}

// The CLI must not try to enforce the TTL cap itself — the cap is the server's,
// and a client-side copy of it would drift and would be bypassable anyway.
func TestBuildMintGatewayTokenRequest_DoesNotCapTTLLocally(t *testing.T) {
	got, err := buildMintGatewayTokenRequest("alice", "kafeido", "", "720h", nil, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.GetTtl().AsDuration() != 720*time.Hour {
		t.Errorf("ttl = %v, want the request passed through unchanged (the server caps it)", got.GetTtl().AsDuration())
	}
}

func TestBuildListGatewayModelsRequest(t *testing.T) {
	if _, err := buildListGatewayModelsRequest("", ""); err == nil {
		t.Error("want an error without --provider")
	}
	got, err := buildListGatewayModelsRequest("kafeido", "alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.GetProvider() != pb.GatewayProvider_GATEWAY_PROVIDER_KAFEIDO || got.GetBox() != "alice" {
		t.Errorf("got %+v", got)
	}
	// No --box means "my own owner", which the server resolves; the CLI must not
	// guess a box name.
	bare, err := buildListGatewayModelsRequest("kafeido", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bare.GetBox() != "" {
		t.Errorf("box = %q, want empty", bare.GetBox())
	}
}

func TestReadGatewayKeyMaterial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.txt")
	if err := os.WriteFile(path, []byte("  sk-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("--key is used as given", func(t *testing.T) {
		got, err := readGatewayKeyMaterial("sk-inline", "")
		if err != nil || got != "sk-inline" {
			t.Errorf("got %q, %v", got, err)
		}
	})

	t.Run("--key-file is read and trimmed", func(t *testing.T) {
		got, err := readGatewayKeyMaterial("", path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "sk-from-file" {
			t.Errorf("got %q, want the trailing newline and padding stripped", got)
		}
	})

	t.Run("both is an error, not a silent winner", func(t *testing.T) {
		if _, err := readGatewayKeyMaterial("sk-inline", path); err == nil {
			t.Error("want an error when both --key and --key-file are passed")
		}
	})

	t.Run("a missing file is an error", func(t *testing.T) {
		if _, err := readGatewayKeyMaterial("", filepath.Join(dir, "nope")); err == nil {
			t.Error("want an error for an unreadable --key-file")
		}
	})

	t.Run("neither yields the empty key, which the builder rejects", func(t *testing.T) {
		got, err := readGatewayKeyMaterial("", "")
		if err != nil || got != "" {
			t.Fatalf("got %q, %v", got, err)
		}
		if _, berr := buildSetTenantProviderKeyRequest("user:alice", "kafeido", got); berr == nil {
			t.Error("an empty key must not build a request")
		}
	})
}

// TestFormatMintGatewayTokenResult_DryRunNeverPrintsAToken is the output-side
// half of the dry-run rule: even if a server ever returned one, the dry-run
// rendering must not put a credential on the operator's terminal or into a
// redirected gateway.env.
func TestFormatMintGatewayTokenResult_DryRunNeverPrintsAToken(t *testing.T) {
	resp := &pb.MintGatewayTokenResponse{
		Token:    "eyJ.should.not.appear",
		BaseUrl:  "http://10.0.0.1:8080/v1/model/kafeido",
		KeyOwner: "user:alice",
		TokenId:  "deadbeef",
	}
	for _, asEnv := range []bool{false, true} {
		out := formatMintGatewayTokenResult(resp, true, asEnv)
		if stringsContains(out, "eyJ.should.not.appear") {
			t.Errorf("dry-run output (env=%v) printed the token: %s", asEnv, out)
		}
		if !stringsContains(out, "dry run") {
			t.Errorf("dry-run output (env=%v) does not say it was a dry run: %s", asEnv, out)
		}
	}
}

func TestFormatMintGatewayTokenResult_EnvIsTheGatewayEnvContract(t *testing.T) {
	resp := &pb.MintGatewayTokenResponse{
		Token:    "eyJ.a.b",
		BaseUrl:  "http://10.0.0.1:8080/v1/model/kafeido",
		KeyOwner: "user:alice",
		TokenId:  "deadbeef",
	}
	out := formatMintGatewayTokenResult(resp, false, true)
	want := "export CONTAINARIUM_MODEL_GATEWAY_URL=http://10.0.0.1:8080/v1/model/kafeido\n" +
		"export CONTAINARIUM_GATEWAY_TOKEN=eyJ.a.b\n"
	if out != want {
		t.Errorf("--env output =\n%q\nwant\n%q", out, want)
	}
}

func TestFormatMintGatewayTokenResult_SummaryNamesTheRevokeVerb(t *testing.T) {
	resp := &pb.MintGatewayTokenResponse{Token: "eyJ.a.b", TokenId: "deadbeef", KeyOwner: "user:alice"}
	out := formatMintGatewayTokenResult(resp, false, false)
	if !stringsContains(out, "containarium token revoke --jti deadbeef") {
		t.Errorf("summary should tell the operator how to revoke this exact token:\n%s", out)
	}
}

func stringsContains(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
