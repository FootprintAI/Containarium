package recipes

import (
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestEmbeddedCatalogLoads(t *testing.T) {
	m := New()
	if err := m.LoadEmbedded(); err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	if len(m.List()) == 0 {
		t.Fatal("embedded catalog is empty")
	}
	for _, id := range []string{"ollama", "llamacpp"} {
		r, err := m.Get(id)
		if err != nil {
			t.Errorf("expected built-in recipe %q: %v", id, err)
			continue
		}
		if r.Image == "" {
			t.Errorf("recipe %q has empty image", id)
		}
		if !r.RequiresGpu {
			t.Errorf("recipe %q expected requires_gpu=true", id)
		}
	}
}

func TestAgentWorkspaceRecipe(t *testing.T) {
	m := New()
	if err := m.LoadEmbedded(); err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	r, err := m.Get("agent-workspace")
	if err != nil {
		t.Fatalf("expected built-in recipe agent-workspace: %v", err)
	}
	if r.RequiresGpu {
		t.Error("agent-workspace should not require a GPU")
	}
	// The exposed port is the in-box auth proxy (:8080), not OpenHands directly.
	if len(r.Ports) != 1 || r.Ports[0].ContainerPort != 8080 {
		t.Errorf("agent-workspace should expose the in-box auth proxy on :8080; got %+v", r.Ports)
	}
	// post_start must run OpenHands Agent Canvas bound to localhost, persist
	// conversations in the box, chown the bind mounts, and stand up the in-box
	// basic-auth proxy (all validated live 2026-06-18).
	joined := strings.Join(r.PostStart, "\n")
	for _, want := range []string{
		"openhands/agent-canvas",
		"/opt/openhands-state", // conversations stored inside the box
		":U",                   // bind mount chowned to the non-root container user
		"127.0.0.1:8000:8000",  // OpenHands not directly reachable
		"caddy hash-password",  // password bcrypt-hashed at deploy
		"basic_auth",           // in-box auth proxy
		"ws_auth=",             // session-cookie handoff for seamless iframe auth
		"SameSite=None",        // cookie sent cross-origin from the embedded iframe
		"/opt/wsauth/token",    // token persisted for the daemon to vend
		"/__ws_login",          // zero-click bootstrap route
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("agent-workspace post_start missing %q", want)
		}
	}
	// The auth password is required (a box is never exposed without it).
	params := map[string]*pb.RecipeParam{}
	for _, p := range r.Parameters {
		params[p.Name] = p
	}
	if pw := params["auth_password"]; pw == nil {
		t.Fatal("agent-workspace should declare an auth_password parameter")
	} else {
		if !pw.Required {
			t.Error("auth_password must be required (box never exposed without auth)")
		}
		if pw.Type != "password" {
			t.Errorf("auth_password type: got %q want password", pw.Type)
		}
	}
	if params["openhands_version"] == nil || params["openhands_version"].Default == "" {
		t.Error("agent-workspace should pin openhands_version to a default tag")
	}
}

func TestOCIServiceRecipe(t *testing.T) {
	m := New()
	if err := m.LoadEmbedded(); err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	r, err := m.Get("oci-service")
	if err != nil {
		t.Fatalf("expected built-in recipe oci-service: %v", err)
	}
	if r.RequiresGpu {
		t.Error("oci-service should not require a GPU")
	}
	// One stable exposed port regardless of what the image listens on.
	if len(r.Ports) != 1 || r.Ports[0].ContainerPort != 8080 {
		t.Errorf("oci-service should expose box port 8080; got %+v", r.Ports)
	}
	// oci_image is the one required parameter; everything else defaults.
	var img *pb.RecipeParam
	for _, p := range r.Parameters {
		if p.Name == "oci_image" {
			img = p
		}
	}
	if img == nil || !img.Required || img.Default != "" {
		t.Errorf("oci_image must be required with no default; got %+v", img)
	}
	if _, err := ResolveParameters(r, map[string]string{}); err == nil {
		t.Error("resolving without oci_image should fail (required)")
	}
	joined := strings.Join(r.PostStart, "\n")
	for _, want := range []string{
		"--restart=always", // survives box reboot and SSH logout
		"--env-file",       // literal env semantics, never bash-sourced
		"--entrypoint",     // command's first token overrides entrypoint
		"CONTAINARIUM_PARAM_OCI_IMAGE",
		"CONTAINARIUM_PARAM_SERVICE_PORT",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("oci-service post_start missing %q", want)
		}
	}
}

func TestRisingWaveRecipe(t *testing.T) {
	m := New()
	if err := m.LoadEmbedded(); err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	r, err := m.Get("risingwave")
	if err != nil {
		t.Fatalf("expected built-in recipe risingwave: %v", err)
	}
	if r.RequiresGpu {
		t.Error("risingwave should not require a GPU")
	}
	// Only the HTTP ports are routed. :4566 is Postgres wire protocol and
	// Caddy is an HTTP reverse proxy, so routing it would produce a URL that
	// no psql can use — it is reached over SSH local-forward instead.
	got := map[int32]string{}
	for _, p := range r.Ports {
		got[p.ContainerPort] = p.Subdomain
	}
	if len(r.Ports) != 2 || got[5691] != "dashboard" || got[4560] != "webhook" {
		t.Errorf("risingwave should route only the dashboard (:5691) and webhook (:4560) ports; got %+v", r.Ports)
	}
	if _, routed := got[4566]; routed {
		t.Error("risingwave must not route :4566 -- pgwire cannot traverse an HTTP reverse proxy")
	}

	joined := strings.Join(r.PostStart, "\n")
	for _, want := range []string{
		"single_node",                // one process, embedded SQLite meta + local-FS state
		"--store-directory",          // v3 flag name; NOT --state-store-directory
		"/var/lib/risingwave",        // persisted on the named volume, not the container layer
		"--listen-addr 0.0.0.0:4566", // a loopback bind makes the published port unreachable
		"-p 4566:4566",               // published on the box for SSH local-forward
		"--restart=always",           // survives box reboot and SSH logout
		"/dev/tcp/127.0.0.1/4566",    // readiness gate: boot failure surfaces at deploy time
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("risingwave post_start missing %q", want)
		}
	}

	// Both tuning parameters are optional -- the recipe must deploy with no
	// --param at all.
	params := map[string]*pb.RecipeParam{}
	for _, p := range r.Parameters {
		params[p.Name] = p
	}
	if params["version"] == nil || params["version"].Default == "" {
		t.Error("risingwave should pin a default version tag")
	}
	for _, name := range []string{"total_memory_bytes", "parallelism"} {
		if p := params[name]; p == nil {
			t.Errorf("risingwave should declare a %q parameter", name)
		} else if p.Required {
			t.Errorf("%q must be optional (auto-detect when empty)", name)
		}
	}
	if _, err := ResolveParameters(r, map[string]string{}); err != nil {
		t.Errorf("risingwave should resolve with no parameters: %v", err)
	}
}

func TestGetUnknown(t *testing.T) {
	m := New()
	_ = m.LoadEmbedded()
	if _, err := m.Get("does-not-exist"); err == nil {
		t.Fatal("expected error for unknown recipe")
	}
}

func TestLoadRejectsMissingImage(t *testing.T) {
	m := New()
	err := m.LoadFromBytes([]byte("recipes:\n  - id: bad\n"))
	if err == nil {
		t.Fatal("expected error for recipe missing image")
	}
}

func TestLoadRejectsDuplicateID(t *testing.T) {
	m := New()
	yaml := "recipes:\n" +
		"  - id: dup\n    image: a\n" +
		"  - id: dup\n    image: b\n"
	if err := m.LoadFromBytes([]byte(yaml)); err == nil {
		t.Fatal("expected duplicate-id error")
	}
}

func TestLoadRejectsBadPort(t *testing.T) {
	m := New()
	yaml := "recipes:\n  - id: x\n    image: a\n    ports:\n      - container_port: 0\n        subdomain: s\n"
	if err := m.LoadFromBytes([]byte(yaml)); err == nil {
		t.Fatal("expected invalid-port error")
	}
}

func TestResolveParametersDefaultsAndRequired(t *testing.T) {
	r := &pb.Recipe{
		Id: "r",
		Parameters: []*pb.RecipeParam{
			{Name: "model", Default: "llama3"},
			{Name: "token", Required: true},
		},
	}

	// Missing required → error.
	if _, err := ResolveParameters(r, map[string]string{}); err == nil {
		t.Fatal("expected error when required parameter missing")
	}

	// Override applied, default kept.
	got, err := ResolveParameters(r, map[string]string{"token": "abc", "model": "qwen"})
	if err != nil {
		t.Fatalf("ResolveParameters: %v", err)
	}
	if got["model"] != "qwen" {
		t.Errorf("model override: got %q want qwen", got["model"])
	}
	if got["token"] != "abc" {
		t.Errorf("token: got %q want abc", got["token"])
	}

	// Default used when override blank.
	got, err = ResolveParameters(r, map[string]string{"token": "abc"})
	if err != nil {
		t.Fatalf("ResolveParameters: %v", err)
	}
	if got["model"] != "llama3" {
		t.Errorf("model default: got %q want llama3", got["model"])
	}
}

func TestParamEnvName(t *testing.T) {
	if got := ParamEnvName("hf_repo"); got != "CONTAINARIUM_PARAM_HF_REPO" {
		t.Errorf("ParamEnvName: got %q", got)
	}
}

// TestMem0Recipe locks the invariants that make the mem0 box safe to expose:
// the memory store never comes up without a Postgres password, telemetry is
// off, and the managed model-gateway (not a key in the box) drives extraction
// and embedding when the daemon brokers models.
func TestMem0Recipe(t *testing.T) {
	m := New()
	if err := m.LoadEmbedded(); err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	r, err := m.Get("mem0")
	if err != nil {
		t.Fatalf("expected built-in recipe mem0: %v", err)
	}
	if r.RequiresGpu {
		t.Error("mem0 should not require a GPU")
	}
	// API on 8000, dashboard on 3000 — the dashboard is optional at deploy but
	// its route is always declared, so enabling it needs no catalog change.
	if len(r.Ports) != 2 || r.Ports[0].ContainerPort != 8000 || r.Ports[1].ContainerPort != 3000 {
		t.Errorf("mem0 should expose 8000 (api) + 3000 (dashboard); got %+v", r.Ports)
	}
	// Memories outlive the container: pgdata and the history log sit on the
	// box volume, not in the image or a podman-managed volume.
	if len(r.Volumes) != 1 || r.Volumes[0].Path != "/var/lib/mem0" {
		t.Errorf("mem0 should persist under /var/lib/mem0; got %+v", r.Volumes)
	}
	// The gateway keeps the real provider key out of the box and meters mem0's
	// own LLM/embedding calls per tenant.
	if r.ModelGatewayProvider != "openai" {
		t.Errorf("mem0 model_gateway_provider: got %q want openai", r.ModelGatewayProvider)
	}
	// postgres_password is the one required parameter — a memory store must
	// never come up with a default credential.
	var pw *pb.RecipeParam
	for _, p := range r.Parameters {
		if p.Name == "postgres_password" {
			pw = p
		}
	}
	if pw == nil || !pw.Required || pw.Default != "" {
		t.Errorf("postgres_password must be required with no default; got %+v", pw)
	}
	if pw != nil && pw.Type != "password" {
		t.Errorf("postgres_password type: got %q want password", pw.Type)
	}
	if _, err := ResolveParameters(r, map[string]string{}); err == nil {
		t.Error("resolving without postgres_password should fail (required)")
	}
	// Every secret-bearing parameter must render masked in a UI.
	for _, name := range []string{"admin_password", "jwt_secret", "openai_api_key"} {
		for _, p := range r.Parameters {
			if p.Name == name && p.Type != "password" {
				t.Errorf("parameter %q type: got %q want password", name, p.Type)
			}
		}
	}
	joined := strings.Join(r.PostStart, "\n")
	for _, want := range []string{
		"--restart=always", // survives box reboot and SSH logout
		"--env-file",       // literal env semantics, never bash-sourced
		"MEM0_TELEMETRY=false",
		"AUTH_DISABLED=false",        // the API is publicly routed; auth stays on
		"listen_addresses=127.0.0.1", // Postgres never reaches the box's routable iface
		"alembic upgrade head",       // the image runs no migrations on its own
		"CONTAINARIUM_MODEL_GATEWAY_URL",
		"CONTAINARIUM_GATEWAY_TOKEN",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("mem0 post_start missing %q", want)
		}
	}
	// Upstream's CMD is a dev server (uvicorn --reload over a bind-mounted
	// source tree). The recipe must override it, never inherit it.
	if strings.Contains(joined, "--reload") {
		t.Error("mem0 post_start must not run uvicorn --reload (upstream's dev CMD)")
	}
	// The arm64-only published image would silently fail to run on an amd64
	// host; the recipe builds from source instead.
	if strings.Contains(joined, "mem0/mem0-api-server") {
		t.Error("mem0 must build from source, not pull the arm64-only published image")
	}
	// Regression: upstream's init-db.sh creates mem0_app with psql's \gexec,
	// which is a META-command — honoured only on stdin (their heredoc). Passed
	// through `psql -c` it is sent as literal SQL and fails with a syntax
	// error, which a live deploy caught. Keep the check-then-create form.
	if strings.Contains(joined, "gexec") {
		t.Error("mem0 post_start must not use psql \\gexec (a meta-command; invalid via psql -c)")
	}
	// Regression: upstream pins the pure-Python `psycopg` but builds on
	// python:3.12-slim, which has no libpq — the image builds clean and then
	// crash-loops on "no pq wrapper available". A live deploy caught this.
	if !strings.Contains(joined, "psycopg[binary]") {
		t.Error("mem0 build must add psycopg[binary]; upstream's slim base ships no libpq")
	}
	// Regression: mem0 validates admin_email with pydantic's EmailStr, which
	// rejects RFC 6761 special-use domains outright. A default in one of them
	// 422s at the seeding step and fails the whole deploy.
	var email *pb.RecipeParam
	for _, p := range r.Parameters {
		if p.Name == "admin_email" {
			email = p
		}
	}
	if email == nil {
		t.Fatal("mem0 must declare admin_email")
	}
	for _, reserved := range []string{".local", ".localhost", ".invalid", ".test", ".example"} {
		if strings.HasSuffix(email.Default, reserved) {
			t.Errorf("admin_email default %q uses reserved domain %q; EmailStr rejects it with 422", email.Default, reserved)
		}
	}
}
