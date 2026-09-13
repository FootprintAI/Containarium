// Command model-gateway is the agent model gateway
// (docs/AGENT-MODEL-GATEWAY-DESIGN.md): a credential proxy that can run
// standalone, without the LXC daemon. It holds the real provider API keys and
// brokers every agent box's model calls so a key never lives in a box: a box
// presents a short-lived, scoped gateway token; the gateway validates it,
// injects the real key, proxies to the provider, and meters token usage per
// tenant. An operator can revoke an issued token on request (#1820).
//
//	model-gateway serve  --secret-file /etc/containarium/jwt.secret [--admin-token-file ...]   (keys from env)
//	model-gateway mint   --secret-file ... --tenant T --provider gemini [--skill S] [--allowed-models a,b] [--ttl 1h] [--print-jti]
//	model-gateway revoke --admin-url http://host:8866 --admin-token-file ... --jti <jti>
//
// `mint` stands in for the daemon's provisionSkillBox, which mints the same
// token alongside the platform JWT in production. `revoke` stands in for the
// daemon driving the same admin endpoint through its own revocation store
// (runlease.End) once a run finishes.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/modelgateway"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "mint":
		mint(os.Args[2:])
	case "revoke":
		revoke(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: model-gateway <serve|mint|revoke> [flags]")
	os.Exit(2)
}

func readSecret(path string) []byte {
	b, err := os.ReadFile(path) // #nosec G304 — path is an operator-supplied CLI flag, not user input
	if err != nil {
		log.Fatalf("read secret %s: %v", path, err)
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		log.Fatalf("secret file %s is empty", path)
	}
	return []byte(s)
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8866", "listen address")
	secretFile := fs.String("secret-file", "/etc/containarium/jwt.secret", "shared HMAC secret (the daemon's jwt.secret)")
	adminTokenFile := fs.String("admin-token-file", "", "path to the admin bearer token; when set, enables POST /__gateway/revoke (empty = revoke disabled)")
	_ = fs.Parse(args)

	secret := readSecret(*secretFile)
	providers := modelgateway.DefaultProviders()

	// The gateway holds the REAL provider keys (read from its OWN env, never a
	// box). A provider with no key in env is simply not served.
	keys := map[string]string{}
	loaded := []string{}
	for name, p := range providers {
		if k := os.Getenv(p.KeyEnv); k != "" {
			keys[name] = k
			loaded = append(loaded, name)
		}
	}
	if len(keys) == 0 {
		log.Fatal("no provider keys in env — set one of ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY")
	}

	cfg := modelgateway.Config{
		Secret:       secret,
		Providers:    providers,
		ProviderKeys: keys,
		// This binary has no Postgres store of its own; a daemon wires the
		// same PgRevocationStore it uses for platform JWTs instead (see
		// internal/modelgateway/revocation.go). MemRevocations is always
		// wired here so isRevoked() has something to consult regardless of
		// whether --admin-token-file is set, since a caller could still wire
		// a token minted with a jti that was revoked through another route.
		Revocations: modelgateway.NewMemRevocations(),
	}
	adminNote := "revoke disabled (no --admin-token-file)"
	if *adminTokenFile != "" {
		cfg.AdminToken = string(readSecret(*adminTokenFile))
		adminNote = "revoke enabled at POST /__gateway/revoke"
	}

	gw := modelgateway.New(cfg)
	log.Printf("model-gateway: listening on %s, providers=%s (provider keys held in the gateway only), %s",
		*addr, strings.Join(loaded, ","), adminNote)
	srv := &http.Server{
		Addr:         *addr,
		Handler:      gw.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second, // model calls can take tens of seconds
		IdleTimeout:  60 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

func mint(args []string) {
	fs := flag.NewFlagSet("mint", flag.ExitOnError)
	secretFile := fs.String("secret-file", "/etc/containarium/jwt.secret", "shared HMAC secret")
	tenant := fs.String("tenant", "", "tenant id (required)")
	skill := fs.String("skill", "", "skill id")
	run := fs.String("run", "", "run id")
	provider := fs.String("provider", "", "provider: anthropic|openai|gemini (required)")
	models := fs.String("allowed-models", "", "comma-separated allowed model ids (empty = any)")
	ttl := fs.Duration("ttl", time.Hour, "token lifetime")
	printJTI := fs.Bool("print-jti", false, "also print the minted jti, to stderr, so `revoke --jti` has something to revoke without re-parsing the token")
	_ = fs.Parse(args)
	if *tenant == "" || *provider == "" {
		log.Fatal("mint: --tenant and --provider are required")
	}
	var allowed []string
	if *models != "" {
		allowed = strings.Split(*models, ",")
	}
	tok, id, err := modelgateway.MintTokenWithID(readSecret(*secretFile), modelgateway.GatewayClaims{
		Tenant:        *tenant,
		SkillID:       *skill,
		RunID:         *run,
		Provider:      *provider,
		AllowedModels: allowed,
	}, *ttl)
	if err != nil {
		log.Fatalf("mint: %v", err)
	}
	// Token stays the only thing on stdout, unchanged, so existing scripts
	// piping `model-gateway mint ... > token.txt` see no difference.
	fmt.Println(tok)
	if *printJTI {
		fmt.Fprintln(os.Stderr, "jti:", id.JTI)
	}
}

// revoke calls a running gateway's POST /__gateway/revoke, standing in for
// the daemon's own revoke path (runlease.End against the same store the
// gateway consults). Requires --jti; --expires-at defaults to a generous
// window since the caller usually doesn't have the original token's exact
// expiry at hand — the value only controls how long MemRevocations keeps the
// entry before its own sweep drops it, not how long the revocation is
// honored (a jti stays revoked from the moment this call succeeds).
func revoke(args []string) {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	adminURL := fs.String("admin-url", "http://127.0.0.1:8866", "base URL of the running gateway")
	adminTokenFile := fs.String("admin-token-file", "/etc/containarium/gateway-admin.token", "path to the admin bearer token")
	jti := fs.String("jti", "", "jti to revoke (required)")
	expiresAt := fs.String("expires-at", "", "RFC3339 expiry to record for the revocation (default: now+24h)")
	reason := fs.String("reason", "operator revoke", "reason recorded with the revocation")
	_ = fs.Parse(args)
	if *jti == "" {
		log.Fatal("revoke: --jti is required")
	}

	exp := *expiresAt
	if exp == "" {
		exp = time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	}

	body, err := json.Marshal(modelgateway.RevokeRequest{JTI: *jti, ExpiresAt: exp, Reason: *reason})
	if err != nil {
		log.Fatalf("revoke: %v", err)
	}

	url := strings.TrimRight(*adminURL, "/") + "/__gateway/revoke"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Fatalf("revoke: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+string(readSecret(*adminTokenFile)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("revoke: request to %s failed: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		log.Fatalf("revoke: gateway returned %d: %s", resp.StatusCode, b)
	}
	fmt.Printf("revoked %s\n", *jti)
}
