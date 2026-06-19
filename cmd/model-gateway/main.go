// Command model-gateway is a prototype of the agent model gateway
// (docs/AGENT-MODEL-GATEWAY-DESIGN.md). It holds the real provider API keys and
// brokers every agent box's model calls so a key never lives in a box: a box
// presents a short-lived, scoped gateway token; the gateway validates it,
// injects the real key, proxies to the provider, and meters token usage per
// tenant.
//
//	model-gateway serve  --secret-file /etc/containarium/jwt.secret   (keys from env)
//	model-gateway mint   --secret-file ... --tenant T --provider gemini [--skill S] [--allowed-models a,b] [--ttl 1h]
//
// `mint` stands in for the daemon's provisionSkillBox, which mints the same
// token alongside the platform JWT in production.
package main

import (
	"flag"
	"fmt"
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
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: model-gateway <serve|mint> [flags]")
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

	gw := modelgateway.New(modelgateway.Config{Secret: secret, Providers: providers, ProviderKeys: keys})
	log.Printf("model-gateway: listening on %s, providers=%s (provider keys held in the gateway only)", *addr, strings.Join(loaded, ","))
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
	_ = fs.Parse(args)
	if *tenant == "" || *provider == "" {
		log.Fatal("mint: --tenant and --provider are required")
	}
	var allowed []string
	if *models != "" {
		allowed = strings.Split(*models, ",")
	}
	tok, err := modelgateway.MintToken(readSecret(*secretFile), modelgateway.GatewayClaims{
		Tenant:        *tenant,
		SkillID:       *skill,
		RunID:         *run,
		Provider:      *provider,
		AllowedModels: allowed,
	}, *ttl)
	if err != nil {
		log.Fatalf("mint: %v", err)
	}
	fmt.Println(tok)
}
