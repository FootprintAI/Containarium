package modelgateway

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
)

// UsageSink receives every metered model call so token usage can be forwarded
// to a durable/billing plane, in ADDITION to the in-memory Meter (which backs
// /__gateway/usage). The daemon wires an OTLP sink that emits per-tenant counters
// into the metrics pipeline (→ VictoriaMetrics → billing); standalone/test runs
// leave it nil. Kept an interface here so modelgateway stays free of an OTel
// dependency (the design's "metering plane writer", decoupled).
type UsageSink interface {
	RecordUsage(tenant, skill, provider string, u Usage)
}

// Config configures a Gateway.
type Config struct {
	Secret       []byte               // shared HMAC secret (the daemon's jwt.secret)
	Providers    map[string]*Provider // provider registry (see DefaultProviders)
	ProviderKeys map[string]string    // provider name -> REAL API key, held here only
	Sink         UsageSink            // optional: durable/billing usage writer (nil = in-memory only)
	Logger       *log.Logger
}

// Gateway brokers every agent box's model calls: it authenticates the box's
// scoped gateway token, injects the real provider key (which never leaves the
// gateway), proxies to the provider, and meters per-tenant token usage.
type Gateway struct {
	cfg   Config
	meter *Meter
}

// New builds a Gateway.
func New(cfg Config) *Gateway {
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	return &Gateway{cfg: cfg, meter: NewMeter()}
}

// Meter exposes the usage rollups (for tests / the usage endpoint).
func (g *Gateway) Meter() *Meter { return g.meter }

const modelPrefix = "/v1/model/"

// Handler returns the gateway's HTTP mux: the model data plane plus a usage
// readout and a health check.
func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(modelPrefix, g.handleModel)
	mux.HandleFunc("/__gateway/usage", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(g.meter.Snapshot())
	})
	mux.HandleFunc("/__gateway/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

// bearer pulls the gateway token from the request, accepting the three shapes
// the provider SDKs use when pointed at a proxy base URL: Authorization Bearer
// (Anthropic ANTHROPIC_AUTH_TOKEN / OpenAI), x-api-key (Anthropic raw), and
// x-goog-api-key (Gemini).
func bearer(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	if v := r.Header.Get("x-api-key"); v != "" {
		return v
	}
	if v := r.Header.Get("x-goog-api-key"); v != "" {
		return v
	}
	return ""
}

func (g *Gateway) handleModel(w http.ResponseWriter, r *http.Request) {
	// path: /v1/model/<provider>/<upstream path...>
	rest := strings.TrimPrefix(r.URL.Path, modelPrefix)
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		http.Error(w, "missing provider in path", http.StatusNotFound)
		return
	}
	provName := rest[:slash]
	upstreamPath := rest[slash:] // includes leading '/'
	prov := g.cfg.Providers[provName]
	if prov == nil {
		http.Error(w, "unknown provider: "+provName, http.StatusNotFound)
		return
	}

	tok := bearer(r)
	if tok == "" {
		http.Error(w, "missing gateway token", http.StatusUnauthorized)
		return
	}
	claims, err := VerifyToken(g.cfg.Secret, tok)
	if err != nil {
		http.Error(w, "invalid gateway token: "+err.Error(), http.StatusUnauthorized)
		return
	}
	if claims.Provider != provName {
		http.Error(w, "token not valid for provider "+provName, http.StatusForbidden)
		return
	}

	key := g.cfg.ProviderKeys[provName]
	if key == "" {
		http.Error(w, "gateway holds no key for provider "+provName, http.StatusBadGateway)
		return
	}

	// Model ceiling (basic tiering): for Gemini the model is in the path, so we
	// can enforce the token's allowed-model set before proxying.
	pathModel := ""
	if provName == "gemini" {
		pathModel = geminiModelFromPath(upstreamPath)
	}
	if len(claims.AllowedModels) > 0 && pathModel != "" && !contains(claims.AllowedModels, pathModel) {
		http.Error(w, "model not allowed by token: "+pathModel, http.StatusForbidden)
		return
	}

	upstream, err := url.Parse(prov.UpstreamURL)
	if err != nil {
		http.Error(w, "bad upstream url", http.StatusInternalServerError)
		return
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = upstream.Scheme
			req.URL.Host = upstream.Host
			req.Host = upstream.Host
			req.URL.Path = upstreamPath
			prov.inject(req.Header, key) // strip gateway token, inject real key
		},
		ModifyResponse: func(resp *http.Response) error {
			// Metering (Phase 1): best-effort on non-streaming, uncompressed
			// JSON. Streaming (SSE) and compressed bodies pass through
			// unmetered in the prototype.
			if resp.Header.Get("Content-Encoding") != "" {
				return nil
			}
			if !strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
				return nil
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				return err
			}
			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
			resp.Header.Set("Content-Length", strconv.Itoa(len(body)))

			var decoded map[string]any
			if json.Unmarshal(body, &decoded) == nil {
				u := prov.parseUsage(decoded, pathModel)
				g.meter.record(claims.Tenant, claims.SkillID, provName, u)
				if g.cfg.Sink != nil {
					g.cfg.Sink.RecordUsage(claims.Tenant, claims.SkillID, provName, u)
				}
				g.cfg.Logger.Printf("model-gateway: tenant=%s skill=%s provider=%s model=%s in=%d out=%d cached=%d",
					claims.Tenant, claims.SkillID, provName, u.Model, u.InputTokens, u.OutputTokens, u.CachedTokens)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		},
	}
	proxy.ServeHTTP(w, r)
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
