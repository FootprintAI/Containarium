package modelgateway

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"math"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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
	// OutputFilter enables prompt-exfiltration redaction on the streaming chat
	// path (a hold-back window over the assistant text; #670 layer 2). Streaming
	// token metering is independent and always on. Fail-open regardless.
	OutputFilter bool

	// Revocations is the kill-switch for issued gateway tokens (see
	// revocation.go). Nil disables the check, which is the pre-existing
	// behavior — a standalone daemon with no Postgres has no revocation store
	// to consult. Production wires the same store used for platform JWTs.
	Revocations RevocationChecker

	// Policy configures per-tenant quota enforcement and the graduated response
	// ladder (see policy.go). Nil leaves the gateway metering-only: every tenant
	// stays in StateObserve and nothing is ever denied, which is the behavior
	// every existing deployment already has.
	Policy *PolicyConfig
}

// Gateway brokers every agent box's model calls: it authenticates the box's
// scoped gateway token, injects the real provider key (which never leaves the
// gateway), proxies to the provider, and meters per-tenant token usage.
type Gateway struct {
	cfg    Config
	meter  *Meter
	policy *Policy

	// Request-lifecycle observability: a monotonic request id, a live
	// in-flight gauge, and lifetime completed/failed counters. These make
	// "did the gateway finish this request or is it still running/hung?"
	// answerable — from the START/END log pair per request and the live
	// counts on /__gateway/status.
	reqSeq    atomic.Uint64
	inflight  atomic.Int64
	completed atomic.Uint64
	failed    atomic.Uint64
}

// New builds a Gateway.
func New(cfg Config) *Gateway {
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	pc := PolicyConfig{}
	if cfg.Policy != nil {
		pc = *cfg.Policy
	}
	return &Gateway{cfg: cfg, meter: NewMeter(), policy: NewPolicy(pc)}
}

// Meter exposes the usage rollups (for tests / the usage endpoint).
func (g *Gateway) Meter() *Meter { return g.meter }

// Policy exposes the enforcement ladder so the daemon can drive the operator
// verbs (revoke / clear) and read tenant state.
func (g *Gateway) Policy() *Policy { return g.policy }

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
	// Per-tenant enforcement state: which rung each tenant is on, what put it
	// there, and its consumption against budget. The readout an operator needs
	// before deciding whether a throttled tenant is a runaway or a false
	// positive.
	mux.HandleFunc("/__gateway/policy", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(g.policy.Status())
	})
	mux.HandleFunc("/__gateway/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	// Live request-lifecycle gauge: how many model calls are in flight right
	// now, and how many have completed/failed over the gateway's lifetime.
	// `inflight` stuck above zero with no new completions is the "hung request"
	// signal the per-request START/END logs let you drill into.
	mux.HandleFunc("/__gateway/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"inflight":  g.inflight.Load(),
			"completed": g.completed.Load(),
			"failed":    g.failed.Load(),
		})
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
		// A token presented against a provider it isn't scoped for is a probe,
		// not a misconfiguration — the box is seeded with exactly one base URL.
		// Recorded so the auth-failure-ratio signal can see it.
		g.policy.RecordDenial(claims.Tenant)
		http.Error(w, "token not valid for provider "+provName, http.StatusForbidden)
		return
	}

	// Kill-switch. Deliberately ahead of the key lookup and the Director, so a
	// revoked token never causes the real provider key to be touched.
	if g.isRevoked(r.Context(), claims.ID) {
		g.cfg.Logger.Printf("model-gateway: REVOKED tenant=%s skill=%s provider=%s jti=%s",
			claims.Tenant, claims.SkillID, provName, claims.ID)
		http.Error(w, "gateway token revoked", http.StatusUnauthorized)
		return
	}

	key := g.cfg.ProviderKeys[provName]
	if key == "" {
		http.Error(w, "gateway holds no key for provider "+provName, http.StatusBadGateway)
		return
	}

	// pathModel: for Gemini the model is in the URL path. Other providers
	// carry it in the request body (reqModel, extracted below) — pathModel
	// stays "" for them and is only ever a fallback for logModel.
	pathModel := ""
	if provName == "gemini" {
		pathModel = geminiModelFromPath(upstreamPath)
	}

	upstream, err := url.Parse(prov.UpstreamURL)
	if err != nil {
		http.Error(w, "bad upstream url", http.StatusInternalServerError)
		return
	}

	// For OpenAI-shaped providers, buffer the request body so we can (a) extract
	// the system prompt (skill persona) for streaming output-filtering and (b)
	// enable a final usage event so the SSE path is metered. Fail-open: any read
	// error leaves the original body in place.
	sysPrompt, reqModel := "", ""
	// Anthropic carries the model in the request body and nowhere else — not in
	// the path like Gemini, and it isn't OpenAI-shaped so it misses the branch
	// below. Without this the model-switch signal is silent for the provider
	// that skill boxes are provisioned for by default, and the lifecycle logs
	// report an empty model for it. Read-only: no body rewriting, since
	// ensureStreamUsage and extractSystemPrompt are OpenAI shapes.
	if provName == "anthropic" {
		if raw, rerr := io.ReadAll(r.Body); rerr == nil {
			_ = r.Body.Close()
			reqModel = requestModel(raw)
			r.Body = io.NopCloser(bytes.NewReader(raw))
			r.ContentLength = int64(len(raw))
			r.Header.Set("Content-Length", strconv.Itoa(len(raw)))
		}
	}
	if provName == "openai" || provName == "gemini-openai" {
		if raw, rerr := io.ReadAll(r.Body); rerr == nil {
			_ = r.Body.Close()
			sysPrompt = extractSystemPrompt(raw)
			reqModel = requestModel(raw)
			body, _ := ensureStreamUsage(raw)
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
			r.Header.Set("Content-Length", strconv.Itoa(len(body)))
		}
	}
	if !g.cfg.OutputFilter {
		sysPrompt = "" // redaction disabled → meter-only (filterSSEStream skips it)
	}

	logModel := reqModel
	if logModel == "" {
		logModel = pathModel
	}

	// Model ceiling (basic tiering), enforced against whichever model was
	// actually resolved — never just pathModel. The original gate only
	// ever compared AllowedModels to pathModel, which only Gemini sets;
	// Anthropic, OpenAI, and Gemini-OpenAI all carry their model in the
	// body (reqModel, above) and got a free pass regardless of what the
	// token was scoped to. A request whose model this gateway couldn't
	// resolve at all (logModel == "") is refused open when the token is
	// scoped, rather than treated as ceiling-exempt: an unresolvable
	// model is exactly the case a restricted token must not get a bypass
	// from.
	if len(claims.AllowedModels) > 0 && !contains(claims.AllowedModels, logModel) {
		g.policy.RecordDenial(claims.Tenant)
		http.Error(w, "model not allowed by token: "+logModel, http.StatusForbidden)
		return
	}

	// Enforcement ladder. Deliberately the last gate before proxying: a denied
	// request never reaches the Director, so the real provider key is never
	// injected and never leaves the gateway on a call we refused.
	if dec := g.policy.Check(RequestInfo{
		Tenant:     claims.Tenant,
		Skill:      claims.SkillID,
		Provider:   provName,
		Model:      logModel,
		Endpoint:   upstreamPath,
		RemoteAddr: r.RemoteAddr,
	}); !dec.Allow {
		if dec.RetryAfter > 0 {
			// Round UP, and floor at 1. Truncating 59.4s to 59 tells a
			// well-behaved client to come back while the circuit is still
			// open, so it gets denied again — and a Retry-After of 0 invites
			// an immediate retry, which is the opposite of a throttle.
			secs := int(math.Ceil(dec.RetryAfter.Seconds()))
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(secs))
		}
		g.cfg.Logger.Printf("model-gateway: DENY tenant=%s skill=%s provider=%s model=%s state=%s reason=%q",
			claims.Tenant, claims.SkillID, provName, logModel, dec.State, dec.Reason)
		http.Error(w, "model gateway: "+dec.Reason, dec.Status)
		return
	}
	// Request-lifecycle capture, read after ServeHTTP returns. Mutex-guarded
	// because the streaming usage callback runs in filterSSEStream's goroutine
	// (the non-streaming path sets them inline in ModifyResponse).
	var (
		mu       sync.Mutex
		streamed bool
		metered  bool
		lastU    Usage
	)
	markStreamed := func() { mu.Lock(); streamed = true; mu.Unlock() }
	captureUsage := func(u Usage) { mu.Lock(); metered = true; lastU = u; mu.Unlock() }

	proxy := &httputil.ReverseProxy{
		// Flush streamed (SSE) responses promptly so chat tokens aren't buffered.
		FlushInterval: -1,
		Director: func(req *http.Request) {
			req.URL.Scheme = upstream.Scheme
			req.URL.Host = upstream.Host
			req.Host = upstream.Host
			req.URL.Path = upstreamPath
			prov.inject(req.Header, key) // strip gateway token, inject real key
			// Drop the client's Accept-Encoding so the upstream returns identity
			// (and Go's transport transparently decompresses any gzip). Otherwise a
			// client that asks for gzip (e.g. LibreChat/undici) makes the provider
			// gzip the SSE stream, and the streaming filter below reads raw
			// compressed bytes as text — corrupting tool_call chunks so the agent
			// client gets garbage and aborts ("terminated"). The non-streaming path
			// already skips compressed bodies; this keeps the streaming path safe.
			req.Header.Del("Accept-Encoding")
		},
		ModifyResponse: func(resp *http.Response) error {
			// Streaming (SSE): intercept to meter usage + redact prompt leakage.
			if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
				meterModel := reqModel
				if meterModel == "" {
					meterModel = pathModel
				}
				markStreamed()
				onUsage := func(u Usage) {
					if u.Model == "" {
						u.Model = meterModel
					}
					g.meter.record(claims.Tenant, claims.SkillID, provName, u)
					g.policy.RecordUsage(claims.Tenant, u)
					if g.cfg.Sink != nil {
						g.cfg.Sink.RecordUsage(claims.Tenant, claims.SkillID, provName, u)
					}
					captureUsage(u) // folded into the END lifecycle log
				}
				pr, pw := io.Pipe()
				go filterSSEStream(pw, resp.Body, sysPrompt,
					func(b map[string]any) Usage { return prov.parseUsage(b, meterModel) }, onUsage)
				resp.Body = pr
				resp.Header.Del("Content-Length")
				resp.ContentLength = -1
				return nil
			}
			// Metering on non-streaming, uncompressed JSON. Compressed bodies
			// pass through unmetered.
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
				g.policy.RecordUsage(claims.Tenant, u)
				if g.cfg.Sink != nil {
					g.cfg.Sink.RecordUsage(claims.Tenant, claims.SkillID, provName, u)
				}
				captureUsage(u) // folded into the END lifecycle log

				// Normalize Gemini's non-conformant tool-call finish_reason
				// ("stop" -> "tool_calls") on the OpenAI-shaped surface, so an
				// agent client runs the tool instead of hanging. Only rewrites
				// when a tool call is actually present; normal responses untouched.
				if (provName == "openai" || provName == "gemini-openai") && normalizeNonStreamToolFinish(decoded) {
					if nb, merr := json.Marshal(decoded); merr == nil {
						resp.Body = io.NopCloser(bytes.NewReader(nb))
						resp.ContentLength = int64(len(nb))
						resp.Header.Set("Content-Length", strconv.Itoa(len(nb)))
					}
				}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		},
	}

	// --- request lifecycle: START → serve → END ---
	// Every accepted request gets a START and a matching END line keyed by a
	// monotonic req id, plus the live inflight gauge. For a streaming response
	// ServeHTTP blocks until the piped SSE stream is fully drained, so END marks
	// the true end of generation — turning "is it done or hung?" into a fact.
	reqID := g.reqSeq.Add(1)
	start := time.Now()
	inflight := g.inflight.Add(1)
	g.cfg.Logger.Printf("model-gateway: req=%d START tenant=%s skill=%s provider=%s model=%s inflight=%d",
		reqID, claims.Tenant, claims.SkillID, provName, logModel, inflight)

	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	proxy.ServeHTTP(sw, r)

	mu.Lock()
	st, md, lu := streamed, metered, lastU
	mu.Unlock()
	dur := time.Since(start)
	status := "ok"
	if sw.status >= 400 {
		status = "error"
		g.failed.Add(1)
	} else {
		g.completed.Add(1)
	}
	warn := ""
	if st && !md {
		// A streaming response that ended without ever emitting a usage event:
		// the upstream stream was cut/abandoned — the classic "looks hung" case.
		warn = " warn=stream-ended-without-usage"
	}
	g.cfg.Logger.Printf("model-gateway: req=%d END status=%s http=%d stream=%t dur=%s in=%d out=%d cached=%d inflight=%d%s",
		reqID, status, sw.status, st, dur.Round(time.Millisecond),
		lu.InputTokens, lu.OutputTokens, lu.CachedTokens, g.inflight.Add(-1), warn)
}

// statusWriter wraps http.ResponseWriter to capture the response status code for
// the END lifecycle log while preserving http.Flusher, so streamed (SSE)
// responses still flush each chunk promptly.
type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wrote {
		s.status = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	s.wrote = true // an implicit 200 if WriteHeader was never called
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
