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
}

// Gateway brokers every agent box's model calls: it authenticates the box's
// scoped gateway token, injects the real provider key (which never leaves the
// gateway), proxies to the provider, and meters per-tenant token usage.
type Gateway struct {
	cfg   Config
	meter *Meter

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

	// For OpenAI-shaped providers, buffer the request body so we can (a) extract
	// the system prompt (skill persona) for streaming output-filtering and (b)
	// enable a final usage event so the SSE path is metered. Fail-open: any read
	// error leaves the original body in place.
	sysPrompt, reqModel := "", ""
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
				if g.cfg.Sink != nil {
					g.cfg.Sink.RecordUsage(claims.Tenant, claims.SkillID, provName, u)
				}
				captureUsage(u) // folded into the END lifecycle log
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
