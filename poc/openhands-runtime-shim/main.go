// Command openhands-runtime-shim is a PROOF-OF-CONCEPT implementation of the
// OpenHands "runtime API" contract on top of Containarium.
//
// OpenHands' SDK (APIRemoteWorkspace) and self-hosted app (RemoteSandboxService)
// both provision agent sandboxes through a small HTTP contract served by a
// "runtime API" provider. This shim implements that contract by mapping:
//
//	runtime session  -> a persistent Containarium box (one per session_id)
//	agent-server pod -> a podman container inside the box (root podman,
//	                    --restart=always, survives SSH logout and box reboot)
//	ingress          -> the box's public managed-TLS subdomain (routes :60000)
//
// Contract implemented (reverse-engineered from the MIT client code; there is
// no published spec):
//
//	POST /start                {image, command, working_dir, environment,
//	                            session_id, ...} -> {runtime_id, url, session_api_key}
//	GET  /sessions/{session_id}                  -> runtime status object
//	GET  /sessions/batch?ids=a&ids=b             -> [runtime status objects]
//	GET  /list                                   -> {"runtimes": [...]}
//	POST /pause                {runtime_id}
//	POST /resume               {runtime_id}      (mints a NEW session_api_key)
//	POST /stop                 {runtime_id}
//
// The shim shells out to the containarium CLI for box lifecycle (create /
// sleep / wake / delete / connect --exec) and calls the REST API directly for
// route management (the CLI expose-port verb is gRPC-only today).
//
// PoC ONLY: single-tenant (one shim API key), state in a local JSON file, no
// warm-image management. See README.md for the productization gaps.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	agentServerPort   = 60000
	defaultEntrypoint = "/usr/local/bin/openhands-agent-server"
	podmanName        = "agent-server"
)

type config struct {
	listen      string
	apiKey      string
	cli         string
	server      string
	credentials string
	urlSuffix   string // appended to the box name to form the public hostname, e.g. "-myorg.containarium.dev"
	statePath   string
	boxCPU      string
	boxMemory   string
	boxDisk     string
}

type session struct {
	SessionID  string            `json:"session_id"`
	RuntimeID  string            `json:"runtime_id"` // == box name
	Box        string            `json:"box"`
	Username   string            `json:"username,omitempty"` // platform tenant user (cld-...); sleep/wake/delete key on this
	Image      string            `json:"image"`
	Command    string            `json:"command"`
	WorkingDir string            `json:"working_dir"`
	Env        map[string]string `json:"env,omitempty"`
	Key        string            `json:"session_api_key"`
	URL        string            `json:"url"`
	Status     string            `json:"status"` // starting|running|paused|stopped|error
	Error      string            `json:"error,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
}

type shim struct {
	cfg   config
	mu    sync.Mutex
	byID  map[string]*session // session_id -> session
	token string              // bearer for the Containarium REST API (route management)
	hc    *http.Client
}

func main() {
	cfg := config{
		listen:      envOr("OH_SHIM_LISTEN", ":8700"),
		apiKey:      os.Getenv("OH_SHIM_API_KEY"),
		cli:         envOr("OH_SHIM_CLI", "containarium"),
		server:      envOr("OH_SHIM_SERVER", "https://cloud.containarium.dev"),
		credentials: envOr("OH_SHIM_CREDENTIALS", filepath.Join(os.Getenv("HOME"), ".containarium", "credentials.json")),
		urlSuffix:   os.Getenv("OH_SHIM_URL_SUFFIX"),
		statePath:   envOr("OH_SHIM_STATE", "oh-shim-state.json"),
		boxCPU:      envOr("OH_SHIM_BOX_CPU", "4"),
		boxMemory:   envOr("OH_SHIM_BOX_MEMORY", "8GB"),
		boxDisk:     envOr("OH_SHIM_BOX_DISK", "30GB"),
	}
	if cfg.apiKey == "" {
		log.Fatal("OH_SHIM_API_KEY is required")
	}
	if cfg.urlSuffix == "" {
		log.Fatal("OH_SHIM_URL_SUFFIX is required (e.g. \"-myorg.containarium.dev\")")
	}

	s := &shim{cfg: cfg, byID: map[string]*session{}, hc: &http.Client{Timeout: 30 * time.Second}}
	if err := s.loadToken(); err != nil {
		log.Fatalf("load REST token: %v", err)
	}
	s.loadState()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /start", s.auth(s.handleStart))
	mux.HandleFunc("GET /sessions/batch", s.auth(s.handleBatch)) // must register before the wildcard
	mux.HandleFunc("GET /sessions/{id}", s.auth(s.handleGetSession))
	mux.HandleFunc("GET /list", s.auth(s.handleList))
	mux.HandleFunc("POST /pause", s.auth(s.handlePause))
	mux.HandleFunc("POST /resume", s.auth(s.handleResume))
	mux.HandleFunc("POST /stop", s.auth(s.handleStop))

	log.Printf("openhands-runtime-shim (PoC) listening on %s -> %s", cfg.listen, cfg.server)
	log.Fatal(http.ListenAndServe(cfg.listen, mux))
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// ---- auth ----

func (s *shim) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-API-Key")
		if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.apiKey)) != 1 {
			httpError(w, http.StatusUnauthorized, "invalid or missing X-API-Key")
			return
		}
		next(w, r)
	}
}

func (s *shim) loadToken() error {
	raw, err := os.ReadFile(s.cfg.credentials)
	if err != nil {
		return err
	}
	var creds struct {
		Servers map[string]struct {
			Token string `json:"token"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(raw, &creds); err != nil {
		return err
	}
	entry, ok := creds.Servers[s.cfg.server]
	if !ok || entry.Token == "" {
		return fmt.Errorf("no token for %s in %s (run `containarium login`)", s.cfg.server, s.cfg.credentials)
	}
	s.token = entry.Token
	return nil
}

// ---- state ----

func (s *shim) loadState() {
	raw, err := os.ReadFile(s.cfg.statePath)
	if err != nil {
		return
	}
	var m map[string]*session
	if err := json.Unmarshal(raw, &m); err == nil {
		s.byID = m
		log.Printf("loaded %d session(s) from %s", len(m), s.cfg.statePath)
	}
}

func (s *shim) saveStateLocked() {
	raw, err := json.MarshalIndent(s.byID, "", " ")
	if err != nil {
		return
	}
	_ = os.WriteFile(s.cfg.statePath, raw, 0o600)
}

// ---- handlers ----

type startRequest struct {
	Image       string            `json:"image"`
	Command     string            `json:"command"`
	WorkingDir  string            `json:"working_dir"`
	Environment map[string]string `json:"environment"`
	SessionID   string            `json:"session_id"`
	// Accepted and ignored (K8s-flavored knobs; the LXC box is the isolation):
	RunAsUser       int    `json:"run_as_user"`
	RunAsGroup      int    `json:"run_as_group"`
	FSGroup         int    `json:"fs_group"`
	ImagePullPolicy string `json:"image_pull_policy"`
	RuntimeClass    string `json:"runtime_class"`
	ResourceFactor  int    `json:"resource_factor"`
}

func (s *shim) handleStart(w http.ResponseWriter, r *http.Request) {
	var req startRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "bad JSON: "+err.Error())
		return
	}
	if req.SessionID == "" || req.Image == "" {
		httpError(w, http.StatusBadRequest, "session_id and image are required")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.byID[req.SessionID]; ok && existing.Status != "stopped" && existing.Status != "error" {
		// Session reuse: same session_id re-attaches to its persistent box.
		writeJSON(w, s.runtimeViewLocked(existing))
		return
	}

	box := "oh-" + hexHash(req.SessionID)[:10]
	sess := &session{
		SessionID:  req.SessionID,
		RuntimeID:  box,
		Box:        box,
		Image:      req.Image,
		Command:    req.Command,
		WorkingDir: req.WorkingDir,
		Env:        req.Environment,
		Key:        newKey(),
		URL:        "https://" + box + s.cfg.urlSuffix,
		Status:     "starting",
		CreatedAt:  time.Now().UTC(),
	}
	s.byID[req.SessionID] = sess
	s.saveStateLocked()

	go s.provision(sess)

	writeJSON(w, s.runtimeViewLocked(sess))
}

func (s *shim) handleGetSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	sess, ok := s.byID[id]
	if !ok {
		s.mu.Unlock()
		httpError(w, http.StatusNotFound, "no such session")
		return
	}
	view := s.runtimeViewLocked(sess)
	s.mu.Unlock()
	writeJSON(w, view)
}

func (s *shim) handleBatch(w http.ResponseWriter, r *http.Request) {
	ids := r.URL.Query()["ids"]
	out := []map[string]any{}
	s.mu.Lock()
	for _, id := range ids {
		if sess, ok := s.byID[id]; ok {
			out = append(out, s.runtimeViewLocked(sess))
		}
	}
	s.mu.Unlock()
	writeJSON(w, out)
}

func (s *shim) handleList(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	out := []map[string]any{}
	keys := make([]string, 0, len(s.byID))
	for k := range s.byID {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sess := s.byID[k]
		if sess.Status == "stopped" {
			continue
		}
		out = append(out, s.runtimeViewLocked(sess))
	}
	s.mu.Unlock()
	writeJSON(w, map[string]any{"runtimes": out})
}

type runtimeIDRequest struct {
	RuntimeID string `json:"runtime_id"`
}

func (s *shim) findByRuntimeID(id string) *session {
	for _, sess := range s.byID {
		if sess.RuntimeID == id {
			return sess
		}
	}
	return nil
}

func (s *shim) handlePause(w http.ResponseWriter, r *http.Request) {
	var req runtimeIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	sess := s.findByRuntimeID(req.RuntimeID)
	s.mu.Unlock()
	if sess == nil {
		httpError(w, http.StatusNotFound, "no such runtime")
		return
	}
	if _, err := s.runCLI("sleep", s.tenantUser(sess)); err != nil {
		httpError(w, http.StatusBadGateway, "sleep failed: "+err.Error())
		return
	}
	s.setStatus(sess, "paused", "")
	writeJSON(w, map[string]any{"runtime_id": sess.RuntimeID, "status": "paused"})
}

func (s *shim) handleResume(w http.ResponseWriter, r *http.Request) {
	var req runtimeIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	sess := s.findByRuntimeID(req.RuntimeID)
	s.mu.Unlock()
	if sess == nil {
		httpError(w, http.StatusNotFound, "no such runtime")
		return
	}

	if _, err := s.runCLI("wake", s.tenantUser(sess)); err != nil {
		httpError(w, http.StatusBadGateway, "wake failed: "+err.Error())
		return
	}

	// Security invariant from the upstream contract: resume invalidates the
	// old session_api_key. Re-run the agent-server container with a new key.
	s.mu.Lock()
	sess.Key = newKey()
	sess.Status = "starting"
	s.saveStateLocked()
	s.mu.Unlock()

	go func() {
		if err := s.startAgentServer(sess); err != nil {
			s.setStatus(sess, "error", "resume: "+err.Error())
			return
		}
		if err := s.ensureRoute(sess); err != nil {
			s.setStatus(sess, "error", "resume route: "+err.Error())
			return
		}
		s.setStatus(sess, "starting", "") // health probe flips it to running
	}()

	s.mu.Lock()
	view := s.runtimeViewLocked(sess)
	s.mu.Unlock()
	writeJSON(w, view)
}

func (s *shim) handleStop(w http.ResponseWriter, r *http.Request) {
	var req runtimeIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	sess := s.findByRuntimeID(req.RuntimeID)
	s.mu.Unlock()
	if sess == nil {
		httpError(w, http.StatusNotFound, "no such runtime")
		return
	}
	if _, err := s.runCLI("delete", s.tenantUser(sess), "--force"); err != nil && !strings.Contains(err.Error(), "not found") {
		httpError(w, http.StatusBadGateway, "delete failed: "+err.Error())
		return
	}
	_ = s.deleteRoute(sess.Box) // best-effort
	s.setStatus(sess, "stopped", "")
	writeJSON(w, map[string]any{"runtime_id": sess.RuntimeID, "status": "stopped"})
}

// runtimeViewLocked renders a session in the wire shape both upstream clients
// parse. Caller holds s.mu.
func (s *shim) runtimeViewLocked(sess *session) map[string]any {
	status := sess.Status
	podStatus := map[string]string{
		"starting": "pending",
		"running":  "ready",
		"paused":   "paused",
		"stopped":  "not found",
		"error":    "failed",
	}[status]
	view := map[string]any{
		"runtime_id":      sess.RuntimeID,
		"session_id":      sess.SessionID,
		"url":             sess.URL,
		"session_api_key": sess.Key,
		"status":          status,
		"pod_status":      podStatus,
		"restart_count":   0,
	}
	if sess.Error != "" {
		view["pod_logs"] = sess.Error
	}
	return view
}

// probeHealth flips a "starting" session to "running" once the agent-server
// answers on its public URL. Called from a background loop.
func (s *shim) probeHealth(sess *session) {
	s.mu.Lock()
	status, url := sess.Status, sess.URL
	s.mu.Unlock()
	if status != "starting" {
		return
	}
	c := &http.Client{Timeout: 4 * time.Second}
	resp, err := c.Get(url + "/health")
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		s.setStatus(sess, "running", "")
	}
}

func (s *shim) setStatus(sess *session, status, errMsg string) {
	s.mu.Lock()
	sess.Status = status
	sess.Error = errMsg
	s.saveStateLocked()
	s.mu.Unlock()
	if errMsg != "" {
		log.Printf("session %s (%s): %s — %s", sess.SessionID, sess.Box, status, errMsg)
	} else {
		log.Printf("session %s (%s): %s", sess.SessionID, sess.Box, status)
	}
}

// ---- provisioning ----

func (s *shim) provision(sess *session) {
	log.Printf("provisioning box %s for session %s", sess.Box, sess.SessionID)

	if out, err := s.runCLI("create", sess.Box, "--no-ssh-key",
		"--cpu", s.cfg.boxCPU, "--memory", s.cfg.boxMemory, "--disk", s.cfg.boxDisk,
		"--labels", "openhands_runtime=poc"); err != nil {
		if !strings.Contains(out, "already exists") && !strings.Contains(err.Error(), "already exists") {
			s.setStatus(sess, "error", "create: "+err.Error())
			return
		}
	}

	if _, err := s.waitBoxRunning(sess.Box, 5*time.Minute); err != nil {
		s.setStatus(sess, "error", err.Error())
		return
	}

	if err := s.startAgentServer(sess); err != nil {
		s.setStatus(sess, "error", err.Error())
		return
	}

	if err := s.ensureRoute(sess); err != nil {
		s.setStatus(sess, "error", err.Error())
		return
	}

	// Health-probe loop: flip to running as soon as the public URL serves.
	for i := 0; i < 300; i++ {
		s.probeHealth(sess)
		s.mu.Lock()
		st := sess.Status
		s.mu.Unlock()
		if st != "starting" {
			return
		}
		time.Sleep(3 * time.Second)
	}
	s.setStatus(sess, "error", "agent-server never became healthy on "+sess.URL)
}

func (s *shim) waitBoxRunning(box string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ip, state, _, err := s.boxInfo(box)
		if err == nil && state == "CONTAINER_STATE_RUNNING" && ip != "" {
			return ip, nil
		}
		time.Sleep(6 * time.Second)
	}
	return "", fmt.Errorf("box %s not RUNNING with an IP after %s", box, timeout)
}

func (s *shim) boxInfo(box string) (ip, state, username string, err error) {
	out, err := s.runCLI("list", "--format", "json")
	if err != nil {
		return "", "", "", err
	}
	// The CLI prints a JSON object; tolerate leading log lines.
	idx := strings.Index(out, "{")
	if idx < 0 {
		return "", "", "", errors.New("no JSON in list output")
	}
	var parsed struct {
		Containers []struct {
			Name      string `json:"Name"`
			Username  string `json:"Username"`
			State     string `json:"State"`
			IPAddress string `json:"IPAddress"`
		} `json:"containers"`
	}
	if err := json.Unmarshal([]byte(out[idx:]), &parsed); err != nil {
		return "", "", "", err
	}
	for _, c := range parsed.Containers {
		if c.Name == box {
			return c.IPAddress, c.State, c.Username, nil
		}
	}
	return "", "", "", fmt.Errorf("box %q not found", box)
}

// tenantUser returns the identifier the container lifecycle endpoints key on
// (sleep/wake/delete take the tenant username, not the box name).
func (s *shim) tenantUser(sess *session) string {
	s.mu.Lock()
	u := sess.Username
	s.mu.Unlock()
	if u != "" {
		return u
	}
	if _, _, username, err := s.boxInfo(sess.Box); err == nil && username != "" {
		s.mu.Lock()
		sess.Username = username
		s.saveStateLocked()
		s.mu.Unlock()
		return username
	}
	return sess.Box // last resort; delete tolerates the box name
}

// startAgentServer runs the agent-server image inside the box via root podman.
// Root podman + --restart=always is the pattern proven by the platform's
// recipes: the container survives SSH logout and box restarts.
func (s *shim) startAgentServer(sess *session) error {
	entry, args := splitCommand(sess.Command)
	workdir := sess.WorkingDir
	if workdir == "" {
		workdir = "/"
	}

	var envFlags strings.Builder
	for k, v := range sess.Env {
		envFlags.WriteString(" -e " + shellQuote(k+"="+v))
	}
	// Both env spellings so v0-era and v1-era agent-server builds authenticate.
	envFlags.WriteString(" -e " + shellQuote("SESSION_API_KEY="+sess.Key))
	envFlags.WriteString(" -e " + shellQuote("OH_SESSION_API_KEYS_0="+sess.Key))

	// Pull DETACHED, then poll with short execs. A multi-GB pull can outlive
	// a proxied SSH connection (resets surface as exit 255 mid-exec), so no
	// single exec may span the slow step — same reason the platform's
	// recipes run their slow provisioning daemon-side, detached.
	kick := fmt.Sprintf(
		"podman image exists %[1]s && echo PRESENT || "+
			"{ nohup podman pull %[1]s > /root/oh-pull.log 2>&1 & echo PULLING; }",
		shellQuote(sess.Image))
	out, err := s.connectExec(sess.Box, "sudo bash -c "+shellQuote(kick), 2*time.Minute)
	if err != nil {
		return fmt.Errorf("start agent-server (pull kick): %w (output: %s)", err, tail(out, 300))
	}
	if !strings.Contains(out, "PRESENT") {
		probe := fmt.Sprintf(
			"podman image exists %[1]s && echo IMAGE_READY || "+
				"{ echo NOT_YET; tail -c 200 /root/oh-pull.log 2>/dev/null; }",
			shellQuote(sess.Image))
		deadline := time.Now().Add(25 * time.Minute)
		for {
			if time.Now().After(deadline) {
				return fmt.Errorf("image pull did not finish within 25m (last: %s)", tail(out, 300))
			}
			time.Sleep(15 * time.Second)
			out, err = s.connectExec(sess.Box, "sudo bash -c "+shellQuote(probe), 2*time.Minute)
			if err != nil {
				continue // transient exec failure; the pull runs detached regardless
			}
			if strings.Contains(out, "IMAGE_READY") {
				break
			}
		}
	}

	run := fmt.Sprintf(
		"podman rm -f %[2]s >/dev/null 2>&1; "+
			"podman run -d --name %[2]s --restart=always -p %[3]d:%[3]d%[4]s -w %[5]s --entrypoint %[6]s %[1]s%[7]s "+
			"&& echo AGENT_SERVER_STARTED",
		shellQuote(sess.Image), podmanName, agentServerPort, envFlags.String(),
		shellQuote(workdir), shellQuote(entry), args,
	)
	out, err = s.connectExec(sess.Box, "sudo bash -c "+shellQuote(run), 3*time.Minute)
	if err != nil {
		return fmt.Errorf("start agent-server: %w (output: %s)", err, tail(out, 400))
	}
	if !strings.Contains(out, "AGENT_SERVER_STARTED") {
		return fmt.Errorf("start agent-server: no confirmation (output: %s)", tail(out, 400))
	}
	return nil
}

// splitCommand maps the contract's `command` string onto podman's
// entrypoint/args split. The agent-server image's default entrypoint already
// launches the server, so passing the full command as args would duplicate it.
func splitCommand(command string) (entry, argStr string) {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		fields = []string{defaultEntrypoint, "--port", fmt.Sprint(agentServerPort)}
	}
	entry = fields[0]
	rest := fields[1:]
	hasHost := false
	for _, f := range rest {
		if f == "--host" {
			hasHost = true
		}
	}
	if !hasHost {
		rest = append(rest, "--host", "0.0.0.0")
	}
	var b strings.Builder
	for _, f := range rest {
		b.WriteString(" " + shellQuote(f))
	}
	return entry, b.String()
}

// connectExec runs one command in the box via `containarium connect --exec`,
// retrying through the transient windows of a freshly created box: sentinel
// key propagation (~2 min, "Permission denied") and in-box user provisioning
// (SSH auth can succeed BEFORE the tenant user is fully written to the box's
// /etc/passwd, surfacing as an su "does not exist / required fields" error).
func (s *shim) connectExec(box, command string, timeout time.Duration) (string, error) {
	transient := []string{
		"Permission denied (publickey)",
		"does not exist or the user entry does not contain all the required fields",
		// Proxied SSH connections can be reset under load; every command the
		// shim runs is idempotent, so a retry is always safe.
		"Connection reset by peer",
		"Broken pipe",
	}
	deadline := time.Now().Add(4 * time.Minute)
	for {
		out, err := s.runCLIWithTimeout(timeout, "connect", box, "--exec", command)
		if err == nil {
			return out, nil
		}
		retryable := false
		for _, marker := range transient {
			if strings.Contains(out, marker) {
				retryable = true
				break
			}
		}
		if retryable && time.Now().Before(deadline) {
			log.Printf("box %s: not yet connectable (key/user still provisioning), retrying...", box)
			time.Sleep(15 * time.Second)
			continue
		}
		return out, err
	}
}

// ---- route management (REST; the CLI expose-port verb is gRPC-only today) ----

func (s *shim) ensureRoute(sess *session) error {
	ip, _, username, err := s.boxInfo(sess.Box)
	if err != nil {
		return fmt.Errorf("route: %w", err)
	}
	if username != "" {
		s.mu.Lock()
		sess.Username = username
		s.saveStateLocked()
		s.mu.Unlock()
	}
	body, _ := json.Marshal(map[string]any{
		"domain":        sess.Box,
		"targetIp":      ip,
		"targetPort":    agentServerPort,
		"containerName": sess.Box + "-container",
		"description":   "openhands-runtime-shim (PoC) session " + sess.SessionID,
	})

	// The box's IP changes across sleep/wake, and the cloud's OSS-compat
	// route surface has no update verb (POST + DELETE only) — a conflicting
	// stale route would keep pointing at the dead IP. Recreate: best-effort
	// DELETE, then POST fresh.
	_ = s.deleteRoute(sess.Box)
	req, _ := http.NewRequest("POST", s.cfg.server+"/v1/network/routes", bytes.NewReader(body))
	status, err := s.doRESTErr(req)
	if err != nil {
		return fmt.Errorf("route create: %w", err)
	}
	if status >= 300 {
		return fmt.Errorf("route create: HTTP %d", status)
	}
	return nil
}

func (s *shim) deleteRoute(domain string) error {
	req, _ := http.NewRequest("DELETE", s.cfg.server+"/v1/network/routes/"+domain, nil)
	_, err := s.doREST(req)
	return err
}

func (s *shim) doREST(req *http.Request) (int, error) {
	status, err := s.doRESTErr(req)
	return status, err
}

func (s *shim) doRESTErr(req *http.Request) (int, error) {
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

// ---- CLI plumbing ----

func (s *shim) runCLI(args ...string) (string, error) {
	return s.runCLIWithTimeout(3*time.Minute, args...)
}

func (s *shim) runCLIWithTimeout(timeout time.Duration, args ...string) (string, error) {
	full := append([]string{"--server", s.cfg.server, "--http"}, args...)
	cmd := exec.Command(s.cfg.cli, full...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return "", err
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return buf.String(), fmt.Errorf("%s: %w: %s", args[0], err, tail(buf.String(), 300))
		}
		return buf.String(), nil
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		return buf.String(), fmt.Errorf("%s: timed out after %s", args[0], timeout)
	}
}

// ---- helpers ----

func hexHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func newKey() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"detail": msg})
}
