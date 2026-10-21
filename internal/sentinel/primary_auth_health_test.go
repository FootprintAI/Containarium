package sentinel

import (
	"crypto/md5"  // #nosec G501 -- test only: proves no MD5 of the secret leaks
	"crypto/sha1" // #nosec G505 -- test only: proves no SHA-1 of the secret leaks
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

// #2892: /status reports, per primary, whether its last daemon-AUTH-gated
// request authenticated or was rejected with 401 — and nothing derived from
// the secret. These tests drive the REAL route table (buildBinaryServerMux),
// so a route that loses its observing gate fails them.

const wrongPrimariesSecret = "wrong-secret-but-still-32-bytes!!"

func newAuthHealthTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	m := &Manager{
		backends:   NewBackendPool(),
		primaries:  NewPrimaryRegistry(),
		certStore:  NewCertStore(),
		hmacSecret: []byte(testPrimariesSecret),
	}
	m.state.Store(StateProxy)
	srv := httptest.NewServer(buildBinaryServerMux("/nonexistent/containarium", m))
	t.Cleanup(srv.Close)
	return srv
}

func getStatus(t *testing.T, srv *httptest.Server) (StatusJSON, string) {
	t.Helper()
	code, body := doPrimaries(t, srv, http.MethodGet, "/status", "", false, nil)
	if code != http.StatusOK {
		t.Fatalf("/status: code %d body %q", code, body)
	}
	var st StatusJSON
	if err := json.Unmarshal([]byte(body), &st); err != nil {
		t.Fatalf("/status: decode %q: %v", body, err)
	}
	return st, body
}

func registerPool(t *testing.T, srv *httptest.Server, pool string) {
	t.Helper()
	body := fmt.Sprintf(`{"pool":%q,"hostname":"%s.example.com","port":443}`, pool, pool)
	if code, resp := doPrimaries(t, srv, http.MethodPost, "/sentinel/primaries", testPrimariesSecret, true, strings.NewReader(body)); code != http.StatusCreated {
		t.Fatalf("register %s: code %d body %q", pool, code, resp)
	}
}

func healthFor(st StatusJSON, pool string) *PrimaryAuthHealthJSON {
	for i := range st.PrimaryAuthHealth {
		if st.PrimaryAuthHealth[i].Pool == pool {
			return &st.PrimaryAuthHealth[i]
		}
	}
	return nil
}

func TestStatus_PrimaryAuthHealth_ReportsSuccessThen401ThenRecovery(t *testing.T) {
	srv := newAuthHealthTestServer(t)
	registerPool(t, srv, "pool-a")

	st, _ := getStatus(t, srv)
	h := healthFor(st, "pool-a")
	if h == nil || h.State != PrimaryAuthOK || h.LastSuccess == "" || h.LastFailure != "" || h.FailuresSinceSuccess != 0 {
		t.Fatalf("after register: health = %+v, want ok with last_success only", h)
	}

	// The primary's heartbeat now signs with a secret the sentinel does not
	// hold (a partial rotation): 401, attributed to the primary by its source
	// address learned from the authenticated registration.
	if code, _ := doPrimaries(t, srv, http.MethodPut, "/sentinel/primaries/pool-a", wrongPrimariesSecret, true, nil); code != http.StatusUnauthorized {
		t.Fatalf("mismatched heartbeat: code %d, want 401", code)
	}
	// Other daemon-AUTH routes count too (peer-cert bootstrap, key resync).
	if code, _ := doPrimaries(t, srv, http.MethodPost, "/sentinel/keys/resync", wrongPrimariesSecret, true, nil); code != http.StatusUnauthorized {
		t.Fatalf("mismatched resync: code %d, want 401", code)
	}
	st, _ = getStatus(t, srv)
	h = healthFor(st, "pool-a")
	if h == nil || h.State != PrimaryAuthFailing401 || h.LastFailure == "" || h.FailuresSinceSuccess != 2 {
		t.Fatalf("after 401s: health = %+v, want failing_401 with 2 failures", h)
	}
	if st.UnattributedAuthFailures != 0 {
		t.Errorf("unattributed = %d, want 0 (both 401s came from the primary's address)", st.UnattributedAuthFailures)
	}

	if code, _ := doPrimaries(t, srv, http.MethodPut, "/sentinel/primaries/pool-a", testPrimariesSecret, true, nil); code != http.StatusOK {
		t.Fatalf("good heartbeat: code %d", code)
	}
	st, _ = getStatus(t, srv)
	if h = healthFor(st, "pool-a"); h == nil || h.State != PrimaryAuthOK || h.FailuresSinceSuccess != 0 {
		t.Fatalf("after recovery: health = %+v, want ok with 0 failures", h)
	}
}

// A deregistered primary keeps its health record: a daemon restarted with a
// new secret deregisters with the old one (accepted) and then 401s on
// re-registration — that 401 is exactly the signal the runbook needs.
func TestStatus_PrimaryAuthHealth_SurvivesDeregister(t *testing.T) {
	srv := newAuthHealthTestServer(t)
	registerPool(t, srv, "pool-a")
	if code, _ := doPrimaries(t, srv, http.MethodDelete, "/sentinel/primaries/pool-a", testPrimariesSecret, true, nil); code != http.StatusNoContent {
		t.Fatalf("deregister: code %d", code)
	}
	body := `{"pool":"pool-a","hostname":"pool-a.example.com","port":443}`
	if code, _ := doPrimaries(t, srv, http.MethodPost, "/sentinel/primaries", wrongPrimariesSecret, true, strings.NewReader(body)); code != http.StatusUnauthorized {
		t.Fatalf("re-register with new secret: code %d, want 401", code)
	}
	st, _ := getStatus(t, srv)
	if h := healthFor(st, "pool-a"); h == nil || h.State != PrimaryAuthFailing401 {
		t.Fatalf("health = %+v, want failing_401 after deregister + 401", h)
	}
}

// An unauthenticated caller cannot create per-primary state, whatever pool
// name it puts in the path or body: no primary has authenticated yet, so the
// 401s only bump the bounded unattributed counter.
func TestStatus_PrimaryAuthHealth_UnauthenticatedCreatesNoPrimaryState(t *testing.T) {
	srv := newAuthHealthTestServer(t)
	for i := 0; i < 50; i++ {
		pool := fmt.Sprintf("attacker-%d", i)
		doPrimaries(t, srv, http.MethodPut, "/sentinel/primaries/"+pool, wrongPrimariesSecret, true, nil)
		doPrimaries(t, srv, http.MethodPost, "/sentinel/primaries", "", false,
			strings.NewReader(fmt.Sprintf(`{"pool":%q,"hostname":"x.example.com","port":443}`, pool)))
	}
	st, _ := getStatus(t, srv)
	if len(st.PrimaryAuthHealth) != 0 {
		t.Fatalf("primary_auth_health = %+v, want empty: unauthenticated requests must not create entries", st.PrimaryAuthHealth)
	}
	if st.UnattributedAuthFailures != 100 || st.LastUnattributedAuthFailure == "" {
		t.Fatalf("unattributed = %d (last %q), want 100 with a timestamp", st.UnattributedAuthFailures, st.LastUnattributedAuthFailure)
	}
}

// The pool name in a rejected request is never trusted. With two primaries
// behind one source address (attribution is ambiguous), a bad request naming
// pool-a must not mark pool-a (or pool-b) failing.
func TestStatus_PrimaryAuthHealth_401NamingAPoolDoesNotPoisonIt(t *testing.T) {
	srv := newAuthHealthTestServer(t)
	registerPool(t, srv, "pool-a")
	registerPool(t, srv, "pool-b")
	if code, _ := doPrimaries(t, srv, http.MethodPut, "/sentinel/primaries/pool-a", wrongPrimariesSecret, true, nil); code != http.StatusUnauthorized {
		t.Fatalf("code %d, want 401", code)
	}
	st, _ := getStatus(t, srv)
	for _, pool := range []string{"pool-a", "pool-b"} {
		if h := healthFor(st, pool); h == nil || h.State != PrimaryAuthOK {
			t.Errorf("%s health = %+v, want ok (an ambiguous 401 must not be attributed)", pool, h)
		}
	}
	if st.UnattributedAuthFailures != 1 {
		t.Errorf("unattributed = %d, want 1", st.UnattributedAuthFailures)
	}
}

// Acceptance criterion: /status never carries the secret or anything derived
// from it — not the raw value, not a hash or fingerprint of it, not a request
// signature computed with it.
func TestStatus_NeverContainsSecretOrHashOfIt(t *testing.T) {
	srv := newAuthHealthTestServer(t)
	registerPool(t, srv, "pool-a")
	doPrimaries(t, srv, http.MethodPut, "/sentinel/primaries/pool-a", wrongPrimariesSecret, true, nil)
	doPrimaries(t, srv, http.MethodPut, "/sentinel/primaries/pool-a", testPrimariesSecret, true, nil)
	doPrimaries(t, srv, http.MethodPut, "/sentinel/primaries/pool-a", wrongPrimariesSecret, true, nil)
	_, body := getStatus(t, srv)
	lower := strings.ToLower(body)

	forbidden := map[string]string{}
	for name, secret := range map[string]string{"sentinel": testPrimariesSecret, "wrong": wrongPrimariesSecret} {
		s := []byte(secret)
		s256 := sha256.Sum256(s)
		s1 := sha1.Sum(s) // #nosec G401 -- test only
		m5 := md5.Sum(s)  // #nosec G401 -- test only
		s512 := sha512.Sum512(s)
		h256 := hex.EncodeToString(s256[:])
		forbidden[name+" raw"] = secret
		forbidden[name+" base64"] = base64.StdEncoding.EncodeToString(s)
		forbidden[name+" hex"] = hex.EncodeToString(s)
		forbidden[name+" sha256 hex"] = h256
		forbidden[name+" sha256 8-char fingerprint"] = h256[:8]
		forbidden[name+" sha256 base64"] = base64.StdEncoding.EncodeToString(s256[:])
		forbidden[name+" sha1 hex"] = hex.EncodeToString(s1[:])
		forbidden[name+" md5 hex"] = hex.EncodeToString(m5[:])
		forbidden[name+" sha512 hex"] = hex.EncodeToString(s512[:])
		// A signature the client would send now — any HMAC under the secret.
		req := httptest.NewRequest(http.MethodPut, "/sentinel/primaries/pool-a", nil)
		auth.SignSentinelRequest(req, s)
		forbidden[name+" request signature"] = req.Header.Get(auth.SentinelHeaderSignature)
	}
	for what, v := range forbidden {
		if v != "" && strings.Contains(lower, strings.ToLower(v)) {
			t.Errorf("/status contains the %s: %s", what, body)
		}
	}
}

func TestPrimaryAuthTracker_Bounded(t *testing.T) {
	var tr primaryAuthTracker
	for i := 0; i < 2*maxTrackedPrimaryAuth; i++ {
		tr.bind(Pool(fmt.Sprintf("pool-%d", i)), fmt.Sprintf("10.0.%d.%d", i/256, i%256))
	}
	for i := 0; i < 10000; i++ {
		tr.observe(fmt.Sprintf("192.0.2.%d", i%256), false)
	}
	health, unattributed, _ := tr.snapshot()
	if len(health) != maxTrackedPrimaryAuth {
		t.Fatalf("tracked %d primaries, want cap %d", len(health), maxTrackedPrimaryAuth)
	}
	if unattributed != 10000 {
		t.Fatalf("unattributed = %d, want 10000", unattributed)
	}
	for _, h := range health {
		if h.State != PrimaryAuthOK {
			t.Fatalf("%s = %+v: failures from unknown addresses must not touch any primary", h.Pool, h)
		}
	}
}

func TestPrimaryAuthTracker_AttributionAndRetention(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tr := primaryAuthTracker{now: func() time.Time { return now }}
	tr.bind("pool-a", "10.0.0.1")
	tr.bind("pool-b", "10.0.0.2")

	tr.observe("10.0.0.1", false) // pool-a's address
	tr.observe("10.0.0.3", false) // nobody's

	health, unattributed, _ := tr.snapshot()
	got := map[Pool]PrimaryAuthState{}
	for _, h := range health {
		got[Pool(h.Pool)] = h.State
	}
	if got["pool-a"] != PrimaryAuthFailing401 || got["pool-b"] != PrimaryAuthOK || unattributed != 1 {
		t.Fatalf("states = %v unattributed = %d; want pool-a failing, pool-b ok, 1 unattributed", got, unattributed)
	}

	// A primary that moved address is re-bound by its next authenticated
	// request; the old address no longer attributes to it.
	tr.bind("pool-a", "10.0.0.9")
	tr.observe("10.0.0.1", false)
	if _, unattributed, _ = tr.snapshot(); unattributed != 2 {
		t.Fatalf("unattributed = %d, want 2 after pool-a moved", unattributed)
	}

	now = now.Add(primaryAuthRetention + time.Minute)
	tr.bind("pool-b", "10.0.0.2")
	health, _, _ = tr.snapshot()
	if len(health) != 1 || health[0].Pool != "pool-b" {
		t.Fatalf("after retention: %+v, want only pool-b", health)
	}
}
