package sentinel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
)

// #2415 — audit-ingest token store + register/deregister handlers.

const auditIngestAdminSecret = "zyxwvutsrqponmlkjihgfedcba9876543210ZYXW"

func newManagerForAuditIngestTest(t *testing.T) (*Manager, string) {
	t.Helper()
	m := &Manager{backends: NewBackendPool()}
	m.SetAdminSecret([]byte(auditIngestAdminSecret))
	path := filepath.Join(t.TempDir(), "audit-ingest-tokens.json")
	m.SetAuditIngestTokenStorePath(path)
	return m, path
}

func signedReq(method string, body any, secret string) *http.Request {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(method, "/sentinel/audit-ingest-tokens", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		auth.SignSentinelRequest(req, []byte(secret))
	}
	return req
}

func serveRegister(m *Manager, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	auth.SentinelHMACMiddleware(m.adminSecret, m.AuditIngestTokenRegisterHandler()).ServeHTTP(rec, req)
	return rec
}

func serveDeregister(m *Manager, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	auth.SentinelHMACMiddleware(m.adminSecret, m.AuditIngestTokenDeregisterHandler()).ServeHTTP(rec, req)
	return rec
}

func TestAuditIngestTokenStore_MissingFileIsEmpty(t *testing.T) {
	got, err := LoadAuditIngestTokenStore(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil || len(got) != 0 {
		t.Fatalf("missing file: got %v err %v", got, err)
	}
}

func TestAuditIngestTokenStore_RoundTripMode0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "t.json")
	want := []AuditIngestTokenEntry{{BackendID: "b1", Token: "tok1"}, {BackendID: "b2", Token: "tok2"}}
	if err := SaveAuditIngestTokenStore(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadAuditIngestTokenStore(path)
	if err != nil || len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("round trip: %v %v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, a bearer-equivalent secret file must be 0600", info.Mode().Perm())
	}
}

func TestAuditIngestTokenStore_CorruptFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.json")
	_ = os.WriteFile(path, []byte("{not json"), 0o600)
	if _, err := LoadAuditIngestTokenStore(path); err == nil {
		t.Fatal("a corrupt token file must be an error, not silently empty")
	}
}

func TestUpsertAndRemoveAuditIngestTokenEntry(t *testing.T) {
	e := upsertAuditIngestTokenEntry(nil, "b1", "t1")
	e = upsertAuditIngestTokenEntry(e, "b2", "t2")
	e = upsertAuditIngestTokenEntry(e, "b1", "t1-rotated") // rotation replaces
	if len(e) != 2 || e[0].Token != "t1-rotated" {
		t.Fatalf("upsert = %v", e)
	}
	e = removeAuditIngestTokenEntry(e, "b1")
	if len(e) != 1 || e[0].BackendID != "b2" {
		t.Fatalf("remove = %v", e)
	}
	if got := removeAuditIngestTokenEntry(e, "absent"); len(got) != 1 {
		t.Fatalf("removing an absent backend must be a no-op, got %v", got)
	}
}

func TestAuditIngestTokenRegisterHandler_PersistsAndRotates(t *testing.T) {
	m, path := newManagerForAuditIngestTest(t)

	rec := serveRegister(m, signedReq(http.MethodPost, AuditIngestTokenRegisterRequest{BackendID: "b1", Token: "t1"}, auditIngestAdminSecret))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	rec = serveRegister(m, signedReq(http.MethodPost, AuditIngestTokenRegisterRequest{BackendID: "b1", Token: "t2"}, auditIngestAdminSecret))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("rotation status = %d", rec.Code)
	}
	got, err := LoadAuditIngestTokenStore(path)
	if err != nil || len(got) != 1 || got[0].Token != "t2" {
		t.Fatalf("store after rotation = %v, %v", got, err)
	}
}

func TestAuditIngestTokenRegisterHandler_Rejections(t *testing.T) {
	tests := []struct {
		name string
		req  *http.Request
		want int
	}{
		{"no hmac", signedReq(http.MethodPost, AuditIngestTokenRegisterRequest{BackendID: "b", Token: "t"}, ""), http.StatusUnauthorized},
		{"wrong secret", signedReq(http.MethodPost, AuditIngestTokenRegisterRequest{BackendID: "b", Token: "t"}, "a-completely-different-secret-value-0000000"), http.StatusUnauthorized},
		{"missing backend", signedReq(http.MethodPost, AuditIngestTokenRegisterRequest{Token: "t"}, auditIngestAdminSecret), http.StatusBadRequest},
		{"missing token", signedReq(http.MethodPost, AuditIngestTokenRegisterRequest{BackendID: "b"}, auditIngestAdminSecret), http.StatusBadRequest},
		{"token with whitespace", signedReq(http.MethodPost, AuditIngestTokenRegisterRequest{BackendID: "b", Token: "a b"}, auditIngestAdminSecret), http.StatusBadRequest},
		{"wrong method", signedReq(http.MethodGet, nil, auditIngestAdminSecret), http.StatusMethodNotAllowed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, path := newManagerForAuditIngestTest(t)
			if rec := serveRegister(m, tc.req); rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.want, rec.Body)
			}
			if _, err := os.Stat(path); err == nil {
				t.Fatal("a rejected request must not create the store file")
			}
		})
	}
}

// #1772's lesson: success must mean durable.
func TestAuditIngestTokenRegisterHandler_PersistFailureIs500(t *testing.T) {
	m, _ := newManagerForAuditIngestTest(t)
	blocker := filepath.Join(t.TempDir(), "blocker")
	_ = os.WriteFile(blocker, []byte("x"), 0o600)
	m.SetAuditIngestTokenStorePath(filepath.Join(blocker, "t.json"))
	rec := serveRegister(m, signedReq(http.MethodPost, AuditIngestTokenRegisterRequest{BackendID: "b", Token: "t"}, auditIngestAdminSecret))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 when the token could not be persisted", rec.Code)
	}
}

func TestAuditIngestTokenDeregisterHandler(t *testing.T) {
	m, path := newManagerForAuditIngestTest(t)
	_ = SaveAuditIngestTokenStore(path, []AuditIngestTokenEntry{{BackendID: "b1", Token: "t1"}, {BackendID: "b2", Token: "t2"}})

	rec := serveDeregister(m, signedReq(http.MethodDelete, AuditIngestTokenDeregisterRequest{BackendID: "b1"}, auditIngestAdminSecret))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	got, _ := LoadAuditIngestTokenStore(path)
	if len(got) != 1 || got[0].BackendID != "b2" {
		t.Fatalf("store = %v", got)
	}
	// Idempotent: deregistering an absent backend is success.
	rec = serveDeregister(m, signedReq(http.MethodDelete, AuditIngestTokenDeregisterRequest{BackendID: "b1"}, auditIngestAdminSecret))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("idempotent deregister status = %d", rec.Code)
	}
	if rec := serveDeregister(m, signedReq(http.MethodDelete, AuditIngestTokenDeregisterRequest{}, auditIngestAdminSecret)); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing backend_id status = %d, want 400", rec.Code)
	}
	if rec := serveDeregister(m, signedReq(http.MethodDelete, AuditIngestTokenDeregisterRequest{BackendID: "b2"}, "")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned status = %d, want 401", rec.Code)
	}
}
