package sentinel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/gateway"
)

// testCertPair returns a PEM cert/key pair whose CommonName is domain.
func testCertPair(t *testing.T, domain string) gateway.CertPair {
	t.Helper()
	return testCertPairFrom(t, domain, "")
}

// testCertPairFrom is testCertPair with the Organization set to from, so a
// test can tell which backend's certificate the store is serving.
func testCertPairFrom(t *testing.T, domain, from string) gateway.CertPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: domain, Organization: []string{from}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{domain},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return gateway.CertPair{
		Domain:  domain,
		CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		KeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
	}
}

// certsBackend serves body verbatim on /certs and returns its host and port.
func certsBackend(t *testing.T, body string) (string, int) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	return host, port
}

func certsBody(t *testing.T, pairs ...gateway.CertPair) string {
	t.Helper()
	b, err := json.Marshal(gateway.CertsResponse{Certs: pairs})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func servedLeaf(t *testing.T, cs *CertStore, sni string) *x509.Certificate {
	t.Helper()
	cert, err := cs.GetCertificate(&tls.ClientHelloInfo{ServerName: sni})
	if err != nil {
		t.Fatalf("GetCertificate(%q): %v", sni, err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf
}

func servedLeafCN(t *testing.T, cs *CertStore, sni string) string {
	t.Helper()
	return servedLeaf(t, cs, sni).Subject.CommonName
}

// servedFrom returns the Organization of the certificate served for sni:
// the backend tag set by testCertPairFrom, or "fallback" for the store's
// self-signed certificate.
func servedFrom(t *testing.T, cs *CertStore, sni string) string {
	t.Helper()
	leaf := servedLeaf(t, cs, sni)
	if leaf.Subject.CommonName == "" {
		return "fallback"
	}
	if len(leaf.Subject.Organization) == 0 {
		return ""
	}
	return leaf.Subject.Organization[0]
}

// scopes is a test scope resolver keyed by backend ID.
type scopes map[string]CertScope

func (s scopes) resolve(backendID string) CertScope { return s[backendID] }

// syncFrom runs one sync of backendID against a backend serving pairs.
func syncFrom(t *testing.T, cs *CertStore, backendID string, pairs ...gateway.CertPair) error {
	t.Helper()
	host, port := certsBackend(t, certsBody(t, pairs...))
	return cs.Sync(backendID, host, port)
}

// seededStore returns a store holding one synced cert for domain, supplied
// by backend "a", which is registered for exactly that domain.
func seededStore(t *testing.T, domain string) *CertStore {
	t.Helper()
	cs := NewCertStore()
	cs.SetScopeResolver(scopes{"a": {Hostname: domain}}.resolve)
	if err := syncFrom(t, cs, "a", testCertPair(t, domain)); err != nil {
		t.Fatalf("seed sync: %v", err)
	}
	if got := cs.SyncedCount(); got != 1 {
		t.Fatalf("seed: synced count = %d, want 1", got)
	}
	return cs
}

func TestCertSync_EmptyResponseKeepsStore(t *testing.T) {
	for _, body := range []string{`{"certs":[]}`, `{}`, `{"certs":null}`} {
		t.Run(body, func(t *testing.T) {
			cs := seededStore(t, "app.example.com")
			host, port := certsBackend(t, body)
			_ = cs.Sync("a", host, port)

			if got := cs.SyncedCount(); got != 1 {
				t.Fatalf("synced count after empty response = %d, want 1", got)
			}
			if !cs.HasSyncedCerts() {
				t.Fatal("HasSyncedCerts = false after empty response")
			}
			if cn := servedLeafCN(t, cs, "app.example.com"); cn != "app.example.com" {
				t.Fatalf("served cert CN = %q, want app.example.com", cn)
			}
		})
	}
}

func TestCertSync_MalformedResponseKeepsStore(t *testing.T) {
	cases := []struct{ name, body string }{
		{"not json", `<html>oops</html>`},
		{"truncated json", `{"certs":[{"domain":"a`},
		{"unparseable pems", `{"certs":[{"domain":"app.example.com","cert_pem":"x","key_pem":"y"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := seededStore(t, "app.example.com")
			host, port := certsBackend(t, tc.body)
			if err := cs.Sync("a", host, port); err == nil {
				t.Fatal("Sync returned nil for a malformed response")
			}
			if got := cs.SyncedCount(); got != 1 {
				t.Fatalf("synced count after malformed response = %d, want 1", got)
			}
			if cn := servedLeafCN(t, cs, "app.example.com"); cn != "app.example.com" {
				t.Fatalf("served cert CN = %q, want app.example.com", cn)
			}
		})
	}
}

func TestCertSync_NonEmptyResponseReplacesOwnSet(t *testing.T) {
	cs := NewCertStore()
	cs.SetScopeResolver(scopes{"a": {BaseDomains: []string{"example.com"}}}.resolve)
	if err := syncFrom(t, cs, "a", testCertPair(t, "old.example.com")); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	if err := syncFrom(t, cs, "a", testCertPair(t, "new.example.com")); err != nil {
		t.Fatalf("second sync: %v", err)
	}
	if got := cs.SyncedCount(); got != 1 {
		t.Fatalf("synced count = %d, want 1", got)
	}
	if cn := servedLeafCN(t, cs, "new.example.com"); cn != "new.example.com" {
		t.Fatalf("served cert CN = %q, want new.example.com", cn)
	}
	if from := servedFrom(t, cs, "old.example.com"); from != "fallback" {
		t.Fatalf("old.example.com served from %q, want fallback after a's set was replaced", from)
	}
}

func TestCertSync_BackendCannotReplaceAnotherBackendsCert(t *testing.T) {
	cs := NewCertStore()
	cs.SetScopeResolver(scopes{
		"a": {Hostname: "a.example.com"},
		"b": {Hostname: "b.example.com"},
	}.resolve)

	if err := syncFrom(t, cs, "b", testCertPairFrom(t, "b.example.com", "b")); err != nil {
		t.Fatalf("sync b: %v", err)
	}
	// a names its own domain and b's.
	if err := syncFrom(t, cs, "a",
		testCertPairFrom(t, "a.example.com", "a"),
		testCertPairFrom(t, "b.example.com", "a"),
	); err != nil {
		t.Fatalf("sync a: %v", err)
	}

	if from := servedFrom(t, cs, "b.example.com"); from != "b" {
		t.Fatalf("b.example.com served from %q, want b", from)
	}
	if from := servedFrom(t, cs, "a.example.com"); from != "a" {
		t.Fatalf("a.example.com served from %q, want a", from)
	}
	if got := cs.RejectedCounts()["a"]; got != 1 {
		t.Fatalf("rejected count for a = %d, want 1", got)
	}
	if got := cs.RejectedCounts()["b"]; got != 0 {
		t.Fatalf("rejected count for b = %d, want 0", got)
	}

	// An empty response from a leaves b's certificate alone too.
	host, port := certsBackend(t, `{"certs":[]}`)
	_ = cs.Sync("a", host, port)
	if from := servedFrom(t, cs, "b.example.com"); from != "b" {
		t.Fatalf("after a's empty response, b.example.com served from %q, want b", from)
	}
}

func TestCertSync_UnregisteredBackendSuppliesNothing(t *testing.T) {
	cs := NewCertStore()
	cs.SetScopeResolver(scopes{}.resolve)

	if err := syncFrom(t, cs, "gcp", testCertPair(t, "*.example.com")); err == nil {
		t.Fatal("Sync returned nil when every entry was outside the backend's domains")
	}
	if got := cs.SyncedCount(); got != 0 {
		t.Fatalf("synced count = %d, want 0", got)
	}
	if got := cs.RejectedCounts()["gcp"]; got != 1 {
		t.Fatalf("rejected count = %d, want 1", got)
	}
	if from := servedFrom(t, cs, "app.example.com"); from != "fallback" {
		t.Fatalf("served from %q, want fallback", from)
	}
}

func TestCertSync_AllOutOfScopeKeepsPreviousSet(t *testing.T) {
	cs := seededStore(t, "app.example.com")
	if err := syncFrom(t, cs, "a", testCertPair(t, "other.example.org")); err == nil {
		t.Fatal("Sync returned nil when every entry was outside the backend's domains")
	}
	if cn := servedLeafCN(t, cs, "app.example.com"); cn != "app.example.com" {
		t.Fatalf("served cert CN = %q, want app.example.com", cn)
	}
}

func TestCertSync_MergePrecedence(t *testing.T) {
	t.Run("longer base domain wins", func(t *testing.T) {
		cs := NewCertStore()
		cs.SetScopeResolver(scopes{
			"apex": {BaseDomains: []string{"example.com"}},
			"lab":  {BaseDomains: []string{"lab.example.com"}},
		}.resolve)
		_ = syncFrom(t, cs, "apex", testCertPairFrom(t, "*.lab.example.com", "apex"), testCertPairFrom(t, "*.example.com", "apex"))
		_ = syncFrom(t, cs, "lab", testCertPairFrom(t, "*.lab.example.com", "lab"))
		if from := servedFrom(t, cs, "x.lab.example.com"); from != "lab" {
			t.Fatalf("x.lab.example.com served from %q, want lab", from)
		}
		if from := servedFrom(t, cs, "x.example.com"); from != "apex" {
			t.Fatalf("x.example.com served from %q, want apex", from)
		}
	})
	t.Run("hostname or alias beats base domain", func(t *testing.T) {
		cs := NewCertStore()
		cs.SetScopeResolver(scopes{
			"apex": {BaseDomains: []string{"example.com"}},
			"api":  {Hostname: "prod.example.com", Aliases: []string{"api.example.com"}},
		}.resolve)
		_ = syncFrom(t, cs, "api", testCertPairFrom(t, "api.example.com", "api"))
		_ = syncFrom(t, cs, "apex", testCertPairFrom(t, "api.example.com", "apex"))
		if from := servedFrom(t, cs, "api.example.com"); from != "api" {
			t.Fatalf("api.example.com served from %q, want api", from)
		}
	})
	t.Run("tie serves neither", func(t *testing.T) {
		cs := NewCertStore()
		cs.SetScopeResolver(scopes{
			"a": {BaseDomains: []string{"example.com"}},
			"b": {BaseDomains: []string{"example.com"}},
		}.resolve)
		_ = syncFrom(t, cs, "a", testCertPairFrom(t, "*.example.com", "a"))
		_ = syncFrom(t, cs, "b", testCertPairFrom(t, "*.example.com", "b"))
		if from := servedFrom(t, cs, "x.example.com"); from != "fallback" {
			t.Fatalf("x.example.com served from %q, want fallback on a tie", from)
		}
		// Once one side leaves, the other is served.
		cs.DropBackend("b")
		if from := servedFrom(t, cs, "x.example.com"); from != "a" {
			t.Fatalf("after dropping b, x.example.com served from %q, want a", from)
		}
	})
}

func TestCertSync_DropBackendRemovesItsSet(t *testing.T) {
	cs := NewCertStore()
	cs.SetScopeResolver(scopes{
		"a": {Hostname: "a.example.com"},
		"b": {Hostname: "b.example.com"},
	}.resolve)
	_ = syncFrom(t, cs, "a", testCertPairFrom(t, "a.example.com", "a"))
	_ = syncFrom(t, cs, "b", testCertPairFrom(t, "b.example.com", "b"))

	cs.DropBackend("b")

	if from := servedFrom(t, cs, "b.example.com"); from != "fallback" {
		t.Fatalf("b.example.com served from %q after drop, want fallback", from)
	}
	if from := servedFrom(t, cs, "a.example.com"); from != "a" {
		t.Fatalf("a.example.com served from %q, want a", from)
	}
	if got := cs.SyncedCount(); got != 1 {
		t.Fatalf("synced count = %d, want 1", got)
	}
}

func TestCertScope_Match(t *testing.T) {
	s := CertScope{
		Hostname:    "prod.example.com",
		Aliases:     []string{"api.example.org"},
		BaseDomains: []string{"example.com"},
	}
	cases := []struct {
		domain string
		in     bool
	}{
		{"prod.example.com", true},
		{"api.example.org", true},
		{"API.example.org", true},
		{"example.com", true},
		{"*.example.com", true},
		{"app.example.com", true},
		{"*.lab.example.com", true},
		{"badexample.com", false},
		{"*.example.org", false},
		{"www.example.org", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := s.match(tc.domain) > 0; got != tc.in {
			t.Errorf("match(%q) in scope = %v, want %v", tc.domain, got, tc.in)
		}
	}
	if (CertScope{}).match("example.com") != 0 {
		t.Error("an empty scope matched a domain")
	}
}

func TestCertScope_Validate(t *testing.T) {
	valid := []CertScope{
		{},
		{Hostname: "prod.example.com"},
		{Aliases: []string{"api.example.com", "voice.example.org"}},
		{BaseDomains: []string{"example.com", "lab.example.org"}},
	}
	for _, s := range valid {
		if err := s.Validate(); err != nil {
			t.Errorf("Validate(%+v) = %v, want nil", s, err)
		}
	}
	invalid := []CertScope{
		{Hostname: "*.example.com"},
		{Hostname: "Prod.example.com"},
		{Aliases: []string{""}},
		{Aliases: []string{"bad_name.example.com"}},
		{Aliases: []string{"-a.example.com"}},
		{BaseDomains: []string{"com"}},
		{BaseDomains: []string{".example.com"}},
		{BaseDomains: []string{"example.com."}},
		{BaseDomains: []string{"*.example.com"}},
		{BaseDomains: []string{"a..example.com"}},
	}
	for _, s := range invalid {
		if err := s.Validate(); err == nil {
			t.Errorf("Validate(%+v) = nil, want an error", s)
		}
	}
}

func TestRenderCertSyncMetrics(t *testing.T) {
	if got := renderCertSyncMetrics(nil); got != "" {
		t.Fatalf("no rejections rendered %q, want empty", got)
	}
	got := renderCertSyncMetrics(map[string]uint64{"tunnel-b": 2, "gcp": 1})
	want := "# HELP sentinel_cert_sync_rejected_total Certificates from a backend's /certs response that were dropped because they name a domain the backend is not registered for.\n" +
		"# TYPE sentinel_cert_sync_rejected_total counter\n" +
		"sentinel_cert_sync_rejected_total{backend=\"gcp\"} 1\n" +
		"sentinel_cert_sync_rejected_total{backend=\"tunnel-b\"} 2\n"
	if got != want {
		t.Fatalf("render:\n%s\nwant:\n%s", got, want)
	}
}

func TestManagerCertScopeFor(t *testing.T) {
	inFleet := CertScope{BaseDomains: []string{"example.com"}}
	m := NewManager(Config{InFleetCertScope: inFleet}, nil)
	m.primaries.Register(Primary{
		Pool:        "lab",
		Hostname:    "lab.example.org",
		Aliases:     []string{"api.example.org"},
		BaseDomains: []string{"lab.example.org"},
		IP:          "127.0.0.2",
		Port:        443,
		BackendID:   "tunnel-spot1",
	})

	if got := m.certScopeFor(inFleetBackendID); got.BaseDomains[0] != "example.com" {
		t.Fatalf("in-fleet scope = %+v, want the configured scope", got)
	}
	got := m.certScopeFor("tunnel-spot1")
	if got.Hostname != "lab.example.org" || len(got.Aliases) != 1 || got.BaseDomains[0] != "lab.example.org" {
		t.Fatalf("tunnel scope = %+v, want the primary registration", got)
	}
	if got := m.certScopeFor("tunnel-unregistered"); !got.Empty() {
		t.Fatalf("unregistered tunnel scope = %+v, want empty", got)
	}
}

// TestManagerInFleetBackendServesDeclaredDomains drives the in-fleet
// backend through the manager's resolver: with domains declared, its
// wildcard is served; with none declared, nothing it sends is served.
func TestManagerInFleetBackendServesDeclaredDomains(t *testing.T) {
	declared := NewManager(Config{InFleetCertScope: CertScope{BaseDomains: []string{"example.com"}}}, nil)
	if err := syncFrom(t, declared.certStore, inFleetBackendID, testCertPairFrom(t, "*.example.com", "gcp")); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if from := servedFrom(t, declared.certStore, "app.example.com"); from != "gcp" {
		t.Fatalf("declared: app.example.com served from %q, want gcp", from)
	}

	undeclared := NewManager(Config{}, nil)
	_ = syncFrom(t, undeclared.certStore, inFleetBackendID, testCertPairFrom(t, "*.example.com", "gcp"))
	if from := servedFrom(t, undeclared.certStore, "app.example.com"); from != "fallback" {
		t.Fatalf("undeclared: app.example.com served from %q, want fallback", from)
	}
	if got := undeclared.certStore.RejectedCounts()[inFleetBackendID]; got != 1 {
		t.Fatalf("undeclared: rejected count = %d, want 1", got)
	}
}
