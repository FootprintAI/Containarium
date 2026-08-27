package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// #1590: ProvisionTLS populated its policy slice only on a 200 and had no
// else-branch, so any other status left the slice nil and control fell through
// to the "no existing policies, create a new one" path. POST to a Caddy admin
// API array path APPENDS, so a transient read failure (500/503, a proxy
// hiccup, the admin API mid-reload) grafted a duplicate policy alongside the
// real ones instead of appending a subject to the existing one.
//
// Duplicate policies aren't cosmetic: Caddy matches the first policy whose
// subjects match, so a duplicate carrying different issuers can shadow the
// intended one — and the caller got nil back either way.
//
// Same defect class fixed in EnsureTLSSubjects on #1589; this is the original.

// askProxyOnPolicyGet serves a Caddy admin API whose TLS app reads fine but
// whose policy read returns `status`, recording whether anything was written.
func askProxyOnPolicyGet(t *testing.T, status int) (*ProxyManager, *bool) {
	t.Helper()
	wrote := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		// Report the TLS app as present so ensureTLSApp doesn't short-circuit
		// into createTLSApp before we reach the policy read.
		case r.URL.Path == "/config/apps/tls" && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"automation":{"policies":[]}}`))
		case r.URL.Path == "/config/apps/tls/automation/policies" && r.Method == http.MethodGet:
			http.Error(w, "boom", status)
		default:
			wrote = true
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)
	return NewProxyManager(srv.URL, "example.com"), &wrote
}

func TestProvisionTLS_ErrorsOnUnexpectedPolicyGetStatus(t *testing.T) {
	for _, status := range []int{
		http.StatusInternalServerError,
		http.StatusServiceUnavailable,
		http.StatusBadGateway,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			p, wrote := askProxyOnPolicyGet(t, status)

			err := p.ProvisionTLS("app.example.com")
			if err == nil {
				t.Fatal("want an error when the policy read fails, got nil — falling through " +
					"POSTs a duplicate policy that can shadow the real one (#1590)")
			}
			if *wrote {
				t.Fatal("must not write configuration after a failed policy read")
			}
		})
	}
}

// The success path must be untouched: a 200 still reads, appends, and writes.
func TestProvisionTLS_StillAppendsOnHealthyRead(t *testing.T) {
	srv, fc := newRWFakeCaddy(tlsConfigWithPolicy(
		[]string{"other.example.com"},
		[]CaddyTLSIssuer{NewACMEIssuer()},
	))
	defer srv.Close()

	p := NewProxyManager(srv.URL, "example.com")

	if err := p.ProvisionTLS("app.example.com"); err != nil {
		t.Fatalf("ProvisionTLS: %v", err)
	}

	policies := readPolicies(t, fc)
	if !hasSubject(policies, "app.example.com") {
		t.Fatalf("subject not appended on the healthy path; subjects: %v", subjectsOf(policies))
	}
	if len(policies) != 1 {
		t.Fatalf("want the subject appended to the existing policy, not a duplicate policy; got %d policies",
			len(policies))
	}
}
