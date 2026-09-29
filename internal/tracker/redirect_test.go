package tracker

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestWithSameOriginRedirectsAllowsSameOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/done", http.StatusFound)
			return
		}
		if r.URL.Path != "/done" {
			t.Fatalf("path = %q, want /done", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	resp, err := WithSameOriginRedirects(&http.Client{}).Get(srv.URL + "/start")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
}

func TestWithSameOriginRedirectsRefusesCrossOrigin(t *testing.T) {
	var decoyHits int
	decoy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decoyHits++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer decoy.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, decoy.URL+"/stolen", http.StatusFound)
	}))
	defer origin.Close()

	_, err := WithSameOriginRedirects(&http.Client{}).Get(origin.URL + "/start")
	if !errors.Is(err, ErrCrossOriginRedirect) {
		t.Fatalf("Get error = %v, want ErrCrossOriginRedirect", err)
	}
	if decoyHits != 0 {
		t.Fatalf("decoy received %d request(s), want 0", decoyHits)
	}
}

func TestWithSameOriginRedirectsRetainsDefaultLimit(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Redirect(w, r, "/loop", http.StatusFound)
	}))
	defer srv.Close()

	_, err := WithSameOriginRedirects(&http.Client{}).Get(srv.URL + "/loop")
	if err == nil || !strings.Contains(err.Error(), "stopped after 10 redirects") {
		t.Fatalf("Get error = %v, want default redirect limit error", err)
	}
	if requests != 10 {
		t.Fatalf("requests = %d, want 10", requests)
	}
}

func TestWithSameOriginRedirectsRechecksCallbackURL(t *testing.T) {
	var decoyHits int
	decoy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decoyHits++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer decoy.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	defer origin.Close()

	decoyURL, err := url.Parse(decoy.URL + "/rewritten")
	if err != nil {
		t.Fatalf("parse decoy URL: %v", err)
	}
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		req.URL = decoyURL
		return nil
	}}

	_, err = WithSameOriginRedirects(client).Get(origin.URL + "/start")
	if !errors.Is(err, ErrCrossOriginRedirect) {
		t.Fatalf("Get error = %v, want ErrCrossOriginRedirect", err)
	}
	if decoyHits != 0 {
		t.Fatalf("decoy received %d request(s), want 0", decoyHits)
	}
}
