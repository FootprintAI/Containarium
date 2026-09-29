package tracker

import (
	"errors"
	"net/http"
	"net/http/httptest"
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
