package modelgateway

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Upstream model listing through the gateway (#1726). The point of the verb is
// that the CALLER never holds a real key: it names an owner and a provider, and
// the gateway spends that owner's stored key exactly as the data plane would.

// fakeModelsUpstream serves an OpenAI-shaped /v1/models and records the
// Authorization header it was called with.
func fakeModelsUpstream(t *testing.T, body string, code int) (*httptest.Server, *string) {
	t.Helper()
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Errorf("upstream path = %q, want /v1/models", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &gotAuth
}

func TestGatewayListModels_SpendsTheOwnersKey(t *testing.T) {
	up, gotAuth := fakeModelsUpstream(t, `{"object":"list","data":[{"id":"m-small"},{"id":"m-large"}]}`, http.StatusOK)

	g := New(Config{
		Logger:    log.New(io.Discard, "", 0),
		Providers: map[string]*Provider{"acmeai": NewOpenAICompatibleProvider("acmeai", up.URL)},
		KeyResolver: KeyResolverFunc(func(_ context.Context, keyOwner, provider string) (string, bool) {
			if keyOwner == OrgKeyOwner("acme") && provider == "acmeai" {
				return "sk-owner", true
			}
			return "", false
		}),
	})

	models, err := g.ListModels(context.Background(), OrgKeyOwner("acme"), "acmeai")
	if err != nil {
		t.Fatalf("ListModels: %v", err)
	}
	if len(models) != 2 || models[0] != "m-small" || models[1] != "m-large" {
		t.Errorf("models = %v, want [m-small m-large]", models)
	}
	if *gotAuth != "Bearer sk-owner" {
		t.Errorf("upstream Authorization = %q, want the OWNER's key", *gotAuth)
	}
}

func TestGatewayListModels_FallsBackToTheGlobalKey(t *testing.T) {
	up, gotAuth := fakeModelsUpstream(t, `{"data":[{"id":"m-small"}]}`, http.StatusOK)

	g := New(Config{
		Logger:       log.New(io.Discard, "", 0),
		Providers:    map[string]*Provider{"acmeai": NewOpenAICompatibleProvider("acmeai", up.URL)},
		ProviderKeys: map[string]string{"acmeai": "sk-global"},
		KeyResolver: KeyResolverFunc(func(context.Context, string, string) (string, bool) {
			return "", false
		}),
	})

	if _, err := g.ListModels(context.Background(), UserKeyOwner("alice"), "acmeai"); err != nil {
		t.Fatalf("ListModels: %v", err)
	}
	if *gotAuth != "Bearer sk-global" {
		t.Errorf("upstream Authorization = %q, want the daemon-global key", *gotAuth)
	}
}

func TestGatewayListModels_NoKeyAnywhere(t *testing.T) {
	up, _ := fakeModelsUpstream(t, `{}`, http.StatusOK)
	g := New(Config{
		Logger:    log.New(io.Discard, "", 0),
		Providers: map[string]*Provider{"acmeai": NewOpenAICompatibleProvider("acmeai", up.URL)},
	})
	_, err := g.ListModels(context.Background(), UserKeyOwner("alice"), "acmeai")
	if !errors.Is(err, ErrNoKey) {
		t.Errorf("err = %v, want ErrNoKey", err)
	}
}

func TestGatewayListModels_UnknownProvider(t *testing.T) {
	g := New(Config{Logger: log.New(io.Discard, "", 0), Providers: map[string]*Provider{}})
	_, err := g.ListModels(context.Background(), UserKeyOwner("alice"), "nope")
	if !errors.Is(err, ErrUnknownProvider) {
		t.Errorf("err = %v, want ErrUnknownProvider", err)
	}
}

// A native-shaped provider (Gemini's generateContent surface, Anthropic's
// x-api-key) has no OpenAI /v1/models contract to read, so the verb must say so
// rather than return an empty list that reads as "this provider has no models".
func TestGatewayListModels_NonOpenAIShapedProviderIsRefused(t *testing.T) {
	g := New(Config{
		Logger:       log.New(io.Discard, "", 0),
		Providers:    DefaultProviders(),
		ProviderKeys: map[string]string{"gemini": "k"},
	})
	_, err := g.ListModels(context.Background(), UserKeyOwner("alice"), "gemini")
	if !errors.Is(err, ErrModelListUnsupported) {
		t.Errorf("err = %v, want ErrModelListUnsupported", err)
	}
}

func TestGatewayListModels_UpstreamErrorIsReported(t *testing.T) {
	up, _ := fakeModelsUpstream(t, `{"error":{"message":"bad key"}}`, http.StatusUnauthorized)
	g := New(Config{
		Logger:       log.New(io.Discard, "", 0),
		Providers:    map[string]*Provider{"acmeai": NewOpenAICompatibleProvider("acmeai", up.URL)},
		ProviderKeys: map[string]string{"acmeai": "sk-bad"},
	})
	_, err := g.ListModels(context.Background(), UserKeyOwner("alice"), "acmeai")
	if err == nil {
		t.Fatal("want an error for a 401 upstream")
	}
	var ue *UpstreamStatusError
	if !errors.As(err, &ue) {
		t.Fatalf("err = %v (%T), want an *UpstreamStatusError so the caller can map the code", err, err)
	}
	if ue.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want 401", ue.StatusCode)
	}
}

// The inbound gateway credential must never reach the upstream on this path
// either — same rule the proxy path has.
func TestGatewayListModels_StripsNothingItShouldNotSend(t *testing.T) {
	var sawExtra bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "" || r.Header.Get("X-Goog-Api-Key") != "" {
			sawExtra = true
		}
		_, _ = io.WriteString(w, `{"data":[]}`)
	}))
	defer srv.Close()

	g := New(Config{
		Logger:       log.New(io.Discard, "", 0),
		Providers:    map[string]*Provider{"acmeai": NewOpenAICompatibleProvider("acmeai", srv.URL)},
		ProviderKeys: map[string]string{"acmeai": "sk-global"},
	})
	if _, err := g.ListModels(context.Background(), UserKeyOwner("alice"), "acmeai"); err != nil {
		t.Fatalf("ListModels: %v", err)
	}
	if sawExtra {
		t.Error("upstream saw a provider-key header the gateway should not have sent")
	}
}
