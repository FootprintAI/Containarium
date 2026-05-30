package releasecheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// newTestChecker wires a Checker at an httptest server with a controllable
// clock and a 1h TTL.
func newTestChecker(baseURL string, now func() time.Time) *Checker {
	return &Checker{
		owner:   "FootprintAI",
		repo:    "Containarium",
		baseURL: baseURL,
		client:  &http.Client{Timeout: 2 * time.Second},
		ttl:     time.Hour,
		now:     now,
	}
}

func TestChecker_FetchAndCache(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		if r.URL.Path != "/repos/FootprintAI/Containarium/releases/latest" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"tag_name":"v0.21.2","name":"ignored"}`))
	}))
	defer srv.Close()

	clock := time.Unix(1_700_000_000, 0)
	c := newTestChecker(srv.URL, func() time.Time { return clock })

	// First call fetches.
	got, err := c.Latest(context.Background())
	if err != nil || got != "v0.21.2" {
		t.Fatalf("Latest() = %q, %v; want v0.21.2", got, err)
	}
	// Second call within TTL is served from cache (no new hit).
	if got, _ := c.Latest(context.Background()); got != "v0.21.2" {
		t.Fatalf("cached Latest() = %q", got)
	}
	if h := atomic.LoadInt64(&hits); h != 1 {
		t.Fatalf("server hit %d times, want 1 (second call should hit cache)", h)
	}

	// Advance past the TTL → refetch.
	clock = clock.Add(time.Hour + time.Minute)
	if got, _ := c.Latest(context.Background()); got != "v0.21.2" {
		t.Fatalf("post-TTL Latest() = %q", got)
	}
	if h := atomic.LoadInt64(&hits); h != 2 {
		t.Fatalf("server hit %d times, want 2 (TTL expiry refetches)", h)
	}
}

func TestChecker_ServesStaleOnError(t *testing.T) {
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"tag_name":"v0.21.2"}`))
	}))
	defer srv.Close()

	clock := time.Unix(1_700_000_000, 0)
	c := newTestChecker(srv.URL, func() time.Time { return clock })

	if got, _ := c.Latest(context.Background()); got != "v0.21.2" {
		t.Fatalf("seed Latest() = %q", got)
	}
	// Expire the cache, then make the server fail: should serve the stale value.
	clock = clock.Add(2 * time.Hour)
	fail.Store(true)
	got, err := c.Latest(context.Background())
	if err != nil {
		t.Fatalf("expected stale value, got error %v", err)
	}
	if got != "v0.21.2" {
		t.Errorf("stale Latest() = %q, want v0.21.2", got)
	}
}

func TestChecker_ErrorWithNoCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden) // e.g. rate limited
	}))
	defer srv.Close()

	c := newTestChecker(srv.URL, time.Now)
	if _, err := c.Latest(context.Background()); err == nil {
		t.Error("want error when the first fetch fails with no cache to fall back on")
	}
}

func TestUpdateAvailable(t *testing.T) {
	cases := []struct {
		current, latest string
		want            bool
	}{
		{"0.21.0", "0.21.2", true},
		{"v0.21.0", "v0.21.2", true}, // tolerant of leading v
		{"0.21.0", "v0.21.0", false}, // equal
		{"0.21.3", "0.21.2", false},  // current newer
		{"v1.0.0", "v0.21.2", false},
		{"", "v0.21.2", false}, // bad current
		{"0.21.0", "", false},  // bad latest
		{"garbage", "0.21.2", false},
	}
	for _, tc := range cases {
		if got := UpdateAvailable(tc.current, tc.latest); got != tc.want {
			t.Errorf("UpdateAvailable(%q, %q) = %v, want %v", tc.current, tc.latest, got, tc.want)
		}
	}
}
