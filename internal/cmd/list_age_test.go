package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/client"
)

// TestListHTTP_AgeColumn_UnixSecondsCreatedAt (#2146): `containarium list
// --http` and `containarium prune --http`'s preview both fetch containers
// through the same HTTPClient.ListContainers() call (see listRemoteHTTP /
// pruneList) and render CreatedAt through the CLI's age formatter
// (ageString, prune.go). Before the fix, a daemon's `createdAt` — which is
// the Container proto's int64 Unix-seconds field, rendered by protojson as
// a quoted decimal string — failed the RFC3339-only parse and silently
// left the zero time, so the age column showed nothing for every box.
//
// This proves the fix end to end at the formatter/client level: a mocked
// HTTP daemon (no live server needed) returns a Unix-seconds createdAt, the
// real HTTPClient parses it, and the real age formatter renders a genuine
// elapsed duration instead of "age=unknown".
func TestListHTTP_AgeColumn_UnixSecondsCreatedAt(t *testing.T) {
	createdAt := time.Now().Add(-90 * time.Minute)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := fmt.Sprintf(
			`{"containers":[{"name":"alice-container","username":"alice","state":"Running","createdAt":"%d"}]}`,
			createdAt.Unix(),
		)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	httpClient, err := client.NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	defer func() { _ = httpClient.Close() }()

	containers, err := httpClient.ListContainers()
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	if len(containers) != 1 {
		t.Fatalf("got %d containers, want 1", len(containers))
	}

	got := ageString(time.Now(), containers[0].CreatedAt)
	if got == "age=unknown" {
		t.Fatalf("age column shows %q for a box with a Unix-seconds createdAt — reproduces #2146", got)
	}

	// Loose bound: the round trip through the fake server takes some time,
	// so assert the age lands near 90m rather than pinning it exactly.
	if !containers[0].CreatedAt.Before(time.Now().Add(-80*time.Minute)) ||
		!containers[0].CreatedAt.After(time.Now().Add(-100*time.Minute)) {
		t.Errorf("CreatedAt = %v, want ~90m ago", containers[0].CreatedAt)
	}
}
