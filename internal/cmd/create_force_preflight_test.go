package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeForceDaemon is a daemon with one existing box ("alice") that records the
// order of what the CLI does to it. rejectDryRun makes the validate-only
// create fail the way a real daemon fails an unknown stack.
type fakeForceDaemon struct {
	mu           sync.Mutex
	calls        []string
	rejectDryRun bool
	srv          *httptest.Server
}

func newFakeForceDaemon(t *testing.T) *fakeForceDaemon {
	t.Helper()
	d := &fakeForceDaemon{}
	d.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/containers/alice":
			d.calls = append(d.calls, "GET")
			_, _ = w.Write([]byte(`{"container":{"name":"alice-container","username":"alice","state":"CONTAINER_STATE_RUNNING"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/containers":
			raw, _ := io.ReadAll(r.Body)
			var body struct {
				DryRun bool `json:"dryRun"`
			}
			_ = json.Unmarshal(raw, &body)
			if !body.DryRun {
				d.calls = append(d.calls, "CREATE")
				_, _ = w.Write([]byte(`{"container":{"name":"alice-container","username":"alice","state":"CONTAINER_STATE_CREATING"}}`))
				return
			}
			d.calls = append(d.calls, "DRYRUN")
			if d.rejectDryRun {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"unknown stack \"typo\"; valid stacks: nodejs"}`))
				return
			}
			_, _ = w.Write([]byte(`{"dryRun":true,"message":"Dry run: accepted. Nothing was created."}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/containers/alice":
			d.calls = append(d.calls, "DELETE")
			_, _ = w.Write([]byte(`{}`))
		default:
			d.calls = append(d.calls, "UNEXPECTED "+r.Method+" "+r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(d.srv.Close)
	return d
}

func (d *fakeForceDaemon) sequence() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return strings.Join(d.calls, ",")
}

func forceCreateAgainst(t *testing.T, d *fakeForceDaemon) error {
	t.Helper()
	savedForce, savedNoKey, savedStack, savedAddr, savedHTTP, savedToken, savedVerbose :=
		forceRecreate, noSSHKey, stackID, serverAddr, httpMode, authToken, verbose
	defer func() {
		forceRecreate, noSSHKey, stackID, serverAddr, httpMode, authToken, verbose =
			savedForce, savedNoKey, savedStack, savedAddr, savedHTTP, savedToken, savedVerbose
	}()
	forceRecreate, noSSHKey, stackID, serverAddr, httpMode, authToken, verbose = true, true, "typo", d.srv.URL, true, "tok", false
	return runCreate(nil, []string{"alice"})
}

// #2925: against a daemon, `create --force` must not delete the existing box
// for a request the daemon would reject. The daemon's own pre-flight decides.
func TestRunCreate_ForceDoesNotDeleteWhenTheDaemonRejectsThePreflight(t *testing.T) {
	d := newFakeForceDaemon(t)
	d.rejectDryRun = true

	err := forceCreateAgainst(t, d)
	if err == nil || !strings.Contains(err.Error(), `unknown stack "typo"`) {
		t.Fatalf("runCreate = %v, want the daemon's rejection surfaced", err)
	}
	if got := d.sequence(); got != "GET,DRYRUN" {
		t.Fatalf("daemon saw %q, want GET,DRYRUN: the box must still exist and nothing else may run", got)
	}
}

func TestRunCreate_ForceDeletesAndCreatesOnlyAfterTheDaemonAcceptsThePreflight(t *testing.T) {
	d := newFakeForceDaemon(t)

	if err := forceCreateAgainst(t, d); err != nil {
		t.Fatalf("runCreate = %v", err)
	}
	if got := d.sequence(); got != "GET,DRYRUN,DELETE,CREATE" {
		t.Fatalf("daemon saw %q, want GET,DRYRUN,DELETE,CREATE", got)
	}
}

// With no existing box there is nothing to protect: no pre-flight round trip,
// the create is the validation. Pins that --force on a fresh name is unchanged.
func TestRunCreate_ForceOnAFreshNameSkipsThePreflight(t *testing.T) {
	d := newFakeForceDaemon(t)
	d.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			d.calls = append(d.calls, "GET")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not found"}`))
		case http.MethodPost:
			d.calls = append(d.calls, "CREATE")
			_, _ = w.Write([]byte(`{"container":{"name":"alice-container","username":"alice","state":"CONTAINER_STATE_CREATING"}}`))
		default:
			d.calls = append(d.calls, "UNEXPECTED "+r.Method)
		}
	})
	if err := forceCreateAgainst(t, d); err != nil {
		t.Fatalf("runCreate = %v", err)
	}
	if got := d.sequence(); got != "GET,CREATE" {
		t.Fatalf("daemon saw %q, want GET,CREATE", got)
	}
}
