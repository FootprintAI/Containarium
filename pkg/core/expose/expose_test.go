package expose

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeClient is a minimal APIClient for unit-testing Run() without a
// real transport. Each test sets the desired LookupContainer response
// and CreateRoute response (or error) up front.
type fakeClient struct {
	// LookupContainer behavior
	lookupName, lookupIP, lookupState string
	lookupErr                         error
	lookupCalls                       int

	// ipAfterCall, when > 0, models a box still coming up: LookupContainer
	// returns an empty IP until the Nth call, then returns lookupIP (the box
	// "got its IP"). Used to test the create→expose wait.
	ipAfterCall int

	// CreateRoute behavior
	createResult *RouteResult
	createErr    error
	createCalls  int
	lastParams   AddRouteParams
}

func (f *fakeClient) LookupContainer(_ context.Context, _ string) (string, string, string, error) {
	f.lookupCalls++
	if f.ipAfterCall > 0 && f.lookupCalls < f.ipAfterCall {
		return f.lookupName, "", f.lookupState, f.lookupErr
	}
	return f.lookupName, f.lookupIP, f.lookupState, f.lookupErr
}

func (f *fakeClient) CreateRoute(_ context.Context, p AddRouteParams) (*RouteResult, error) {
	f.createCalls++
	f.lastParams = p
	return f.createResult, f.createErr
}

func TestRun_HappyPath(t *testing.T) {
	c := &fakeClient{
		lookupName:   "alice-container",
		lookupIP:     "10.0.3.42",
		lookupState:  "Running",
		createResult: &RouteResult{Domain: "blog.example.com", ContainerIP: "10.0.3.42", Port: 8080, Message: "ok"},
	}
	got, err := Run(context.Background(), c, Options{
		Username:      "alice",
		ContainerPort: 8080,
		Domain:        "blog.example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.lookupCalls != 1 || c.createCalls != 1 {
		t.Errorf("call counts: lookup=%d create=%d (want 1/1)", c.lookupCalls, c.createCalls)
	}
	// Run must use the resolved IP, not anything caller-supplied.
	if c.lastParams.TargetIP != "10.0.3.42" {
		t.Errorf("CreateRoute got TargetIP=%q, want resolved 10.0.3.42", c.lastParams.TargetIP)
	}
	if c.lastParams.TargetPort != 8080 {
		t.Errorf("CreateRoute got TargetPort=%d, want 8080", c.lastParams.TargetPort)
	}
	if c.lastParams.ContainerName != "alice-container" {
		t.Errorf("CreateRoute got ContainerName=%q, want alice-container", c.lastParams.ContainerName)
	}
	if got.Domain != "blog.example.com" {
		t.Errorf("result Domain=%q, want blog.example.com", got.Domain)
	}
}

func TestRun_RejectsBadOptions(t *testing.T) {
	cases := []struct {
		name string
		opts Options
	}{
		{"no username", Options{ContainerPort: 80, Domain: "x.example"}},
		{"no domain", Options{Username: "alice", ContainerPort: 80}},
		{"port zero", Options{Username: "alice", ContainerPort: 0, Domain: "x.example"}},
		{"port too big", Options{Username: "alice", ContainerPort: 65536, Domain: "x.example"}},
		{"port negative", Options{Username: "alice", ContainerPort: -1, Domain: "x.example"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &fakeClient{}
			_, err := Run(context.Background(), c, tc.opts)
			if err == nil {
				t.Errorf("expected error for invalid options")
			}
			if c.lookupCalls != 0 || c.createCalls != 0 {
				t.Errorf("validation must short-circuit; saw lookup=%d create=%d",
					c.lookupCalls, c.createCalls)
			}
		})
	}
}

func TestRun_RejectsNoIP(t *testing.T) {
	c := &fakeClient{
		lookupName:  "alice-container",
		lookupIP:    "",
		lookupState: "Stopped",
	}
	_, err := Run(context.Background(), c, Options{
		Username: "alice", ContainerPort: 8080, Domain: "x.example",
	})
	if err == nil {
		t.Fatal("expected error when container has no IP")
	}
	if c.createCalls != 0 {
		t.Errorf("must not call CreateRoute when IP unresolved")
	}
}

func TestRun_PropagatesLookupError(t *testing.T) {
	c := &fakeClient{lookupErr: errors.New("not found")}
	_, err := Run(context.Background(), c, Options{
		Username: "alice", ContainerPort: 8080, Domain: "x.example",
	})
	if err == nil {
		t.Fatal("expected lookup error to propagate")
	}
	if c.createCalls != 0 {
		t.Errorf("must not call CreateRoute when lookup fails")
	}
}

func TestRun_PropagatesCreateError(t *testing.T) {
	c := &fakeClient{
		lookupName:  "alice-container",
		lookupIP:    "10.0.3.42",
		lookupState: "Running",
		createErr:   errors.New("domain already exists"),
	}
	_, err := Run(context.Background(), c, Options{
		Username: "alice", ContainerPort: 8080, Domain: "x.example",
	})
	if err == nil {
		t.Fatal("expected create error to propagate")
	}
}

// TestRun_WaitsForIPThroughCreating: a box that has no IP yet (still CREATING)
// is waited out — Run polls LookupContainer until the IP appears, then exposes.
// This is the create→expose race an agent hits when it exposes right after
// create.
func TestRun_WaitsForIPThroughCreating(t *testing.T) {
	oldT, oldI := exposeReadyTimeout, exposePollInterval
	exposeReadyTimeout = 2 * time.Second
	exposePollInterval = 5 * time.Millisecond
	defer func() { exposeReadyTimeout, exposePollInterval = oldT, oldI }()

	c := &fakeClient{
		lookupName:   "alice-container",
		lookupIP:     "10.0.3.42",
		lookupState:  "Creating",
		ipAfterCall:  3, // IP appears on the 3rd lookup
		createResult: &RouteResult{Domain: "x.example", ContainerIP: "10.0.3.42", Port: 8080},
	}
	got, err := Run(context.Background(), c, Options{Username: "alice", ContainerPort: 8080, Domain: "x.example"})
	if err != nil {
		t.Fatalf("expected Run to wait for the IP, got: %v", err)
	}
	if c.lookupCalls < 3 {
		t.Errorf("expected ≥3 lookups (polled until IP), got %d", c.lookupCalls)
	}
	if c.createCalls != 1 || c.lastParams.TargetIP != "10.0.3.42" {
		t.Errorf("expected one CreateRoute with the resolved IP; create=%d ip=%q", c.createCalls, c.lastParams.TargetIP)
	}
	_ = got
}

// TestRun_TimesOutStillCreating: a box stuck CREATING with no IP past the
// deadline returns the actionable "no IP address yet" error (and never routes).
func TestRun_TimesOutStillCreating(t *testing.T) {
	oldT, oldI := exposeReadyTimeout, exposePollInterval
	exposeReadyTimeout = 30 * time.Millisecond
	exposePollInterval = 5 * time.Millisecond
	defer func() { exposeReadyTimeout, exposePollInterval = oldT, oldI }()

	c := &fakeClient{lookupName: "alice-container", lookupIP: "", lookupState: "Creating"}
	_, err := Run(context.Background(), c, Options{Username: "alice", ContainerPort: 8080, Domain: "x.example"})
	if err == nil {
		t.Fatal("expected a timeout error for a box stuck creating")
	}
	if c.lookupCalls < 2 {
		t.Errorf("expected the box to be polled more than once, got %d", c.lookupCalls)
	}
	if c.createCalls != 0 {
		t.Errorf("must not route a box with no IP")
	}
}
