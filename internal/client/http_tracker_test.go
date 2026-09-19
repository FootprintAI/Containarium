package client

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestSetTrackerConnection_PathMethodAndBody(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"message": "connection created",
			"connection": {
				"username": "alice",
				"name": "default",
				"provider": "TRACKER_PROVIDER_GITHUB",
				"project": "acme/widgets",
				"credentialSecret": "GH_TOKEN"
			}
		}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	conn, msg, err := c.SetTrackerConnection(&pb.SetTrackerConnectionRequest{
		Username:         "alice",
		Name:             "default",
		Provider:         pb.TrackerProvider_TRACKER_PROVIDER_GITHUB,
		Project:          "acme/widgets",
		CredentialSecret: "GH_TOKEN",
	})
	if err != nil {
		t.Fatalf("SetTrackerConnection: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/v1/tracker/connections" {
		t.Errorf("path = %q, want /v1/tracker/connections", gotPath)
	}
	// The request body is built with protojson.Marshal on the generated
	// type, so field names come from the proto descriptor rather than a
	// hand-typed struct tag that could drift (#1219's class of bug).
	// Spot-check the fields that matter, rather than the exact bytes.
	bodyStr := string(gotBody)
	for _, want := range []string{`"username":"alice"`, `"project":"acme/widgets"`, `"credentialSecret":"GH_TOKEN"`} {
		if !strings.Contains(bodyStr, want) {
			t.Errorf("request body %s does not contain %s", bodyStr, want)
		}
	}
	if msg != "connection created" {
		t.Errorf("message = %q, want %q", msg, "connection created")
	}
	if conn.GetProvider() != pb.TrackerProvider_TRACKER_PROVIDER_GITHUB || conn.GetProject() != "acme/widgets" {
		t.Errorf("connection = %+v, want provider=GITHUB project=acme/widgets", conn)
	}
}

func TestListTrackerConnections_DecodesGatewayCamelCase(t *testing.T) {
	const gatewayJSON = `{
	  "connections": [
	    {
	      "username": "alice",
	      "name": "default",
	      "provider": "TRACKER_PROVIDER_GITLAB",
	      "baseUrl": "https://gitlab.example.com",
	      "project": "acme/widgets",
	      "credentialSecret": "GL_TOKEN"
	    }
	  ]
	}`

	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(gatewayJSON))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	list, err := c.ListTrackerConnections("alice")
	if err != nil {
		t.Fatalf("ListTrackerConnections: %v", err)
	}
	if gotPath != "/v1/tracker/connections/alice" {
		t.Errorf("path = %q, want /v1/tracker/connections/alice", gotPath)
	}
	if len(list) != 1 {
		t.Fatalf("got %d connections, want 1", len(list))
	}
	if list[0].GetBaseUrl() != "https://gitlab.example.com" || list[0].GetProvider() != pb.TrackerProvider_TRACKER_PROVIDER_GITLAB {
		t.Errorf("connection = %+v, want baseUrl=https://gitlab.example.com provider=GITLAB", list[0])
	}
}

func TestDeleteTrackerConnection_PathAndMethod(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message": "connection default deleted"}`))
	}))
	defer srv.Close()

	c, err := NewHTTPClient(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}

	msg, err := c.DeleteTrackerConnection("alice", "default")
	if err != nil {
		t.Fatalf("DeleteTrackerConnection: %v", err)
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("method = %q, want DELETE", gotMethod)
	}
	if gotPath != "/v1/tracker/connections/alice/default" {
		t.Errorf("path = %q, want /v1/tracker/connections/alice/default", gotPath)
	}
	if msg != "connection default deleted" {
		t.Errorf("message = %q, want %q", msg, "connection default deleted")
	}
}
