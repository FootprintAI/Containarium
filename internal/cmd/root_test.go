package cmd

import "testing"

// --- FootprintAI/Containarium#2089 ---------------------------------------
//
// Every command against an `https://` --server failed with "name resolver
// error: produced zero addresses": the gRPC dialer was handed an HTTP
// origin because --http was the only thing that selected the HTTP
// transport. The scheme already says which transport applies.

func TestSchemeSelectsHTTP(t *testing.T) {
	for _, tc := range []struct {
		server string
		want   bool
	}{
		{"https://cp.example.com", true},
		{"http://host:8080", true},
		// Case-sensitive on purpose: client.NewHTTPClient matches the
		// scheme the same way, and would prepend one to an uppercase URL.
		{"HTTPS://cp.example.com", false},
		{"host.example.com:50051", false},
		{"10.0.0.5:50051", false},
		{"", false},
	} {
		if got := schemeSelectsHTTP(tc.server); got != tc.want {
			t.Errorf("schemeSelectsHTTP(%q) = %v, want %v", tc.server, got, tc.want)
		}
	}
}

func TestPersistentPreRunE_URLSchemeSelectsTransport(t *testing.T) {
	origServer, origHTTP, origToken := serverAddr, httpMode, authToken
	t.Cleanup(func() { serverAddr, httpMode, authToken = origServer, origHTTP, origToken })

	for _, tc := range []struct {
		name   string
		server string
		want   bool
	}{
		{"https URL selects HTTP", "https://cp.example.com", true},
		{"http URL selects HTTP", "http://host:8080", true},
		{"bare host:port stays gRPC", "10.0.0.5:50051", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverAddr = tc.server
			httpMode = false
			// Non-empty so the credentials-file lookup is skipped.
			authToken = "test-token"
			if err := rootCmd.PersistentPreRunE(rootCmd, nil); err != nil {
				t.Fatalf("PersistentPreRunE: %v", err)
			}
			if httpMode != tc.want {
				t.Errorf("--server %q: httpMode = %v, want %v", tc.server, httpMode, tc.want)
			}
		})
	}
}
