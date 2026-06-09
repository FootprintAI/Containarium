package reqrate

import "testing"

func TestParseHost(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		wantHost string
		wantOK   bool
	}{
		{
			name:     "typical caddy access record",
			line:     `{"level":"info","ts":1718000000.1,"logger":"http.log.access.log0","msg":"handled request","request":{"remote_ip":"203.0.113.7","method":"GET","host":"alice.example.com","uri":"/"},"status":200}`,
			wantHost: "alice.example.com",
			wantOK:   true,
		},
		{
			name:     "host carries a port",
			line:     `{"msg":"handled request","request":{"host":"bob.example.com:443"}}`,
			wantHost: "bob.example.com",
			wantOK:   true,
		},
		{
			name:     "uppercase host is lower-cased",
			line:     `{"request":{"host":"Carol.Example.COM"}}`,
			wantHost: "carol.example.com",
			wantOK:   true,
		},
		{
			name:   "not json",
			line:   `this is not json`,
			wantOK: false,
		},
		{
			name:   "json without a request host (e.g. a startup line)",
			line:   `{"level":"info","msg":"serving initial configuration"}`,
			wantOK: false,
		},
		{
			name:   "empty host",
			line:   `{"request":{"host":""}}`,
			wantOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, ok := ParseHost([]byte(tc.line))
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && host != tc.wantHost {
				t.Errorf("host = %q, want %q", host, tc.wantHost)
			}
		})
	}
}
