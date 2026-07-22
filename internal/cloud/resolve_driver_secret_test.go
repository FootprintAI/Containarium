package cloud

import (
	"errors"
	"testing"
)

// TestResolveDriverSecretFile pins the cloud#888/#903 postmortem semantics:
// an EMPTY jwt_secret_file (what every pre-#557 enroll wrote) must fall back
// to the default daemon secret rather than silently disabling refresh — that
// silence is exactly how legacy hosts' cloud-stored driver tokens expired at
// the 30-day cap unnoticed. Only the explicit driver_token_disabled marker
// opts out.
func TestResolveDriverSecretFile(t *testing.T) {
	exists := func(string) error { return nil }
	missing := func(string) error { return errors.New("no such file") }

	cases := []struct {
		name string
		cfg  *Config
		stat func(string) error
		want string
	}{
		{"explicit path wins without stat", &Config{JWTSecretFile: "/custom/jwt.secret"}, missing, "/custom/jwt.secret"},
		{"legacy empty falls back to default when readable", &Config{}, exists, DefaultDaemonJWTSecretFile},
		{"legacy empty with no default file resolves empty", &Config{}, missing, ""},
		{"explicit opt-out beats an existing default", &Config{DriverTokenDisabled: true}, exists, ""},
		{"explicit opt-out beats an explicit path", &Config{DriverTokenDisabled: true, JWTSecretFile: "/custom/jwt.secret"}, exists, ""},
		{"nil config resolves empty", nil, exists, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ResolveDriverSecretFile(c.cfg, c.stat); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

// TestConfigRoundTripsDriverTokenDisabled: the durable --no-driver-token
// marker must survive a Save/Load cycle, or the daemon's fallback would
// re-enable drivability on the next restart against the operator's choice.
func TestConfigRoundTripsDriverTokenDisabled(t *testing.T) {
	path := t.TempDir() + "/cloud.yaml"
	in := &Config{
		ControlPlane:        "https://cp.example.com",
		HostID:              "0f000000-0000-0000-0000-000000000001",
		Token:               "0f000000-0000-0000-0000-000000000001.secret",
		DriverTokenDisabled: true,
	}
	if err := Save(path, in); err != nil {
		t.Fatalf("save: %v", err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if out == nil || !out.DriverTokenDisabled {
		t.Fatalf("DriverTokenDisabled lost in round-trip: %+v", out)
	}
}
