package config

import "testing"

func TestLoadJWTEmpty(t *testing.T) {
	for _, k := range []string{EnvJWTSecret, EnvJWTToken, EnvJWTTokenFile, EnvJWTAudience} {
		t.Setenv(k, "")
	}
	if got := LoadJWT(); got != (JWT{}) {
		t.Errorf("LoadJWT with empty env = %+v, want zero value", got)
	}
}

func TestLoadJWTReadsEnv(t *testing.T) {
	t.Setenv(EnvJWTSecret, "s3cr3t")
	t.Setenv(EnvJWTToken, "bearer-xyz")
	t.Setenv(EnvJWTTokenFile, "/run/jwt.token")
	t.Setenv(EnvJWTAudience, "containarium-api")

	want := JWT{Secret: "s3cr3t", Token: "bearer-xyz", TokenFile: "/run/jwt.token", Audience: "containarium-api"}
	if got := LoadJWT(); got != want {
		t.Errorf("LoadJWT = %+v, want %+v", got, want)
	}
}
