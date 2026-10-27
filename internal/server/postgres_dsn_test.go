package server

import (
	"testing"

	"github.com/jackc/pgx/v5"
)

// The daemon builds its Postgres URL from a password an operator chose. A
// password containing a character that is meaningful in a URL (@ / : # ? %)
// used to be pasted in raw, which either broke the URL or, worse, parsed as a
// different host or database. PostgresDSN escapes it, so the password pgx
// reads back is exactly the one that was given (#2091).
func TestPostgresDSN_PasswordSurvivesTheRoundTrip(t *testing.T) {
	passwords := []string{
		"plainAlnum123",
		"with@at",
		"slash/in/it",
		"colon:inside",
		"hash#tag",
		"q?mark",
		"percent%41sign",
		"all@/:#?%&=+ together",
		"üñíçødé",
	}
	for _, pw := range passwords {
		t.Run(pw, func(t *testing.T) {
			dsn := PostgresDSN("containarium", pw, "10.100.0.242", 5432, "containarium")

			cfg, err := pgx.ParseConfig(dsn)
			if err != nil {
				t.Fatalf("pgx could not parse %q: %v", dsn, err)
			}
			if cfg.Password != pw {
				t.Fatalf("password round-tripped as %q, want %q", cfg.Password, pw)
			}
			if cfg.User != "containarium" || cfg.Host != "10.100.0.242" || cfg.Port != 5432 || cfg.Database != "containarium" {
				t.Fatalf("a special character in the password changed another field: user=%q host=%q port=%d db=%q",
					cfg.User, cfg.Host, cfg.Port, cfg.Database)
			}
		})
	}
}

func TestPostgresDSN_KeepsTheLegacyShape(t *testing.T) {
	got := PostgresDSN("containarium", "containarium", "10.100.0.242", 5432, "containarium")
	want := "postgres://containarium:containarium@10.100.0.242:5432/containarium?sslmode=disable"
	if got != want {
		t.Fatalf("dsn = %q, want %q (existing hosts must keep the exact string they have today)", got, want)
	}
}

func TestPostgresDSN_UserIsEscapedToo(t *testing.T) {
	cfg, err := pgx.ParseConfig(PostgresDSN("odd@user", "pw", "10.100.0.242", 5432, "db"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.User != "odd@user" {
		t.Fatalf("user = %q", cfg.User)
	}
}
