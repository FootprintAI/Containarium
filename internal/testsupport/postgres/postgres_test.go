package postgres

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestValidateDSN(t *testing.T) {
	for _, tc := range []struct {
		name, dsn, force string
		ok               bool
	}{
		{"test database URL", "postgres://user@localhost/containarium_test", "", true},
		{"test prefix", "postgresql://user@localhost/test_2749", "", true},
		{"test token", "dbname=containarium-test-2749", "", true},
		{"keyword database", "dbname=containarium_test", "", true},
		{"URL application", "postgres://user@localhost/production?application_name=containarium-test", "", true},
		{"keyword application", "dbname=production application_name=containarium-test", "", true},
		{"unsafe", "postgres://user@localhost/production", "", false},
		{"substring is not identity", "dbname=contest", "", false},
		{"password is not identity", "postgres://user:containarium-test@localhost/production", "", false},
		{"application must match", "dbname=production application_name=containarium-test-other", "", false},
		{"force", "dbname=production", "1", true},
		{"force must be explicit", "dbname=production", "true", false},
		{"force still parses", "postgres://user@localhost:bad/production", "1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDSN(tc.dsn, tc.force)
			if (err == nil) != tc.ok {
				t.Fatalf("validateDSN = %v, want accepted=%v", err, tc.ok)
			}
		})
	}
}

func TestSchemaDSN(t *testing.T) {
	for _, dsn := range []string{
		"postgres://user:secret@localhost/containarium_test?search_path=public&application_name=containarium-test",
		"postgresql://user@localhost/containarium_test?search_path=public&search_path=other",
		"dbname=containarium_test user=user password='a b' search_path=public",
	} {
		cfg, err := pgx.ParseConfig(schemaDSN(dsn, "test_012345"))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.RuntimeParams["search_path"] != "test_012345" {
			t.Fatalf("search_path = %q", cfg.RuntimeParams["search_path"])
		}
		if cfg.Database != "containarium_test" || cfg.User != "user" {
			t.Fatal("connection identity changed")
		}
	}
}

func TestRunRejectsUnsafeBeforeConnecting(t *testing.T) {
	t.Setenv(dsnEnv, "postgres://user@127.0.0.1:1/production")
	t.Setenv(forceEnv, "")
	called := false
	if code := Run(func() int { called = true; return 0 }); code != 1 || called {
		t.Fatalf("code=%d, tests ran=%v", code, called)
	}
}

func TestRunWithoutDSN(t *testing.T) {
	t.Setenv(dsnEnv, "")
	if code := Run(func() int { return 7 }); code != 7 {
		t.Fatalf("code=%d", code)
	}
}

func TestSchemaIsolationAndCleanup(t *testing.T) {
	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		t.Skip("set CONTAINARIUM_TEST_DSN for PostgreSQL isolation coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const runs = 4
	schemas := make([]string, runs)
	var wg sync.WaitGroup
	for i := range runs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scoped, cleanup, err := newSchema(ctx, dsn, "")
			if err != nil {
				t.Error(err)
				return
			}
			defer func() {
				if err := cleanup(); err != nil {
					t.Error(err)
				}
			}()
			conn, err := pgx.Connect(ctx, scoped)
			if err != nil {
				t.Error(err)
				return
			}
			defer func() { _ = conn.Close(context.Background()) }()
			if err := conn.QueryRow(ctx, "SELECT current_schema()").Scan(&schemas[i]); err != nil {
				t.Error(err)
				return
			}
			if _, err := conn.Exec(ctx, "CREATE TABLE isolation_probe (id int); INSERT INTO isolation_probe VALUES (1); TRUNCATE isolation_probe; INSERT INTO isolation_probe VALUES (2)"); err != nil {
				t.Error(err)
				return
			}
			var id int
			if err := conn.QueryRow(ctx, "SELECT id FROM isolation_probe").Scan(&id); err != nil || id != 2 {
				t.Errorf("own row = %d, error=%v", id, err)
			}
		}()
	}
	wg.Wait()
	if t.Failed() {
		return
	}
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(context.Background()) }()
	seen := map[string]bool{}
	for _, schema := range schemas {
		if !strings.HasPrefix(schema, "test_") || seen[schema] {
			t.Fatalf("invalid or reused schema %q", schema)
		}
		seen[schema] = true
		var exists bool
		if err := admin.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname=$1)", schema).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists {
			t.Errorf("schema %q was not cleaned up", schema)
		}
	}
}

func TestRunCleansUpAfterFailure(t *testing.T) {
	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		t.Skip("set CONTAINARIUM_TEST_DSN for PostgreSQL cleanup coverage")
	}
	t.Setenv(dsnEnv, dsn)
	t.Setenv(forceEnv, "")
	var schema string
	code := Run(func() int {
		conn, err := pgx.Connect(context.Background(), os.Getenv(dsnEnv))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close(context.Background()) }()
		if err := conn.QueryRow(context.Background(), "SELECT current_schema()").Scan(&schema); err != nil {
			t.Fatal(err)
		}
		return 7
	})
	if code != 7 {
		t.Fatalf("failed test exit code changed: %d", code)
	}
	if os.Getenv(dsnEnv) != dsn {
		t.Fatal("DSN was not restored")
	}
	conn, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	var exists bool
	if err := conn.QueryRow(context.Background(), "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname=$1)", schema).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("failed run left its schema behind")
	}
}
