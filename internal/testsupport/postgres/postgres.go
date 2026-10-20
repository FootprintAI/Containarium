// Package postgres isolates PostgreSQL-backed test binaries. It is test support
// only; production connection configuration must not use this package.
package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const dsnEnv = "CONTAINARIUM_TEST_DSN"
const forceEnv = "CONTAINARIUM_TEST_DSN_FORCE"

var testDatabase = regexp.MustCompile(`(^|[_-])test([_-]|$)`)

// Run is called by TestMain before any test can connect. Every package binary
// gets its own schema, including concurrent invocations of the same package.
// Updating the process-local DSN also isolates reconnects and restart tests.
// An unset DSN retains the package's existing skip/fail behavior.
func Run(run func() int) int {
	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		return run()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	scoped, cleanup, err := newSchema(ctx, dsn, os.Getenv(forceEnv))
	cancel()
	if err != nil {
		fmt.Fprintln(os.Stderr, "PostgreSQL test setup:", err)
		return 1
	}
	if err := os.Setenv(dsnEnv, scoped); err != nil {
		fmt.Fprintln(os.Stderr, "set isolated test DSN:", err)
		if err := cleanup(); err != nil {
			fmt.Fprintln(os.Stderr, "PostgreSQL test cleanup:", err)
		}
		return 1
	}
	code := run()
	if err := os.Setenv(dsnEnv, dsn); err != nil {
		fmt.Fprintln(os.Stderr, "restore test DSN:", err)
		code = 1
	}
	if err := cleanup(); err != nil {
		fmt.Fprintln(os.Stderr, "PostgreSQL test cleanup:", err)
		code = 1
	}
	return code
}

// FORCE bypasses identity validation only. Parsing, schema isolation, and
// cleanup still apply. A marker is a database-name token "test" (for example
// containarium_test) or the exact application_name "containarium-test".
func validateDSN(dsn, force string) error {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return errors.New("invalid PostgreSQL test DSN")
	}
	if force != "1" && !testDatabase.MatchString(strings.ToLower(cfg.Database)) && cfg.RuntimeParams["application_name"] != "containarium-test" {
		return errors.New("refusing unsafe CONTAINARIUM_TEST_DSN: use a test database name or application_name=containarium-test (CONTAINARIUM_TEST_DSN_FORCE=1 bypasses identity validation only)")
	}
	return nil
}

func schemaDSN(dsn, schema string) string {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, _ := url.Parse(dsn) // validateDSN has already parsed the connection string.
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		return u.String()
	}
	// The last keyword wins. schema is generated from a fixed prefix and hex.
	return dsn + " search_path=" + schema
}

func newSchema(ctx context.Context, dsn, force string) (string, func() error, error) {
	if err := validateDSN(dsn, force); err != nil {
		return "", nil, err
	}
	var suffix [16]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", nil, fmt.Errorf("schema name: %w", err)
	}
	schema := "test_" + hex.EncodeToString(suffix[:])
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return "", nil, fmt.Errorf("connect test database: %w", err)
	}
	closeAdmin := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = admin.Close(ctx)
	}
	ident := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+ident); err != nil {
		closeAdmin()
		return "", nil, fmt.Errorf("create test schema: %w", err)
	}
	cleanup := func() error {
		defer closeAdmin()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err := admin.Exec(ctx, "DROP SCHEMA "+ident+" CASCADE")
		return err
	}
	return schemaDSN(dsn, schema), cleanup, nil
}
