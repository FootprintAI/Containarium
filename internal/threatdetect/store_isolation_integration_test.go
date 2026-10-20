//go:build integration

package threatdetect

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
)

// Exercise separate test binaries: each setup used to drop the other run's
// security_findings table, even when both used the same disposable test database.
func TestStoreRunsAreIsolated(t *testing.T) {
	pool := threatdetectPool(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `CREATE TABLE security_findings (id text); INSERT INTO security_findings VALUES ('parent')`); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const children = 2
	var wg sync.WaitGroup
	outputs := make([][]byte, children)
	errs := make([]error, children)
	for i := range children {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.Command(exe, "-test.run=^TestStoreIsolationChild$", "-test.timeout=30s")
			cmd.Env = append(os.Environ(), "CONTAINARIUM_ISOLATION_CHILD=1")
			outputs[i], errs[i] = cmd.CombinedOutput()
		}()
	}
	wg.Wait()
	for i := range children {
		if errs[i] != nil {
			t.Errorf("child %d: %v\n%s", i, errs[i], outputs[i])
		}
		for _, line := range strings.Split(string(outputs[i]), "\n") {
			if schema, ok := strings.CutPrefix(line, "isolation-schema="); ok {
				var exists bool
				if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname=$1)`, schema).Scan(&exists); err != nil {
					t.Fatal(err)
				}
				if exists {
					t.Errorf("child schema %q remains after process exit", schema)
				}
			}
		}
	}
	var id string
	if err := pool.QueryRow(ctx, `SELECT id FROM security_findings`).Scan(&id); err != nil {
		t.Fatalf("another test process modified this run's table: %v", err)
	}
	if id != "parent" {
		t.Fatalf("another test process replaced this run's row: %q", id)
	}
}

func TestStoreIsolationChild(t *testing.T) {
	if os.Getenv("CONTAINARIUM_ISOLATION_CHILD") != "1" {
		return
	}
	pool := threatdetectPool(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `CREATE TABLE security_findings (id text); INSERT INTO security_findings VALUES ('child'); TRUNCATE security_findings`); err != nil {
		t.Fatal(err)
	}
	var schema string
	if err := pool.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	fmt.Println("isolation-schema=" + schema)
}
