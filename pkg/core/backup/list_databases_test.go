package backup

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// #3600: database discovery tells "no Postgres answered" and "it answered
// with no database" apart from a platform fault.

// shellOps runs ListDatabases' command with the local bash, the way the
// container exec runs it, with only binDir on PATH: a test puts a stand-in
// psql there, or none. A non-zero exit is an error the way the Incus client
// reports one. execErr, when set, is a failure to run the command at all.
type shellOps struct {
	*fakeOps
	binDir  string
	execErr error
}

func (o *shellOps) ExecWithOutput(_ string, command []string) (string, string, error) {
	if o.execErr != nil {
		return "", "", o.execErr
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		return "", "", err
	}
	cmd := exec.Command(bash, command[1:]...) // #nosec G204 -- the test's own command
	cmd.Env = []string{"PATH=" + o.binDir}
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return stdout.String(), stderr.String(), fmt.Errorf("command exited with code %d", ee.ExitCode())
		}
		return "", "", err
	}
	return stdout.String(), stderr.String(), nil
}

// newShellOps returns a shellOps whose PATH holds a psql that prints stdout,
// prints stderr and exits with code; withPsql false leaves psql out.
func newShellOps(t *testing.T, withPsql bool, stdout, stderr string, code int) *shellOps {
	t.Helper()
	dir := t.TempDir()
	if withPsql {
		script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' '%s'\nprintf '%%s\\n' '%s' >&2\nexit %d\n", stdout, stderr, code)
		if err := os.WriteFile(filepath.Join(dir, "psql"), []byte(script), 0o700); err != nil { // #nosec G306 -- a test executable
			t.Fatal(err)
		}
	}
	return &shellOps{fakeOps: newFakeOps(nil), binDir: dir}
}

func TestListDatabases_UnavailableWhenNoPostgresAnswers(t *testing.T) {
	for _, tc := range []struct {
		name     string
		withPsql bool
		stderr   string
		code     int
	}{
		{"connection refused (psql exit 2)", true, `psql: error: connection to server at "127.0.0.1", port 5432 failed: Connection refused`, 2},
		{"authentication failed (psql exit 2)", true, `psql: error: FATAL:  password authentication failed for user "postgres"`, 2},
		{"no psql in the container (exit 127)", false, "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ops := newShellOps(t, tc.withPsql, "", tc.stderr, tc.code)
			_, err := newTestManager(t, ops).ListDatabases("alice-container", PgConn{})
			if !errors.Is(err, ErrDatabaseUnavailable) {
				t.Fatalf("err = %v, want ErrDatabaseUnavailable", err)
			}
			if tc.stderr != "" && !strings.Contains(err.Error(), tc.stderr) {
				t.Errorf("err = %q, want it to carry psql's stderr for the daemon log", err)
			}
			if strings.Contains(err.Error(), listDatabasesExitMarker) {
				t.Errorf("err = %q still holds the exit marker", err)
			}
		})
	}
}

// psql failing for another reason, or the exec itself failing, is not "no
// Postgres": it stays a plain error, which the server reports as a fault.
func TestListDatabases_OtherFailuresAreNotUnavailable(t *testing.T) {
	t.Run("psql exit 1", func(t *testing.T) {
		ops := newShellOps(t, true, "", "psql: error: out of memory", 1)
		_, err := newTestManager(t, ops).ListDatabases("alice-container", PgConn{})
		if err == nil || errors.Is(err, ErrDatabaseUnavailable) {
			t.Fatalf("err = %v, want a plain error", err)
		}
		if !strings.Contains(err.Error(), "out of memory") || strings.Contains(err.Error(), listDatabasesExitMarker) {
			t.Errorf("err = %q, want psql's stderr without the marker", err)
		}
	})
	t.Run("exec failed", func(t *testing.T) {
		ops := newShellOps(t, true, "", "", 0)
		ops.execErr = errors.New("failed to execute command: instance is not running")
		_, err := newTestManager(t, ops).ListDatabases("alice-container", PgConn{})
		if err == nil || errors.Is(err, ErrDatabaseUnavailable) {
			t.Fatalf("err = %v, want a plain error", err)
		}
	})
}

func TestListDatabases_SuccessThroughTheShell(t *testing.T) {
	ops := newShellOps(t, true, "app\nanalytics\n", "", 0)
	dbs, err := newTestManager(t, ops).ListDatabases("alice-container", PgConn{Password: "pw"})
	if err != nil {
		t.Fatalf("ListDatabases: %v", err)
	}
	if strings.Join(dbs, ",") != "app,analytics" {
		t.Errorf("dbs = %v, want app, analytics", dbs)
	}
}

func TestCreateAll_TypedErrorsWhenNothingCanBeBackedUp(t *testing.T) {
	t.Run("no Postgres", func(t *testing.T) {
		ops := newShellOps(t, false, "", "", 0)
		records, errs := newTestManager(t, ops).CreateAll(CreateOptions{Username: "alice", ContainerName: "alice-container", Destination: DestLocal})
		if len(records) != 0 || len(errs) != 1 || !errors.Is(errs[0], ErrDatabaseUnavailable) {
			t.Fatalf("records = %v, errs = %v; want one ErrDatabaseUnavailable", records, errs)
		}
	})
	t.Run("no database", func(t *testing.T) {
		ops := newFakeOps(nil)
		records, errs := newTestManager(t, ops).CreateAll(CreateOptions{Username: "alice", ContainerName: "alice-container", Destination: DestLocal})
		if len(records) != 0 || len(errs) != 1 || !errors.Is(errs[0], ErrNoDatabaseFound) {
			t.Fatalf("records = %v, errs = %v; want one ErrNoDatabaseFound", records, errs)
		}
	})
	t.Run("other listing failure", func(t *testing.T) {
		ops := newFakeOps(nil)
		ops.listDatabasesErr = errExec
		_, errs := newTestManager(t, ops).CreateAll(CreateOptions{Username: "alice", ContainerName: "alice-container", Destination: DestLocal})
		if len(errs) != 1 || errors.Is(errs[0], ErrDatabaseUnavailable) || errors.Is(errs[0], ErrNoDatabaseFound) {
			t.Fatalf("errs = %v, want one untyped error", errs)
		}
	})
}

func TestSplitListDatabasesExit(t *testing.T) {
	rest, code, ok := splitListDatabasesExit("psql: error: refused\n" + listDatabasesExitMarker + "2\n")
	if !ok || code != 2 || rest != "psql: error: refused" {
		t.Errorf("= %q, %d, %v; want the stderr without the marker, 2, true", rest, code, ok)
	}
	if _, _, ok := splitListDatabasesExit("exec failed"); ok {
		t.Error("no marker reported as one")
	}
	if _, _, ok := splitListDatabasesExit(listDatabasesExitMarker + "x"); ok {
		t.Error("a marker without a number reported as one")
	}
}
