//go:build integration

// Integration coverage for the restore test (#1159), run against real
// Postgres containers rather than the in-memory fake.
//
// The unit tests in verify_test.go pin the orchestration: what gets
// created, what gets dropped, what is refused. They cannot show that the
// dump a real pg_dump produces is loadable by a real pg_restore, which is
// the entire claim `backup verify` makes. This file does.
//
//	go test -tags=integration ./pkg/core/backup/ -run TestIntegrationVerify -v
//
// Requires podman (or docker via CONTAINARIUM_TEST_RUNTIME=docker) on
// PATH. Containers are disposable and removed on teardown.
package backup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// podmanOps implements ContainerOps against real containers, so the
// manager under test runs the same pg_dump / pg_restore / psql commands
// it would run in production.
type podmanOps struct {
	t       *testing.T
	runtime string
}

func (p *podmanOps) run(container string, stdin []byte, command []string) (string, string, error) {
	args := []string{"exec"}
	if stdin != nil {
		args = append(args, "-i")
	}
	args = append(args, container)
	args = append(args, command...)

	cmd := exec.Command(p.runtime, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func (p *podmanOps) Exec(container string, command []string) error {
	_, _, err := p.run(container, nil, command)
	return err
}

func (p *podmanOps) ExecWithOutput(container string, command []string) (string, string, error) {
	return p.run(container, nil, command)
}

func (p *podmanOps) ReadFile(container, path string) ([]byte, error) {
	cmd := exec.Command(p.runtime, "exec", container, "cat", path)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func (p *podmanOps) WriteFile(container, path string, content []byte, _ string) error {
	_, stderr, err := p.run(container, content, []string{"sh", "-c", "cat > " + path})
	if err != nil {
		p.t.Logf("WriteFile stderr: %s", stderr)
	}
	return err
}

func runtimeBin(t *testing.T) string {
	bin := os.Getenv("CONTAINARIUM_TEST_RUNTIME")
	if bin == "" {
		bin = "podman"
	}
	if _, err := exec.LookPath(bin); err != nil {
		t.Skipf("%s not on PATH; skipping integration test", bin)
	}
	return bin
}

// startPostgres launches a disposable Postgres and waits for it to accept
// connections. Registers its own teardown.
func startPostgres(t *testing.T, rt, name string) {
	t.Helper()
	_ = exec.Command(rt, "rm", "-f", name).Run()

	out, err := exec.Command(rt, "run", "-d", "--name", name,
		"-e", "POSTGRES_HOST_AUTH_METHOD=trust",
		"-e", "POSTGRES_PASSWORD=unused",
		"docker.io/library/postgres:16-alpine").CombinedOutput()
	if err != nil {
		t.Skipf("could not start %s (%v): %s", name, err, out)
	}
	t.Cleanup(func() { _ = exec.Command(rt, "rm", "-f", name).Run() })

	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if err := exec.Command(rt, "exec", name, "pg_isready", "-U", "postgres").Run(); err == nil {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("%s never became ready", name)
}

// TestIntegrationVerifyAgainstRealPostgres is the end-to-end claim: a
// dump taken from a real database restores into a throwaway target and
// passes its checks, and the source database is left untouched.
func TestIntegrationVerifyAgainstRealPostgres(t *testing.T) {
	rt := runtimeBin(t)
	const src, tgt = "containarium-verify-src", "containarium-verify-tgt"
	startPostgres(t, rt, src)
	startPostgres(t, rt, tgt)

	ops := &podmanOps{t: t, runtime: rt}

	// Seed the source with a table and a known row count.
	seed := `CREATE DATABASE app;
\c app
CREATE TABLE widgets (id serial PRIMARY KEY, name text);
INSERT INTO widgets (name) SELECT 'w' || g FROM generate_series(1,25) g;`
	if _, stderr, err := ops.run(src, []byte(seed), []string{"psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1"}); err != nil {
		t.Fatalf("seed source: %v: %s", err, stderr)
	}

	m := NewManager(ops, nil, t.TempDir())
	rec, err := m.Create(CreateOptions{
		Username:      "alice",
		ContainerName: src,
		Conn:          PgConn{Database: "app"},
		Destination:   DestLocal,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Logf("created backup %s (%d bytes, sha %s)", rec.ID, rec.SizeBytes, rec.SHA256[:12])

	// The manifest must reflect the one user table seeded above, not the
	// ~60 system catalog relations every database carries.
	if rec.RelationCount == nil {
		t.Fatal("no relation manifest recorded at backup time")
	}
	if *rec.RelationCount != 1 {
		t.Errorf("manifest = %d user relations, want 1 (system catalogs must be excluded)", *rec.RelationCount)
	}
	t.Logf("manifest: %d user relation(s) at dump time", *rec.RelationCount)

	v, err := m.Verify(VerifyOptions{
		ID:              rec.ID,
		TargetContainer: tgt,
		SourceContainer: src,
		VerifiedBy:      "integration-test",
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	for _, c := range v.Checks {
		t.Logf("  check %-18s passed=%t  %s", c.Name, c.Passed, c.Detail)
	}
	if v.Result != VerificationPassed {
		t.Fatalf("result = %q, error = %q", v.Result, v.Error)
	}

	// The scratch database must be gone from the target.
	stdout, _, err := ops.ExecWithOutput(tgt, []string{
		"psql", "-U", "postgres", "-d", "postgres", "-Atc",
		"SELECT count(*) FROM pg_database WHERE datname = '" + v.ScratchDatabase + "';",
	})
	if err != nil {
		t.Fatalf("scratch lookup: %v", err)
	}
	if got := strings.TrimSpace(stdout); got != "0" {
		t.Errorf("scratch database %s survived verification (count=%s)", v.ScratchDatabase, got)
	}

	// The source database must be untouched: same row count as seeded.
	stdout, _, err = ops.ExecWithOutput(src, []string{
		"psql", "-U", "postgres", "-d", "app", "-Atc", "SELECT count(*) FROM widgets;",
	})
	if err != nil {
		t.Fatalf("source row count: %v", err)
	}
	if got := strings.TrimSpace(stdout); got != "25" {
		t.Errorf("source row count = %s, want 25 — verification touched the source", got)
	}
}

// TestIntegrationVerifyDetectsManifestShortfall is the check the checksum
// cannot make, against a real engine: a dump that restores perfectly but
// carries fewer tables than the source had must fail verification.
//
// The dump here is a genuine, valid pg_dump archive — it loads without a
// single engine error. Only the comparison against the manifest catches
// it, which is exactly the truncated-export case from the issue.
func TestIntegrationVerifyDetectsManifestShortfall(t *testing.T) {
	rt := runtimeBin(t)
	const src, tgt = "containarium-verify-src3", "containarium-verify-tgt3"
	startPostgres(t, rt, src)
	startPostgres(t, rt, tgt)

	ops := &podmanOps{t: t, runtime: rt}

	// Source has three tables.
	seed := `CREATE DATABASE app;
\c app
CREATE TABLE a (id int);
CREATE TABLE b (id int);
CREATE TABLE c (id int);`
	if _, stderr, err := ops.run(src, []byte(seed), []string{"psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1"}); err != nil {
		t.Fatalf("seed source: %v: %s", err, stderr)
	}

	m := NewManager(ops, nil, t.TempDir())
	rec, err := m.Create(CreateOptions{
		Username:      "alice",
		ContainerName: src,
		Conn:          PgConn{Database: "app"},
		Destination:   DestLocal,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if rec.RelationCount == nil || *rec.RelationCount != 3 {
		t.Fatalf("manifest = %v, want 3", rec.RelationCount)
	}

	// Now swap in a valid dump of a *smaller* database — a dump that is
	// perfectly well-formed and will restore without error, but is
	// short. This is a truncated export in effect.
	partial := `CREATE DATABASE partial;
\c partial
CREATE TABLE a (id int);`
	if _, stderr, err := ops.run(src, []byte(partial), []string{"psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1"}); err != nil {
		t.Fatalf("seed partial: %v: %s", err, stderr)
	}
	if _, stderr, err := ops.ExecWithOutput(src, []string{
		"bash", "-c", "pg_dump -U postgres -d partial -Fc -f /tmp/partial.dump",
	}); err != nil {
		t.Fatalf("dump partial: %v: %s", err, stderr)
	}
	partialBytes, err := ops.ReadFile(src, "/tmp/partial.dump")
	if err != nil {
		t.Fatalf("read partial dump: %v", err)
	}
	if err := os.WriteFile(rec.Location, partialBytes, 0o600); err != nil {
		t.Fatalf("swap dump: %v", err)
	}
	rec.SHA256 = sha256Hex(partialBytes)
	if err := m.writeSidecar(rec); err != nil {
		t.Fatalf("rewrite sidecar: %v", err)
	}

	v, err := m.Verify(VerifyOptions{
		ID:              rec.ID,
		TargetContainer: tgt,
		SourceContainer: src,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	for _, c := range v.Checks {
		t.Logf("  check %-18s passed=%t  %s", c.Name, c.Passed, c.Detail)
	}
	if v.Result != VerificationFailed {
		t.Fatalf("a short dump must fail verification, got %q", v.Result)
	}
	if !strings.Contains(v.Error, "incomplete") {
		t.Errorf("error should name the shortfall, got %q", v.Error)
	}
}

// TestIntegrationVerifyCapturesRealEngineError is AC #2 against a real
// engine: a dump that is not a valid archive fails verification with
// pg_restore's own message, and does not error the call.
func TestIntegrationVerifyCapturesRealEngineError(t *testing.T) {
	rt := runtimeBin(t)
	const src, tgt = "containarium-verify-src2", "containarium-verify-tgt2"
	startPostgres(t, rt, src)
	startPostgres(t, rt, tgt)

	ops := &podmanOps{t: t, runtime: rt}
	if _, stderr, err := ops.run(src, []byte("CREATE DATABASE app;"), []string{"psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1"}); err != nil {
		t.Fatalf("seed source: %v: %s", err, stderr)
	}

	dir := t.TempDir()
	m := NewManager(ops, nil, dir)
	rec, err := m.Create(CreateOptions{
		Username:      "alice",
		ContainerName: src,
		Conn:          PgConn{Database: "app"},
		Destination:   DestLocal,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Replace the dump with bytes that are not a pg archive, and update
	// the recorded checksum so the integrity gate passes and the failure
	// has to come from the engine itself — the "hashes fine, will not
	// restore" case the issue is about.
	garbage := []byte("this is not a postgres custom-format archive")
	if err := os.WriteFile(rec.Location, garbage, 0o600); err != nil {
		t.Fatalf("overwrite dump: %v", err)
	}
	rec.SHA256 = sha256Hex(garbage)
	if err := m.writeSidecar(rec); err != nil {
		t.Fatalf("rewrite sidecar: %v", err)
	}

	v, err := m.Verify(VerifyOptions{
		ID:              rec.ID,
		TargetContainer: tgt,
		SourceContainer: src,
	})
	if err != nil {
		t.Fatalf("an unrestorable dump must be a recorded failure, not an error: %v", err)
	}
	if v.Result != VerificationFailed {
		t.Fatalf("result = %q, want failed", v.Result)
	}
	t.Logf("captured engine error: %s", v.Error)
	if !strings.Contains(strings.ToLower(v.Error), "pg_restore") {
		t.Errorf("engine's own error not captured, got %q", v.Error)
	}
}
