package backup

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// VerificationResult is the outcome of a restore test. Kept as a string
// in the core so the package stays free of the pb dependency; the server
// maps it to/from pb.VerificationResult.
type VerificationResult string

const (
	VerificationPassed VerificationResult = "passed"
	VerificationFailed VerificationResult = "failed"
)

// Check is one engine-appropriate assertion made during a restore test,
// recorded individually so the evidence shows *what* was checked rather
// than just a pass/fail bit.
type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// Verification is the audit artifact for one restore test: who ran it,
// when, against what, and what the engine said. Persisted on the Record
// so the evidence outlives the run that produced it.
type Verification struct {
	VerifiedAt      time.Time          `json:"verified_at"`
	Result          VerificationResult `json:"result"`
	Error           string             `json:"error,omitempty"`
	TargetContainer string             `json:"target_container"`
	ScratchDatabase string             `json:"scratch_database"`
	DurationMS      int64              `json:"duration_ms"`
	VerifiedBy      string             `json:"verified_by,omitempty"`
	Checks          []Check            `json:"checks,omitempty"`
}

// VerifyOptions parameterizes a restore test.
type VerifyOptions struct {
	// ID of the backup to verify.
	ID string
	// TargetContainer is the throwaway container the dump is restored
	// into. Required, and must differ from SourceContainer.
	TargetContainer string
	// SourceContainer is the container the backup was taken from,
	// resolved by the caller. Verification refuses to run when it
	// matches TargetContainer — a restore test must never be able to
	// load a dump over the database it came from.
	SourceContainer string
	// Conn is the target container's Postgres connection. Conn.Database
	// is ignored: the scratch database name is generated here.
	Conn PgConn
	// VerifiedBy is the authenticated subject requesting the test, for
	// the "who" half of the audit record.
	VerifiedBy string
}

// scratchPrefix marks the throwaway databases verification creates, so a
// leaked one is identifiable on sight during an incident.
const scratchPrefix = "containarium_verify_"

// maxIdentLen is Postgres's identifier limit; a longer name is silently
// truncated by the server, which would break the DROP that pairs with the
// CREATE. Truncate deliberately instead.
const maxIdentLen = 63

// Verify restore-tests a stored dump against a throwaway database inside
// TargetContainer and records the outcome on the backup record.
//
// An unrestorable dump is a *result*, not an error: it comes back as a
// Verification with Result == VerificationFailed and the engine's own
// message in Error. A non-nil error means the test could not be run at
// all (unknown backup, missing or unsafe target) — that distinction is
// what lets a scheduled verification report "backup X is not restorable"
// instead of failing like a broken job.
func (m *Manager) Verify(opts VerifyOptions) (*Verification, error) {
	r, err := m.Get(opts.ID)
	if err != nil {
		return nil, err
	}
	if opts.TargetContainer == "" {
		return nil, fmt.Errorf("target container is required: a restore test needs a throwaway container to load into")
	}
	// The whole control depends on this: a restore test that can reach
	// the source container is a destructive operation wearing a
	// read-only name. Fail closed, before anything runs.
	if opts.TargetContainer == opts.SourceContainer {
		return nil, fmt.Errorf(
			"verification target %q must differ from the source container: a restore test must never load a dump over the database it came from",
			opts.TargetContainer)
	}

	started := m.now()
	conn := opts.Conn.withDefaults()
	scratch := scratchName(r.ID)

	v := &Verification{
		Result:          VerificationPassed,
		TargetContainer: opts.TargetContainer,
		ScratchDatabase: scratch,
		VerifiedBy:      opts.VerifiedBy,
	}
	fail := func(check, detail string) {
		v.Result = VerificationFailed
		if v.Error == "" {
			v.Error = detail
		}
		v.Checks = append(v.Checks, Check{Name: check, Passed: false, Detail: detail})
	}
	pass := func(check, detail string) {
		v.Checks = append(v.Checks, Check{Name: check, Passed: true, Detail: detail})
	}

	// 1. Integrity — a corrupt dump never reaches the engine.
	data, err := m.fetchDump(r)
	if err != nil {
		fail("integrity", err.Error())
		return m.commitVerification(r, v, started)
	}
	pass("integrity", fmt.Sprintf("sha256 matches recorded checksum (%d bytes)", len(data)))

	// 2. Create the throwaway database in the target container.
	if _, stderr, err := m.ops.ExecWithOutput(opts.TargetContainer,
		wrapPg(conn.Password, psqlCmd(conn, "postgres", fmt.Sprintf("CREATE DATABASE %s", quoteIdent(scratch))))); err != nil {
		fail("scratch_database", fmt.Sprintf("could not create scratch database: %s", engineErr(stderr, err)))
		return m.commitVerification(r, v, started)
	}
	pass("scratch_database", "created "+scratch)

	// The scratch database is dropped on every path out from here —
	// including a failed restore — so the target is left as found.
	defer func() {
		_, _, _ = m.ops.ExecWithOutput(opts.TargetContainer,
			wrapPg(conn.Password, psqlCmd(conn, "postgres", fmt.Sprintf("DROP DATABASE IF EXISTS %s", quoteIdent(scratch)))))
	}()

	// 3. Load the dump into the scratch database.
	inContainerPath := "/tmp/containarium-verify-" + r.ID + ".dump"
	if err := m.ops.WriteFile(opts.TargetContainer, inContainerPath, data, "0600"); err != nil {
		fail("restore", fmt.Sprintf("could not push dump into target container: %v", err))
		return m.commitVerification(r, v, started)
	}
	defer func() { _ = m.ops.Exec(opts.TargetContainer, []string{"rm", "-f", inContainerPath}) }()

	restoreScript := fmt.Sprintf(
		"pg_restore -h %s -p %d -U %s -d %s %s",
		shellQuote(conn.Host), conn.Port, shellQuote(conn.User),
		shellQuote(scratch), shellQuote(inContainerPath),
	)
	if _, stderr, err := m.ops.ExecWithOutput(opts.TargetContainer, wrapPg(conn.Password, restoreScript)); err != nil {
		fail("restore", engineErr(stderr, err))
		return m.commitVerification(r, v, started)
	}
	pass("restore", "dump loaded into "+scratch)

	// 4. Compare what landed against the manifest recorded at dump time.
	//    This is the check the integrity hash cannot make: a truncated
	//    export hashes perfectly and restores without complaint, and only
	//    shows up as a shortfall against the source's own relation count.
	count, err := m.countUserRelations(opts.TargetContainer, conn, scratch)
	if err != nil {
		fail("relation_count", fmt.Sprintf("could not query restored schema: %v", err))
		return m.commitVerification(r, v, started)
	}
	switch {
	case r.RelationCount == nil:
		// Backups taken before verification existed carry no manifest.
		// Record what we found — that is still evidence — but do not
		// invent a threshold to judge it against.
		pass("relation_count", fmt.Sprintf(
			"%d user relations restored (no manifest recorded at backup time — nothing to compare against)", count))
	case count != *r.RelationCount:
		fail("relation_count", fmt.Sprintf(
			"restored schema has %d user relations, but the source had %d at dump time — the dump is incomplete",
			count, *r.RelationCount))
		return m.commitVerification(r, v, started)
	default:
		pass("relation_count", fmt.Sprintf("%d user relations, matching the source at dump time", count))
	}

	return m.commitVerification(r, v, started)
}

// commitVerification stamps the timing fields, persists the evidence onto
// the record's sidecar, and returns it. Called on every exit path so a
// failed test is recorded just as durably as a passing one — evidence
// that only survives success is not evidence.
func (m *Manager) commitVerification(r *Record, v *Verification, started time.Time) (*Verification, error) {
	v.VerifiedAt = m.now().UTC()
	v.DurationMS = v.VerifiedAt.Sub(started.UTC()).Milliseconds()

	r.LastVerification = v
	if err := m.writeSidecar(r); err != nil {
		return v, fmt.Errorf("verification ran but its evidence could not be recorded: %w", err)
	}
	return v, nil
}

// userRelationQuery counts tables and partitioned tables belonging to the
// *user's* schemas.
//
// Counting pg_class unfiltered is useless here: every database, however
// empty, carries ~60 system catalog relations, so an unfiltered count can
// never reach zero and a check against it would pass for a dump that
// restored nothing at all. Excluding pg_catalog / information_schema /
// pg_toast is what makes the number mean "the tenant's data".
const userRelationQuery = `SELECT count(*) FROM pg_class c ` +
	`JOIN pg_namespace n ON n.oid = c.relnamespace ` +
	`WHERE c.relkind IN ('r','p') ` +
	`AND n.nspname NOT IN ('pg_catalog','information_schema') ` +
	`AND n.nspname !~ '^pg_toast';`

// countUserRelations runs userRelationQuery against db inside container.
func (m *Manager) countUserRelations(container string, conn PgConn, db string) (int64, error) {
	stdout, stderr, err := m.ops.ExecWithOutput(container, wrapPg(conn.Password, psqlCmd(conn, db, userRelationQuery)))
	if err != nil {
		return 0, fmt.Errorf("%s", engineErr(stderr, err))
	}
	n, err := strconv.ParseInt(strings.TrimSpace(stdout), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("unreadable relation count %q", strings.TrimSpace(stdout))
	}
	return n, nil
}

// scratchName derives a safe, unquoted-identifier-shaped Postgres
// database name from a backup id (which carries hyphens and is
// mixed-case).
func scratchName(id string) string {
	var b strings.Builder
	b.WriteString(scratchPrefix)
	for _, r := range strings.ToLower(id) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
			continue
		}
		b.WriteRune('_')
	}
	name := b.String()
	if len(name) > maxIdentLen {
		name = name[:maxIdentLen]
	}
	return name
}

// quoteIdent double-quotes a Postgres identifier for use in DDL.
// scratchName already restricts the character set; this is belt-and-braces
// against the name ever becoming caller-controlled.
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// psqlCmd builds a single-statement psql invocation against db, in the
// tuples-only/unaligned form the callers parse.
func psqlCmd(conn PgConn, db, sql string) string {
	return fmt.Sprintf("psql -h %s -p %d -U %s -d %s -Atc %s",
		shellQuote(conn.Host), conn.Port, shellQuote(conn.User),
		shellQuote(db), shellQuote(sql))
}

// engineErr prefers the engine's own stderr over the exec wrapper's
// error, which is what an operator needs to see; it falls back to the Go
// error when the engine said nothing.
func engineErr(stderr string, err error) string {
	if s := strings.TrimSpace(stderr); s != "" {
		return s
	}
	return err.Error()
}
