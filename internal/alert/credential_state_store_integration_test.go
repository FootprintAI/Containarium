//go:build integration

// Integration coverage for the credential-watch state store (#2371): the
// "once per flip, not again after a restart" guarantee is only as good as
// this table's round trip.
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/alert/
package alert

import (
	"context"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func credentialStateStore(t *testing.T) *PGCredentialStateStore {
	t.Helper()
	pool := alertPool(t)
	if _, err := pool.Exec(context.Background(), `DROP TABLE IF EXISTS code_credential_watch_state`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	s, err := NewPGCredentialStateStore(context.Background(), pool)
	if err != nil {
		t.Fatalf("NewPGCredentialStateStore: %v", err)
	}
	return s
}

// TestCredentialStateStore_RoundTripsAndUpserts: an unseen skill reports
// ok=false, a recorded source comes back as the same enum value, and a
// second record for the same skill replaces the first.
func TestCredentialStateStore_RoundTripsAndUpserts(t *testing.T) {
	ctx := context.Background()
	s := credentialStateStore(t)

	if _, ok, err := s.LastSeen(ctx, "s1"); err != nil || ok {
		t.Fatalf("LastSeen(unseen) = ok %v, err %v; want ok=false, nil", ok, err)
	}
	if err := s.Record(ctx, "s1", pb.CodeCredentialSource_CODE_CREDENTIAL_SOURCE_INTERACTIVE, time.Now()); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := s.Record(ctx, "s1", pb.CodeCredentialSource_CODE_CREDENTIAL_SOURCE_EXPIRED, time.Now()); err != nil {
		t.Fatalf("Record (upsert): %v", err)
	}
	src, ok, err := s.LastSeen(ctx, "s1")
	if err != nil || !ok || src != pb.CodeCredentialSource_CODE_CREDENTIAL_SOURCE_EXPIRED {
		t.Fatalf("LastSeen = %v, ok %v, err %v; want EXPIRED, true, nil", src, ok, err)
	}
}

// TestCredentialWatcher_PostgresRestartDoesNotRefire is AC2's restart
// clause against the real table: a second watcher built over a second
// store instance (a restarted daemon re-running initSchema on the same
// database) sees the expired state the first one recorded and stays quiet.
func TestCredentialWatcher_PostgresRestartDoesNotRefire(t *testing.T) {
	ctx := context.Background()
	first := credentialStateStore(t)
	prober := oneTargetProber(pb.CodeCredentialSource_CODE_CREDENTIAL_SOURCE_INTERACTIVE)
	notifier := &recordingNotifier{}

	w := NewCredentialWatcher(prober, first, notifier)
	w.Sweep(ctx)
	prober.set("s1", pb.CodeCredentialSource_CODE_CREDENTIAL_SOURCE_EXPIRED)
	w.Sweep(ctx)

	second, err := NewPGCredentialStateStore(ctx, first.pool)
	if err != nil {
		t.Fatalf("NewPGCredentialStateStore after restart: %v", err)
	}
	restarted := NewCredentialWatcher(prober, second, notifier)
	restarted.Sweep(ctx)

	if got := notifier.count(); got != 1 {
		t.Fatalf("alerts fired across a restart = %d, want exactly 1", got)
	}
}
