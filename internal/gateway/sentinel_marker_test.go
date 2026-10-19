package gateway

import (
	"testing"

	"github.com/footprintai/containarium/internal/sshauthz"
)

// The ssh_keys backfill (#2517) skips the sentinel's marked block by
// matching this marker; if the two drift apart, the sentinel's upstream key
// would be registered as a user key.
func TestSentinelKeyMarker_MatchesBackfill(t *testing.T) {
	if sentinelKeyMarker != sshauthz.SentinelKeyMarker {
		t.Fatalf("gateway marker %q != sshauthz.SentinelKeyMarker %q", sentinelKeyMarker, sshauthz.SentinelKeyMarker)
	}
}
