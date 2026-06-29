package container

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"time"
)

const (
	orphanReaperInterval  = 5 * time.Minute
	orphanReaperHomeRoot  = "/home"
	orphanReaperGracePeriod = 30 * time.Second // delay before first sweep to avoid racing startup
)

// RunOrphanReaper periodically removes host-user accounts whose container no
// longer exists.  A deleted container whose `userdel -r` failed (lock
// contention with google-guest-agent on GCP) leaves a stale `/home/<user>`
// dir with an authorized_keys.  ServeAuthorizedKeys already filters these
// from the keysync response, but without cleanup the dirs accumulate and the
// O(orphans) walk + ssh-keygen per tick widens the #830 first-connect race.
//
// containerExistsFn returns true when a live container exists for username.
// Blocks until ctx is cancelled.
func RunOrphanReaper(ctx context.Context, containerExistsFn func(username string) bool) {
	RunOrphanReaperWithRoot(ctx, orphanReaperHomeRoot, containerExistsFn)
}

// RunOrphanReaperWithRoot is the testable variant that accepts an explicit homeRoot.
func RunOrphanReaperWithRoot(ctx context.Context, homeRoot string, containerExistsFn func(username string) bool) {
	// Grace period: let the daemon finish startup before first sweep.
	select {
	case <-ctx.Done():
		return
	case <-time.After(orphanReaperGracePeriod):
	}

	reapOnce(homeRoot, containerExistsFn)

	ticker := time.NewTicker(orphanReaperInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reapOnce(homeRoot, containerExistsFn)
		}
	}
}

func reapOnce(homeRoot string, containerExistsFn func(username string) bool) {
	entries, err := os.ReadDir(homeRoot)
	if err != nil {
		log.Printf("[orphan-reaper] failed to read %s: %v", homeRoot, err)
		return
	}

	var orphans []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		username := e.Name()
		akPath := filepath.Join(homeRoot, username, ".ssh", "authorized_keys")
		if _, statErr := os.Stat(akPath); os.IsNotExist(statErr) {
			continue // no authorized_keys → not a containarium user
		}
		if containerExistsFn(username) {
			continue
		}
		orphans = append(orphans, username)
	}

	if len(orphans) == 0 {
		return
	}

	log.Printf("[orphan-reaper] found %d orphaned host accounts; reaping", len(orphans))
	reaped, failed := 0, 0
	for _, username := range orphans {
		if err := DeleteJumpServerAccount(username, false); err != nil {
			log.Printf("[orphan-reaper] userdel %s failed: %v", username, err)
			failed++
		} else {
			reaped++
		}
	}
	if reaped > 0 || failed > 0 {
		log.Printf("[orphan-reaper] reaped=%d failed=%d (failed entries retry next tick)", reaped, failed)
	}
}
