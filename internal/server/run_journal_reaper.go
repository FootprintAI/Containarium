package server

import (
	"context"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The run journal reaper (#2096): member boxes are long-lived and reused
// across runs, so every run leaves a directory under runJournalRoot. A daemon
// sweep removes the ones older than the retention window.

// DefaultRunJournalRetention is how long a run's journal stays on a member box.
const DefaultRunJournalRetention = 7 * 24 * time.Hour

// runJournalSweepInterval is how often the reaper sweeps every agent box.
const runJournalSweepInterval = time.Hour

// clearRunJournalsScript empties the journal root; provisionSkillBox runs it
// on a freshly built box.
const clearRunJournalsScript = "rm -rf " + runJournalRoot

// runJournalListScript prints "<mtime-epoch> <name>" per run directory. A
// missing root prints nothing.
const runJournalListScript = `[ -d ` + runJournalRoot + ` ] || exit 0
for d in ` + runJournalRoot + `/*/; do
  [ -d "$d" ] || continue
  echo "$(stat -c %Y "$d") $(basename "$d")"
done`

// runDir is one run directory on a box.
type runDir struct {
	name  string
	mtime time.Time
}

// parseRunDirListing parses runJournalListScript output, skipping lines it
// cannot read.
func parseRunDirListing(out string) []runDir {
	var dirs []runDir
	for _, line := range strings.Split(out, "\n") {
		secs, name, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(secs, 10, 64)
		if err != nil {
			continue
		}
		dirs = append(dirs, runDir{name: name, mtime: time.Unix(n, 0)})
	}
	return dirs
}

// staleRunDirs returns the run directories last modified more than window
// before now, sorted. A name that is not a safe run id is never returned, so
// the removal can only ever name a single directory under the root.
func staleRunDirs(dirs []runDir, now time.Time, window time.Duration) []string {
	var out []string
	for _, d := range dirs {
		if validRunPathID(d.name) && now.Sub(d.mtime) > window {
			out = append(out, d.name)
		}
	}
	sort.Strings(out)
	return out
}

// SetRunJournalRetention sets how long a run's journal is kept on a member
// box. Zero or negative keeps the default.
func (s *AgentSkillServer) SetRunJournalRetention(d time.Duration) { s.journalRetention = d }

func (s *AgentSkillServer) runJournalRetention() time.Duration {
	if s.journalRetention > 0 {
		return s.journalRetention
	}
	return DefaultRunJournalRetention
}

// reapRunJournals removes the stale run directories on each box and returns
// the paths it removed. Per box and best-effort: one unreachable box never
// stops the sweep of the next.
//
// #2122: every reaped run id's durable skill-run record (if it has one) is
// deleted in the same pass, coupling the record's lifetime to the journal's.
// Called for both crew and skill run ids — reapSkillRun (nil-guarded) is a
// no-op for a crew run id, so this can never touch a crew's record.
func (s *AgentSkillServer) reapRunJournals(ctx context.Context, boxes []string, now time.Time) []string {
	exec := s.boxScript()
	if exec == nil {
		return nil
	}
	var removed []string
	for _, box := range boxes {
		out, err := exec(box, runJournalListScript)
		if err != nil {
			log.Printf("[run-journal-reaper] list %s: %v", box, err)
			continue
		}
		stale := staleRunDirs(parseRunDirListing(out), now, s.runJournalRetention())
		if len(stale) == 0 {
			continue
		}
		paths := make([]string, len(stale))
		for i, name := range stale {
			paths[i] = shellSingleQuote(runJournalRoot + "/" + name)
		}
		if _, err := exec(box, "rm -rf -- "+strings.Join(paths, " ")); err != nil {
			log.Printf("[run-journal-reaper] remove on %s: %v", box, err)
			continue
		}
		for _, name := range stale {
			removed = append(removed, box+":"+runJournalRoot+"/"+name)
			if s.reapSkillRun != nil {
				if err := s.reapSkillRun(ctx, name); err != nil {
					log.Printf("[run-journal-reaper] delete run record %s: %v", name, err)
				}
			}
		}
	}
	return removed
}

// agentBoxes lists the containers that are skill boxes (agent-<skill>-container).
func (s *AgentSkillServer) agentBoxes() []string {
	if s.recipes == nil || s.recipes.containers == nil || s.recipes.containers.manager == nil {
		return nil
	}
	list, err := s.recipes.containers.manager.List()
	if err != nil {
		log.Printf("[run-journal-reaper] list containers: %v", err)
		return nil
	}
	var boxes []string
	for _, c := range list {
		if strings.HasPrefix(c.Name, agentBoxPrefix) && strings.HasSuffix(c.Name, "-container") && c.State == "Running" {
			boxes = append(boxes, c.Name)
		}
	}
	return boxes
}

// StartRunJournalReaper sweeps every running skill box now and then hourly
// until ctx ends.
func (s *AgentSkillServer) StartRunJournalReaper(ctx context.Context) {
	go func() {
		sweep := func() {
			if removed := s.reapRunJournals(ctx, s.agentBoxes(), time.Now()); len(removed) > 0 {
				log.Printf("[run-journal-reaper] removed %d run journal dir(s) older than %s", len(removed), s.runJournalRetention())
			}
		}
		sweep()
		t := time.NewTicker(runJournalSweepInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				sweep()
			}
		}
	}()
}
