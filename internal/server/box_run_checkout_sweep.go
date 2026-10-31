package server

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/agentbox"
	"github.com/footprintai/containarium/pkg/core/box"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The per-run checkout sweep (#3296). A platform-started run clones into a
// directory of its own directly under a box user's ~/work, named
// <repo>-run-<8 hex>, and nothing removes it afterwards (the run's agent may
// not use rm). The daemon, which runs as root and can see which runs are
// live, removes the stale ones.
//
// This deletes files as root inside a box whose users can write ~/work, so
// every step is written against a box user racing it:
//
//   - Only a name matching runCheckoutNamePattern is ever considered, checked
//     in Go and again in the box script; a person's ~/work/<repo> never is.
//   - The scripts cd into ~/work with `cd -P` and require `pwd -P` to be
//     exactly <home>/work, so a symlinked ~/work (or home) is refused rather
//     than followed. From then on everything is relative to that pinned
//     working directory, so swapping a path component afterwards cannot move
//     the sweep anywhere else.
//   - An entry is only inspected with find -P / du (neither follows links) and
//     only removed with `rm -rf --one-file-system -- ./<name>`: rm never
//     follows a symlink operand (a link swapped in at the last moment is
//     removed itself, never its target) and GNU rm descends with openat and
//     O_NOFOLLOW, so a link planted inside the tree is not followed either.
//   - Every guard the decision used (name, real directory, age, no process
//     cwd inside) is checked again in the box immediately before each rm.

// DefaultRunCheckoutMaxAge is how old a per-run checkout's newest modification
// must be before the sweep removes it.
const DefaultRunCheckoutMaxAge = 7 * 24 * time.Hour

// runCheckoutSweepInterval is how often every eligible box is swept.
const runCheckoutSweepInterval = time.Hour

// runCheckoutNameERE is the only shape of name the sweep ever touches. It is
// used as a Go regexp and, verbatim, as a grep -E pattern in the box scripts.
const runCheckoutNameERE = `^[A-Za-z0-9._-]+-run-[0-9a-f]{8}$`

var runCheckoutNamePattern = regexp.MustCompile(runCheckoutNameERE)

// runCheckoutScriptPrelude enters <home>/work (the shell variable w) or exits
// quietly when there is none, and prints "X" and exits when the real path is
// not exactly $w (a symlinked ~/work or home). It defines okname, inuse,
// newest and kib for the script that follows. Callers set w first.
const runCheckoutScriptPrelude = `if [ -L "$w" ]; then echo X; exit 0; fi
[ -d "$w" ] || exit 0
cd -P -- "$w" 2>/dev/null || exit 0
[ "$(pwd -P)" = "$w" ] || { echo X; exit 0; }
okname() {
  case "$1" in ''|*[!A-Za-z0-9._-]*) return 1;; esac
  printf '%s\n' "$1" | grep -qxE '` + runCheckoutNameERE + `'
}
inuse() {
  for p in /proc/[0-9]*; do readlink "$p/cwd" 2>/dev/null; done |
    awk -v w="$w/" 'index($0, w) == 1 { s = substr($0, length(w) + 1); sub(/\/.*/, "", s); if (s != "") print s }' | sort -u
}
newest() { find -P "./$1" -xdev -printf '%T@\n' 2>/dev/null | sed 's/\..*//' | sort -n | tail -n 1; }
kib() { du -skx -- "./$1" 2>/dev/null | cut -f1; }
`

// runCheckoutListScript prints one line per entry of home/work whose name
// matches: "C <name> <kind> <newest-epoch|-> <KiB|-> <in-use 0|1>", kind d
// (directory), l (symlink) or o (anything else). Read-only.
func runCheckoutListScript(home string) string {
	return "w=" + shellSingleQuote(home+"/work") + "\n" + runCheckoutScriptPrelude + `u=$(inuse)
for n in * .[!.]* ..?*; do
  [ -e "$n" ] || [ -L "$n" ] || continue
  okname "$n" || continue
  if [ -L "$n" ]; then echo "C $n l - - 0"; continue; fi
  if [ ! -d "$n" ]; then echo "C $n o - - 0"; continue; fi
  busy=0
  printf '%s\n' "$u" | grep -qxF -- "$n" && busy=1
  t=$(newest "$n"); k=$(kib "$n")
  echo "C $n d ${t:--} ${k:--} $busy"
done
`
}

// runCheckoutRemoveScript removes the named entries of home/work, re-checking
// each guard first: the name, a real directory, newest modification strictly
// before cutoff, and no process cwd inside. Prints "R <name>" (removed),
// "K <name>" (no longer qualified, left alone) or "F <name>" (rm failed).
// names must already match runCheckoutNamePattern.
func runCheckoutRemoveScript(home string, names []string, cutoff int64) string {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = shellSingleQuote(n)
	}
	return "w=" + shellSingleQuote(home+"/work") + "\ncutoff=" + strconv.FormatInt(cutoff, 10) + "\n" + runCheckoutScriptPrelude +
		"for n in " + strings.Join(quoted, " ") + `; do
  okname "$n" || { echo "K $n"; continue; }
  [ -d "$n" ] && [ ! -L "$n" ] || { echo "K $n"; continue; }
  t=$(newest "$n")
  [ -n "$t" ] && [ "$t" -lt "$cutoff" ] || { echo "K $n"; continue; }
  if inuse | grep -qxF -- "$n"; then echo "K $n"; continue; fi
  if rm -rf --one-file-system -- "./$n" 2>/dev/null && [ ! -e "./$n" ] && [ ! -L "./$n" ]; then echo "R $n"; else echo "F $n"; fi
done
`
}

// runCheckoutEntry is one line of runCheckoutListScript's output.
type runCheckoutEntry struct {
	name    string
	kind    byte // 'd', 'l' or 'o'
	newest  time.Time
	hasTime bool
	sizeKiB int64
	inUse   bool
}

// parseRunCheckoutList parses runCheckoutListScript's output. A line that does
// not parse, or names something the pattern does not match, is dropped (never
// a removal candidate). refused reports the X line.
func parseRunCheckoutList(out string) (entries []runCheckoutEntry, refused bool) {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 1 && f[0] == "X" {
			refused = true
			continue
		}
		if len(f) != 6 || f[0] != "C" || len(f[2]) != 1 || !runCheckoutNamePattern.MatchString(f[1]) {
			continue
		}
		e := runCheckoutEntry{name: f[1], kind: f[2][0], inUse: f[5] == "1"}
		if secs, err := strconv.ParseInt(f[3], 10, 64); err == nil {
			e.newest, e.hasTime = time.Unix(secs, 0), true
		}
		if k, err := strconv.ParseInt(f[4], 10, 64); err == nil && k >= 0 {
			e.sizeKiB = k
		}
		entries = append(entries, e)
	}
	return entries, refused
}

// runCheckoutLiveRuns is what the sweep knows about the box's live runs.
type runCheckoutLiveRuns struct {
	// since is the earliest start of a RUNNING run; zero when none is.
	since time.Time
	// cwds are the working directories RUNNING runs' records name.
	cwds []string
}

// liveRunsFromList derives runCheckoutLiveRuns from boxRunListScript's output.
// Only RUNNING (same boot, PID alive) counts: an UNKNOWN run's PID is gone, and
// counting one would protect every later checkout until the box reboots.
func liveRunsFromList(out string) (live runCheckoutLiveRuns, records int) {
	views, boot, alive := parseBoxRunViews(out)
	for _, v := range views {
		if agentbox.ResolveOutcome(v.record, boot, func(pid int) bool { return pid > 0 && alive[pid] }) != agentbox.RunOutcomeRunning {
			continue
		}
		if live.since.IsZero() || v.record.StartedAt.Before(live.since) {
			live.since = v.record.StartedAt
		}
		if v.record.Cwd != "" {
			live.cwds = append(live.cwds, v.record.Cwd)
		}
	}
	return live, len(views)
}

// decideRunCheckout is the sweep's whole decision for one entry of home/work.
// cutoff is now minus the maximum age: an entry is removable only when its
// newest modification is strictly before it.
func decideRunCheckout(e runCheckoutEntry, home string, cutoff time.Time, live runCheckoutLiveRuns) pb.BoxRunCheckoutDisposition {
	switch {
	case !runCheckoutNamePattern.MatchString(e.name):
		return pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_UNSPECIFIED
	case e.kind == 'l':
		return pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_KEPT_SYMLINK
	case e.kind != 'd':
		return pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_KEPT_NOT_DIRECTORY
	case e.inUse:
		return pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_KEPT_IN_USE
	}
	dir := home + "/work/" + e.name
	for _, c := range live.cwds {
		if c == dir || strings.HasPrefix(c, dir+"/") {
			return pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_KEPT_LIVE_RUN
		}
	}
	// A run's checkout is created after the run starts, so anything modified
	// at or after the start of a run still going may be that run's.
	if !live.since.IsZero() && e.hasTime && !e.newest.Before(live.since) {
		return pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_KEPT_LIVE_RUN
	}
	if !e.hasTime || !e.newest.Before(cutoff) {
		return pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_KEPT_RECENT
	}
	return pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_WOULD_REMOVE
}

// runCheckoutSweep is one sweep of one box: the seams it needs and its
// settings, so the whole path runs against a temp directory in tests.
type runCheckoutSweep struct {
	exec   boxScriptFunc
	box    string
	now    time.Time
	maxAge time.Duration
	dryRun bool
	live   runCheckoutLiveRuns
	logf   func(format string, args ...any)
}

// sweepHome sweeps user's ~/work (home is that user's home directory, already
// validated) and returns every matching entry with its disposition.
func (sw runCheckoutSweep) sweepHome(user, home string) ([]*pb.BoxRunCheckout, error) {
	if !validHomePath(home) {
		return nil, fmt.Errorf("refusing to sweep %q: not a plain absolute home path", home)
	}
	out, err := sw.exec(sw.box, runCheckoutListScript(home))
	if err != nil {
		return nil, fmt.Errorf("list %s's ~/work: %w", user, err)
	}
	entries, refused := parseRunCheckoutList(out)
	if refused {
		sw.logf("[run-checkout-sweep] %s: %s's ~/work is a symlink or under one; not swept", sw.box, user)
		return nil, nil
	}
	cutoff := sw.now.Add(-sw.maxAge)
	result := make([]*pb.BoxRunCheckout, 0, len(entries))
	byName := map[string]*pb.BoxRunCheckout{}
	var remove []string
	for _, e := range entries {
		d := decideRunCheckout(e, home, cutoff, sw.live)
		if d == pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_UNSPECIFIED {
			continue
		}
		c := &pb.BoxRunCheckout{User: user, Name: e.name, SizeBytes: e.sizeKiB * 1024, Disposition: d}
		if e.hasTime {
			c.NewestModification = timestamppb.New(e.newest)
		}
		result = append(result, c)
		byName[e.name] = c
		if d == pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_WOULD_REMOVE {
			remove = append(remove, e.name)
		}
	}
	if sw.dryRun || len(remove) == 0 {
		return result, nil
	}

	out, err = sw.exec(sw.box, runCheckoutRemoveScript(home, remove, cutoff.Unix()))
	if err != nil {
		return nil, fmt.Errorf("remove from %s's ~/work: %w", user, err)
	}
	// Anything chosen that the script did not report on was not removed.
	for _, name := range remove {
		byName[name].Disposition = pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_KEPT_CHANGED
	}
	for _, line := range strings.Split(out, "\n") {
		verdict, name, ok := strings.Cut(strings.TrimSpace(line), " ")
		c := byName[name]
		if !ok || c == nil || c.Disposition != pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_KEPT_CHANGED {
			continue
		}
		switch verdict {
		case "R":
			c.Disposition = pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_REMOVED
			sw.logf("[run-checkout-sweep] %s: removed %s from %s's ~/work (%d bytes)", sw.box, name, user, c.SizeBytes)
		case "F":
			c.Disposition = pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_REMOVE_FAILED
			sw.logf("[run-checkout-sweep] %s: removing %s from %s's ~/work failed", sw.box, name, user)
		}
	}
	return result, nil
}

// runCheckoutHomesScript prints "H <user> <home>" for each user that exists.
func runCheckoutHomesScript(users []string) string {
	quoted := make([]string, len(users))
	for i, u := range users {
		quoted[i] = shellSingleQuote(u)
	}
	return "for u in " + strings.Join(quoted, " ") + `; do
  h=$(getent passwd "$u" | cut -d: -f6) && [ -n "$h" ] && echo "H $u $h"
done
exit 0
`
}

// SetRunCheckoutMaxAge sets the per-run checkout sweep's maximum age
// (--run-checkout-max-age). Zero turns the sweep off; negative keeps the
// default.
func (s *ContainerServer) SetRunCheckoutMaxAge(d time.Duration) {
	if d < 0 {
		d = DefaultRunCheckoutMaxAge
	}
	s.runCheckoutMaxAge, s.runCheckoutMaxAgeSet = d, true
}

func (s *ContainerServer) runCheckoutMaxAgeOrDefault() time.Duration {
	if s.runCheckoutMaxAgeSet {
		return s.runCheckoutMaxAge
	}
	return DefaultRunCheckoutMaxAge
}

func (s *ContainerServer) runCheckoutLogf(format string, args ...any) {
	if s.runCheckoutLog != nil {
		s.runCheckoutLog(format, args...)
		return
	}
	log.Printf(format, args...)
}

func (s *ContainerServer) runCheckoutClock() time.Time {
	if s.runCheckoutNow != nil {
		return s.runCheckoutNow()
	}
	return time.Now()
}

// runCheckoutUserHomes resolves the homes of the box's owner and of the run
// user, skipping a user that does not exist and any home that is not a plain
// absolute path.
func (s *ContainerServer) runCheckoutUserHomes(exec boxScriptFunc, boxName, owner string) ([][2]string, error) {
	users := []string{owner, boxRunUnprivilegedUser}
	var homes map[string]string
	if s.runCheckoutHomes != nil {
		var err error
		if homes, err = s.runCheckoutHomes(boxName, users); err != nil {
			return nil, err
		}
	} else {
		out, err := exec(boxName, runCheckoutHomesScript(users))
		if err != nil {
			return nil, err
		}
		homes = map[string]string{}
		for _, line := range strings.Split(out, "\n") {
			if f := strings.Fields(line); len(f) == 3 && f[0] == "H" {
				homes[f[1]] = f[2]
			}
		}
	}
	var res [][2]string
	seen := map[string]bool{}
	for _, u := range users {
		h, ok := homes[u]
		if !ok || !validHomePath(h) || seen[h] {
			continue
		}
		seen[h] = true
		res = append(res, [2]string{u, h})
	}
	return res, nil
}

// sweepBoxRunCheckouts sweeps one running box. toolAccess is the box's
// recorded level ("" = none). platformRuns is false, and nothing is touched,
// when the box has neither a recorded level nor a run record.
func (s *ContainerServer) sweepBoxRunCheckouts(username, toolAccess string, dryRun bool) (platformRuns bool, checkouts []*pb.BoxRunCheckout, err error) {
	exec := s.boxRunExecFn()
	if exec == nil {
		return false, nil, status.Error(codes.Unavailable, "no container backend to sweep run checkouts on")
	}
	boxName := username + "-container"
	lockAny, _ := s.runCheckoutLocks.LoadOrStore(boxName, &sync.Mutex{})
	lock := lockAny.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()

	out, err := exec(boxName, boxRunListScript(s.boxRunDir()))
	if err != nil {
		return false, nil, status.Errorf(codes.Unavailable, "read run records of %q: %v", username, err)
	}
	live, records := liveRunsFromList(out)
	if toolAccess == "" && records == 0 {
		return false, nil, nil
	}
	homes, err := s.runCheckoutUserHomes(exec, boxName, username)
	if err != nil {
		return true, nil, status.Errorf(codes.Unavailable, "resolve home directories on %q: %v", username, err)
	}
	sw := runCheckoutSweep{
		exec:   exec,
		box:    boxName,
		now:    s.runCheckoutClock(),
		maxAge: s.runCheckoutMaxAgeOrDefault(),
		dryRun: dryRun,
		live:   live,
		logf:   s.runCheckoutLogf,
	}
	for _, uh := range homes {
		got, err := sw.sweepHome(uh[0], uh[1])
		if err != nil {
			return true, checkouts, status.Errorf(codes.Unavailable, "%q: %v", username, err)
		}
		checkouts = append(checkouts, got...)
	}
	sort.SliceStable(checkouts, func(i, j int) bool {
		if checkouts[i].GetUser() != checkouts[j].GetUser() {
			return checkouts[i].GetUser() < checkouts[j].GetUser()
		}
		return checkouts[i].GetName() < checkouts[j].GetName()
	})
	return true, checkouts, nil
}

// runCheckoutGetBox reads one box's status (nil when it does not exist).
func (s *ContainerServer) runCheckoutGetBox(ctx context.Context, username string) (*box.BoxStatus, error) {
	if s.runCheckoutBoxes != nil {
		all, err := s.runCheckoutBoxes(ctx)
		if err != nil {
			return nil, err
		}
		for i := range all {
			if all[i].Ref.Tenant == username {
				return &all[i], nil
			}
		}
		return nil, nil
	}
	if s.manager == nil && s.boxBackend == nil {
		return nil, fmt.Errorf("no box backend")
	}
	return s.boxes().Get(ctx, box.BoxRef{Tenant: username})
}

// SweepBoxRunCheckouts runs the per-run checkout sweep once on one box
// (#3296). dry_run reports the same removal set and removes nothing.
func (s *ContainerServer) SweepBoxRunCheckouts(ctx context.Context, req *pb.SweepBoxRunCheckoutsRequest) (*pb.SweepBoxRunCheckoutsResponse, error) {
	if err := validateBoxRunOwner(req.GetUsername()); err != nil {
		return nil, err
	}
	if err := s.authorizeBoxRuns(ctx, req.GetUsername()); err != nil {
		return nil, err
	}
	maxAge := s.runCheckoutMaxAgeOrDefault()
	if maxAge == 0 {
		return nil, status.Error(codes.FailedPrecondition, "the run checkout sweep is turned off on this daemon (--run-checkout-max-age=0)")
	}
	if s.boxRunExecFn() == nil {
		return nil, status.Error(codes.Unavailable, "no container backend to sweep run checkouts on")
	}
	info, err := s.runCheckoutGetBox(ctx, req.GetUsername())
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "look up %q: %v", req.GetUsername(), err)
	}
	if info == nil {
		return nil, status.Errorf(codes.NotFound, "no box for %q", req.GetUsername())
	}
	if info.State != pb.ContainerState_CONTAINER_STATE_RUNNING {
		return nil, status.Errorf(codes.FailedPrecondition, "%q is not running; a stopped box is not swept", req.GetUsername())
	}
	platformRuns, checkouts, err := s.sweepBoxRunCheckouts(req.GetUsername(), info.ToolAccess, req.GetDryRun())
	if err != nil {
		return nil, err
	}
	return &pb.SweepBoxRunCheckoutsResponse{PlatformRuns: platformRuns, MaxAge: durationpb.New(maxAge), Checkouts: checkouts}, nil
}

// sweepAllBoxRunCheckouts is one timer tick: every running, non-core box with a
// valid owner name. Best-effort per box.
func (s *ContainerServer) sweepAllBoxRunCheckouts(ctx context.Context) {
	if s.runCheckoutMaxAgeOrDefault() == 0 || s.boxRunExecFn() == nil {
		return
	}
	var all []box.BoxStatus
	var err error
	switch {
	case s.runCheckoutBoxes != nil:
		all, err = s.runCheckoutBoxes(ctx)
	case s.manager == nil && s.boxBackend == nil:
		return
	default:
		all, err = s.boxes().List(ctx)
	}
	if err != nil {
		s.runCheckoutLogf("[run-checkout-sweep] list boxes: %v", err)
		return
	}
	for _, b := range all {
		if ctx.Err() != nil {
			return
		}
		// The sweep addresses a box as <tenant>-container, like every box-run
		// RPC; a box whose name differs is not one of those.
		if b.IsCore || b.State != pb.ContainerState_CONTAINER_STATE_RUNNING || !validRunPathID(b.Ref.Tenant) ||
			(b.Ref.Name != "" && b.Ref.Name != b.Ref.Tenant+"-container") {
			continue
		}
		if _, _, err := s.sweepBoxRunCheckouts(b.Ref.Tenant, b.ToolAccess, false); err != nil {
			s.runCheckoutLogf("[run-checkout-sweep] %s-container: %v", b.Ref.Tenant, err)
		}
	}
}

// sweepBoxRunCheckoutsAfterRun sweeps one box in the background after a run on
// it ended (StopBoxRun). Errors are logged; a stopped box is skipped.
func (s *ContainerServer) sweepBoxRunCheckoutsAfterRun(username string) {
	if s.runCheckoutMaxAgeOrDefault() == 0 || s.boxRunExecFn() == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		info, err := s.runCheckoutGetBox(ctx, username)
		if err != nil || info == nil || info.State != pb.ContainerState_CONTAINER_STATE_RUNNING {
			return
		}
		if _, _, err := s.sweepBoxRunCheckouts(username, info.ToolAccess, false); err != nil {
			s.runCheckoutLogf("[run-checkout-sweep] %s-container: %v", username, err)
		}
	}()
}

// StartRunCheckoutSweeper sweeps every eligible box now and then hourly until
// ctx ends. A daemon with the sweep turned off starts nothing.
func (s *ContainerServer) StartRunCheckoutSweeper(ctx context.Context) {
	maxAge := s.runCheckoutMaxAgeOrDefault()
	if maxAge == 0 {
		log.Printf("[run-checkout-sweep] off (--run-checkout-max-age=0)")
		return
	}
	log.Printf("[run-checkout-sweep] removing per-run checkouts older than %s, every %s", maxAge, runCheckoutSweepInterval)
	go func() {
		s.sweepAllBoxRunCheckouts(ctx)
		t := time.NewTicker(runCheckoutSweepInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.sweepAllBoxRunCheckouts(ctx)
			}
		}
	}()
}
