package server

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/agentbox"
	"github.com/footprintai/containarium/pkg/core/sdlcskills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Re-applying a box's SDLC skill sets (#3374). `code install --skill-sets`
// installs the pinned role skills when a box is set up; ApplyBoxSkillSets
// changes that selection on a box that already exists, through the same
// installer (scripts/install-sdlc-skills.sh at a release, via
// sdlcskills.InstallScript) and the same lock
// (pkg/core/sdlcskills/sdlc-skills.lock).
//
// The skills tree of record is the box OWNER's ~/.claude/skills: what `code
// install` writes, and what the unprivileged run user's copy is refreshed
// from at the start of every platform run (boxRunStageScript). So every step
// here runs as the box's own user through boxRunStartExecFn — never as root —
// exactly like `code install` over SSH.
//
// Two manifests live beside the skills. The installer's own
// .sdlc-skills-manifest lists every directory it owns (so its re-run prunes
// only those); the per-box .sdlc-skill-sets.json this RPC keeps records WHICH
// SET each of those directories belongs to, so a removal is "the directories
// recorded under this set" and a set installed before the manifest existed is
// detectable (installer-owned directories under a set's namespaces that no
// recorded set claims). Per the decision on #3503: such a set can be adopted
// by keeping it in the list, and omitting it is the typed refusal, because
// what it installed was never recorded. A skill the owner installed by hand is
// in neither manifest and is never touched.

// DaemonCapBoxSkillSets: the ApplyBoxSkillSets RPC (#3374).
const DaemonCapBoxSkillSets = "box_skill_sets"

// boxSkillSetsField is the request field a BadRequest refusal names.
const boxSkillSetsField = "skill_sets"

const (
	// boxSkillSetsManifestFile is the per-box, per-set manifest this RPC keeps
	// beside the skills (relative to ~/.claude/skills).
	boxSkillSetsManifestFile = ".sdlc-skill-sets.json"
	// boxSkillSetsInstallerManifestFile is the installer's own list of the
	// directories it owns, one per line.
	boxSkillSetsInstallerManifestFile = ".sdlc-skills-manifest"
	// boxSkillSetManifestVersion is the manifest's format version.
	boxSkillSetManifestVersion = 1
	// boxSkillSetsSharedDir is installed whenever at least one set is and
	// belongs to no set.
	boxSkillSetsSharedDir = "_shared"
)

// skillSetIDPattern is the charset of a set id, the same the lock and the
// installer enforce: nothing in it can carry shell syntax.
var skillSetIDPattern = regexp.MustCompile(`^[a-z0-9-]+$`)

// skillDirPattern is the only shape of directory name the installer owns or
// prunes; anything else reported by the box is dropped.
var skillDirPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// boxSkillSetManifest is the on-box per-set manifest.
type boxSkillSetManifest struct {
	Version int `json:"version"`
	// Release the sets were last applied from.
	Release string `json:"release,omitempty"`
	// Sets maps a set id to the skill directories it installed, sorted.
	Sets map[string][]string `json:"sets"`
}

// boxSkillSetsInstallFunc runs the installer in box as username for release
// with the selection sets. Production is the shared installer script through
// the box user's exec; tests run the real installer against a temp home.
type boxSkillSetsInstallFunc func(box, username, release string, sets sdlcskills.SkillSets) (string, error)

// boxSkillSetsInstallFn returns the install seam: the injected fake, else the
// shared installer script run as the box user.
func (s *ContainerServer) boxSkillSetsInstallFn() boxSkillSetsInstallFunc {
	if s.boxSkillSetsInstall != nil {
		return s.boxSkillSetsInstall
	}
	exec := s.boxRunStartExecFn()
	if exec == nil {
		return nil
	}
	return func(box, username, release string, sets sdlcskills.SkillSets) (string, error) {
		return exec(box, username, sdlcskills.InstallScript(sdlcskills.DefaultRepo, release, sets))
	}
}

// boxSkillSetsRefusal is the typed refusal of ApplyBoxSkillSets: the human
// message for people, and reason for callers, spelled as the enum value's
// name so a control plane switches on it rather than on message text. An
// UNKNOWN_SKILL_SET is the caller's mistake, so it is INVALID_ARGUMENT with a
// google.rpc.BadRequest field violation on skill_sets (subject is the id,
// carried in the description); every other reason is the box's state, so it
// is FAILED_PRECONDITION with a google.rpc.PreconditionFailure violation
// whose subject is the box or the set.
func boxSkillSetsRefusal(reason pb.BoxSkillSetsRefusal, subject, msg string) error {
	if reason == pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_UNKNOWN_SKILL_SET {
		st := status.New(codes.InvalidArgument, msg)
		if detailed, err := st.WithDetails(&errdetails.BadRequest{
			FieldViolations: []*errdetails.BadRequest_FieldViolation{{Field: boxSkillSetsField, Description: msg, Reason: reason.String()}},
		}); err == nil {
			st = detailed
		}
		return st.Err()
	}
	st := status.New(codes.FailedPrecondition, msg)
	if detailed, err := st.WithDetails(&errdetails.PreconditionFailure{
		Violations: []*errdetails.PreconditionFailure_Violation{{Type: reason.String(), Subject: subject, Description: msg}},
	}); err == nil {
		st = detailed
	}
	return st.Err()
}

// knownSkillSets is the set id -> namespaces map of the lock this daemon was
// built with: what ApplyBoxSkillSets accepts and attributes skills by.
func knownSkillSets() (map[string][]string, error) {
	lock, err := sdlcskills.Embedded()
	if err != nil {
		return nil, err
	}
	return lock.Sets, nil
}

// sortedSkillSetIDs lists known's ids in order, for messages and responses.
func sortedSkillSetIDs(known map[string][]string) []string {
	ids := make([]string, 0, len(known))
	for id := range known {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// validateSkillSetIDs checks a request's target list against the known sets
// and returns it sorted and without duplicates. An id the lock does not define
// — including the installer's "all" and "none" literals, an empty id, or
// anything outside [a-z0-9-] — is the typed UNKNOWN_SKILL_SET refusal naming
// the known ids. Nothing else in the request is looked at, so this runs before
// the box is touched.
func validateSkillSetIDs(ids []string, known map[string][]string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		if _, ok := known[id]; !ok || !skillSetIDPattern.MatchString(id) {
			return nil, boxSkillSetsRefusal(pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_UNKNOWN_SKILL_SET, id,
				fmt.Sprintf("unknown skill set %q; known skill sets: %s", id, strings.Join(sortedSkillSetIDs(known), ", ")))
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Markers of boxSkillSetsStateScript's output.
const (
	boxSkillSetsStateSets      = "=== sets"
	boxSkillSetsStateInstaller = "=== installer"
	boxSkillSetsStateEnd       = "=== end"
)

// boxSkillSetsStateScript prints, as the box user, the per-set manifest and
// the installer's manifest between markers. Read-only; a box with neither
// prints empty sections.
func boxSkillSetsStateScript() string {
	return `d="$HOME/.claude/skills"
echo '` + boxSkillSetsStateSets + `'
cat "$d/` + boxSkillSetsManifestFile + `" 2>/dev/null
echo
echo '` + boxSkillSetsStateInstaller + `'
cat "$d/` + boxSkillSetsInstallerManifestFile + `" 2>/dev/null
echo
echo '` + boxSkillSetsStateEnd + `'
`
}

// boxSkillSetsWriteManifestScript writes the per-set manifest atomically, as
// the box user, beside the skills.
func boxSkillSetsWriteManifestScript(m boxSkillSetManifest) (string, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	q := shellSingleQuote
	f := `"$d/` + boxSkillSetsManifestFile + `"`
	return `set -e
d="$HOME/.claude/skills"
mkdir -p "$d"
printf '%s\n' ` + q(string(data)) + ` > ` + f + `.tmp
mv -f ` + f + `.tmp ` + f + "\n", nil
}

// boxSkillSetsState is what the box reports about its skills before or after
// an install.
type boxSkillSetsState struct {
	manifest    boxSkillSetManifest
	hasManifest bool
	// installerDirs are the directories the installer's own manifest owns,
	// sorted, _shared included.
	installerDirs []string
}

// parseBoxSkillSetsState parses boxSkillSetsStateScript's output. The box's
// user writes both files, so they are data: a directory name outside the
// installer's charset is dropped, a set id outside the lock's charset or a
// manifest that is not JSON is an error (nothing is removed on a guess).
func parseBoxSkillSetsState(out string) (boxSkillSetsState, error) {
	st := boxSkillSetsState{manifest: boxSkillSetManifest{Sets: map[string][]string{}}}
	_, rest, ok := strings.Cut(out, boxSkillSetsStateSets+"\n")
	if !ok {
		return st, fmt.Errorf("skill-set state: missing %q", boxSkillSetsStateSets)
	}
	setsText, rest, ok := strings.Cut(rest, boxSkillSetsStateInstaller+"\n")
	if !ok {
		return st, fmt.Errorf("skill-set state: missing %q", boxSkillSetsStateInstaller)
	}
	installerText, _, ok := strings.Cut(rest, boxSkillSetsStateEnd)
	if !ok {
		return st, fmt.Errorf("skill-set state: missing %q", boxSkillSetsStateEnd)
	}
	if setsText = strings.TrimSpace(setsText); setsText != "" {
		var m boxSkillSetManifest
		if err := json.Unmarshal([]byte(setsText), &m); err != nil {
			return st, fmt.Errorf("%s is not valid JSON: %v", boxSkillSetsManifestFile, err)
		}
		if m.Version > boxSkillSetManifestVersion {
			return st, fmt.Errorf("%s is version %d; this daemon reads version %d", boxSkillSetsManifestFile, m.Version, boxSkillSetManifestVersion)
		}
		st.manifest = boxSkillSetManifest{Version: m.Version, Release: m.Release, Sets: map[string][]string{}}
		for id, dirs := range m.Sets {
			if !skillSetIDPattern.MatchString(id) {
				return st, fmt.Errorf("%s names set %q, which is not a set id", boxSkillSetsManifestFile, id)
			}
			st.manifest.Sets[id] = validSkillDirs(dirs)
		}
		st.hasManifest = true
	}
	st.installerDirs = validSkillDirs(strings.Split(installerText, "\n"))
	return st, nil
}

// validSkillDirs keeps the names the installer could own, deduplicated and
// sorted.
func validSkillDirs(names []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" || !skillDirPattern.MatchString(n) || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// owningSkillSet returns the set among candidates whose namespace prefixes
// dir ("<ns>-"), the longest namespace winning, or "" when none does.
func owningSkillSet(dir string, candidates []string, known map[string][]string) string {
	best, bestLen := "", 0
	for _, id := range candidates {
		for _, ns := range known[id] {
			if len(ns) > bestLen && strings.HasPrefix(dir, ns+"-") {
				best, bestLen = id, len(ns)
			}
		}
	}
	return best
}

// attributeSkillDirs assigns installer-owned directories to the sets among
// sets that claim them by namespace. _shared belongs to no set and is not
// reported; a directory no set in sets claims is returned as loose (sorted)
// rather than dropped, so a removal is never silent. Every set in sets has an
// entry (possibly empty) in the result.
func attributeSkillDirs(dirs, sets []string, known map[string][]string) (bySet map[string][]string, loose []string) {
	bySet = map[string][]string{}
	for _, id := range sets {
		bySet[id] = []string{}
	}
	for _, dir := range dirs {
		if dir == boxSkillSetsSharedDir {
			continue
		}
		if id := owningSkillSet(dir, sets, known); id != "" {
			bySet[id] = append(bySet[id], dir)
		} else {
			loose = append(loose, dir)
		}
	}
	for id := range bySet {
		sort.Strings(bySet[id])
	}
	sort.Strings(loose)
	return bySet, loose
}

// skillSetsPredatingManifest lists the known sets the box holds without a
// manifest record: an installer-owned directory under one of the set's
// namespaces that no recorded set claims. Sorted.
func skillSetsPredatingManifest(st boxSkillSetsState, known map[string][]string) []string {
	recorded := map[string]bool{}
	for _, dirs := range st.manifest.Sets {
		for _, d := range dirs {
			recorded[d] = true
		}
	}
	var unrecorded []string
	for _, d := range st.installerDirs {
		if !recorded[d] {
			unrecorded = append(unrecorded, d)
		}
	}
	var out []string
	for _, id := range sortedSkillSetIDs(known) {
		if _, ok := st.manifest.Sets[id]; ok {
			continue
		}
		for _, d := range unrecorded {
			if owningSkillSet(d, []string{id}, known) == id {
				out = append(out, id)
				break
			}
		}
	}
	return out
}

// diffSkillSetManifests reports what changed between two per-set manifests:
// installed is, per set in after, the directories not under that set in
// before; removed is, per set in before, the directories no longer under it
// in after. Sets are in order; a set with nothing to report is omitted.
func diffSkillSetManifests(before, after map[string][]string) (installed, removed []*pb.BoxSkillSetChange) {
	diff := func(a, b map[string][]string) []*pb.BoxSkillSetChange {
		var out []*pb.BoxSkillSetChange
		for _, id := range sortedSkillSetIDs(a) {
			have := map[string]bool{}
			for _, d := range b[id] {
				have[d] = true
			}
			var dirs []string
			for _, d := range a[id] {
				if !have[d] {
					dirs = append(dirs, d)
				}
			}
			if len(dirs) > 0 {
				out = append(out, &pb.BoxSkillSetChange{SkillSet: id, Skills: dirs})
			}
		}
		return out
	}
	return diff(after, before), diff(before, after)
}

// liveBoxRunNames lists the names of the RUNNING code runs in
// boxRunListScript's output: same boot, PID alive. An UNKNOWN run (its PID is
// gone, or it predates this boot) is not in progress.
func liveBoxRunNames(out string) []string {
	views, boot, alive := parseBoxRunViews(out)
	var names []string
	for _, v := range views {
		if agentbox.ResolveOutcome(v.record, boot, func(pid int) bool { return pid > 0 && alive[pid] }) == agentbox.RunOutcomeRunning {
			names = append(names, v.record.Name)
		}
	}
	sort.Strings(names)
	return names
}

// boxSkillSetsRunInProgress is the RUN_IN_PROGRESS refusal naming the runs.
func boxSkillSetsRunInProgress(boxName string, codeRuns, skillRuns []string) error {
	var parts []string
	if len(codeRuns) > 0 {
		parts = append(parts, fmt.Sprintf("code run(s) %s", quoteAll(codeRuns)))
	}
	if len(skillRuns) > 0 {
		parts = append(parts, fmt.Sprintf("skill run(s) %s", quoteAll(skillRuns)))
	}
	return boxSkillSetsRefusal(pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_RUN_IN_PROGRESS, boxName,
		fmt.Sprintf("%s has a run in progress (%s); its skills are not changed under a run. Retry once the run has ended, or stop it first.", boxName, strings.Join(parts, "; ")))
}

// boxSkillSetGate is box's gate between ApplyBoxSkillSets and run starts
// (#3510). An apply holds it for writing from before its run-in-progress check
// until it returns, which also serializes applies on one box. A run start holds
// it for reading from before its first touch of the box until the run's record
// is written, so an apply that arrives meanwhile waits for that start and then
// sees the run. The run-in-progress check and the install are therefore atomic
// against every run start.
func (s *ContainerServer) boxSkillSetGate(box string) *sync.RWMutex {
	v, _ := s.boxSkillSetLocks.LoadOrStore(box, &sync.RWMutex{})
	return v.(*sync.RWMutex)
}

// enterBoxRunStart takes box's gate for a run start, or refuses the start with
// APPLY_IN_PROGRESS when an apply holds it (an apply that is only waiting does not count, #3530): never a wait,
// per the decision on #3524 (Q3). The caller runs release once the run's
// record is written (or the start has failed).
func (s *ContainerServer) enterBoxRunStart(box, runName string) (release func(), err error) {
	gate := s.boxSkillSetGate(box)
	if !gate.TryRLock() {
		return nil, boxSkillSetsRefusal(pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_APPLY_IN_PROGRESS, box,
			fmt.Sprintf("%s is applying skill sets (ApplyBoxSkillSets) right now; a run does not start while its skills are being changed. Retry once the apply has returned.", box))
	}
	s.boxRunStarts.add(box, runName)
	return func() {
		s.boxRunStarts.remove(box, runName)
		gate.RUnlock()
	}, nil
}

// boxSkillSetsGateWait caps how long ApplyBoxSkillSets waits for run starts to
// finish (#3530); boxSkillSetsGatePoll is how often it retries. Variables so
// tests can shorten them.
var (
	boxSkillSetsGateWait = 30 * time.Second
	boxSkillSetsGatePoll = 25 * time.Millisecond
)

// boxRunStartHolders records which run starts hold a box's gate, so a refused
// apply can name them. The zero value is ready to use.
type boxRunStartHolders struct {
	mu    sync.Mutex
	byBox map[string]map[string]int
}

func (h *boxRunStartHolders) add(box, run string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.byBox == nil {
		h.byBox = map[string]map[string]int{}
	}
	if h.byBox[box] == nil {
		h.byBox[box] = map[string]int{}
	}
	h.byBox[box][run]++
}

func (h *boxRunStartHolders) remove(box, run string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.byBox[box][run]--; h.byBox[box][run] <= 0 {
		delete(h.byBox[box], run)
	}
}

func (h *boxRunStartHolders) names(box string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	names := make([]string, 0, len(h.byBox[box]))
	for n := range h.byBox[box] {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// lockBoxSkillSetGate takes box's gate for writing, retrying TryLock until ctx
// is done or boxSkillSetsGateWait has passed. A TryLock that fails does not
// queue as a writer, so run starts are not refused while the apply only waits;
// they are refused (APPLY_IN_PROGRESS) once it holds the gate. On the cap it
// refuses with RUN_IN_PROGRESS naming the run starts holding the gate.
func (s *ContainerServer) lockBoxSkillSetGate(ctx context.Context, box string) error {
	gate := s.boxSkillSetGate(box)
	timeout := time.NewTimer(boxSkillSetsGateWait)
	defer timeout.Stop()
	tick := time.NewTicker(boxSkillSetsGatePoll)
	defer tick.Stop()
	for !gate.TryLock() {
		select {
		case <-ctx.Done():
			return status.FromContextError(ctx.Err()).Err()
		case <-timeout.C:
			return boxSkillSetsRefusal(pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_RUN_IN_PROGRESS, box,
				fmt.Sprintf("%s has a run start in progress (%s) that did not finish within %s; its skills are not changed under a run. Retry shortly.",
					box, quoteAll(s.boxRunStarts.names(box)), boxSkillSetsGateWait))
		case <-tick.C:
		}
	}
	return nil
}

func quoteAll(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = fmt.Sprintf("%q", n)
	}
	return strings.Join(q, ", ")
}

// ApplyBoxSkillSets re-applies a box's SDLC skill sets (#3374): validates and
// authorizes, refuses under a run in progress, reads the box's manifests as
// its user, refuses to drop a set that predates the manifest, runs the shared
// installer with the full target list (its own manifest makes it add the new
// sets' directories and prune the dropped sets' ones, nothing else), records
// which directories each target set now owns, and reports the difference.
func (s *ContainerServer) ApplyBoxSkillSets(ctx context.Context, req *pb.ApplyBoxSkillSetsRequest) (*pb.ApplyBoxSkillSetsResponse, error) {
	if err := validateBoxRunOwner(req.GetUsername()); err != nil {
		return nil, err
	}
	if err := s.authorizeBoxRuns(ctx, req.GetUsername()); err != nil {
		return nil, err
	}
	known, err := knownSkillSets()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read the embedded skill-set lock: %v", err)
	}
	target, err := validateSkillSetIDs(req.GetSkillSets(), known)
	if err != nil {
		return nil, err
	}
	release := strings.TrimSpace(req.GetRelease())
	if release == "" {
		release = agentRuntimeReleaseTag()
	}
	if !sdlcskills.ValidReleaseTag(release) {
		return nil, status.Errorf(codes.InvalidArgument, "release %q is not a release tag (expected something like v0.89.0)", release)
	}
	rootExec, userExec, install := s.boxRunExecFn(), s.boxRunStartExecFn(), s.boxSkillSetsInstallFn()
	if rootExec == nil || userExec == nil || install == nil {
		return nil, status.Error(codes.Unavailable, "no container backend to apply skill sets on")
	}
	username := req.GetUsername()
	info, err := s.runCheckoutGetBox(ctx, username)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "look up %q: %v", username, err)
	}
	if info == nil {
		return nil, status.Errorf(codes.NotFound, "no box for %q", username)
	}
	if info.State != pb.ContainerState_CONTAINER_STATE_RUNNING {
		return nil, status.Errorf(codes.FailedPrecondition, "%q is not running; skill sets are applied to a running box", username)
	}
	boxName := username + "-container"
	// Held until return: no run starts between the check below and the install
	// (#3510); see boxSkillSetGate.
	if err := s.lockBoxSkillSetGate(ctx, boxName); err != nil {
		return nil, err
	}
	defer s.boxSkillSetGate(boxName).Unlock()

	// Held until return, a failure or panic included: a run started over SSH
	// reads it in the box owner's tree and refuses (#3529). Taken before the
	// run-in-progress check, so an SSH run that starts after the check is kept
	// out too.
	releaseMarker, err := s.holdSkillSetsApplyMarker(userExec, boxName, username)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "mark %q as applying skill sets: %v", username, err)
	}
	defer releaseMarker()

	// A run in progress: a RUNNING code run, or a skill run in this box.
	out, err := rootExec(boxName, boxRunListScript(s.boxRunDir()))
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read run records of %q: %v", username, err)
	}
	codeRuns := liveBoxRunNames(out)
	var skillRuns []string
	if s.runRegistry != nil {
		skillRuns = s.runRegistry.LiveInBox(boxName)
	}
	if len(codeRuns) > 0 || len(skillRuns) > 0 {
		return nil, boxSkillSetsRunInProgress(boxName, codeRuns, skillRuns)
	}

	out, err = userExec(boxName, username, boxSkillSetsStateScript())
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read the skill manifests of %q: %v", username, err)
	}
	before, err := parseBoxSkillSetsState(out)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%q: %v; fix or remove the file, nothing was changed", username, err)
	}
	inTarget := map[string]bool{}
	for _, id := range target {
		inTarget[id] = true
	}
	for _, id := range skillSetsPredatingManifest(before, known) {
		if !inTarget[id] {
			return nil, boxSkillSetsRefusal(pb.BoxSkillSetsRefusal_BOX_SKILL_SETS_REFUSAL_SET_PREDATES_MANIFEST, id,
				fmt.Sprintf("skill set %q was installed on %q before the per-box manifest existed, so what it installed is not recorded and it cannot be removed; keep %q in the list to adopt it (this call then records it, and a later call can remove it)", id, boxName, id))
		}
	}

	sets := sdlcskills.SkillSetsFromIDs(target)
	if _, err := install(boxName, username, release, sets); err != nil {
		return nil, status.Errorf(codes.Unavailable, "install SDLC skills (%s, %s) on %q: %v", sets, release, username, err)
	}

	out, err = userExec(boxName, username, boxSkillSetsStateScript())
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read the skill manifests of %q after the install: %v", username, err)
	}
	after, err := parseBoxSkillSetsState(out)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%q: %v", username, err)
	}
	bySet, loose := attributeSkillDirs(after.installerDirs, target, known)
	manifest := boxSkillSetManifest{Version: boxSkillSetManifestVersion, Release: release, Sets: bySet}
	script, err := boxSkillSetsWriteManifestScript(manifest)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encode the skill-set manifest: %v", err)
	}
	if _, err := userExec(boxName, username, script); err != nil {
		return nil, status.Errorf(codes.Unavailable, "write the skill-set manifest of %q: %v", username, err)
	}
	if len(loose) > 0 {
		s.runCheckoutLogf("[skill-sets] %q: installer-owned directories no set in this daemon's lock claims, left as they are: %s", boxName, quoteAll(loose))
	}

	installed, removed := diffSkillSetManifests(before.manifest.Sets, manifest.Sets)
	// Installer-owned directories that were recorded under no set and are gone
	// now (the installer pruned a namespace the lock no longer has) are reported
	// without a set rather than silently.
	recordedBefore := map[string]bool{}
	for _, dirs := range before.manifest.Sets {
		for _, d := range dirs {
			recordedBefore[d] = true
		}
	}
	stillThere := map[string]bool{}
	for _, d := range after.installerDirs {
		stillThere[d] = true
	}
	var unrecordedGone []string
	for _, d := range before.installerDirs {
		if d != boxSkillSetsSharedDir && !recordedBefore[d] && !stillThere[d] {
			unrecordedGone = append(unrecordedGone, d)
		}
	}
	if len(unrecordedGone) > 0 {
		removed = append(removed, &pb.BoxSkillSetChange{Skills: unrecordedGone})
	}
	return &pb.ApplyBoxSkillSetsResponse{
		SkillSets: target,
		Installed: installed,
		Removed:   removed,
		Unchanged: len(installed) == 0 && len(removed) == 0,
		Release:   release,
	}, nil
}
