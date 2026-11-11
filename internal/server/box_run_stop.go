package server

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/agentbox"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// StopBoxRun (#2603) is the daemon-API counterpart to `containarium code stop`
// for a caller with no SSH client. It reads the run's record through the same
// list script ListBoxRuns uses, resolves the outcome the same way, and only
// signals a run that is RUNNING on this boot, so a recycled PID is never hit.
//
// The record is written by the box's own user, so its PID is not trusted
// blindly: the kill script refuses any process the box user does not own.

// boxRunStopScript signals the process group of pid (StartBoxRun and `code run`
// both setsid the run, so PGID == PID), waits briefly for the group to go and,
// once all of it did, leaves the exit sidecar the killed wrapper could not
// write. "Gone" means the whole group, not just its leader: the leader is the
// wrapper shell, and an engine child that ignores SIGTERM outlives it.
//
// The record names the PID and the box user can write it, so nothing is
// signaled unless every member of the group belongs to the box user. Prints one
// line: "refused" (a member is not the box user's), "gone" (no such group), or
// "alive" / "dead" after the signal.
func boxRunStopScript(dir, name, username string, pid int, force bool) string {
	q := shellSingleQuote
	sig := "TERM"
	code := 143
	if force {
		sig = "KILL"
		code = 137
	}
	exit := dir + "/" + name + ".exit"
	return fmt.Sprintf(`pid=%d
user=%s
[ "$pid" -gt 1 ] || { echo refused; exit 0; }
uid=$(id -u "$user" 2>/dev/null) || { echo refused; exit 0; }
grp() { ps -eo pgid=,uid= 2>/dev/null | awk -v g="$pid" -v u="$uid" '$1==g{n++; if($2!=u)b=1} END{if(!n)print "none"; else if(b)print "foreign"; else print "ok"}'; }
case "$(grp)" in ok) ;; none) echo gone; exit 0;; *) echo refused; exit 0;; esac # no ps/awk, or a foreign member: fail closed
kill -%s "-$pid" 2>/dev/null || true # no "--": dash's kill builtin does not take it
i=0
while [ $i -lt 40 ] && [ "$(grp)" != none ]; do sleep 0.05; i=$((i+1)); done
if [ "$(grp)" != none ]; then echo alive; exit 0; fi
if [ ! -e %s ] && [ ! -L %s ]; then
  printf '%%s %%s' %d "$(date -u +%%s)" > %s && chown "$user" %s && mv -f %s %s
fi
echo dead
`, pid, q(username), sig, q(exit), q(exit), code, q(exit+".tmp"), q(exit+".tmp"), q(exit+".tmp"), q(exit))
}

// StopBoxRun stops a box's code run.
func (s *ContainerServer) StopBoxRun(ctx context.Context, req *pb.StopBoxRunRequest) (*pb.StopBoxRunResponse, error) {
	if err := validateBoxRunOwner(req.GetUsername()); err != nil {
		return nil, err
	}
	name := req.GetRunName()
	if !validRunPathID(name) {
		return nil, status.Errorf(codes.InvalidArgument, "run_name must match %s and not be . or ..", runIDPattern.String())
	}
	if err := s.authorizeBoxRuns(ctx, req.GetUsername()); err != nil {
		return nil, err
	}
	exec := s.boxRunExecFn()
	if exec == nil {
		return nil, status.Error(codes.Unavailable, "no container backend to stop a run on")
	}
	box := req.GetUsername() + "-container"
	dir := s.boxRunDir()

	// Serialized with StartBoxRun for the same (box, name): a stop must not
	// land between a start's collision check and its record write.
	lock := s.boxRunLockFor(boxRunLockKey(box, name))
	lock.Lock()
	defer lock.Unlock()

	read := func() (boxRunView, string, map[int]bool, error) {
		out, err := exec(box, boxRunListScript(dir))
		if err != nil {
			return boxRunView{}, "", nil, status.Errorf(codes.Unavailable, "read run records of %q: %v", req.GetUsername(), err)
		}
		views, boot, alive := parseBoxRunViews(out)
		for _, v := range views {
			if v.fileName == name {
				return v, boot, alive, nil
			}
		}
		return boxRunView{}, "", nil, status.Errorf(codes.NotFound, "no run named %q on %q", name, req.GetUsername())
	}
	resolve := func(v boxRunView, boot string, alive map[int]bool) agentbox.RunOutcome {
		return agentbox.ResolveOutcome(v.record, boot, func(pid int) bool { return pid > 0 && alive[pid] })
	}

	view, boot, alive, err := read()
	if err != nil {
		return nil, err
	}
	switch resolve(view, boot, alive) {
	case agentbox.RunOutcomeExited:
		return &pb.StopBoxRunResponse{Run: boxRunView2Proto(dir, view, agentbox.RunOutcomeExited), Signal: pb.BoxRunStopSignal_BOX_RUN_STOP_SIGNAL_NONE, Exited: true}, nil
	case agentbox.RunOutcomeRunning:
	default:
		// Unknown on THIS boot is a run whose wrapper died (a soft stop does
		// that) while its engine may still be going: the script decides, by who
		// owns the group. Unknown from another boot means the PID may belong to
		// anything now: never signaled.
		if boot == "" || view.record.BootID != boot {
			return nil, status.Errorf(codes.FailedPrecondition,
				"run %q on %q predates this boot; refusing to signal pid %d, which may have been reassigned",
				name, req.GetUsername(), view.record.PID)
		}
	}

	out, err := exec(box, boxRunStopScript(dir, name, req.GetUsername(), view.record.PID, req.GetForce()))
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "stop run %q on %q: %v", name, req.GetUsername(), err)
	}
	result := strings.TrimSpace(out)
	if result == "refused" {
		return nil, status.Errorf(codes.FailedPrecondition, "run %q on %q: process group %s has a member that is not the box user's; refusing to signal it", name, req.GetUsername(), strconv.Itoa(view.record.PID))
	}

	signal := pb.BoxRunStopSignal_BOX_RUN_STOP_SIGNAL_SIGTERM
	if req.GetForce() {
		signal = pb.BoxRunStopSignal_BOX_RUN_STOP_SIGNAL_SIGKILL
	}
	if result == "gone" {
		signal = pb.BoxRunStopSignal_BOX_RUN_STOP_SIGNAL_NONE
	}
	view, boot, alive, err = read()
	if err != nil {
		return nil, err
	}
	if result == "dead" || result == "gone" {
		// The run ended: sweep the box's stale per-run checkouts (#3296).
		s.sweepBoxRunCheckoutsAfterRun(req.GetUsername())
	}
	return &pb.StopBoxRunResponse{
		Run:    boxRunView2Proto(dir, view, resolve(view, boot, alive)),
		Signal: signal,
		Exited: result == "dead" || result == "gone",
	}, nil
}

func boxRunView2Proto(dir string, v boxRunView, outcome agentbox.RunOutcome) *pb.BoxRun {
	run := boxRunProto(v.fileName, dir, v.record, outcome)
	run.SessionId = v.sessionID
	return run
}
