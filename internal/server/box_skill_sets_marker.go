package server

import (
	"time"

	"github.com/footprintai/containarium/pkg/core/sdlcskills"
)

// holdSkillSetsApplyMarker takes the skill-set apply marker in box as
// username (#3529; the contract is in pkg/core/sdlcskills/apply_marker.go): a
// run started over SSH reads it and refuses while it is held, the way the
// daemon's gate refuses its own run starts (#3510). It renews the lease every
// third of it until release, so a long download keeps it held and only an
// apply that stopped running lets it lapse. release stops renewing and removes
// the marker, and the directories taking it created while they are still
// empty, so a refused apply changes nothing; the caller defers it, so a failed
// or panicking apply removes it too. A marker the apply cannot take is an
// error: the skills are not changed under SSH runs it could not keep out.
func (s *ContainerServer) holdSkillSetsApplyMarker(exec boxRunStartFunc, box, username string) (release func(), err error) {
	lease := s.skillSetsApplyLease
	if lease <= 0 {
		lease = sdlcskills.ApplyMarkerLease
	}
	out, err := exec(box, username, sdlcskills.ApplyMarkerWriteScript(0, lease))
	if err != nil {
		return nil, err
	}
	taken, err := sdlcskills.ParseApplyMarkerTaken(out)
	if err != nil {
		_, _ = exec(box, username, sdlcskills.ApplyMarkerRemoveScript(0))
		return nil, err
	}

	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(lease / 3)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				if _, err := exec(box, username, sdlcskills.ApplyMarkerWriteScript(taken.StartedAt, lease)); err != nil {
					s.runCheckoutLogf("[skill-sets] %q: renew the apply marker: %v", box, err)
				}
			}
		}
	}()
	return func() {
		close(stop)
		<-done
		if _, err := exec(box, username, sdlcskills.ApplyMarkerRemoveScript(taken.CreatedLevels)); err != nil {
			s.runCheckoutLogf("[skill-sets] %q: remove the apply marker (it lapses on its own within %s): %v", box, lease, err)
		}
	}, nil
}
