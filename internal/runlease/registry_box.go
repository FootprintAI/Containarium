package runlease

import "sort"

// LiveInBox returns the ids of the runs currently registered in THIS daemon
// process whose box is box (a container name), sorted. It is how an operation
// that would change files under a run — ApplyBoxSkillSets (#3374) — tells a
// skill run executing in a box from no run at all. The same single-process,
// non-durable view as Live applies.
func (r *Registry) LiveInBox(box string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var ids []string
	for id, info := range r.runs {
		if info.Box == box {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}
