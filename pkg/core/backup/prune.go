package backup

import "fmt"

// PruneOptions parameterizes a retention sweep (#1839): delete older
// backups for a tenant, keeping only the newest Keep per (username,
// database) group. A hook backup's Database field already holds its
// label (see hookLabel / Create's hookMode branch), so no special-casing
// is needed — grouping by Database alone covers plaintext, hook, and
// encrypted records uniformly.
type PruneOptions struct {
	// Username is required — pruning is always scoped to one tenant.
	Username string
	// Database, when set, prunes only that (username, database) group.
	// Empty prunes every database this tenant has backups for, each
	// independently down to Keep.
	Database string
	// Keep is how many of the newest records to retain per group. Must
	// be >= 1: a request to prune everything for a group is `backup
	// delete` making its own explicit per-record choice, not this call
	// guessing that Keep=0 was intended.
	Keep int
}

// PruneResult reports what a prune sweep actually did.
type PruneResult struct {
	// Deleted holds the IDs of every record actually removed.
	Deleted []string
	// Failures holds one message per record whose delete failed. A
	// failure never aborts pruning the rest of the group, or the other
	// groups (mirrors CreateAll's per-database partial-failure posture,
	// #954) — one bad object store error should not leave every other
	// eligible record un-pruned.
	Failures []string
}

// Prune deletes older backups for opts.Username, keeping only the newest
// opts.Keep per (username, database) group. Nothing is touched for any
// other tenant, and — when opts.Database is empty — every database this
// tenant has backups for is pruned independently, so one database's
// history never counts against another's retention.
func (m *Manager) Prune(opts PruneOptions) (*PruneResult, error) {
	if opts.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if opts.Keep < 1 {
		return nil, fmt.Errorf("keep must be at least 1 (got %d); use backup delete to remove a specific backup by id", opts.Keep)
	}

	all, err := m.List(opts.Username)
	if err != nil {
		return nil, err
	}

	// List returns newest-first per database already sorted by
	// CreatedAt; grouping preserves that order, so recs[Keep:] in each
	// group is exactly "everything older than the newest Keep".
	groups := map[string][]*Record{}
	for _, r := range all {
		if opts.Database != "" && r.Database != opts.Database {
			continue
		}
		groups[r.Database] = append(groups[r.Database], r)
	}

	res := &PruneResult{}
	for _, recs := range groups {
		if len(recs) <= opts.Keep {
			continue
		}
		for _, r := range recs[opts.Keep:] {
			if err := m.Delete(r.ID); err != nil {
				res.Failures = append(res.Failures, fmt.Sprintf("%s: %v", r.ID, err))
				continue
			}
			res.Deleted = append(res.Deleted, r.ID)
		}
	}
	return res, nil
}
