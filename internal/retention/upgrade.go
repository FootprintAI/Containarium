package retention

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// QuarantineOrgID is the id a hold whose stored org id is empty once
// trimmed is re-stored under: deterministic for the stored value, non-empty
// and slash-free, so the hold stays active and can be released through the
// API by this id.
func QuarantineOrgID(stored string) string {
	sum := sha256.Sum256([]byte(stored))
	return "quarantined-blank-org-id-" + hex.EncodeToString(sum[:])[:12]
}

// Changes a store's bootstrap makes to data an earlier release stored (Q31
// on #2727): a window above MaxDays is clamped, and legal-hold org ids are
// normalised. Each change is a compliance-setting change, so it is recorded
// durably in the same transaction as the change and audited once an audit
// store exists (see UpgradeAuditor).

// UpgradeActor is the username on the audit entry of an upgrade change and
// the updated_by of a policy revision a clamp creates.
const UpgradeActor = "containarium-upgrade"

// Audit actions of upgrade changes.
const (
	// UpgradeActionClamp: windows above MaxDays were clamped to it; the
	// policy revision was bumped.
	UpgradeActionClamp = "retention.policy.clamp"
	// UpgradeActionHoldNormalise: a padded hold id was re-stored trimmed.
	UpgradeActionHoldNormalise = "retention.hold.normalise"
	// UpgradeActionHoldMerge: a hold whose id trims to an org already held by
	// an earlier hold was removed; the org stays held.
	UpgradeActionHoldMerge = "retention.hold.merge"
	// UpgradeActionHoldQuarantine: a hold whose id is empty once trimmed was
	// re-stored under QuarantineOrgID, still active, so it can be released.
	UpgradeActionHoldQuarantine = "retention.hold.quarantine"
)

// UpgradeEvent is one recorded upgrade change waiting for its audit entry.
// Detail is the JSON of one of the Upgrade*Detail types below.
type UpgradeEvent struct {
	ID           int64
	Action       string
	ResourceType string
	ResourceID   string
	Detail       string
	CreatedAt    time.Time
}

// UpgradeAuditor is implemented by a store that records upgrade changes.
type UpgradeAuditor interface {
	// AuditUpgradeEvents passes each event not yet audited to write, oldest
	// first, and marks it audited only once write succeeded. It stops at the
	// first error from write and returns it; that event and the ones after it
	// stay pending for a later call. It returns how many were audited.
	AuditUpgradeEvents(ctx context.Context, write func(UpgradeEvent) error) (int, error)
}

// UpgradeClampedWindow is one clamped class.
type UpgradeClampedWindow struct {
	Class      string `json:"class"`
	StoredDays int32  `json:"stored_days"`
	Days       int32  `json:"days"`
}

// UpgradeClampDetail is the detail of a retention.policy.clamp entry.
type UpgradeClampDetail struct {
	PreviousRevision int64                  `json:"previous_revision"`
	Revision         int64                  `json:"revision"`
	Windows          []UpgradeClampedWindow `json:"windows"`
}

// UpgradeHold is a stored hold exactly as it was found.
type UpgradeHold struct {
	OrgID  string    `json:"org_id"`
	Reason string    `json:"reason"`
	SetBy  string    `json:"set_by"`
	SetAt  time.Time `json:"set_at"`
}

// UpgradeHoldDetail is the detail of a retention.hold.normalise, .merge or
// .quarantine entry: the hold as it was stored, and the org id the org is
// held under afterwards.
type UpgradeHoldDetail struct {
	StoredAs UpgradeHold `json:"stored_as"`
	HeldAs   string      `json:"held_as"`
}
