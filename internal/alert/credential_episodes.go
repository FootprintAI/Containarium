package alert

import (
	"context"
	"time"
)

// Credential episodes contain only source/outcome metadata, never credential data.
type CredentialEpisode struct {
	ID            string `json:"id"`
	AfterRecovery bool   `json:"afterRecovery"`
}
type CredentialEpisodes struct {
	Version int                 `json:"version"`
	Active  bool                `json:"active"`
	Pending []CredentialEpisode `json:"pending"`
}

// Optional extension keeps existing probers and older runtimes compatible.
type CredentialEpisodeProber interface {
	CredentialEpisodes(context.Context, CredentialWatchTarget) (CredentialEpisodes, error)
	AcknowledgeCredentialEpisodes(context.Context, CredentialWatchTarget, []string) error
}
type CredentialEpisodeStore interface {
	RecordEpisode(context.Context, string, string, time.Time) (bool, error)
}
