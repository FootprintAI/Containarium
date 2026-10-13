package cmd

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/footprintai/containarium/internal/sshkey"
)

// SSH maintenance is best-effort: its failure cannot undo a successful login.
func maybeCheckPostLoginSSHKeys(out io.Writer, srv string) {
	client, err := newSSHHTTPClient(srv)
	if err != nil {
		fmt.Fprintf(out, "Could not check SSH keys: %v\n", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	keys, err := client.ListSSHKeys(ctx)
	if isUnimplemented(err) {
		return
	}
	if err != nil {
		fmt.Fprintf(out, "Could not check SSH keys: %v\n", err)
		return
	}
	now := time.Now()
	removed, cleanupErr := sshkey.RemoveRetired(sshkey.LocateOpts{}, keys, now)
	for _, path := range removed {
		fmt.Fprintf(out, "Removed retired SSH key %s\n", path)
	}
	if cleanupErr != nil {
		fmt.Fprintf(out, "Could not clean up retired SSH keys: %v\n", cleanupErr)
	}
	for _, key := range keys {
		if key.RetiredAt != nil && !key.RetiredAt.IsZero() && !key.RetiredAt.After(now) {
			continue
		}
		if key.ExpiresAt.IsZero() || key.ExpiresAt.After(now.Add(7*24*time.Hour)) {
			continue
		}
		fmt.Fprintf(out, "SSH key %q expires at %s; rotate it with containarium ssh rotate --name %q --server %q\n",
			key.Name, key.ExpiresAt.UTC().Format(time.RFC3339), key.Name, srv)
	}
}
