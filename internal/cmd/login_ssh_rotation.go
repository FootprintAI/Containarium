package cmd

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/internal/credentials"
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
	cleanupKeys, ownershipErr := protectKeysOnOtherServers(ctx, srv, keys, now)
	var removed []string
	var cleanupErr error
	if ownershipErr == nil {
		removed, cleanupErr = sshkey.RemoveRetired(sshkey.LocateOpts{}, cleanupKeys, now)
	} else {
		fmt.Fprintln(out, "Keeping retired SSH keys because another configured server's key status could not be confirmed.")
	}
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
		fmt.Fprintf(out, "SSH key %q expires at %s; rotate it with containarium ssh rotate --name %s --server %s\n",
			key.Name, key.ExpiresAt.UTC().Format(time.RFC3339), coderun.ShellQuoteSingle(key.Name), coderun.ShellQuoteSingle(srv))
	}
}

// A key retired by one server can still be active on another. Use each
// profile's stored credential, not a global --token override, to check that
// ownership. Unavailable key status conservatively prevents local deletion.
func protectKeysOnOtherServers(ctx context.Context, srv string, keys []sshkey.SSHKey, now time.Time) ([]sshkey.SSHKey, error) {
	candidate := false
	for _, key := range keys {
		if key.Fingerprint != "" && key.RetiredAt != nil && !key.RetiredAt.IsZero() && !key.RetiredAt.After(now) {
			candidate = true
			break
		}
	}
	if !candidate {
		return keys, nil
	}
	path, err := credentials.DefaultPath()
	if err != nil {
		return nil, err
	}
	cf, err := credentials.Load(path)
	if err != nil {
		return nil, err
	}
	protected := append([]sshkey.SSHKey(nil), keys...)
	for server, creds := range cf.Servers {
		if credentials.NormalizeServer(server) == credentials.NormalizeServer(srv) {
			continue
		}
		if creds.Token == "" {
			return nil, fmt.Errorf("missing credential for another configured server")
		}
		other := &sshHTTPClient{server: server, token: creds.Token, hc: loginHTTPClient()}
		otherKeys, err := other.ListSSHKeys(ctx)
		if err != nil {
			return nil, err
		}
		for _, key := range otherKeys {
			if key.RetiredAt != nil && !key.RetiredAt.IsZero() && !key.RetiredAt.After(now) {
				continue
			}
			fp := key.Fingerprint
			if fp == "" {
				fp, err = sshkey.Fingerprint(key.PublicKey)
				if err != nil {
					return nil, err
				}
			}
			// Only protect active keys; other profiles cannot authorize cleanup
			// of additional keys absent from the current server's retired list.
			protected = append(protected, sshkey.SSHKey{Fingerprint: fp})
		}
	}
	return protected, nil
}
