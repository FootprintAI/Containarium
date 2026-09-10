//go:build containarium_client

package cmd

import "github.com/footprintai/containarium/internal/credentials"

// resolveServerAddr adds the client-only third link in the server
// resolution chain: --server flag > CONTAINARIUM_SERVER env (both already
// collapsed into flagOrEnv by the time this runs, since the flag's default
// is the env var) > credentials.json's default_server.
//
// Client-only: containariumd must NOT pick up a stale default_server on an
// operator's host and silently repoint local-mode commands at a remote
// fleet — see server_resolve_default.go and
// docs/architecture/cli-client-server-split.md ("Server resolution in the
// client").
func resolveServerAddr(flagOrEnv string) string {
	if flagOrEnv != "" {
		return flagOrEnv
	}
	path, err := credentials.DefaultPath()
	if err != nil {
		return flagOrEnv
	}
	cf, err := credentials.Load(path)
	if err != nil {
		return flagOrEnv
	}
	return cf.DefaultServer
}
