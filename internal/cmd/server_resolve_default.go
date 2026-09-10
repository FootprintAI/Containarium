//go:build !containarium_client

package cmd

// resolveServerAddr is the identity function under containariumd: the
// credentials-file default_server fallback is client-only (see
// server_resolve_client.go) so an operator's host never gets silently
// repointed from local Incus to a stale remote fleet by a leftover
// credentials file.
func resolveServerAddr(flagOrEnv string) string {
	return flagOrEnv
}
