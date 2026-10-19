package sshban

import "github.com/tg123/sshpiper/libplugin"

// PluginConfig preserves the bundled failtoban's callback and routing contract.
func (g *Guard) PluginConfig() libplugin.SshPiperPluginConfig {
	return libplugin.SshPiperPluginConfig{
		NoClientAuthCallback: func(libplugin.ConnMetadata) (*libplugin.Upstream, error) {
			return &libplugin.Upstream{Auth: libplugin.CreateNextPluginAuth(map[string]string{})}, nil
		},
		NewConnectionCallback: func(conn libplugin.ConnMetadata) error { return g.Check(conn.RemoteAddr()) },
		UpstreamAuthFailureCallback: func(conn libplugin.ConnMetadata, _ string, _ error, _ []string) {
			g.Fail(conn.RemoteAddr(), "auth_failure")
		},
		PipeCreateErrorCallback: func(remote string, _ error) { g.Fail(remote, "pipe_create_error") },
	}
}
