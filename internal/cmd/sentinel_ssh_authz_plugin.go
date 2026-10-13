//go:build !windows && !containarium_client

package cmd

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/tg123/sshpiper/libplugin"

	"github.com/footprintai/containarium/internal/sentinel/sshauthz"
)

var (
	sentinelSSHAuthzPluginDaemonURL string
	sentinelSSHAuthzPluginGrace     time.Duration
	sentinelSSHAuthzPluginTimeout   time.Duration
)

var sentinelSSHAuthzPluginCmd = &cobra.Command{
	Use:   "ssh-authz-plugin",
	Short: "sshpiperd plugin: sentinel SSH live-authorization in audit-only mode (#2518)",
	Long: `Run as an sshpiperd chained plugin, NOT as a command a human invokes directly.

On every public-key auth attempt this plugin calls POST /v1/ssh/authorize on
the backend daemon (sentinel-signed, same as keysync/certsync) and stashes the
decision as ConnMeta metadata for the ssh-session-plugin to record. It is
AUDIT-ONLY: it never rejects a connection regardless of the backend's answer —
it always defers to the next plugin in the chain (UpstreamNextPluginAuth).

Positive results are cached per (backendURL, login, fingerprint) with the TTL
the backend returns. When the backend is unreachable (transport error or 5xx)
and the grace window has not expired, the last known positive is honoured
(fail-closed grace: an ALLOW within --grace of its expiry is extended). Outside
the grace window the absence of a fresh positive is recorded as
UPSTREAM_UNAVAILABLE — still without rejecting the connection.

Wire it between the ssh-session-plugin and the routing plugin ("yaml"):

  sshpiperd -i host_key -p 22 \
    containarium sentinel ssh-session-plugin --records-file /var/log/containarium/ssh-sessions.jsonl \
    -- containarium sentinel ssh-authz-plugin --daemon-url http://<backend>:8080 \
    -- yaml --config /etc/sshpiper/config.yaml \
    -- failtoban --max-failures 100 --ban-duration 5m

Blocks serving the plugin gRPC protocol over stdio until sshpiperd closes it.`,
	RunE: runSentinelSSHAuthzPlugin,
}

func init() {
	sentinelCmd.AddCommand(sentinelSSHAuthzPluginCmd)

	sentinelSSHAuthzPluginCmd.Flags().StringVar(&sentinelSSHAuthzPluginDaemonURL, "daemon-url", "",
		"REST base URL of the backend daemon, e.g. http://10.0.0.2:8080 (required)")
	sentinelSSHAuthzPluginCmd.Flags().DurationVar(&sentinelSSHAuthzPluginGrace, "grace", 5*time.Minute,
		"How long a cached positive is honoured when the backend is unreachable")
	sentinelSSHAuthzPluginCmd.Flags().DurationVar(&sentinelSSHAuthzPluginTimeout, "timeout", 3*time.Second,
		"Per-call deadline for POST /v1/ssh/authorize")

	_ = sentinelSSHAuthzPluginCmd.MarkFlagRequired("daemon-url")
}

// staticResolver maps every login to the same backend URL. Suitable for
// single-backend sentinels; multi-backend support is a follow-up issue.
type staticResolver struct{ url string }

func (r *staticResolver) ResolveLogin(_ string) (string, bool) { return r.url, true }

func runSentinelSSHAuthzPlugin(cmd *cobra.Command, args []string) error {
	plugin, err := sshauthz.New(sshauthz.Config{
		Resolver:   &staticResolver{url: sentinelSSHAuthzPluginDaemonURL},
		Authorizer: sshauthz.NewHTTPAuthorizer(&http.Client{}),
		Grace:      sentinelSSHAuthzPluginGrace,
		Timeout:    sentinelSSHAuthzPluginTimeout,
		Logf:       log.Printf,
	})
	if err != nil {
		return fmt.Errorf("ssh-authz-plugin: %w", err)
	}

	// sentinel.SignRequest is wired inside NewHTTPAuthorizer; it stamps the
	// sentinel's ed25519 / HMAC signature on each /v1/ssh/authorize call,
	// driven by CONTAINARIUM_SENTINEL_AUTH_SECRET /
	// CONTAINARIUM_SENTINEL_SIGNING_KEY — identical to keysync/certsync.

	piperPlugin, err := libplugin.NewFromStdio(plugin.PluginConfig())
	if err != nil {
		return fmt.Errorf("create sshpiperd plugin: %w", err)
	}
	piperPlugin.SetConfigLoggerCallback(libplugin.ConfigLoggerSlog)

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigc)

	done := make(chan error, 1)
	go func() { done <- piperPlugin.Serve() }()

	select {
	case err := <-done:
		return err
	case <-sigc:
		return nil
	}
}
