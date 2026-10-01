//go:build !windows && !containarium_client

package cmd

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/tg123/sshpiper/libplugin"

	"github.com/footprintai/containarium/internal/sentinel"
	"github.com/footprintai/containarium/internal/sentinel/anondoor"
)

var (
	sentinelAnonDoorDaemonURL   string
	sentinelAnonDoorUpstreamKey string
	sentinelAnonDoorTimeout     time.Duration
	sentinelAnonDoorBanner      string
)

var sentinelAnonDoorPluginCmd = &cobra.Command{
	Use:   "anon-door-plugin",
	Short: "sshpiperd plugin: the `ssh new.<domain>` door — any SSH key gets its own anonymous VM (#2198)",
	Long: `Run as an sshpiperd chained plugin in the door's OWN sshpiperd instance
(sshpiper-anon.service), never on the tenant listener and never by hand.

On public-key auth it asks the anon-pool daemon's AnonymousBoxService for the
box that belongs to the key's fingerprint (POST /v1/anon/boxes:ensure, signed
with the sentinel's existing request signature from
CONTAINARIUM_SENTINEL_AUTH_SECRET / CONTAINARIUM_SENTINEL_SIGNING_KEY — the
daemon's gateway maps that signature to the anon:door scope) and returns an
upstream pipe to it using /etc/sshpiper/upstream_key, exactly like a tenant
pipe. Any non-OK answer rejects the auth; password and keyboard-interactive
are refused outright.

Wire it after the audit plugin, e.g.:

  sshpiperd -i /etc/sshpiper/host_key -l <door ip> -p 22 \
    containarium sentinel ssh-session-plugin --records-file /var/log/containarium/ssh-sessions.jsonl \
    -- containarium sentinel anon-door-plugin --daemon-url http://<anon-pool daemon>:8080 \
    -- failtoban --max-failures 100 --ban-duration 5m`,
	RunE: runSentinelAnonDoorPlugin,
}

func init() {
	sentinelCmd.AddCommand(sentinelAnonDoorPluginCmd)
	sentinelAnonDoorPluginCmd.Flags().StringVar(&sentinelAnonDoorDaemonURL, "daemon-url", "",
		"REST base URL of the anon-pool daemon, e.g. http://10.0.0.5:8080 (required)")
	sentinelAnonDoorPluginCmd.Flags().StringVar(&sentinelAnonDoorUpstreamKey, "upstream-key", anondoor.DefaultUpstreamKeyPath,
		"Private key sshpiper authenticates to the box with")
	sentinelAnonDoorPluginCmd.Flags().DurationVar(&sentinelAnonDoorTimeout, "timeout", anondoor.DefaultTimeout,
		"Deadline for one ensure call (a cold VM boot sits inside it; keep under sshpiperd's login grace)")
	sentinelAnonDoorPluginCmd.Flags().StringVar(&sentinelAnonDoorBanner, "banner", "",
		"Pre-auth banner text (default: the built-in 'use an SSH key' hint)")
	_ = sentinelAnonDoorPluginCmd.MarkFlagRequired("daemon-url")
}

func runSentinelAnonDoorPlugin(cmd *cobra.Command, args []string) error {
	plugin, err := anondoor.New(anondoor.Config{
		DaemonURL:       sentinelAnonDoorDaemonURL,
		UpstreamKeyPath: sentinelAnonDoorUpstreamKey,
		Sign:            sentinel.SignRequest,
		Timeout:         sentinelAnonDoorTimeout,
		Banner:          sentinelAnonDoorBanner,
		Logf:            log.Printf,
	})
	if err != nil {
		return err
	}
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
