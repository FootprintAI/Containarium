//go:build !windows && !containarium_client

package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshauthz"
	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	"github.com/spf13/cobra"
	"github.com/tg123/sshpiper/libplugin"
)

var (
	sentinelSSHAuthzSocket       string
	sentinelSSHAuthzPluginSocket string
	sentinelSSHAuthzGrace        time.Duration
	sentinelSSHAuthzTimeout      time.Duration
	sentinelSSHAuthzEnforce      bool
	sentinelSSHAuthzRecordsFile  string
	sentinelSSHAuthzConfigFile   string
)

var sentinelSSHAuthzPluginCmd = &cobra.Command{
	Use:   "ssh-authz-plugin",
	Short: "sshpiperd plugin: check live SSH authorization before ssh-session-plugin",
	Long: `Run as the first sshpiperd chained plugin. Every offered raw key is
checked against its routed backend through the sentinel manager's private
Unix socket; the manager signs the daemon request. Only publickey is offered
to the client; password, keyboard-interactive and none are refused here.
Positive cache TTL comes from the daemon, and outage grace never renews the
last successful authorization.

Audit-only (the default): every offer defers to the next plugin with the
decision as metadata. Certificates and unknown logins are not checked.
ssh-session-plugin writes the session records, and yaml's static
authorized_keys decides who gets in.

Enforce (--ssh-authz-enforce): nothing defers. A DENY, including
UPSTREAM_UNAVAILABLE once the outage grace has passed, and a login no synced
backend lists, refuse the key: yaml is never consulted for it, and a "denied"
record with enforced=true is appended to --records-file. Every other offer
(an ALLOW, a certificate) is routed by this plugin from --sshpiper-config
exactly as yaml would route it, so a later offer on the same connection is
still checked here. This plugin writes the session's open and close records
itself, with enforced=true and the target it routed to; ssh-session-plugin
and yaml never see these connections. The plugin reopens --records-file on
SIGHUP, like ssh-session-plugin.`,
	RunE: runSentinelSSHAuthzPlugin,
}

func init() {
	sentinelCmd.AddCommand(sentinelSSHAuthzPluginCmd)
	sentinelCmd.Flags().StringVar(&sentinelSSHAuthzSocket, "ssh-authz-socket", sshauthz.DefaultSocket, "Private Unix socket serving the ssh-authz-plugin (empty disables)")
	sentinelSSHAuthzPluginCmd.Flags().StringVar(&sentinelSSHAuthzPluginSocket, "ssh-authz-socket", sshauthz.DefaultSocket, "Sentinel manager's private authorization socket")
	sentinelSSHAuthzPluginCmd.Flags().DurationVar(&sentinelSSHAuthzGrace, "ssh-authz-grace", sshauthz.DefaultGrace, "Maximum age of a successful authorization reused during an outage; also caps an ALLOW's cache TTL")
	sentinelSSHAuthzPluginCmd.Flags().DurationVar(&sentinelSSHAuthzTimeout, "ssh-authz-timeout", sshauthz.DefaultTimeout, "Deadline for resolving and authorizing one offered key")
	sentinelSSHAuthzPluginCmd.Flags().BoolVar(&sentinelSSHAuthzEnforce, "ssh-authz-enforce", false, "Refuse a key the daemon denies (fails closed after --ssh-authz-grace); false only audits")
	sentinelSSHAuthzPluginCmd.Flags().StringVar(&sentinelSSHAuthzRecordsFile, "records-file", sshsession.DefaultRecordsFile, "Session record JSONL that enforced denials and enforce-mode session records are appended to (empty disables; unused without --ssh-authz-enforce)")
	sentinelSSHAuthzPluginCmd.Flags().StringVar(&sentinelSSHAuthzConfigFile, "sshpiper-config", "/etc/sshpiper/config.yaml", "sshpiper config.yaml that enforce mode routes from, as the yaml plugin would (unused without --ssh-authz-enforce)")
}

func runSentinelSSHAuthzPlugin(cmd *cobra.Command, args []string) error {
	if sentinelSSHAuthzGrace < 0 || sentinelSSHAuthzTimeout <= 0 || sentinelSSHAuthzPluginSocket == "" {
		return fmt.Errorf("ssh authz: socket and positive timeout required; grace must be non-negative")
	}
	cfg := sshauthz.Config{Enforce: sentinelSSHAuthzEnforce, Cache: sshauthz.NewCache(sentinelSSHAuthzGrace, 0, nil), Timeout: sentinelSSHAuthzTimeout, Logf: log.Printf}
	if sentinelSSHAuthzEnforce {
		cfg.Router = sshauthz.NewRouter(sentinelSSHAuthzConfigFile)
		cfg.Target = sshsession.NewTargetResolver(sentinelSSHAuthzConfigFile)
		// Warn-only (#3125): a stale unit without --login-grace-time drops
		// logins during device approval. Never fails startup.
		sshauthz.CheckParentLoginGrace(sshauthz.ParentCmdline, log.Printf)
	}
	var recorder *sshsession.JSONLRecorder
	if sentinelSSHAuthzEnforce && sentinelSSHAuthzRecordsFile != "" {
		var err error
		recorder, err = sshsession.NewJSONLFileRecorder(sentinelSSHAuthzRecordsFile)
		if err != nil {
			return fmt.Errorf("open records sink: %w", err)
		}
		defer func() { _ = recorder.Close() }()
		cfg.Recorder = recorder
	}
	bridge := sshauthz.NewBridgeClient(sentinelSSHAuthzPluginSocket)
	cfg.Resolver, cfg.Authorizer = bridge, bridge
	plugin, err := sshauthz.New(cfg)
	if err != nil {
		return err
	}
	piper, err := libplugin.NewFromStdio(plugin.PluginConfig())
	if err != nil {
		return fmt.Errorf("create ssh authz plugin: %w", err)
	}
	piper.SetConfigLoggerCallback(libplugin.ConfigLoggerSlog)
	// As in ssh-session-plugin: close out open sessions once, however the
	// process ends. A no-op in audit-only mode, which writes no session records.
	var shutdownOnce sync.Once
	flush := func() { shutdownOnce.Do(plugin.Shutdown) }
	defer flush()
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigc)
	// logrotate HUPs both record writers. Go's default SIGHUP action would
	// exit and take the sshpiperd chain down, so register even without a sink.
	hupc := make(chan os.Signal, 1)
	signal.Notify(hupc, syscall.SIGHUP)
	defer signal.Stop(hupc)
	if recorder != nil {
		reopenCtx, stopReopen := context.WithCancel(context.Background())
		defer stopReopen()
		go sshsession.ReopenOn(reopenCtx, hupc, recorder, log.Printf)
	}
	done := make(chan error, 1)
	go func() { done <- piper.Serve() }()
	select {
	case err := <-done:
		return err
	case <-sigc:
		flush()
		return nil
	}
}
