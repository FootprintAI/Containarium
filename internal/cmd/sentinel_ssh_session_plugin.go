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

	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	"github.com/spf13/cobra"
	"github.com/tg123/sshpiper/libplugin"
)

var (
	sentinelSSHSessionPluginRecordsFile string
	sentinelSSHSessionPluginConfigFile  string
)

var sentinelSSHSessionPluginCmd = &cobra.Command{
	Use:   "ssh-session-plugin",
	Short: "sshpiperd plugin: emit a structured record for every accepted/closed SSH session (containarium#1980)",
	Long: `Run as an sshpiperd chained plugin, NOT as a command a human invokes directly.

sshpiperd on the sentinel is the only place a client's SSH key or certificate is
verified — containers run no sshd of their own — but an accepted connection has
never produced a structured record: only the failtoban plugin's auth-failure
line exists. This subcommand IS that missing record: chained as the FIRST
plugin in sshpiperd's invocation (ahead of the "yaml" routing plugin), it
observes the offered credential (certificate key_id/serial/CA fingerprint, or a
raw key's fingerprint) and the accept/close of every pipe, and appends one
JSON line per event to --records-file. It never accepts or rejects a
connection itself — it always defers the routing decision to the next plugin
in the chain — so it cannot change sshpiper's own auth behavior, including the
failure path failtoban's fail2ban regex depends on.

Wire it into sshpiperd's ExecStart ahead of "yaml", e.g.:

  sshpiperd -i host_key -p 22 \
    containarium sentinel ssh-session-plugin --records-file /var/log/containarium/ssh-sessions.jsonl \
    -- yaml --config /etc/sshpiper/config.yaml \
    -- failtoban --max-failures 100 --ban-duration 5m

Blocks serving the plugin gRPC protocol over stdio until sshpiperd closes it
(e.g. on its own shutdown/restart), at which point any session this process
saw an open for but never a close gets a final record with
close_reason=proxy_shutdown, so it isn't left indistinguishable from a session
still legitimately running.

On SIGHUP it closes and reopens --records-file at the same path, so logrotate
can rotate the sink (rename + create) without restarting sshpiperd:
  postrotate: pkill -HUP -f '^/usr/local/bin/containarium sentinel ssh-session-plugin'
The pattern is anchored because sshpiperd's own command line CONTAINS this
plugin's, and it must not receive the signal.`,
	RunE: runSentinelSSHSessionPlugin,
}

func init() {
	sentinelCmd.AddCommand(sentinelSSHSessionPluginCmd)

	sentinelSSHSessionPluginCmd.Flags().StringVar(&sentinelSSHSessionPluginRecordsFile, "records-file", sshsession.DefaultRecordsFile,
		"Path to append session lifecycle records to, one JSON object per line")
	// Must match internal/sentinel/keysync.go's sshpiperConfigFile — the
	// file the sentinel's keysync daemon generates and sshpiperd's own
	// "yaml" plugin reads. Kept as its own flag (rather than importing
	// that unexported constant) to keep this plugin's process usable
	// standalone, e.g. in tests or a non-default sshpiper layout.
	sentinelSSHSessionPluginCmd.Flags().StringVar(&sentinelSSHSessionPluginConfigFile, "sshpiper-config", "/etc/sshpiper/config.yaml",
		"Path to the sshpiper config.yaml to resolve a login's routed target from (best-effort; empty target if unreadable)")
}

func runSentinelSSHSessionPlugin(cmd *cobra.Command, args []string) error {
	recorder, err := sshsession.NewJSONLFileRecorder(sentinelSSHSessionPluginRecordsFile)
	if err != nil {
		return fmt.Errorf("open records sink: %w", err)
	}
	defer func() { _ = recorder.Close() }()

	plugin := &sshsession.Plugin{
		Recorder: recorder,
		Target:   sshsession.NewTargetResolver(sentinelSSHSessionPluginConfigFile),
	}

	piperPlugin, err := libplugin.NewFromStdio(plugin.Config())
	if err != nil {
		return fmt.Errorf("create sshpiperd plugin: %w", err)
	}

	// sshpiperd's plugin SDK (v1.6+, switched from logrus to log/slog — see
	// containarium#1980's discussion of why sshpiperd's own log output is
	// not a usable audit source) calls this back with the writer/level/tty
	// it wants the plugin's operational log lines sent to; ConfigLoggerSlog
	// is the SDK's own default (wires slog's default logger to that
	// writer). This only forwards the plugin's own log lines to sshpiperd,
	// not session records themselves, which always go through recorder
	// above.
	piperPlugin.SetConfigLoggerCallback(libplugin.ConfigLoggerSlog)

	// Flush open sessions exactly once, however this process ends: either
	// Serve() returns on its own (sshpiperd closed our stdio — its own
	// shutdown/restart, or EOF from a plugin chain misconfiguration), or
	// this process receives SIGTERM/SIGINT directly. Observed in practice
	// (containarium#1980): sshpiperd stopping does not always leave time
	// for Serve()'s own return path to run before the process is asked to
	// exit, so a direct signal handler is the reliable path — without it, a
	// session this process saw an open for but never a close would be left
	// dangling, indistinguishable from a session still legitimately
	// running. See Plugin.Shutdown's doc comment.
	var shutdownOnce sync.Once
	flush := func() { shutdownOnce.Do(plugin.Shutdown) }
	defer flush()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigc)

	// SIGHUP: logrotate (create mode) renamed the sink — reopen the path
	// (#2415). Registering the handler also matters on its own: Go's default
	// action for SIGHUP is to terminate, which would take the SSH proxy's
	// plugin chain down on every rotation.
	hupc := make(chan os.Signal, 1)
	signal.Notify(hupc, syscall.SIGHUP)
	defer signal.Stop(hupc)
	reopenCtx, stopReopen := context.WithCancel(context.Background())
	defer stopReopen()
	go sshsession.ReopenOn(reopenCtx, hupc, recorder, log.Printf)

	done := make(chan error, 1)
	go func() { done <- piperPlugin.Serve() }()

	select {
	case err := <-done:
		return err
	case <-sigc:
		flush()
		return nil
	}
}
