//go:build !windows && !containarium_client

package cmd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/footprintai/containarium/internal/sentinel/sshban"
	"github.com/footprintai/containarium/internal/sentinel/sshsession"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
	"github.com/tg123/sshpiper/libplugin"
)

// init makes the ban plugin part of the existing daemon release artifact.
func init() { sentinelCmd.AddCommand(newSSHBanPluginCommand()) }

// newSSHBanPluginCommand isolates configuration per invocation and validates it
// before opening the stdio protocol or its privileged control socket.
func newSSHBanPluginCommand() *cobra.Command {
	var listener, socket, recordsFile string
	var maxRecords int
	var maximum, capacity uint32
	var duration time.Duration
	var ignore []string
	c := &cobra.Command{Use: "ssh-ban-plugin", Short: "sshpiperd plugin: enforce and inspect source-IP failure budgets", Args: cobra.NoArgs}
	c.Flags().StringVar(&listener, "listener", "main", "Listener identity: main or anonymous")
	c.Flags().StringVar(&socket, "control-socket", "", "Private Unix control socket (default per listener)")
	c.Flags().Uint32Var(&maximum, "max-failures", 100, "Failed callbacks before blocking a source IP")
	c.Flags().DurationVar(&duration, "ban-duration", 5*time.Minute, "Fixed failure window from the first connection")
	c.Flags().Uint32Var(&capacity, "max-entries", 65536, "Maximum live source-IP entries")
	c.Flags().StringSliceVar(&ignore, "ignore-ip", nil, "CIDR exemptions from IP banning; key authentication still applies")
	c.Flags().StringVar(&recordsFile, "records-file", "", "JSONL sink for audit records of failed authentications and bans (#2419), shared with the ssh-session-plugin so the existing shipper delivers them. Empty disables. Reopened on SIGHUP for logrotate")
	c.Flags().IntVar(&maxRecords, "audit-max-records-per-minute", 600, "Failed-authentication summaries written individually per minute; the rest are folded into one overflow record. Bans are never capped")
	c.RunE = func(cmd *cobra.Command, _ []string) error {
		kind := pb.SSHBanListener_SSH_BAN_LISTENER_MAIN
		switch listener {
		case "main":
		case "anonymous":
			kind = pb.SSHBanListener_SSH_BAN_LISTENER_ANONYMOUS
		default:
			return fmt.Errorf("invalid listener %q", listener)
		}
		logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
		var audit *sshban.AuditRecorder
		var sink *sshsession.JSONLRecorder
		auditStarted := false
		if recordsFile != "" {
			var err error
			if sink, err = sshsession.NewJSONLFileRecorder(recordsFile); err != nil {
				return err
			}
			defer func() {
				if !auditStarted { // after startup the recorder goroutine owns the sink
					_ = sink.Close()
				}
			}()
			audit = sshban.NewAuditRecorder(sshban.AuditConfig{
				Listener: kind, Out: sink, MaxPerMinute: maxRecords,
				Logf: func(f string, a ...any) { logger.Error(fmt.Sprintf(f, a...)) },
			})
		}
		g, err := sshban.New(sshban.Config{Listener: kind, MaxFailures: maximum, Duration: duration, IgnoreCIDRs: ignore, MaxEntries: capacity,
			Emit: func(e sshban.Event) {
				logger.Warn("ssh_ban_policy", "event", e.Kind, "source_ip", e.IP, "failures", e.Failures, "expires_at", e.ExpiresAt, "reason", e.Reason)
				if audit != nil {
					audit.Emit(e) // enqueue only: this runs under the policy mutex
				}
			},
		})
		if err != nil {
			return err
		}
		if socket == "" {
			socket = sshban.DefaultSocket(kind)
		}
		state, err := g.GetSSHBan(cmd.Context(), &pb.GetSSHBanRequest{Listener: kind, Ip: "127.0.0.1"})
		if err != nil {
			return err
		}
		logger = logger.With("listener", listener, "generation", state.Generation, "policy_hash", state.Policy.Hash, "max_failures", maximum)
		stop, err := sshban.ListenControl(socket, g)
		if err != nil {
			return err
		}
		defer func() {
			if !auditStarted { // shutdownAudit starts stop without an unbounded wait
				stop()
			}
		}()
		logger.Info("ssh_ban_policy", "event", "policy_loaded", "window", duration, "ignore_cidrs", ignore, "max_entries", capacity)
		plugin, err := libplugin.NewFromStdio(g.PluginConfig())
		if err != nil {
			return err
		}
		plugin.SetConfigLoggerCallback(libplugin.ConfigLoggerSlog)
		signals := make(chan os.Signal, 1)
		var stopReopen context.CancelFunc
		var reopenDone chan struct{}
		// SIGHUP never clears unrelated IPs; bans are cleared only through the
		// targeted control operation or process restart. With a records file it
		// reopens that file for log rotation, and otherwise it is ignored.
		if sink != nil {
			hup := make(chan os.Signal, 1)
			signal.Notify(hup, syscall.SIGHUP)
			defer signal.Stop(hup)
			reopenCtx, cancelReopen := context.WithCancel(context.Background())
			stopReopen = cancelReopen
			reopenDone = make(chan struct{})
			go func() {
				defer close(reopenDone)
				sshsession.ReopenOn(reopenCtx, hup, sink, func(f string, a ...any) { logger.Error(fmt.Sprintf(f, a...)) })
			}()
		} else {
			signal.Ignore(syscall.SIGHUP)
		}
		signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(signals)
		if audit != nil {
			tick := time.NewTicker(time.Minute)
			defer tick.Stop()
			// The recorder owns the sink after startup. A timed-out shutdown may
			// return while it is blocked, but cannot close a sink still in use.
			runCtx, stopAudit := context.WithCancel(context.Background())
			auditStarted = true
			auditDone := startSSHBanAudit(runCtx, audit, tick.C, g, stopReopen, reopenDone, sink)
			defer func() {
				quiesceCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				stopReopen()
				if err := shutdownSSHBanAudit(quiesceCtx, stop, g, audit, stopAudit, auditDone); err != nil {
					logger.Error("ssh-ban shutdown deadline exceeded; queued or final audit records may be lost", "error", err)
				}
			}()
		}
		done := make(chan error, 1)
		go func() { done <- plugin.Serve() }()
		select {
		case err := <-done:
			return err
		case <-signals:
			return nil
		case <-cmd.Context().Done():
			return cmd.Context().Err()
		}
	}
	return c
}

// startSSHBanAudit keeps the sink open until the recorder and SIGHUP reopener
// have both stopped. The caller can leave on deadline without closing it early.
func startSSHBanAudit(ctx context.Context, audit *sshban.AuditRecorder, ticks <-chan time.Time, g *sshban.Guard, stopReopen context.CancelFunc, reopenDone <-chan struct{}, sink io.Closer) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			stopReopen()
			<-reopenDone
			_ = sink.Close()
		}()
		audit.Run(ctx, ticks, g.TrySweep, g.FlushFailureWindows)
	}()
	return done
}

// shutdownSSHBanAudit bounds the whole shutdown, including control Stop and
// recorder I/O. On deadline, Abort prevents a future final pass and the caller
// returns; the recorder retains sink ownership until any blocked call returns.
// Queued events and completed or open windows may then be lost. A permanently
// blocked callback, Stop, or write cannot be canceled by Go; the plugin process
// must exit to reclaim those goroutines and its still-open sink.
func shutdownSSHBanAudit(ctx context.Context, stopControl func(), g *sshban.Guard, audit *sshban.AuditRecorder, stopAudit context.CancelFunc, auditDone <-chan struct{}) error {
	controlDone := make(chan struct{})
	go func() { stopControl(); close(controlDone) }()
	if err := g.QuiesceCallbacks(ctx); err != nil {
		audit.Abort()
		stopAudit()
		return err
	}
	select {
	case <-controlDone:
	case <-ctx.Done():
		audit.Abort()
		stopAudit()
		return ctx.Err()
	}
	stopAudit()
	select {
	case <-auditDone:
		return nil
	case <-ctx.Done():
		audit.Abort()
		return ctx.Err()
	}
}
