package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/boxlogs"
	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `containarium logs <box>` (#3643) reads a box's systemd journal and the
// logs of the docker containers inside it through the daemon API
// (TailBoxLogs), merged in time order. The MCP box_logs tool reads through
// the same boxlogs.Fetch.

// logsOptions are the flags of `containarium logs`.
type logsOptions struct {
	since      string
	tail       int
	units      []string
	containers []string
	maxLines   int
	follow     bool
}

var logsOpts logsOptions

var logsCmd = &cobra.Command{
	Use:   "logs <box>",
	Short: "Print a box's journal and container logs through the daemon API",
	Long: `Print a box's logs: its systemd journal and the logs of the docker
containers running inside it, merged oldest first. Each line is labelled
journal/<unit> or container/<name>.

Without --since it starts with the last --tail lines (100 by default).
--follow keeps reading; a dropped connection loses nothing, since every read
resumes from the cursor the previous one returned. A stopped box is reported,
not started. Boxes whose containers run on podman or rootless docker are not
supported yet.

Reads through the daemon API, so it needs no SSH access of its own — only a
token that may connect to the box (its owner or a collaborator, with the
ssh:write scope).

Examples:
  containarium logs alice --server <host>
  containarium logs alice --since 15m --unit nginx --server <host>
  containarium logs alice --container web --follow --server <host> --http`,
	Args: cobra.ExactArgs(1),
	RunE: runLogs,
}

func init() {
	rootCmd.AddCommand(logsCmd)
	f := logsCmd.Flags()
	f.StringVar(&logsOpts.since, "since", "", "Start at this time: a duration back from now (15m, 2h) or an RFC 3339 time")
	f.IntVar(&logsOpts.tail, "tail", 0, "Start with only the last N lines (0-1000; default 100 without --since)")
	f.StringArrayVar(&logsOpts.units, "unit", nil, "Only this systemd unit (repeatable; \"nginx\" means nginx.service)")
	f.StringArrayVar(&logsOpts.containers, "container", nil, "Only this container, by name (repeatable)")
	f.IntVar(&logsOpts.maxLines, "max-lines", 0, "Most lines per read (default 200, at most 1000)")
	f.BoolVarP(&logsOpts.follow, "follow", "f", false, "Keep reading new lines until interrupted")
}

// logsRequest turns the flags into the first TailBoxLogs request.
func logsRequest(box string, o logsOptions, now time.Time) (*pb.TailBoxLogsRequest, error) {
	req := &pb.TailBoxLogsRequest{Username: box, Units: o.units, Containers: o.containers}
	if o.since != "" {
		t, err := time.Parse(time.RFC3339Nano, o.since)
		if err != nil {
			d, derr := time.ParseDuration(o.since)
			if derr != nil || d < 0 {
				return nil, fmt.Errorf("--since %q is neither a duration like 15m nor an RFC 3339 time", o.since)
			}
			t = now.Add(-d)
		}
		req.Since = timestamppb.New(t)
	}
	if o.tail < 0 || o.tail > boxlogs.MaxLinesLimit {
		return nil, fmt.Errorf("--tail must be 0..%d", boxlogs.MaxLinesLimit)
	}
	if o.maxLines < 0 {
		return nil, fmt.Errorf("--max-lines must be >= 0")
	}
	req.Tail = int32(o.tail)                                     // #nosec G115 -- checked 0..1000
	req.MaxLines = int32(min(o.maxLines, boxlogs.MaxLinesLimit)) // #nosec G115 -- clamped
	return req, nil
}

func runLogs(cmd *cobra.Command, args []string) error {
	if err := validateBoxName(args[0]); err != nil {
		return err
	}
	req, err := logsRequest(args[0], logsOpts, time.Now())
	if err != nil {
		return err
	}
	if serverAddr == "" {
		return fmt.Errorf("--server is required")
	}
	var t interface {
		boxlogs.Tailer
		Close() error
	}
	if httpMode {
		t, err = client.NewHTTPClient(serverAddr, authToken)
	} else {
		t, err = client.NewGRPCClient(serverAddr, certsDir, insecure)
	}
	if err != nil {
		return err
	}
	defer func() { _ = t.Close() }()
	return boxLogs(cmd.Context(), t, req, logsOpts.follow, os.Stdout)
}

// boxLogs copies the box's logs to w through boxlogs.Copy, the reader the
// MCP box_logs tool's window comes from.
func boxLogs(ctx context.Context, t boxlogs.Tailer, req *pb.TailBoxLogsRequest, follow bool, w io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	_, err := boxlogs.Copy(ctx, t, req, w, follow)
	return err
}
