// `containarium security exec-events [--container] [--since] [--follow]
// [--json]` — the host-side eBPF exec telemetry (#2637): every process exec
// in a tenant box, attributed to the container, as the kernel saw it.
// CLI-first per the repo convention; talks to the grpc-gateway REST route for
// the server-streaming StreamExecEvents RPC (newline-delimited JSON, each
// line `{"result": <ExecEvent>}` or `{"error": {...}}`) and decodes each
// event with the generated protobuf type (protojson), never an ad-hoc map.
package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

const execEventsPath = "/v1/security/exec-events"

var (
	execEventsContainer string
	execEventsSince     string
	execEventsFollow    bool
	execEventsJSONOut   bool
)

var securityExecEventsCmd = &cobra.Command{
	Use:   "exec-events",
	Short: "Show process execs observed in tenant boxes by the host-side eBPF exec telemetry (#2637)",
	Long: `Show every process exec the host-side eBPF exec telemetry observed in
tenant boxes, attributed to the container: host pid/ppid/uid, the executable
path and the argument vector (capped at 512 bytes, never the environment).

The daemon keeps only a short in-memory buffer of recent events (they are
not written to the audit log; only matched findings are). --since replays
that buffer for the window; --follow keeps the stream open for new events.
With neither, the last 5 minutes are printed and the command returns.

The daemon reports "exec-telemetry: unavailable (<reason>)" in
` + "`containarium security sentry status`" + ` when the kernel program could
not be loaded (no BTF, verifier rejection, object not built); this command
then fails with the same reason. The flow rules keep running either way.`,
	Example: `  # the last five minutes of execs across all boxes
  containarium security exec-events

  # one box, live
  containarium security exec-events --container box-a --follow

  # the last hour, machine-readable (one ExecEvent JSON per line)
  containarium security exec-events --since 1h --json`,
	Args: cobra.NoArgs,
	RunE: runSecurityExecEvents,
}

func runSecurityExecEvents(cmd *cobra.Command, _ []string) error {
	if serverAddr == "" {
		return errServerRequired()
	}
	q := url.Values{}
	if execEventsContainer != "" {
		q.Set("container", execEventsContainer)
	}
	if execEventsSince != "" {
		d, err := time.ParseDuration(execEventsSince)
		if err != nil || d < 0 {
			return fmt.Errorf("invalid --since %q: want a duration such as 5m or 1h (0 for no replay)", execEventsSince)
		}
		if d > 0 {
			// google.protobuf.Duration in a query string is its protojson
			// form: decimal seconds with an "s" suffix.
			q.Set("since", strconv.FormatFloat(d.Seconds(), 'f', -1, 64)+"s")
		}
	}
	if execEventsFollow {
		q.Set("follow", "true")
	}
	rawURL := strings.TrimSuffix(serverAddr, "/") + execEventsPath
	if enc := q.Encode(); enc != "" {
		rawURL += "?" + enc
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return streamExecEvents(ctx, rawURL, cmd.OutOrStdout(), execEventsJSONOut)
}

// gatewayStreamChunk is one newline-delimited chunk of a grpc-gateway
// server stream: either a message under "result" or a status under "error".
type gatewayStreamChunk struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// streamExecEvents reads the gateway stream at rawURL and writes one line
// per event (or the raw event JSON with jsonOut) until the stream ends, the
// server reports an error, or ctx is cancelled (Ctrl-C under --follow).
func streamExecEvents(ctx context.Context, rawURL string, w io.Writer, jsonOut bool) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}
	// No client timeout: --follow is open-ended; ctx ends it.
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("request %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("status %d: %s", resp.StatusCode, gatewayErrorMessage(body))
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var chunk gatewayStreamChunk
		if err := json.Unmarshal([]byte(line), &chunk); err != nil {
			return fmt.Errorf("decode stream chunk: %w", err)
		}
		if chunk.Error != nil {
			return fmt.Errorf("stream error (code %d): %s", chunk.Error.Code, chunk.Error.Message)
		}
		if len(chunk.Result) == 0 {
			continue
		}
		if jsonOut {
			fmt.Fprintln(w, string(chunk.Result))
			continue
		}
		var ev pb.ExecEvent
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(chunk.Result, &ev); err != nil {
			return fmt.Errorf("decode exec event: %w", err)
		}
		fmt.Fprintln(w, formatExecEvent(&ev))
	}
	if err := sc.Err(); err != nil && ctx.Err() == nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("read stream: %w", err)
	}
	return nil
}

// gatewayErrorMessage pulls the message out of a grpc-gateway error body,
// falling back to the trimmed body.
func gatewayErrorMessage(body []byte) string {
	var e struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &e) == nil && e.Message != "" {
		return e.Message
	}
	msg := strings.TrimSpace(string(body))
	if len(msg) > 512 {
		msg = msg[:512]
	}
	return msg
}

// formatExecEvent renders one event on one line:
//
//	2026-10-19T05:07:18Z  box-a  pid=4242 ppid=4100 uid=1000  /tmp/.x/xmrig  ./xmrig -o pool:3333  [argv truncated]
func formatExecEvent(ev *pb.ExecEvent) string {
	at := ""
	if ev.GetAt() != nil {
		at = ev.GetAt().AsTime().UTC().Format(time.RFC3339)
	}
	x := ev.GetExec()
	var b strings.Builder
	fmt.Fprintf(&b, "%s  %s  pid=%d ppid=%d uid=%d  %s", at, ev.GetContainer(), x.GetPid(), x.GetPpid(), x.GetUid(), x.GetFilename())
	if argv := x.GetArgv(); argv != "" {
		fmt.Fprintf(&b, "  %s", argv)
	}
	if x.GetArgvTruncated() {
		b.WriteString("  [argv truncated]")
	}
	return b.String()
}

func init() {
	securityExecEventsCmd.Flags().StringVar(&execEventsContainer, "container", "", "Only this container's execs (default: every watched box)")
	securityExecEventsCmd.Flags().StringVar(&execEventsSince, "since", "5m", "Replay the daemon's recent-event buffer for this window first (0 = no replay)")
	securityExecEventsCmd.Flags().BoolVar(&execEventsFollow, "follow", false, "Keep the stream open and print new execs as they happen (Ctrl-C to stop)")
	securityExecEventsCmd.Flags().BoolVar(&execEventsJSONOut, "json", false, "Print one ExecEvent JSON object per line instead of the formatted line")
	securityCmd.AddCommand(securityExecEventsCmd)
}
