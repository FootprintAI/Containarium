// `containarium security flow-history` — which box contacted a destination, and
// when (#3709). It answers a provider egress alert after the fact: the alert
// names a VM and a destination, this names the box. CLI-first per the repo
// convention; the MCP tool (internal/mcp/security.go) wraps the same REST call.
//
// The log behind it is opt-in (CONTAINARIUM_THREAT_FLOWLOG_HOURS on the daemon)
// and in memory, so an empty answer is only meaningful from the "covered since"
// time the response reports.
package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

var securityFlowHistoryCmd = &cobra.Command{
	Use:   "flow-history <destination-ip>",
	Short: "Show which boxes contacted a destination, and when",
	Long: `Shows which boxes opened a flow to a public destination address, from the
daemon's opt-in in-memory flow log. Use it to attribute a provider egress alert
(a firewall deny names a VM and a destination, not a box) to the box that did it.

The log is off unless the daemon sets CONTAINARIUM_THREAT_FLOWLOG_HOURS. It only
holds history from when it started recording, up to its retention, and empties
on a daemon restart: the output states the time it covers, and an empty result
for a time before that proves nothing. Entries flagged "reply?" have an
ephemeral destination port and may be the box answering a client, not dialing
out. Non-admin callers only see their own tenant.

--since and --until take an RFC3339 timestamp or a duration meaning that long
ago (for example 2h).`,
	Example: `  containarium security flow-history 91.121.106.55 --port 4444 --since 24h`,
	Args:    cobra.ExactArgs(1),
	RunE:    runSecurityFlowHistory,
}

var (
	flowHistoryPort    int
	flowHistorySince   string
	flowHistoryUntil   string
	flowHistoryTenant  string
	flowHistoryLimit   int
	flowHistoryJSONOut bool
)

func init() {
	f := securityFlowHistoryCmd.Flags()
	f.IntVar(&flowHistoryPort, "port", 0, "Only flows to this destination port (0 = any)")
	f.StringVar(&flowHistorySince, "since", "", "Only flows last seen at or after this RFC3339 time, or this long ago (e.g. 2h)")
	f.StringVar(&flowHistoryUntil, "until", "", "Only flows first seen at or before this RFC3339 time, or this long ago")
	f.StringVar(&flowHistoryTenant, "tenant", "", "Only this tenant (admins; others are limited to their own)")
	f.IntVar(&flowHistoryLimit, "limit", 0, "Maximum entries (server default 100, maximum 500)")
	f.BoolVar(&flowHistoryJSONOut, "json", false, "Print the raw response as JSON")
	securityCmd.AddCommand(securityFlowHistoryCmd)
}

// flowHistoryTime turns a --since/--until value into the RFC3339 string the REST
// API takes: an RFC3339 timestamp passes through, a duration means that long
// before now. "" stays "" (unset).
func flowHistoryTime(v string, now time.Time) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UTC().Format(time.RFC3339), nil
	}
	if d, err := time.ParseDuration(v); err == nil {
		if d < 0 {
			return "", fmt.Errorf("%q must not be negative", v)
		}
		return now.Add(-d).UTC().Format(time.RFC3339), nil
	}
	return "", fmt.Errorf("%q is neither an RFC3339 time (2026-11-13T16:30:00Z) nor a duration (2h)", v)
}

// flowHistoryQuery builds the REST query string, validating before any request
// is sent. The destination must be an IPv4 address: the log only holds IPv4.
func flowHistoryQuery(dst string, port int, since, until, tenant string, limit int, now time.Time) (url.Values, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(dst))
	if err != nil || !addr.Is4() {
		return nil, fmt.Errorf("destination %q must be an IPv4 address", dst)
	}
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("--port %d is out of range", port)
	}
	q := url.Values{"dst_ip": {addr.String()}}
	if port > 0 {
		q.Set("dst_port", strconv.Itoa(port))
	}
	for name, v := range map[string]string{"since": since, "until": until} {
		ts, err := flowHistoryTime(v, now)
		if err != nil {
			return nil, fmt.Errorf("--%s: %w", name, err)
		}
		if ts != "" {
			q.Set(name, ts)
		}
	}
	if tenant != "" {
		q.Set("tenant_id", tenant)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	return q, nil
}

func runSecurityFlowHistory(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return errServerRequired()
	}
	q, err := flowHistoryQuery(args[0], flowHistoryPort, flowHistorySince, flowHistoryUntil, flowHistoryTenant, flowHistoryLimit, time.Now())
	if err != nil {
		return err
	}
	reqURL := strings.TrimSuffix(serverAddr, "/") + "/v1/security/flow-history?" + q.Encode()
	var out pb.QueryFlowHistoryResponse
	if err := policyRoundTrip(http.MethodGet, reqURL, nil, &out); err != nil {
		return err
	}
	w := cmd.OutOrStdout()
	if flowHistoryJSONOut {
		b, err := protojson.MarshalOptions{Multiline: true}.Marshal(&out)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(b))
		return err
	}
	renderFlowHistory(w, &out)
	return nil
}

// renderFlowHistory prints the entries and, always, what the log covers, so an
// empty table is read against the right window. Tenant-controlled strings go
// through escapeControl.
func renderFlowHistory(w io.Writer, out *pb.QueryFlowHistoryResponse) {
	fmt.Fprintf(w, "Flow log covers %s onward (retention %s).\n",
		timestampText(out.GetCoveredSince()), time.Duration(out.GetRetentionSeconds())*time.Second)
	if len(out.GetEntries()) == 0 {
		fmt.Fprintln(w, "No box is recorded as contacting that destination in this window.")
		return
	}
	fmt.Fprintf(w, "%-24s %-14s %-15s %-15s %-6s %-5s %-20s %-20s %s\n",
		"BOX", "TENANT", "SOURCE", "DESTINATION", "PORT", "PROTO", "FIRST SEEN", "LAST SEEN", "NOTE")
	for _, e := range out.GetEntries() {
		box := escapeControl(e.GetContainer())
		if box == "" {
			box = "(unknown box)"
		}
		note := ""
		if e.GetLikelyReply() {
			note = "reply?"
		}
		fmt.Fprintf(w, "%-24s %-14s %-15s %-15s %-6d %-5s %-20s %-20s %s\n",
			box, escapeControl(e.GetTenantId()), e.GetSrcIp(), e.GetDstIp(), e.GetDstPort(), e.GetProtocol(),
			timestampText(e.GetFirstSeen()), timestampText(e.GetLastSeen()), note)
	}
}
