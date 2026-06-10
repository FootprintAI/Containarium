package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

// `containarium traffic` exposes the TrafficService over the CLI — the
// canonical surface per CLAUDE.md (the webui and MCP are other consumers of the
// same endpoints). These are thin read-only wrappers over the grpc-gateway REST
// routes generated from proto/containarium/v1/traffic.proto:
//
//	GET /v1/containers/{name}/connections          → connections
//	GET /v1/containers/{name}/connections/summary  → summary
//	GET /v1/containers/{name}/traffic/history      → history
//
// Server + token resolution mirrors the ssh/connect commands (pickSSHServer +
// the bearer token auto-filled by root's PersistentPreRunE), so `traffic` works
// against whatever server you're logged into without re-passing --server.
var (
	trafficServerFlag string
	trafficFormat     string
	trafficProtocol   string
	trafficDestIP     string
	trafficDestPort   uint32
	trafficLimit      int32
	trafficSince      time.Duration
)

var trafficCmd = &cobra.Command{
	Use:   "traffic",
	Short: "Inspect a box's network traffic (connections, summary, history)",
	Long: `Inspect network traffic for one of your boxes.

Subcommands:
  connections <box>   active connections (source/dest IP, port, proto, bytes)
  summary <box>       per-box totals + top destinations
  history <box>       closed connections recorded in the traffic history

Reads the platform daemon's TrafficService over its HTTP API, using the
server + token you logged in with (override with --server / --token).`,
}

var trafficConnectionsCmd = &cobra.Command{
	Use:     "connections <box>",
	Aliases: []string{"conns", "ls"},
	Short:   "List active connections for a box",
	Args:    cobra.ExactArgs(1),
	RunE:    runTrafficConnections,
}

var trafficSummaryCmd = &cobra.Command{
	Use:   "summary <box>",
	Short: "Show connection totals + top destinations for a box",
	Args:  cobra.ExactArgs(1),
	RunE:  runTrafficSummary,
}

var trafficHistoryCmd = &cobra.Command{
	Use:   "history <box>",
	Short: "List closed connections from the traffic history",
	Args:  cobra.ExactArgs(1),
	RunE:  runTrafficHistory,
}

func init() {
	rootCmd.AddCommand(trafficCmd)
	trafficCmd.AddCommand(trafficConnectionsCmd, trafficSummaryCmd, trafficHistoryCmd)

	for _, c := range []*cobra.Command{trafficConnectionsCmd, trafficSummaryCmd, trafficHistoryCmd} {
		c.Flags().StringVar(&trafficServerFlag, "server", "", "server to query (default: the logged-in server)")
		c.Flags().StringVarP(&trafficFormat, "format", "f", "table", "output format: table, json")
	}
	trafficConnectionsCmd.Flags().StringVar(&trafficProtocol, "protocol", "", "filter by protocol: tcp, udp, icmp")
	trafficConnectionsCmd.Flags().StringVar(&trafficDestIP, "dest-ip", "", "filter by destination IP prefix")
	trafficConnectionsCmd.Flags().Uint32Var(&trafficDestPort, "dest-port", 0, "filter by destination port")
	trafficConnectionsCmd.Flags().Int32Var(&trafficLimit, "limit", 0, "max rows to return (0 = server default)")
	trafficHistoryCmd.Flags().DurationVar(&trafficSince, "since", time.Hour, "look back this far (e.g. 30m, 24h)")
	trafficHistoryCmd.Flags().Int32Var(&trafficLimit, "limit", 0, "max rows to return (0 = server default)")
}

// flexInt64 decodes a proto3-JSON int64, which grpc-gateway emits as a QUOTED
// string (e.g. "8456"), while still tolerating a bare number. Without this the
// bytes_sent/received + packet fields fail to decode.
type flexInt64 int64

func (v *flexInt64) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*v = 0
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("flexInt64: %w", err)
	}
	*v = flexInt64(n)
	return nil
}

// Wire DTOs — mirror the grpc-gateway JSON of traffic.proto. Enums arrive as
// their proto NAMES (e.g. "PROTOCOL_TCP"); we shorten them for display.
type trafficConnection struct {
	ContainerName string    `json:"containerName"`
	Protocol      string    `json:"protocol"`
	SourceIP      string    `json:"sourceIp"`
	SourcePort    uint32    `json:"sourcePort"`
	DestIP        string    `json:"destIp"`
	DestPort      uint32    `json:"destPort"`
	State         string    `json:"state"`
	Direction     string    `json:"direction"`
	BytesSent     flexInt64 `json:"bytesSent"`
	BytesReceived flexInt64 `json:"bytesReceived"`
	LastSeen      string    `json:"lastSeen"`
}

type getConnectionsResp struct {
	Connections []trafficConnection `json:"connections"`
	TotalCount  int32               `json:"totalCount"`
}

type destinationStats struct {
	DestIP          string    `json:"destIp"`
	ConnectionCount int32     `json:"connectionCount"`
	BytesTotal      flexInt64 `json:"bytesTotal"`
}

type connectionSummaryResp struct {
	ContainerName      string             `json:"containerName"`
	ActiveConnections  int32              `json:"activeConnections"`
	TCPConnections     int32              `json:"tcpConnections"`
	UDPConnections     int32              `json:"udpConnections"`
	TotalBytesSent     flexInt64          `json:"totalBytesSent"`
	TotalBytesReceived flexInt64          `json:"totalBytesReceived"`
	TopDestinations    []destinationStats `json:"topDestinations"`
}

type historicalConnection struct {
	Protocol      string    `json:"protocol"`
	SourceIP      string    `json:"sourceIp"`
	SourcePort    uint32    `json:"sourcePort"`
	DestIP        string    `json:"destIp"`
	DestPort      uint32    `json:"destPort"`
	BytesSent     flexInt64 `json:"bytesSent"`
	BytesReceived flexInt64 `json:"bytesReceived"`
	StartedAt     string    `json:"startedAt"`
	EndedAt       string    `json:"endedAt"`
}

type queryHistoryResp struct {
	Connections []historicalConnection `json:"connections"`
	TotalCount  int32                  `json:"totalCount"`
}

// trafficGet performs an authenticated GET against the resolved traffic server
// and decodes the JSON body into out.
func trafficGet(ctx context.Context, path string, query url.Values, out any) error {
	srv := pickSSHServer(trafficServerFlag) // creds-aware: explicit flag → default_server → cloud
	u := strings.TrimRight(srv, "/") + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	if tok := resolveAuthToken(srv); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", u, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("api error (status %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// protocolEnum maps a user-facing protocol string to the proto enum NAME the
// grpc-gateway query param expects. Empty input → "" (no filter).
func protocolEnum(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return "", nil
	case "tcp":
		return "PROTOCOL_TCP", nil
	case "udp":
		return "PROTOCOL_UDP", nil
	case "icmp":
		return "PROTOCOL_ICMP", nil
	default:
		return "", fmt.Errorf("unknown protocol %q (want tcp, udp, or icmp)", s)
	}
}

// shortEnum trims the proto enum prefix for display: "PROTOCOL_TCP" → "tcp",
// "TRAFFIC_DIRECTION_EGRESS" → "egress", "CONNECTION_STATE_ESTABLISHED" →
// "established". An empty / unspecified value renders as "-".
func shortEnum(v string) string {
	if v == "" {
		return "-"
	}
	for _, p := range []string{"PROTOCOL_", "TRAFFIC_DIRECTION_", "CONNECTION_STATE_"} {
		v = strings.TrimPrefix(v, p)
	}
	if strings.HasSuffix(v, "UNSPECIFIED") {
		return "-"
	}
	return strings.ToLower(v)
}

func runTrafficConnections(cmd *cobra.Command, args []string) error {
	box := args[0]
	proto, err := protocolEnum(trafficProtocol)
	if err != nil {
		return err
	}
	q := url.Values{}
	if proto != "" {
		q.Set("protocol", proto)
	}
	if trafficDestIP != "" {
		q.Set("destIpPrefix", trafficDestIP)
	}
	if trafficDestPort != 0 {
		q.Set("destPort", strconv.FormatUint(uint64(trafficDestPort), 10))
	}
	if trafficLimit != 0 {
		q.Set("limit", strconv.FormatInt(int64(trafficLimit), 10))
	}

	var resp getConnectionsResp
	if err := trafficGet(cmd.Context(), "/v1/containers/"+url.PathEscape(box)+"/connections", q, &resp); err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	if trafficFormat == "json" {
		return writeJSON(out, resp)
	}
	if len(resp.Connections) == 0 {
		fmt.Fprintf(out, "No active connections for %q.\n", box)
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "PROTO\tSOURCE\tDESTINATION\tDIR\tSTATE\tSENT\tRECV")
	for _, c := range resp.Connections {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			shortEnum(c.Protocol),
			hostPort(c.SourceIP, c.SourcePort),
			hostPort(c.DestIP, c.DestPort),
			shortEnum(c.Direction), shortEnum(c.State),
			humanBytes(int64(c.BytesSent)), humanBytes(int64(c.BytesReceived)))
	}
	_ = tw.Flush()
	fmt.Fprintf(out, "\n%d connection(s).\n", resp.TotalCount)
	return nil
}

func runTrafficSummary(cmd *cobra.Command, args []string) error {
	box := args[0]
	var resp connectionSummaryResp
	if err := trafficGet(cmd.Context(), "/v1/containers/"+url.PathEscape(box)+"/connections/summary", nil, &resp); err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	if trafficFormat == "json" {
		return writeJSON(out, resp)
	}
	fmt.Fprintf(out, "Box:               %s\n", box)
	fmt.Fprintf(out, "Active connections: %d (tcp %d, udp %d)\n", resp.ActiveConnections, resp.TCPConnections, resp.UDPConnections)
	fmt.Fprintf(out, "Bytes sent / recv:  %s / %s\n", humanBytes(int64(resp.TotalBytesSent)), humanBytes(int64(resp.TotalBytesReceived)))
	if len(resp.TopDestinations) > 0 {
		fmt.Fprintln(out, "\nTop destinations:")
		tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "  DEST IP\tCONNS\tBYTES")
		for _, d := range resp.TopDestinations {
			fmt.Fprintf(tw, "  %s\t%d\t%s\n", d.DestIP, d.ConnectionCount, humanBytes(int64(d.BytesTotal)))
		}
		_ = tw.Flush()
	}
	return nil
}

func runTrafficHistory(cmd *cobra.Command, args []string) error {
	box := args[0]
	q := url.Values{}
	// google.protobuf.Timestamp query params are RFC3339 via grpc-gateway.
	q.Set("startTime", time.Now().Add(-trafficSince).UTC().Format(time.RFC3339))
	if trafficLimit != 0 {
		q.Set("limit", strconv.FormatInt(int64(trafficLimit), 10))
	}

	var resp queryHistoryResp
	if err := trafficGet(cmd.Context(), "/v1/containers/"+url.PathEscape(box)+"/traffic/history", q, &resp); err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	if trafficFormat == "json" {
		return writeJSON(out, resp)
	}
	if len(resp.Connections) == 0 {
		fmt.Fprintf(out, "No history for %q in the last %s.\n", box, trafficSince)
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "PROTO\tSOURCE\tDESTINATION\tSENT\tRECV\tENDED")
	for _, c := range resp.Connections {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			shortEnum(c.Protocol),
			hostPort(c.SourceIP, c.SourcePort),
			hostPort(c.DestIP, c.DestPort),
			humanBytes(int64(c.BytesSent)), humanBytes(int64(c.BytesReceived)),
			c.EndedAt)
	}
	_ = tw.Flush()
	fmt.Fprintf(out, "\n%d historical connection(s).\n", resp.TotalCount)
	return nil
}

// --- small display helpers (writeJSON + humanBytes are shared, see runner.go /
// backup_create.go) ---

// hostPort renders "ip:port", omitting the port when 0 (ICMP / unset).
func hostPort(ip string, port uint32) string {
	if ip == "" {
		return "-"
	}
	if port == 0 {
		return ip
	}
	return ip + ":" + strconv.FormatUint(uint64(port), 10)
}
