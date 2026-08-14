//go:build !windows

package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/config"
	"github.com/spf13/cobra"
)

var (
	sentinelPprofURL     string
	sentinelPprofProfile string
	sentinelPprofOutput  string
	sentinelPprofSeconds int
	sentinelPprofDebug   int
	sentinelPprofGC      bool
	sentinelPprofList    bool
	sentinelPprofSecret  string
)

var sentinelPprofCmd = &cobra.Command{
	Use:   "pprof",
	Short: "Capture a runtime profile from a running sentinel (#1352)",
	Long: `Download a pprof profile from a running sentinel and write it to a file.

The sentinel's profile endpoint is HMAC-gated, and ` + "`go tool pprof`" + ` cannot sign
its own requests — so it cannot fetch the URL directly. This command signs the
request, saves the profile, and prints the go tool pprof invocation to run next.

Authenticated with CONTAINARIUM_SENTINEL_ADMIN_SECRET, NOT the cluster-wide
CONTAINARIUM_SENTINEL_AUTH_SECRET that daemons hold for keysync/certsync. A heap
profile is a snapshot of everything the process holds in memory — tunnel-join
tokens, TLS key material — so it is gated like tunnel-token registration rather
than like a routine daemon pull.

Treat the downloaded file as sensitive: it belongs on an operator workstation,
not in a bug report or a shared bucket.

Examples:

  # Heap profile — the one that answers "what is holding all this memory"
  containarium sentinel pprof --url http://<sentinel-host>:8888 --profile heap -o heap.pb.gz

  # Force a GC first, so inuse_space is live memory rather than uncollected garbage
  containarium sentinel pprof --url http://<sentinel-host>:8888 --profile heap --gc

  # Compare two snapshots hours apart to find what grows (the #1349 workflow)
  go tool pprof -base heap-t0.pb.gz heap-t1.pb.gz

  # Goroutine dump as readable text, no go tool pprof needed
  containarium sentinel pprof --url http://<sentinel-host>:8888 --profile goroutine --debug 1 -o -

  # What profiles does this sentinel have?
  containarium sentinel pprof --url http://<sentinel-host>:8888 --list`,
	RunE: runSentinelPprof,
}

func init() {
	sentinelCmd.AddCommand(sentinelPprofCmd)

	sentinelPprofCmd.Flags().StringVar(&sentinelPprofURL, "url", "", "Sentinel binary-server base URL, e.g. http://<sentinel-host>:8888 (required)")
	sentinelPprofCmd.Flags().StringVar(&sentinelPprofProfile, "profile", "heap", "Profile to capture: heap, goroutine, allocs, threadcreate, block, mutex, or profile (CPU)")
	sentinelPprofCmd.Flags().StringVarP(&sentinelPprofOutput, "output", "o", "", "Write to this path ('-' for stdout). Default: <profile>.pb.gz, or stdout in --debug/--list mode")
	sentinelPprofCmd.Flags().IntVar(&sentinelPprofSeconds, "seconds", 0, "CPU profile duration in seconds (1-60, only with --profile profile)")
	sentinelPprofCmd.Flags().IntVar(&sentinelPprofDebug, "debug", 0, "0 = binary profile for go tool pprof; 1 or 2 = human-readable text")
	sentinelPprofCmd.Flags().BoolVar(&sentinelPprofGC, "gc", false, "Force a GC before a heap snapshot so inuse_space reflects live memory, not uncollected garbage")
	sentinelPprofCmd.Flags().BoolVar(&sentinelPprofList, "list", false, "List the profiles this sentinel offers, with current object counts")
	sentinelPprofCmd.Flags().StringVar(&sentinelPprofSecret, "secret", os.Getenv(config.EnvSentinelAdminSecret), "Sentinel admin secret (defaults to $CONTAINARIUM_SENTINEL_ADMIN_SECRET)")

	_ = sentinelPprofCmd.MarkFlagRequired("url")
}

// buildPprofURL assembles the sentinel profile URL. Pure, so the query
// assembly is testable without a server.
func buildPprofURL(base, profile string, seconds, debug int, gc, list bool) (string, error) {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		return "", fmt.Errorf("empty --url")
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("invalid --url %q: %w", base, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("invalid --url %q: want an http:// or https:// base URL", base)
	}

	path := "/debug/pprof/"
	if !list {
		if strings.TrimSpace(profile) == "" {
			return "", fmt.Errorf("empty --profile")
		}
		path += profile
	}

	q := url.Values{}
	if debug > 0 {
		q.Set("debug", strconv.Itoa(debug))
	}
	if gc {
		q.Set("gc", "1")
	}
	if seconds > 0 {
		q.Set("seconds", strconv.Itoa(seconds))
	}

	out := base + path
	if len(q) > 0 {
		out += "?" + q.Encode()
	}
	return out, nil
}

// pprofOutputPath resolves where the profile lands. Text and list output go to
// stdout by default (you want to read it); a binary profile defaults to a file
// because dumping gzip to a terminal is never what anyone meant. Pure.
func pprofOutputPath(explicit, profile string, debug int, list bool) string {
	if explicit != "" {
		return explicit
	}
	if list || debug > 0 {
		return "-"
	}
	return profile + ".pb.gz"
}

// pprofClientTimeout leaves room for a CPU profile to run its full window plus
// transfer, without letting a stuck sentinel hang the operator forever.
func pprofClientTimeout(seconds int) time.Duration {
	const slack = 30 * time.Second
	if seconds > 0 {
		return time.Duration(seconds)*time.Second + slack
	}
	return 60 * time.Second
}

func runSentinelPprof(cmd *cobra.Command, args []string) error {
	if sentinelPprofSecret == "" {
		return fmt.Errorf("sentinel admin secret is required — pass --secret or set %s", config.EnvSentinelAdminSecret)
	}
	if sentinelPprofDebug < 0 || sentinelPprofDebug > 2 {
		return fmt.Errorf("--debug must be 0, 1, or 2")
	}
	if sentinelPprofSeconds != 0 && sentinelPprofProfile != "profile" {
		return fmt.Errorf("--seconds applies only to --profile profile (the CPU profile)")
	}

	endpoint, err := buildPprofURL(sentinelPprofURL, sentinelPprofProfile, sentinelPprofSeconds, sentinelPprofDebug, sentinelPprofGC, sentinelPprofList)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	auth.SignSentinelRequest(req, []byte(sentinelPprofSecret))

	if sentinelPprofSeconds > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "profiling CPU for %ds…\n", sentinelPprofSeconds)
	}

	client := &http.Client{Timeout: pprofClientTimeout(sentinelPprofSeconds)}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		msg := strings.TrimSpace(string(body))
		if resp.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf("sentinel returned 401 — check %s matches the value on the sentinel host, and that both clocks are within 5 minutes (%s)",
				config.EnvSentinelAdminSecret, msg)
		}
		return fmt.Errorf("sentinel returned %d: %s", resp.StatusCode, msg)
	}

	outPath := pprofOutputPath(sentinelPprofOutput, sentinelPprofProfile, sentinelPprofDebug, sentinelPprofList)
	if outPath == "-" {
		if _, err := io.Copy(cmd.OutOrStdout(), resp.Body); err != nil {
			return fmt.Errorf("write to stdout: %w", err)
		}
		return nil
	}

	// 0600: the profile may contain tokens and key material lifted straight
	// out of the sentinel's heap.
	f, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create %s: %w", outPath, err)
	}
	n, copyErr := io.Copy(f, resp.Body)
	closeErr := f.Close()
	if copyErr != nil {
		return fmt.Errorf("write %s: %w", outPath, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close %s: %w", outPath, closeErr)
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s (%d bytes, mode 0600 — contains sentinel heap contents)\n", outPath, n)
	fmt.Fprintf(cmd.ErrOrStderr(), "inspect with: go tool pprof %s\n", outPath)
	if sentinelPprofProfile == "heap" {
		fmt.Fprintf(cmd.ErrOrStderr(), "to find a leak, capture a second snapshot later and diff: go tool pprof -base %s <later>.pb.gz\n", outPath)
	}
	return nil
}
