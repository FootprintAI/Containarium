//go:build !containarium_client

package cmd

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/spf13/cobra"
)

var statusDomain string

var hostingStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check hosting infrastructure status",
	Long: `Check the status of the hosting infrastructure including:
  - Caddy service status
  - DNS resolution
  - HTTPS certificate validity

Examples:
  # Check status for a domain
  containarium hosting status --domain example.com

  # Check status without domain verification
  containarium hosting status`,
	RunE: runHostingStatus,
}

func init() {
	hostingCmd.AddCommand(hostingStatusCmd)
	hostingStatusCmd.Flags().StringVar(&statusDomain, "domain", "", "Domain to check (optional)")
}

func runHostingStatus(cmd *cobra.Command, args []string) error {
	fmt.Println("Hosting Infrastructure Status")
	fmt.Println("==============================")
	fmt.Println()

	// Check Caddy installation
	fmt.Print("Caddy binary:     ")
	if _, err := os.Stat("/usr/local/bin/caddy"); err == nil {
		fmt.Println("installed (/usr/local/bin/caddy)")
	} else {
		fmt.Println("not installed")
	}

	// Check Caddy service status
	fmt.Print("Caddy service:    ")
	caddyStatus := exec.Command("systemctl", "is-active", "--quiet", "caddy")
	if err := caddyStatus.Run(); err == nil {
		fmt.Println("running")
	} else {
		fmt.Println("not running")
	}

	// Check Caddy Admin API
	fmt.Print("Caddy Admin API:  ")
	client := &http.Client{Timeout: 5 * time.Second}
	if resp, err := client.Get("http://localhost:2019/config/"); err == nil {
		resp.Body.Close()
		fmt.Println("responding (localhost:2019)")
	} else {
		fmt.Println("not responding")
	}

	// Check Caddyfile
	fmt.Print("Caddyfile:        ")
	if _, err := os.Stat("/etc/caddy/Caddyfile"); err == nil {
		fmt.Println("exists (/etc/caddy/Caddyfile)")
	} else {
		fmt.Println("not found")
	}

	// Domain-specific checks
	if statusDomain != "" {
		fmt.Println()
		fmt.Printf("Domain: %s\n", statusDomain)
		fmt.Println("--------" + repeatString("-", len(statusDomain)))

		// Check DNS resolution
		fmt.Print("DNS resolution:   ")
		dnsCheck := exec.Command("dig", "+short", statusDomain)
		if output, err := dnsCheck.Output(); err == nil && len(output) > 0 {
			fmt.Printf("OK (%s)\n", trimNewline(string(output)))
		} else {
			fmt.Println("failed or no record")
		}

		// Check wildcard DNS
		fmt.Print("Wildcard DNS:     ")
		wildcardCheck := exec.Command("dig", "+short", "test."+statusDomain)
		if output, err := wildcardCheck.Output(); err == nil && len(output) > 0 {
			fmt.Printf("OK (%s)\n", trimNewline(string(output)))
		} else {
			fmt.Println("failed or no record")
		}

		// Check HTTPS
		fmt.Print("HTTPS:            ")
		httpsClient := &http.Client{Timeout: 30 * time.Second}
		if resp, err := httpsClient.Get("https://" + statusDomain); err == nil {
			resp.Body.Close()
			fmt.Printf("OK (HTTP %d)\n", resp.StatusCode)
		} else {
			fmt.Printf("failed (%v)\n", err)
		}
	}

	fmt.Println()
	return nil
}

func repeatString(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
