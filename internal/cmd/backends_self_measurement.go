package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var selfMeasurementFormat string

var backendsSelfMeasurementCmd = &cobra.Command{
	Use:   "self-measurement [backend-id]",
	Short: "Fetch a backend's signed integrity self-measurement",
	Long: `Fetch a backend's signed integrity self-measurement: digests of the running
daemon binary, the loaded in-kernel network-policy program object(s), and the
canonical policy/config state, signed with the node's identity key (the
sentinel-issued peer leaf; TPM-backed when a TPM is present).

The daemon also emits this measurement on its heartbeat. The control plane
verifies it to detect tampering of a backend's control plane.

With no backend-id it measures the local/primary daemon's host; with a peer id
it forwards to that peer (which measures its own host).

Admin-only. See #683.

Requires --server pointing at the daemon's HTTP address.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runBackendsSelfMeasurement,
}

func init() {
	backendsCmd.AddCommand(backendsSelfMeasurementCmd)
	backendsSelfMeasurementCmd.Flags().StringVarP(&selfMeasurementFormat, "format", "f", "text",
		"Output format: text, json")
}

// programDigest mirrors the proto ProgramDigest wire shape.
type programDigest struct {
	Name   string `json:"name,omitempty"`
	Digest string `json:"digest,omitempty"`
}

// selfMeasurement mirrors the proto SelfMeasurement wire shape (camelCase via
// grpc-gateway JSON).
type selfMeasurement struct {
	HashAlgorithm      string          `json:"hashAlgorithm,omitempty"`
	BinaryDigest       string          `json:"binaryDigest,omitempty"`
	ProgramDigests     []programDigest `json:"programDigests,omitempty"`
	ConfigDigest       string          `json:"configDigest,omitempty"`
	MeasurementDigest  string          `json:"measurementDigest,omitempty"`
	Signature          string          `json:"signature,omitempty"`
	SignatureAlgorithm string          `json:"signatureAlgorithm,omitempty"`
	TpmBacked          bool            `json:"tpmBacked,omitempty"`
	Signed             bool            `json:"signed,omitempty"`
	SigningCertPem     string          `json:"signingCertPem,omitempty"`
	MeasuredAt         string          `json:"measuredAt,omitempty"`
	DaemonVersion      string          `json:"daemonVersion,omitempty"`
}

// selfMeasurementResp mirrors GetSelfMeasurementResponse.
type selfMeasurementResp struct {
	Measurement *selfMeasurement `json:"measurement"`
	BackendID   string           `json:"backendId"`
}

func runBackendsSelfMeasurement(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return fmt.Errorf("--server is required (the platform daemon's HTTP address, e.g. http://host:8080)")
	}
	backendID := ""
	if len(args) == 1 {
		backendID = args[0]
	}

	url := strings.TrimSuffix(serverAddr, "/") + "/v1/integrity/self-measurement"
	if backendID != "" {
		url += "?backend_id=" + backendID
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	httpClient := &http.Client{Timeout: 1 * time.Minute}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	if selfMeasurementFormat == "json" {
		if _, err := cmd.OutOrStdout().Write(body); err != nil {
			return fmt.Errorf("write response: %w", err)
		}
		fmt.Fprintln(cmd.OutOrStdout())
		return nil
	}

	var out selfMeasurementResp
	if err := json.Unmarshal(body, &out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	target := out.BackendID
	if target == "" {
		target = "(local)"
	}
	if out.Measurement == nil {
		fmt.Fprintf(cmd.OutOrStdout(), "no self-measurement returned for %s\n", target)
		return nil
	}

	m := out.Measurement
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "Integrity self-measurement for %s:\n", target)
	fmt.Fprintf(w, "  Measured at:     %s\n", orDash(m.MeasuredAt))
	fmt.Fprintf(w, "  Daemon version:  %s\n", orDash(m.DaemonVersion))
	fmt.Fprintf(w, "  Hash algorithm:  %s\n", orDash(m.HashAlgorithm))
	fmt.Fprintf(w, "  Binary digest:   %s\n", orDash(m.BinaryDigest))
	if len(m.ProgramDigests) == 0 {
		fmt.Fprintf(w, "  Program objects: none\n")
	} else {
		fmt.Fprintf(w, "  Program objects:\n")
		for _, p := range m.ProgramDigests {
			fmt.Fprintf(w, "    %s = %s\n", p.Name, p.Digest)
		}
	}
	fmt.Fprintf(w, "  Config digest:   %s\n", orDash(m.ConfigDigest))
	fmt.Fprintf(w, "  Measurement:     %s\n", orDash(m.MeasurementDigest))
	if m.Signed {
		tpm := "software key"
		if m.TpmBacked {
			tpm = "TPM-backed key"
		}
		fmt.Fprintf(w, "  Signature:       SIGNED (%s, %s)\n", orDash(m.SignatureAlgorithm), tpm)
	} else {
		fmt.Fprintf(w, "  Signature:       UNSIGNED (no node identity key bootstrapped — unverifiable, not tamper)\n")
	}
	return nil
}
