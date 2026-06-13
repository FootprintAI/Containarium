package mcp

import (
	"fmt"
	"strings"
)

// kmsTools is the MCP-side catalog for KMS envelope-encryption
// administration. Pulled into tools.go's registration list via
// kmsTools(), mirroring backupTools().
//
// Per CLAUDE.md: every tool is a thin wrapper over the same REST
// endpoint the CLI's `containarium kms` subcommands call (the
// generated KmsService gateway). Backend *configuration* is
// deliberately absent — selecting a backend / supplying credentials
// stays an operator concern, never an agent action.
func kmsTools() []Tool {
	return []Tool{
		{
			Name: "kms_status",
			Description: "Report the active KMS envelope-encryption backend " +
				"(none|inproc|vault|gcp|aws), a human-readable description, " +
				"whether a real KMS is active, and whether envelope mode is " +
				"required. Read-only. Mirrors `containarium kms status`.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
			Handler: handleKMSStatus,
		},
		{
			Name: "kms_envelope_coverage",
			Description: "Count stored secrets by encryption mode: total, " +
				"legacy (master-key only), and envelope (KMS-wrapped). " +
				"legacy=0 means fully migrated. Mirrors " +
				"`containarium kms envelope-coverage`.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
			Handler: handleKMSCoverage,
		},
		{
			Name: "kms_migrate_to_envelope",
			Description: "Re-wrap legacy secrets under the active KMS KEK. " +
				"Idempotent and resumable. Use dry_run to verify without " +
				"writing, and max_rows to chunk a large backlog. Fails if no " +
				"KMS backend is configured. Mirrors " +
				"`containarium kms migrate-to-envelope`.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dry_run": map[string]interface{}{
						"type":        "boolean",
						"description": "Walk + verify rows would round-trip, but write nothing. Default false.",
					},
					"max_rows": map[string]interface{}{
						"type":        "integer",
						"description": "Cap on rows processed in one call. 0/omitted = unlimited.",
					},
				},
			},
			Handler: handleKMSMigrate,
		},
	}
}

func handleKMSStatus(client API, args map[string]interface{}) (string, error) {
	resp, err := client.GetKMSStatus()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "KMS backend:      %s\n", resp.Backend)
	fmt.Fprintf(&b, "Description:      %s\n", resp.Description)
	fmt.Fprintf(&b, "KMS active:       %t\n", resp.KmsConfigured)
	fmt.Fprintf(&b, "Require envelope: %t\n", resp.RequireEnvelope)
	return b.String(), nil
}

func handleKMSCoverage(client API, args map[string]interface{}) (string, error) {
	resp, err := client.GetEnvelopeCoverage()
	if err != nil {
		return "", err
	}
	out := fmt.Sprintf("Secrets envelope coverage — total: %s, legacy: %s, envelope: %s",
		resp.Total, resp.Legacy, resp.Envelope)
	if resp.Legacy == "0" && resp.Total != "0" {
		out += "\n✓ Fully migrated."
	} else if resp.Legacy != "0" {
		out += fmt.Sprintf("\n%s legacy row(s) remain — run kms_migrate_to_envelope.", resp.Legacy)
	}
	return out, nil
}

func handleKMSMigrate(client API, args map[string]interface{}) (string, error) {
	maxRows := 0
	if v, ok := getIntArg(args, "max_rows"); ok {
		maxRows = v
	}
	resp, err := client.MigrateToEnvelope(MigrateToEnvelopeBody{
		DryRun:  getBoolArg(args, "dry_run", false),
		MaxRows: int64(maxRows),
	})
	if err != nil {
		return "", err
	}
	mode := "MIGRATE"
	if resp.DryRun {
		mode = "DRY-RUN"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s — scanned: %s, migrated: %s, already done: %s, failed: %s\n",
		mode, resp.Scanned, resp.Migrated, resp.AlreadyDone, resp.Failed)
	for _, e := range resp.Errors {
		fmt.Fprintf(&b, "  ✗ %s/%s — %s\n", e.Username, e.Name, e.Error)
	}
	return b.String(), nil
}
