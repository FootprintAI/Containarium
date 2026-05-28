package containariumotel

import (
	"context"
	"fmt"
	"io"
	"strings"
)

// redactedHeaderKeys (lowercased) get their values replaced with
// "<redacted>" in PrintConfig output.
var redactedHeaderKeys = map[string]struct{}{
	"authorization": {},
	"x-api-key":     {},
}

// PrintConfig writes a human-readable rendering of the resolved
// telemetry config to w. Mirrors the Python distro's
// `containarium-instrument --dry-run` output so operators see the
// same thing across languages.
//
// Bearer tokens and API keys are redacted by default. Pass
// WithoutHeaderRedaction to disable redaction (rarely useful — only
// when debugging the exact wire format and you've verified no token
// leaks).
func PrintConfig(_ context.Context, w io.Writer, opts ...PrintOption) error {
	popts := printOptions{redactBearer: true}
	for _, o := range opts {
		o(&popts)
	}
	cfg := ConfigFromEnv()
	return printConfig(w, cfg, popts.redactBearer)
}

// PrintOption configures PrintConfig.
type PrintOption func(*printOptions)

type printOptions struct {
	redactBearer bool
}

// WithoutHeaderRedaction disables the default Authorization /
// X-API-Key redaction in PrintConfig output. Don't use this in any
// path that touches logs or external systems.
func WithoutHeaderRedaction() PrintOption {
	return func(o *printOptions) { o.redactBearer = false }
}

func printConfig(w io.Writer, cfg DistroConfig, redact bool) error {
	var sb strings.Builder
	sb.WriteString("# containariumotel resolved config\n")
	fmt.Fprintf(&sb, "distro_version       : %s\n", version)
	fmt.Fprintf(&sb, "endpoint             : %s\n", or(cfg.Endpoint, "<unset>"))
	fmt.Fprintf(&sb, "protocol             : %s\n", or(cfg.Protocol, "<default: http/protobuf>"))
	fmt.Fprintf(&sb, "service_name         : %s\n", or(cfg.ServiceName, "<unset — SDK will default to unknown_service>"))
	fmt.Fprintf(&sb, "resource_attributes  : %s\n", or(cfg.ResourceAttributes, "<unset>"))
	fmt.Fprintf(&sb, "headers              : %s\n", formatHeaders(cfg.Headers, redact))
	sb.WriteString("\n# Containarium identity (CONTAINARIUM_* env)\n")
	fmt.Fprintf(&sb, "container.id         : %s\n", or(cfg.ContainerID, "<unset>"))
	fmt.Fprintf(&sb, "backend.id           : %s\n", or(cfg.BackendID, "<unset>"))
	fmt.Fprintf(&sb, "tenant.id            : %s\n", or(cfg.TenantID, "<unset>"))
	fmt.Fprintf(&sb, "service.version      : %s\n", or(cfg.ServiceVersion, "<unset>"))
	sb.WriteString("\n# Defended distro stamp (always present, never overridable)\n")
	fmt.Fprintf(&sb, "containarium.distro  : go/%s\n", version)
	sb.WriteString("\n")
	if cfg.Endpoint != "" {
		sb.WriteString("Status: telemetry pipeline will be configured.\n")
	} else {
		sb.WriteString("Status: TELEMETRY WILL BE NO-OP. Endpoint env not set; Init() will fail-open.\n")
		sb.WriteString("Enable monitoring on this LXC with:\n")
		sb.WriteString("  containarium monitoring enable <username>\n")
	}
	_, err := io.WriteString(w, sb.String())
	return err
}

func or(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func formatHeaders(raw string, redact bool) string {
	if raw == "" {
		return "<unset>"
	}
	if !redact {
		return raw
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, kv := range parts {
		idx := strings.IndexByte(kv, '=')
		if idx < 0 {
			out = append(out, kv)
			continue
		}
		k := kv[:idx]
		if _, hit := redactedHeaderKeys[strings.ToLower(strings.TrimSpace(k))]; hit {
			out = append(out, strings.TrimSpace(k)+"=<redacted>")
		} else {
			out = append(out, kv)
		}
	}
	return strings.Join(out, ",")
}
