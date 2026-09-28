// Package gatewayprovider maps the GatewayProvider proto enum to and from the
// provider names the model gateway's registry is keyed by.
//
// It exists as its own package because three layers need exactly the same
// mapping and none of them may import the others: the daemon's
// ModelGatewayServer (enum -> registry key), the typed client, and the CLI's
// --provider flag (name -> enum). The CLI is built with `-tags
// containarium_client`, which deliberately excludes internal/server, so "just
// export it from the server" is not available — and two copies of this mapping
// is exactly how a flag's vocabulary drifts from the contract.
//
// The mapping is DERIVED from the enum's own value names rather than written out
// by hand, so a new enum value cannot ship without a provider name:
//
//	GATEWAY_PROVIDER_GEMINI_OPENAI -> "gemini-openai"
//
// which is what modelgateway.DefaultProviders and ProvidersFromEnv
// (<PROVIDER>_UPSTREAM_URL) key on.
package gatewayprovider

import (
	"fmt"
	"sort"
	"strings"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// enumPrefix is stripped from an enum value's name to get the provider name.
const enumPrefix = "GATEWAY_PROVIDER_"

// Name returns the gateway registry's provider name for p.
//
// GATEWAY_PROVIDER_UNSPECIFIED is an error, not a default: "the caller did not
// say which provider" must never silently become one.
func Name(p pb.GatewayProvider) (string, error) {
	if p == pb.GatewayProvider_GATEWAY_PROVIDER_UNSPECIFIED {
		return "", fmt.Errorf("provider is required (one of: %s)", strings.Join(Names(), ", "))
	}
	name, ok := pb.GatewayProvider_name[int32(p)]
	if !ok {
		return "", fmt.Errorf("unknown provider (enum value %d)", int32(p))
	}
	return strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(name, enumPrefix), "_", "-")), nil
}

// FromName is Name's inverse, for the CLI's --provider flag.
func FromName(name string) (pb.GatewayProvider, error) {
	want := strings.TrimSpace(strings.ToLower(name))
	if want == "" {
		return pb.GatewayProvider_GATEWAY_PROVIDER_UNSPECIFIED,
			fmt.Errorf("provider is required (one of: %s)", strings.Join(Names(), ", "))
	}
	for value := range pb.GatewayProvider_name {
		p := pb.GatewayProvider(value)
		if p == pb.GatewayProvider_GATEWAY_PROVIDER_UNSPECIFIED {
			continue
		}
		if got, err := Name(p); err == nil && got == want {
			return p, nil
		}
	}
	return pb.GatewayProvider_GATEWAY_PROVIDER_UNSPECIFIED,
		fmt.Errorf("unknown provider %q (one of: %s)", name, strings.Join(Names(), ", "))
}

// Names lists every provider name the enum can express, in enum-value order, for
// flag help and error messages.
//
// Sorted by value rather than ranged over the map, so the order — and therefore
// every error message quoting it — is stable between runs.
func Names() []string {
	values := make([]int32, 0, len(pb.GatewayProvider_name))
	for value := range pb.GatewayProvider_name {
		if pb.GatewayProvider(value) == pb.GatewayProvider_GATEWAY_PROVIDER_UNSPECIFIED {
			continue
		}
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })

	out := make([]string, 0, len(values))
	for _, value := range values {
		if name, err := Name(pb.GatewayProvider(value)); err == nil {
			out = append(out, name)
		}
	}
	return out
}
