package containariumotel

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// containariumDistroAttrKey is the defended resource-attr key.
const containariumDistroAttrKey = "containarium.distro"

// buildResource composes a *resource.Resource per the precedence
// table in TELEMETRY-DISTRO-DESIGN.md, low to high (later wins):
//
//  1. SDK defaults  (resource.Default merge baseline)
//  2. Standard detectors (host, process, container)
//  3. Containarium env attrs (container.id, backend.id,
//     service.namespace, service.version)
//  4. OTEL_RESOURCE_ATTRIBUTES env (resource.WithFromEnv())
//  5. Caller's extra_attrs
//  6. containarium.distro stamp (defended — wins all)
//
// Unlike Python's Resource.create() which silently runs the env
// detector, Go's resource.New() only runs the detectors you ask for.
// That gives us cleaner precedence control: each layer is an explicit
// resource.Merge call.
func buildResource(
	ctx context.Context,
	cfg DistroConfig,
	extraAttrs map[string]string,
	distroVersion string,
) (*resource.Resource, error) {
	// Layers 1 + 2: SDK defaults + host/process/container detectors.
	// We deliberately don't pass WithSchemaURL — the detectors set the
	// resource's schema URL themselves, and pinning ours to an older
	// semconv version conflicts at merge time.
	base, err := resource.New(ctx,
		resource.WithHost(),
		resource.WithProcess(),
		resource.WithContainer(),
	)
	if err != nil {
		return nil, fmt.Errorf("base resource: %w", err)
	}

	// Layer 3: Containarium env attrs.
	var contAttrs []attribute.KeyValue
	if cfg.ContainerID != "" {
		contAttrs = append(contAttrs, semconv.ContainerID(cfg.ContainerID))
	}
	if cfg.BackendID != "" {
		contAttrs = append(contAttrs, attribute.String("backend.id", cfg.BackendID))
	}
	if cfg.TenantID != "" {
		contAttrs = append(contAttrs, semconv.ServiceNamespace(cfg.TenantID))
	}
	if cfg.ServiceVersion != "" {
		contAttrs = append(contAttrs, semconv.ServiceVersion(cfg.ServiceVersion))
	}
	if len(contAttrs) > 0 {
		contRes := resource.NewSchemaless(contAttrs...)
		base, err = resource.Merge(base, contRes)
		if err != nil {
			return nil, fmt.Errorf("merge containarium attrs: %w", err)
		}
	}

	// Layer 4: OTEL_RESOURCE_ATTRIBUTES env (user-set, wins over
	// Containarium env attrs per the precedence in the design doc).
	envRes, err := resource.New(ctx, resource.WithFromEnv())
	if err != nil {
		return nil, fmt.Errorf("env resource: %w", err)
	}
	base, err = resource.Merge(base, envRes)
	if err != nil {
		return nil, fmt.Errorf("merge env attrs: %w", err)
	}

	// Layer 5: caller's extra attrs.
	if len(extraAttrs) > 0 {
		attrs := make([]attribute.KeyValue, 0, len(extraAttrs))
		for k, v := range extraAttrs {
			attrs = append(attrs, attribute.String(k, v))
		}
		extraRes := resource.NewSchemaless(attrs...)
		base, err = resource.Merge(base, extraRes)
		if err != nil {
			return nil, fmt.Errorf("merge extra attrs: %w", err)
		}
	}

	// Layer 6: defended distro stamp. Merged last so nothing in any
	// prior layer can override it. This is a support signal —
	// containarium.distro is intentionally not user-overridable.
	stampRes := resource.NewSchemaless(
		attribute.String(containariumDistroAttrKey, "go/"+distroVersion),
	)
	return resource.Merge(base, stampRes)
}
