package modelgateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Upstream model listing (#1726, the ListGatewayModels RPC).
//
// A caller that is about to point an engine at the gateway wants to know which
// models it may ask for — and the honest answer is "whatever the key this
// gateway would spend can see". So this reads the provider's own model list
// through the SAME key resolution the proxy path uses (resolveKey), rather than
// returning a list compiled into the daemon: the list a caller gets is the list
// its calls will actually be able to use.
//
// The caller never holds a provider key. It names an owner and a provider; the
// key is resolved here and never leaves this process, exactly as on the data
// plane.

var (
	// ErrUnknownProvider means the daemon serves no provider by that name —
	// either it was never compiled in, or no operator registered its upstream.
	ErrUnknownProvider = errors.New("modelgateway: unknown provider")
	// ErrNoKey means neither the key owner nor the daemon has a key for this
	// provider, so there is nothing to spend on the lookup.
	ErrNoKey = errors.New("modelgateway: no key for this owner or provider")
	// ErrModelListUnsupported means the provider is not OpenAI-shaped and so has
	// no /v1/models contract to read. Returned rather than an empty list, which
	// would read as "this provider offers no models".
	ErrModelListUnsupported = errors.New("modelgateway: provider has no OpenAI-shaped model list")
)

// UpstreamStatusError is a non-2xx answer from the provider. It carries the
// status code so the caller can map it (401 from upstream is a bad customer key,
// not an internal failure) and a trimmed body for the operator-facing message.
type UpstreamStatusError struct {
	Provider   string
	StatusCode int
	Body       string
}

func (e *UpstreamStatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("modelgateway: %s model list: upstream returned %d", e.Provider, e.StatusCode)
	}
	return fmt.Sprintf("modelgateway: %s model list: upstream returned %d: %s", e.Provider, e.StatusCode, e.Body)
}

// modelListTimeout bounds one upstream model-list lookup. Short: it sits in
// front of an interactive CLI verb and an install-time preflight, and a provider
// that cannot answer in this window is a provider the caller should hear about
// rather than wait on.
const modelListTimeout = 10 * time.Second

// maxModelListErrorBody caps how much of an upstream error body is quoted back.
const maxModelListErrorBody = 512

// HasProvider reports whether this gateway brokers a provider by that name —
// either compiled in (DefaultProviders) or registered from the environment
// (ProvidersFromEnv). The mint path asks before issuing a token, so "this daemon
// does not serve that provider" is named at mint time rather than discovered as
// a 404 on the box's first model call.
func (g *Gateway) HasProvider(name string) bool {
	p, ok := g.cfg.Providers[name]
	return ok && p != nil
}

// ListModels returns the model ids provider exposes, read on keyOwner's key
// (falling back to the daemon-global key for the provider, same precedence as
// the proxy path). keyOwner may be empty, which resolves to the global key only.
func (g *Gateway) ListModels(ctx context.Context, keyOwner, provider string) ([]string, error) {
	p, ok := g.cfg.Providers[provider]
	if !ok || p == nil {
		return nil, fmt.Errorf("%w: %s", ErrUnknownProvider, provider)
	}
	if !p.openAIShaped {
		return nil, fmt.Errorf("%w: %s", ErrModelListUnsupported, provider)
	}
	key, ok := g.resolveKey(ctx, &GatewayClaims{KeyOwner: keyOwner}, provider)
	if !ok || key == "" {
		return nil, fmt.Errorf("%w: key_owner=%s provider=%s", ErrNoKey, keyOwner, provider)
	}

	ctx, cancel := context.WithTimeout(ctx, modelListTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.UpstreamURL+"/v1/models", nil)
	if err != nil {
		return nil, err
	}
	// Same injection the proxy path uses, so the real key is set and any inbound
	// gateway credential is stripped in one place rather than two.
	p.inject(req.Header, key)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("modelgateway: %s model list: %w", provider, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxModelListErrorBody))
		return nil, &UpstreamStatusError{
			Provider:   provider,
			StatusCode: resp.StatusCode,
			Body:       strings.TrimSpace(string(body)),
		}
	}

	// The OpenAI model-list shape. A named struct rather than
	// map[string]interface{} — every wire payload gets a type (CLAUDE.md).
	var payload struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("modelgateway: %s model list: decoding upstream response: %w", provider, err)
	}
	out := make([]string, 0, len(payload.Data))
	for _, m := range payload.Data {
		if m.ID != "" {
			out = append(out, m.ID)
		}
	}
	return out, nil
}
