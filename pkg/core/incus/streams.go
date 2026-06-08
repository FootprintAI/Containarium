package incus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Phase 3.1 Phase-A — simplestreams index resolver. Audit
// B-HIGH-1 deeper half. See
// docs/security/IMAGE-DIGEST-VERIFY-DESIGN.md for the full
// design.
//
// This file builds the resolver only. It does NOT wire
// into CreateContainer — that's Phase B. Phase A's
// contract is narrow: given a simplestreams server and an
// image alias, return the set of SHA-256 digests the
// registry has published for that alias. The caller (in
// Phase B) checks membership of the operator-supplied
// `@sha256:` digest.
//
// We deliberately avoid go-incus or a third-party
// simplestreams parser. Reasons:
//
//   - Our usage is one endpoint and one JSON shape; ~100
//     lines of Go.
//   - The full simplestreams library carries product-
//     resolution / signature-validation logic we don't
//     need (Incus already does both during the actual
//     pull). Phase A is just "match the digest in the
//     index;" Phase B + C handle the rest.
//   - One fewer dependency in govulncheck and the supply
//     chain.
//
// Wire shape (subset of the simplestreams products:1.0
// schema):
//
//   GET <server>/streams/v1/images.json
//   →  {
//        "format": "products:1.0",
//        "products": {
//          "ubuntu:24.04:amd64:default": {
//            "aliases": "24.04,noble,ubuntu/24.04",
//            "arch": "amd64",
//            "versions": {
//              "20240519_07:42": {
//                "items": {
//                  "lxd.tar.xz":           {"ftype": "...", "sha256": "..."},
//                  "root.squashfs":        {"ftype": "...", "sha256": "..."},
//                  "lxd_combined.tar.gz":  {"ftype": "...", "sha256": "..."}
//                }
//              },
//              "20240520_07:42": {...}
//            }
//          }
//        }
//      }
//
// "aliases" is a comma-separated list because each product
// can have several human-readable shortnames.

// indexPath is the simplestreams products:1.0 endpoint
// every supported remote serves.
const indexPath = "/streams/v1/images.json"

// StreamsResolver fetches and caches the simplestreams
// index for one or more registry servers. Construction is
// cheap; the network call lands on the first Resolve.
//
// Phase B+ follow-up: the resolver now caches each
// fetched index in memory for `cacheTTL`. A CreateContainer
// burst against the same registry (e.g., 50 containers
// pulled from images.linuxcontainers.org during a fleet
// rollout) collapses into a single index fetch. TTL
// defaults to 5 minutes — a window short enough that a
// freshly-published image becomes verifiable within one
// pull cycle, but long enough to absorb operator bursts.
//
// Cache is keyed by server URL. Each entry holds the raw
// imagesIndex plus its fetch time. Expired entries are
// re-fetched on the next Resolve; a parallel re-fetch
// during expiry is acceptable (worst case: one extra
// network call) and avoids the singleflight machinery
// that would otherwise be needed.
type StreamsResolver struct {
	client *http.Client

	cacheTTL time.Duration

	mu    sync.Mutex
	cache map[string]cachedIndex
}

type cachedIndex struct {
	idx       imagesIndex
	fetchedAt time.Time
}

// defaultCacheTTL is the cache horizon when callers don't
// override it. Five minutes balances "operator burst
// absorption" against "freshly-published image visibility."
const defaultCacheTTL = 5 * time.Minute

// NewStreamsResolver builds a resolver. timeout caps every
// network call to the registry index; 10s is the
// suggested default (matches Vault/GCP KMS timeouts and
// gives room for simplestreams indexes that have grown to
// a few MB).
//
// Cache TTL defaults to 5 minutes. Use NewStreamsResolverWithCacheTTL
// to override (tests pass 0 to disable caching).
func NewStreamsResolver(timeout time.Duration) *StreamsResolver {
	return NewStreamsResolverWithCacheTTL(timeout, defaultCacheTTL)
}

// NewStreamsResolverWithCacheTTL is the full constructor
// — same as NewStreamsResolver but lets callers control
// cache TTL. Pass 0 to disable caching (each Resolve
// fetches fresh).
func NewStreamsResolverWithCacheTTL(timeout, cacheTTL time.Duration) *StreamsResolver {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if cacheTTL < 0 {
		cacheTTL = 0
	}
	return &StreamsResolver{
		client:   &http.Client{Timeout: timeout},
		cacheTTL: cacheTTL,
		cache:    make(map[string]cachedIndex),
	}
}

// imagesIndex is a subset of the simplestreams products:1.0
// schema, decoded just enough to walk the (alias →
// version → item.sha256) chain. Unknown fields are
// ignored by encoding/json.
type imagesIndex struct {
	Format   string                  `json:"format"`
	Products map[string]productEntry `json:"products"`
}

type productEntry struct {
	// Aliases is the human-readable shortname list,
	// comma-separated. Examples:
	//   "24.04,noble"
	//   "ubuntu/24.04"
	// We normalize on parse — split, trim, lowercase.
	Aliases string `json:"aliases"`

	Arch string `json:"arch"`

	// Versions is keyed by build timestamp
	// ("20240519_07:42"). The map order from JSON is
	// non-deterministic; we sort by key when walking.
	Versions map[string]versionEntry `json:"versions"`
}

type versionEntry struct {
	Items map[string]itemEntry `json:"items"`
}

type itemEntry struct {
	FType  string `json:"ftype"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Path   string `json:"path"`
}

// ResolveImageDigests fetches the simplestreams index at
// `server` and returns every SHA-256 digest the registry
// has published for any version of any product whose
// aliases match `alias`. The set semantics is intentional:
// each version publishes multiple items (rootfs,
// metadata, combined), each carrying its own digest, and
// the operator's `@sha256:...` reference can point at any
// of them. The caller (Phase B) checks membership.
//
// Empty result + nil error means "alias not found in the
// index" — the caller decides how to surface that (a
// recently-deleted product? a typo? a stale index?).
//
// Returns a non-nil error only for network failure, HTTP
// status >= 400, or malformed JSON.
func (r *StreamsResolver) ResolveImageDigests(ctx context.Context, server, alias string) ([]string, error) {
	if server == "" {
		return nil, errors.New("simplestreams resolver: server URL is required")
	}
	if alias == "" {
		return nil, errors.New("simplestreams resolver: alias is required")
	}
	idx, err := r.fetchIndex(ctx, server)
	if err != nil {
		return nil, err
	}
	return collectDigests(idx, alias), nil
}

// fetchIndex returns the simplestreams index for `server`,
// from the in-memory cache if fresh, or from the network
// otherwise. The cache is best-effort: a concurrent
// fetch-during-expiry produces at most one extra network
// call, no correctness impact.
func (r *StreamsResolver) fetchIndex(ctx context.Context, server string) (imagesIndex, error) {
	key := strings.TrimRight(server, "/")

	if r.cacheTTL > 0 {
		r.mu.Lock()
		entry, ok := r.cache[key]
		r.mu.Unlock()
		if ok && time.Since(entry.fetchedAt) < r.cacheTTL {
			return entry.idx, nil
		}
	}

	idx, err := r.fetchIndexFromNetwork(ctx, key)
	if err != nil {
		return imagesIndex{}, err
	}

	if r.cacheTTL > 0 {
		r.mu.Lock()
		r.cache[key] = cachedIndex{idx: idx, fetchedAt: time.Now()}
		r.mu.Unlock()
	}
	return idx, nil
}

// fetchIndexFromNetwork performs the actual HTTP GET +
// decode. Pulled out so the cache logic stays readable
// and so tests can stub it via the public Resolve path.
func (r *StreamsResolver) fetchIndexFromNetwork(ctx context.Context, server string) (imagesIndex, error) {
	url := server + indexPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return imagesIndex{}, fmt.Errorf("build request: %w", err)
	}
	// Identify ourselves to the registry. Helps operators
	// chase down "where is this traffic from" questions
	// in registry access logs.
	req.Header.Set("User-Agent", "containarium-streams-resolver/1.0")
	resp, err := r.client.Do(req)
	if err != nil {
		return imagesIndex{}, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return imagesIndex{}, fmt.Errorf("fetch %s: status %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var idx imagesIndex
	if err := json.NewDecoder(resp.Body).Decode(&idx); err != nil {
		return imagesIndex{}, fmt.Errorf("decode index: %w", err)
	}
	if idx.Format != "products:1.0" {
		// The simplestreams ecosystem could ship a v2
		// someday. Don't silently mis-parse — fail noisily
		// so a Phase B+ follow-up can teach the resolver
		// the new shape.
		return imagesIndex{}, fmt.Errorf("unrecognized index format %q (want products:1.0)", idx.Format)
	}
	return idx, nil
}

// InvalidateCache clears any cached index entries. Useful
// when the operator knows the registry has just published
// a new image and wants the daemon to see it before the
// TTL expires (e.g., after a release-ship workflow).
func (r *StreamsResolver) InvalidateCache() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache = make(map[string]cachedIndex)
}

// collectDigests walks products whose alias list contains
// the requested alias and gathers every sha256 across
// every version's items. Pure-function for testability.
//
// Alias matching is case-insensitive and tolerates the
// simplestreams convention of comma-separating multiple
// aliases per product. We also tolerate the operator
// passing either "ubuntu/24.04" or "24.04" — we accept
// any exact match within the comma-split list, but NOT
// substring matches (an alias entry "24.04" doesn't
// satisfy a request for "4.04").
func collectDigests(idx imagesIndex, alias string) []string {
	want := strings.ToLower(strings.TrimSpace(alias))
	seen := make(map[string]struct{})
	var out []string
	for _, p := range idx.Products {
		if !productMatchesAlias(p.Aliases, want) {
			continue
		}
		for _, v := range p.Versions {
			for _, item := range v.Items {
				digest := strings.ToLower(strings.TrimSpace(item.SHA256))
				if digest == "" {
					continue
				}
				if _, dup := seen[digest]; dup {
					continue
				}
				seen[digest] = struct{}{}
				out = append(out, digest)
			}
		}
	}
	return out
}

// productMatchesAlias returns true when `aliases` (the
// product's comma-separated list) contains `want` as a
// distinct entry. Whitespace + case insensitive.
func productMatchesAlias(aliases, want string) bool {
	for _, raw := range strings.Split(aliases, ",") {
		if strings.ToLower(strings.TrimSpace(raw)) == want {
			return true
		}
	}
	return false
}

// DigestMatchesSet returns true when `requested` (a
// lowercase 64-char hex string, e.g. from an
// `@sha256:...` reference) appears in `published`. Helper
// for Phase B's gate; lives here so the lookup semantics
// stay co-located with the resolver.
//
// We normalize both sides — leading whitespace, optional
// "sha256:" prefix, case — so the caller can pass whatever
// shape the operator wrote.
func DigestMatchesSet(requested string, published []string) bool {
	want := normalizeDigest(requested)
	if want == "" {
		return false
	}
	for _, p := range published {
		if normalizeDigest(p) == want {
			return true
		}
	}
	return false
}

// normalizeDigest strips "sha256:" prefix and whitespace,
// lowercases hex. Returns "" for anything that doesn't
// look like a 64-char hex string after normalization.
func normalizeDigest(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "sha256:")
	s = strings.TrimPrefix(s, "SHA256:")
	s = strings.ToLower(s)
	if len(s) != 64 {
		return ""
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return ""
		}
	}
	return s
}
