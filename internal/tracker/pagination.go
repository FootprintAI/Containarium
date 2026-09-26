package tracker

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// MaxListPages bounds how many pages a provider's list call follows
// (#2040). At 100 items per page that is 5,000 items per list call, and
// it guarantees a misbehaving upstream that always answers with a next
// link cannot loop forever.
//
// The bound is on what the upstream returns, not on what the caller
// keeps. The dispatcher lists ALL open issues with no label filter, and
// on GitHub the /issues endpoint also returns open pull requests (the
// adapter drops them only after fetching), so the real ceiling is 5,000
// open issues plus pull requests per project.
//
// Both GitHub and GitLab return newest first by default, so hitting the
// bound silently drops the OLDEST items — the same failure mode as
// #2040, only at 5,000 instead of 100. An adapter that hits the bound
// returns what it collected with a nil error and only logs the
// truncation; the caller is not told.
const MaxListPages = 50

// ErrCrossOriginNextLink is returned when a pagination Link header
// names a different scheme or host than the request that produced it.
// Following it would send the connection's credential to a host the
// operator never configured, so the list call fails instead.
//
// This guards only the Link header. HTTP redirects are followed by the
// adapters' http.Client, and Go strips Authorization on a cross-domain
// redirect but not custom headers such as GitLab's PRIVATE-TOKEN; that
// gap predates pagination and is not closed here.
var ErrCrossOriginNextLink = errors.New("refusing to follow pagination link to a different host")

// NextPageURL returns the rel="next" target of an RFC 8288 Link header
// — the pagination mechanism both GitHub and GitLab use — or "" when
// there is no next page.
func NextPageURL(linkHeader string) string {
	for _, part := range strings.Split(linkHeader, ",") {
		segs := strings.Split(part, ";")
		target := strings.TrimSpace(segs[0])
		if !strings.HasPrefix(target, "<") || !strings.HasSuffix(target, ">") {
			continue
		}
		for _, param := range segs[1:] {
			k, v, ok := strings.Cut(strings.TrimSpace(param), "=")
			if !ok || strings.TrimSpace(k) != "rel" {
				continue
			}
			for _, rel := range strings.Fields(strings.Trim(strings.TrimSpace(v), `"`)) {
				if rel == "next" {
					return target[1 : len(target)-1]
				}
			}
		}
	}
	return ""
}

// CheckSameOrigin refuses a pagination link whose scheme or host
// differs from the request that produced it: following it would send
// the connection's credential to a host the operator never configured.
func CheckSameOrigin(current, next string) error {
	cu, err := url.Parse(current)
	if err != nil {
		return fmt.Errorf("parse current page URL: %w", err)
	}
	nu, err := url.Parse(next)
	if err != nil {
		return fmt.Errorf("parse next page URL: %w", err)
	}
	if !strings.EqualFold(cu.Scheme, nu.Scheme) || !strings.EqualFold(cu.Host, nu.Host) {
		return fmt.Errorf("%w (%s://%s, expected %s://%s)", ErrCrossOriginNextLink, nu.Scheme, nu.Host, cu.Scheme, cu.Host)
	}
	return nil
}
