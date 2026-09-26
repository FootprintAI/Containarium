package tracker

import (
	"fmt"
	"net/url"
	"strings"
)

// MaxListPages bounds how many pages a provider's list call follows
// (#2040). At 100 items per page that is 5,000 issues — far past any
// label-filtered dispatch query, while still guaranteeing a misbehaving
// upstream that always answers with a next link cannot loop forever.
// An adapter that hits the bound returns what it collected and logs
// that the result was truncated.
const MaxListPages = 50

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
		return fmt.Errorf("refusing to follow pagination link to a different host (%s://%s, expected %s://%s)", nu.Scheme, nu.Host, cu.Scheme, cu.Host)
	}
	return nil
}
