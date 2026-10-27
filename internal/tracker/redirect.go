package tracker

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ErrCrossOriginRedirect is returned when a provider client is asked to
// follow a redirect to a different scheme or host. Following it could send
// the connection credential to an endpoint the operator did not configure.
var ErrCrossOriginRedirect = errors.New("refusing to follow HTTP redirect to a different origin")

// WithSameOriginRedirects returns a shallow copy of client whose redirects
// are restricted to the original scheme and host. The caller's client is not
// mutated; its transport, timeout, cookie jar, and existing same-origin
// redirect policy are preserved.
func WithSameOriginRedirects(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{}
	}
	clone := *client
	previous := clone.CheckRedirect
	clone.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		var current *url.URL
		if len(via) > 0 {
			if via[len(via)-1].URL == nil {
				return checkSameOriginRedirect(nil, req.URL)
			}
			origin := *via[len(via)-1].URL
			current = &origin
			if err := checkSameOriginRedirect(current, req.URL); err != nil {
				return err
			}
		}
		if previous != nil {
			if err := previous(req, via); err != nil {
				return err
			}
			if current != nil {
				return checkSameOriginRedirect(current, req.URL)
			}
			return nil
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	return &clone
}

func checkSameOriginRedirect(current, next *url.URL) error {
	if current == nil || next == nil {
		return fmt.Errorf("%w: redirect URL is missing", ErrCrossOriginRedirect)
	}
	if !strings.EqualFold(current.Scheme, next.Scheme) || !strings.EqualFold(current.Host, next.Host) {
		return fmt.Errorf("%w (%s://%s, expected %s://%s)", ErrCrossOriginRedirect, next.Scheme, next.Host, current.Scheme, current.Host)
	}
	return nil
}
