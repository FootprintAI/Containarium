package server

import (
	"context"
	"fmt"
	"time"
)

// adoptIPWait bounds how long the adopting daemon waits for a just-started
// container to get its address. A container is running before its DHCP lease
// exists, so reading the address once, right after the start, fails even when
// nothing is wrong.
const adoptIPWait = 60 * time.Second

// waitForContainerIP polls get until it returns an address, the timeout
// passes, or ctx ends. An empty address means "not yet"; an error from get is
// returned at once, since waiting will not fix it.
func waitForContainerIP(ctx context.Context, get func() (string, error), timeout, interval time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for {
		ip, err := get()
		if err != nil {
			return "", err
		}
		if ip != "" {
			return ip, nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("adopted container has no IP address after %s (still initializing?)", timeout)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(interval):
		}
	}
}
