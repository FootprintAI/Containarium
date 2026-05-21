package server

import (
	"os"
	"strings"
)

// envBool reads the named env var and returns true when
// it's set to a recognized truthy value (case-insensitive
// `1`, `true`, `yes`, `on`). Anything else — including the
// unset case, an empty string, or an unrecognized value
// like `maybe` — returns false.
//
// Fail-off semantics by design: a typo on a security-
// affecting toggle (CONTAINARIUM_REQUIRE_ENVELOPE,
// CONTAINARIUM_OTEL_REQUIRE_AUTH) shouldn't silently flip
// the daemon into a state it can't actually serve. The
// surrounding callsite is responsible for logging the
// active state at startup so operators can confirm the
// flag took effect.
func envBool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
