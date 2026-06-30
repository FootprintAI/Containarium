// Package config centralizes Containarium's environment-driven configuration.
//
// Containarium reads ~110 CONTAINARIUM_* environment variables. Historically
// each was read inline via os.Getenv at its point of use — frequently the same
// variable in many places — stringly-typed, with ad-hoc per-site defaults and
// no validation. That sprawl (hundreds of os.Getenv call sites) is the problem
// this package replaces, one namespace at a time, with:
//
//   - a typed struct per CONTAINARIUM_<NAMESPACE>_ prefix (the prefixes already
//     are the de-facto namespaces: SENTINEL_, K8S_, AWS_, VAULT_, …),
//   - exported Env* name constants so each variable name has a single home
//     instead of being a magic string repeated across the tree,
//   - a Load<Namespace>() that reads the environment once and applies defaults,
//   - a Validate() that fails fast at startup rather than deep inside a request.
//
// The Kubernetes backend (pkg/core/box/k8s.Config) already follows this shape;
// this package generalizes it. Migrate consumers incrementally: a half-migrated
// namespace is safe because Load reads exactly the same variables that any
// remaining inline os.Getenv calls do — values cannot diverge.
package config

import "os"

// getString returns the value of the environment variable key, or def when it
// is unset or empty. It is the building block Load<Namespace>() functions use so
// the empty-means-unset convention lives in one place.
func getString(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
