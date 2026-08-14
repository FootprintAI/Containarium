package sentinel

import (
	"fmt"
	"log"
	"net/http"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Sentinel self-profiling (#1352).
//
// The sentinel had no way to produce a heap profile from a running process.
// When #1349 OOM-killed it at 565 MB RSS — after ~27 days of ~18 MB/day growth
// — the process was gone before anything could be captured, and the leak could
// not be located without building an instrumented binary and waiting weeks for
// it to reproduce in production. This endpoint is that missing diagnostic.
//
// Two deliberate choices:
//
//  1. runtime/pprof, NOT net/http/pprof. The latter's init() registers
//     /debug/pprof/* on http.DefaultServeMux merely by being imported, blank
//     or named. Nothing serves DefaultServeMux in this binary today, so the
//     exposure would be invisible — right up until someone adds an
//     http.ListenAndServe(addr, nil) for something unrelated and silently
//     publishes an unauthenticated heap dump of the daemon, the agent-box, or
//     the sentinel (all the same binary). Wiring runtime/pprof by hand costs
//     ~40 lines and has no global side effects. TestPprofNotRegisteredOnDefaultServeMux
//     fails if the import ever comes back.
//
//  2. Gated on the ADMIN secret, not the cluster-wide daemon HMAC secret. A
//     heap profile contains whatever the process is holding: tunnel-join
//     tokens, TLS private key material, in-flight request bodies. Every
//     backend daemon in the cluster holds the daemon secret for
//     keysync/certsync, so gating there would let any one of them dump the
//     sentinel's memory. This is an operator/control-plane capability, gated
//     like /sentinel/tunnel-tokens and /peer/ (#1102, #733).
//
// The path stays at the conventional /debug/pprof/ rather than under
// /sentinel/*: it is what operators and `go tool pprof` expect, and it is the
// exact path internal/pentest probes for an exposed profiler — so our own
// scanner now validates this gate instead of missing a route it doesn't know
// about.

const (
	// pprofDefaultCPUSeconds matches net/http/pprof's default.
	pprofDefaultCPUSeconds = 30

	// pprofMaxCPUSeconds bounds ?seconds= so a request cannot outlive the
	// binary server's 120s WriteTimeout (which would drop the response after
	// paying the whole profiling cost) or pin the profiler indefinitely.
	pprofMaxCPUSeconds = 60

	pprofPathPrefix = "/debug/pprof/"
)

// PprofHandler serves runtime profiles. Mount it behind the admin-secret HMAC
// middleware — it is never safe to expose unauthenticated.
//
//	GET /debug/pprof/              index of available profiles
//	GET /debug/pprof/heap          heap profile (add ?gc=1 to force GC first)
//	GET /debug/pprof/goroutine     goroutine profile (?debug=1 for text)
//	GET /debug/pprof/allocs        cumulative allocations
//	GET /debug/pprof/profile       CPU profile (?seconds=1..60, default 30)
func (m *Manager) PprofHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, pprofPathPrefix)

		// Profiles are never worth caching or sniffing.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		switch name {
		case "", "index":
			servePprofIndex(w)
		case "profile":
			servePprofCPU(w, r)
		default:
			servePprofNamed(w, r, name)
		}
	})
}

// servePprofIndex lists the profiles this runtime actually has, with their
// current object counts — enough to pick one without a second round trip.
func servePprofIndex(w http.ResponseWriter) {
	profiles := pprof.Profiles()
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Name() < profiles[j].Name() })

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "sentinel runtime profiles (%s, %d goroutines)\n\n", runtime.Version(), runtime.NumGoroutine())
	fmt.Fprintf(w, "%-16s %s\n", "PROFILE", "COUNT")
	for _, p := range profiles {
		fmt.Fprintf(w, "%-16s %d\n", p.Name(), p.Count())
	}
	fmt.Fprintf(w, "%-16s %s\n", "profile", "(CPU; ?seconds=1..60)")
	fmt.Fprint(w, "\nAdd ?debug=1 for text output, ?gc=1 to force a GC before a heap snapshot.\n")
	fmt.Fprint(w, "Fetch with: containarium sentinel pprof --url <sentinel-url> --profile heap -o heap.pb.gz\n")
}

// servePprofNamed writes one of the runtime's registered profiles.
func servePprofNamed(w http.ResponseWriter, r *http.Request, name string) {
	p := pprof.Lookup(name)
	if p == nil {
		http.Error(w, fmt.Sprintf("unknown profile %q — GET %s for the list\n", name, pprofPathPrefix), http.StatusNotFound)
		return
	}

	debug, err := pprofIntParam(r, "debug", 0)
	if err != nil || debug < 0 || debug > 2 {
		http.Error(w, "debug must be 0, 1, or 2\n", http.StatusBadRequest)
		return
	}

	// A heap profile taken without a GC counts garbage that is merely
	// unswept, which reads as a leak that isn't one. ?gc=1 forces a
	// collection first so inuse_space reflects genuinely live memory — the
	// distinction that matters when chasing #1349.
	if name == "heap" && r.FormValue("gc") == "1" {
		runtime.GC()
	}

	writePprofHeaders(w, name, debug)
	if err := p.WriteTo(w, debug); err != nil {
		// Headers are already out; the truncated body is the only signal the
		// client gets, so make sure the operator sees it host-side too.
		//
		// Log p.Name(), not the request-derived `name`: they are equal by
		// construction here (Lookup succeeded), but p.Name() comes from the
		// runtime's own profile registry rather than the URL, so no caller
		// can smuggle newlines into the journal.
		//
		// #nosec G706 -- p.Name() is a registered runtime profile name, and
		// %q quotes it besides. gosec chases the taint back through
		// pprof.Lookup to the request path and doesn't recognize either as a
		// sanitizer — same false positive already annotated in
		// binaryserver.go.
		log.Printf("[sentinel] pprof: writing %q profile failed: %v", p.Name(), err)
	}
}

// servePprofCPU runs a bounded CPU profile.
func servePprofCPU(w http.ResponseWriter, r *http.Request) {
	seconds, err := pprofIntParam(r, "seconds", pprofDefaultCPUSeconds)
	if err != nil {
		http.Error(w, "seconds must be an integer\n", http.StatusBadRequest)
		return
	}
	if seconds < 1 || seconds > pprofMaxCPUSeconds {
		http.Error(w, fmt.Sprintf("seconds must be between 1 and %d\n", pprofMaxCPUSeconds), http.StatusBadRequest)
		return
	}

	writePprofHeaders(w, "profile", 0)
	if err := pprof.StartCPUProfile(w); err != nil {
		// The runtime allows only one CPU profile at a time process-wide.
		// 409 rather than 500: the caller's request is fine, the resource is
		// busy, and retrying later is the correct response.
		http.Error(w, fmt.Sprintf("CPU profile already in progress: %v\n", err), http.StatusConflict)
		return
	}
	defer pprof.StopCPUProfile()

	select {
	case <-time.After(time.Duration(seconds) * time.Second):
	case <-r.Context().Done():
		// Client hung up — stop early via the deferred StopCPUProfile rather
		// than holding the profiler for the full window.
	}
}

// writePprofHeaders sets the content type and, for binary profiles, a filename
// so a plain `curl -O` lands something go tool pprof can open by name.
func writePprofHeaders(w http.ResponseWriter, name string, debug int) {
	if debug > 0 {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.pb.gz"`, name))
}

// pprofIntParam reads an integer query parameter, returning def when absent.
func pprofIntParam(r *http.Request, key string, def int) (int, error) {
	raw := r.FormValue(key)
	if raw == "" {
		return def, nil
	}
	return strconv.Atoi(raw)
}
