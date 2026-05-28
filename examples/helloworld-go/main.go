// helloworld-go: tiny HTTP server demonstrating containariumotel.
// Symmetric to examples/helloworld-python.
//
// Three things to look at:
//   - containariumotel.Init wires the MeterProvider per the LXC's env
//     (fail-open if monitoring isn't enabled).
//   - containariumotel.HTTPMiddleware wraps the mux with otelhttp
//     under the hood, so http.server metrics light up automatically.
//   - A hand-rolled helloworld.requests counter shows how to emit
//     custom OTel metrics alongside the auto-instrumentation.
package main

import (
	"context"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/footprintai/containarium/distros/go/containariumotel"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	shutdown, err := containariumotel.Init(ctx)
	if err != nil {
		log.Printf("telemetry init: %v", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdown(shutdownCtx)
	}()

	meter := otel.GetMeterProvider().Meter("helloworld")
	requestCounter, err := meter.Int64Counter(
		"helloworld.requests",
		metric.WithDescription("Total HTTP requests served"),
	)
	if err != nil {
		log.Printf("failed to create counter: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if requestCounter != nil {
			requestCounter.Add(r.Context(), 1,
				metric.WithAttributes(attribute.String("http.method", r.Method)))
		}

		forwarded := r.Header.Get("X-Forwarded-For")
		ip := r.RemoteAddr
		if forwarded != "" {
			ip = forwarded
		}
		now := time.Now().Format(time.RFC3339)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// X-Forwarded-For is attacker-controllable upstream of any
		// proxy that doesn't sanitize it; escape before interpolating
		// into the response body. `now` is RFC3339-bounded by
		// time.Format, no escape needed.
		fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Hello (Go)</title></head><body>
<h1>Hello, world (Go)</h1>
<p>Your IP: <code>%s</code></p>
<p>Server time: <code>%s</code></p>
</body></html>`, html.EscapeString(ip), now)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           containariumotel.HTTPMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("helloworld-go listening on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}
