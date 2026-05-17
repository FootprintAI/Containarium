package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// primaryRegisterTTL must align with sentinel.PrimaryTTL. Hardcoded here to
// avoid importing internal/sentinel from internal/server (the sentinel package
// imports from server in tests, so a back-edge would create a cycle).
const primaryRegisterTTL = 90 * time.Second

// primaryHeartbeatInterval is one third of TTL — gives two missed beats before
// eviction.
const primaryHeartbeatInterval = primaryRegisterTTL / 3

// PrimaryRegisterConfig describes the inputs needed to advertise a primary
// daemon to the sentinel registry.
type PrimaryRegisterConfig struct {
	SentinelURL      string   // e.g. http://10.128.0.5:8888
	Pool             string   // pool name (must match peers' --pool)
	PublicHostname   string   // primary's own subdomain (e.g. containarium-prod.kafeido.app)
	PublicAliases    []string // additional hostnames the primary's Caddy serves (e.g. api.kafeido.app, voice.kafeido.app)
	PublicBaseDomain string   // suffix-match anchor: <anything>.<PublicBaseDomain> routes here (e.g. "containarium.dev")
	Port             int      // public HTTPS port (typically 443 or 8443)
	BackendID        string   // optional; for ops visibility in /sentinel/primaries
}

// runPrimaryRegistration registers with the sentinel, sends periodic
// heartbeats, and unregisters on context cancellation. It returns immediately
// if any required field is missing — primary registration is opt-in.
//
// The registration request is best-effort: sentinel reachability is not
// required for the daemon to start. Failures are logged and retried on the
// next heartbeat tick.
func runPrimaryRegistration(ctx context.Context, cfg PrimaryRegisterConfig) {
	if cfg.SentinelURL == "" || cfg.Pool == "" || cfg.PublicHostname == "" || cfg.Port == 0 {
		// Opt-in: silently skip if the operator hasn't configured all fields.
		return
	}

	base := strings.TrimRight(cfg.SentinelURL, "/")
	registerURL := base + "/sentinel/primaries"
	heartbeatURL := base + "/sentinel/primaries/" + cfg.Pool

	body := map[string]any{
		"pool":        cfg.Pool,
		"hostname":    cfg.PublicHostname,
		"aliases":     cfg.PublicAliases,
		"base_domain": cfg.PublicBaseDomain,
		"port":        cfg.Port,
		"backend_id":  cfg.BackendID,
		// IP intentionally omitted — sentinel infers from RemoteAddr.
	}

	client := &http.Client{Timeout: 5 * time.Second}

	// Initial registration. Failures are non-fatal: heartbeat ticker will retry.
	if err := postJSON(ctx, client, registerURL, body); err != nil {
		log.Printf("[primary-register] initial registration failed: %v (will retry)", err)
	} else {
		log.Printf("[primary-register] registered: pool=%q hostname=%q aliases=%v base_domain=%q port=%d", cfg.Pool, cfg.PublicHostname, cfg.PublicAliases, cfg.PublicBaseDomain, cfg.Port)
	}

	go func() {
		ticker := time.NewTicker(primaryHeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				// Best-effort deregister with a fresh short-lived context.
				deregCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				if err := deleteRequest(deregCtx, client, heartbeatURL); err != nil {
					log.Printf("[primary-register] deregister failed: %v", err)
				} else {
					log.Printf("[primary-register] deregistered: pool=%q", cfg.Pool)
				}
				cancel()
				return
			case <-ticker.C:
				if err := putRequest(ctx, client, heartbeatURL, nil); err != nil {
					// 404 means the sentinel doesn't know us — re-register.
					var notFound bool
					if hErr, ok := err.(*httpStatusError); ok && hErr.code == http.StatusNotFound {
						notFound = true
					}
					if notFound {
						if err2 := postJSON(ctx, client, registerURL, body); err2 != nil {
							log.Printf("[primary-register] re-registration failed: %v", err2)
						} else {
							log.Printf("[primary-register] re-registered after sentinel restart: pool=%q", cfg.Pool)
						}
					} else {
						log.Printf("[primary-register] heartbeat failed: %v", err)
					}
				}
			}
		}
	}()
}

type httpStatusError struct {
	code int
	body string
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("status=%d body=%q", e.code, e.body)
}

func postJSON(ctx context.Context, client *http.Client, url string, body any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return &httpStatusError{code: resp.StatusCode, body: string(bodyBytes)}
	}
	return nil
}

func putRequest(ctx context.Context, client *http.Client, url string, body any) error {
	var reader *bytes.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(buf)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, reader)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return &httpStatusError{code: resp.StatusCode, body: string(bodyBytes)}
	}
	return nil
}

func deleteRequest(ctx context.Context, client *http.Client, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotFound {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return &httpStatusError{code: resp.StatusCode, body: string(bodyBytes)}
	}
	return nil
}
