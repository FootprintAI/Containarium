package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/anonbox"
)

func TestAnonReminderWebhook_Send(t *testing.T) {
	var got anonReminderPayload
	var ct string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	exp := time.Date(2026, 10, 2, 16, 0, 0, 0, time.UTC)
	err := newAnonReminderWebhook(srv.URL).Send(context.Background(), anonbox.Reminder{
		Email: "alice@example.com", BoxName: "anon-1a2b3c4d-container", ClaimURL: "https://cloud.example.test/claim?token=v1.x", ExpiresAt: exp,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ct != "application/json" || got.Email != "alice@example.com" || got.BoxName != "anon-1a2b3c4d-container" || got.ClaimURL != "https://cloud.example.test/claim?token=v1.x" || got.ExpiresAt != "2026-10-02T16:00:00Z" {
		t.Errorf("payload = %+v (content-type %q)", got, ct)
	}
}

func TestAnonReminderWebhook_NonSuccessIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer srv.Close()
	if err := newAnonReminderWebhook(srv.URL).Send(context.Background(), anonbox.Reminder{Email: "a@b.c"}); err == nil {
		t.Error("503 must be an error")
	}
	if err := newAnonReminderWebhook("http://127.0.0.1:1").Send(context.Background(), anonbox.Reminder{Email: "a@b.c"}); err == nil {
		t.Error("unreachable must be an error")
	}
}
