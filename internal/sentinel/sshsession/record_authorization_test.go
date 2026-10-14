package sshsession

import (
	"bytes"
	"encoding/json"
	"testing"
)

// #2519: these JSONL-only cases do not need #2516's generated enum types.
// They cover the real recorder, not a replacement implementation. Proto
// conversion and backend ingestion are deliberately separate integration work.
func TestRecord_AuthorizationIdentitySurvivesJSONL(t *testing.T) {
	for _, tc := range []struct {
		name     string
		userID   string
		enforced bool
	}{
		{"known user audit only", "user-test", false},
		{"known user enforced", "user-test", true},
		{"unknown user audit only", "", false},
		{"unknown user enforced", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Starting at JSON catches a missing field without making the
			// test fail to compile before that field has been implemented.
			input := struct {
				SessionID  string `json:"session_id"`
				Phase      string `json:"phase"`
				OccurredAt string `json:"occurred_at"`
				Login      string `json:"login"`
				UserID     string `json:"user_id"`
				Enforced   bool   `json:"enforced"`
			}{"session-test", "open", "2026-10-13T00:00:00Z", "login-test", tc.userID, tc.enforced}
			raw, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			var rec Record
			if err := json.Unmarshal(raw, &rec); err != nil {
				t.Fatal(err)
			}
			var sink bytes.Buffer
			if err := NewJSONLRecorder(&sink).Record(rec); err != nil {
				t.Fatal(err)
			}
			if bytes.Count(sink.Bytes(), []byte("\n")) != 1 {
				t.Fatal("recorder must emit exactly one JSONL line")
			}
			var got struct {
				SessionID string `json:"session_id"`
				Login     string `json:"login"`
				UserID    string `json:"user_id"`
				Enforced  bool   `json:"enforced"`
			}
			if err := json.Unmarshal(sink.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.UserID != tc.userID || got.Enforced != tc.enforced {
				t.Errorf("authorization identity lost: user_id=%q enforced=%v, want %q/%v", got.UserID, got.Enforced, tc.userID, tc.enforced)
			}
			if got.SessionID != input.SessionID || got.Login != input.Login {
				t.Errorf("existing session identity changed: %+v", got)
			}
		})
	}
}

func TestRecord_LegacyJSONLRemainsReadable(t *testing.T) {
	for _, phase := range []string{"open", "close"} {
		t.Run(phase, func(t *testing.T) {
			raw := []byte(`{"session_id":"legacy-session","phase":"` + phase + `","occurred_at":"2026-10-13T00:00:00Z","login":"legacy-login","client_ip":"192.0.2.1"}`)
			var rec Record
			if err := json.Unmarshal(raw, &rec); err != nil {
				t.Fatal(err)
			}
			var sink bytes.Buffer
			if err := NewJSONLRecorder(&sink).Record(rec); err != nil {
				t.Fatal(err)
			}
			var got struct {
				SessionID string `json:"session_id"`
				Phase     string `json:"phase"`
				UserID    string `json:"user_id"`
				Enforced  bool   `json:"enforced"`
			}
			if err := json.Unmarshal(sink.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.SessionID != "legacy-session" || got.Phase != phase || got.UserID != "" || got.Enforced {
				t.Fatalf("legacy defaults changed: %+v", got)
			}
		})
	}
}
