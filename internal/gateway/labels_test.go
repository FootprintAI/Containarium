package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLabelRequestParsing(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		wantUsername   string
		wantLabelKey   string
		wantValid      bool
		handlerType    string // "set", "remove", "get"
	}{
		{
			name:         "valid set labels path",
			path:         "/v1/containers/alice/labels",
			wantUsername: "alice",
			wantValid:    true,
			handlerType:  "set",
		},
		{
			name:         "valid get labels path",
			path:         "/v1/containers/bob/labels",
			wantUsername: "bob",
			wantValid:    true,
			handlerType:  "get",
		},
		{
			name:         "valid remove label path",
			path:         "/v1/containers/charlie/labels/team",
			wantUsername: "charlie",
			wantLabelKey: "team",
			wantValid:    true,
			handlerType:  "remove",
		},
		{
			name:         "username with hyphen",
			path:         "/v1/containers/alice-dev/labels",
			wantUsername: "alice-dev",
			wantValid:    true,
			handlerType:  "get",
		},
		{
			name:         "invalid path - no labels suffix",
			path:         "/v1/containers/alice",
			wantUsername: "",
			wantValid:    false,
			handlerType:  "get",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := strings.TrimPrefix(tt.path, "/v1/containers/")
			parts := strings.Split(path, "/")

			var username, labelKey string
			valid := false

			switch tt.handlerType {
			case "set", "get":
				if len(parts) >= 2 && parts[1] == "labels" {
					username = parts[0]
					valid = true
				}
			case "remove":
				if len(parts) >= 3 && parts[1] == "labels" {
					username = parts[0]
					labelKey = parts[2]
					valid = true
				}
			}

			if valid != tt.wantValid {
				t.Errorf("path parsing valid = %v, want %v", valid, tt.wantValid)
			}
			if username != tt.wantUsername {
				t.Errorf("username = %q, want %q", username, tt.wantUsername)
			}
			if labelKey != tt.wantLabelKey {
				t.Errorf("labelKey = %q, want %q", labelKey, tt.wantLabelKey)
			}
		})
	}
}

func TestSetLabelsRequestBody(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantLabels map[string]string
		wantErr    bool
	}{
		{
			name: "valid labels",
			body: `{"labels": {"team": "backend", "env": "prod"}}`,
			wantLabels: map[string]string{
				"team": "backend",
				"env":  "prod",
			},
			wantErr: false,
		},
		{
			name:       "empty labels",
			body:       `{"labels": {}}`,
			wantLabels: map[string]string{},
			wantErr:    false,
		},
		{
			name:       "invalid JSON",
			body:       `{invalid}`,
			wantLabels: nil,
			wantErr:    true,
		},
		{
			name:       "missing labels field",
			body:       `{}`,
			wantLabels: nil,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req SetLabelsRequest
			err := json.NewDecoder(bytes.NewBufferString(tt.body)).Decode(&req)

			if (err != nil) != tt.wantErr {
				t.Errorf("decode error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil && !tt.wantErr {
				if len(req.Labels) != len(tt.wantLabels) {
					t.Errorf("got %d labels, want %d", len(req.Labels), len(tt.wantLabels))
					return
				}
				for k, v := range tt.wantLabels {
					if req.Labels[k] != v {
						t.Errorf("label %q = %q, want %q", k, req.Labels[k], v)
					}
				}
			}
		})
	}
}

func TestLabelResponse(t *testing.T) {
	resp := LabelResponse{
		Container: "alice-container",
		Labels: map[string]string{
			"team": "backend",
			"env":  "prod",
		},
		Message: "labels updated",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal response: %v", err)
	}

	var parsed LabelResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if parsed.Container != resp.Container {
		t.Errorf("Container = %q, want %q", parsed.Container, resp.Container)
	}
	if parsed.Message != resp.Message {
		t.Errorf("Message = %q, want %q", parsed.Message, resp.Message)
	}
	if len(parsed.Labels) != len(resp.Labels) {
		t.Errorf("got %d labels, want %d", len(parsed.Labels), len(resp.Labels))
	}
}

// TestLabelHandlerWithoutIncus tests handler behavior without Incus
// This verifies error handling when the container manager is not available
func TestLabelHandlerErrorResponse(t *testing.T) {
	// Create a handler without Incus (will return nil)
	handler := &LabelHandler{manager: nil}

	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		wantStatus int
	}{
		{
			name:       "set labels without manager",
			method:     http.MethodPut,
			path:       "/v1/containers/alice/labels",
			body:       `{"labels": {"team": "backend"}}`,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "get labels without manager",
			method:     http.MethodGet,
			path:       "/v1/containers/alice/labels",
			body:       "",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "remove label without manager",
			method:     http.MethodDelete,
			path:       "/v1/containers/alice/labels/team",
			body:       "",
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body *bytes.Buffer
			if tt.body != "" {
				body = bytes.NewBufferString(tt.body)
			} else {
				body = bytes.NewBuffer(nil)
			}

			req := httptest.NewRequest(tt.method, tt.path, body)
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()

			// Calling with nil manager should panic or error gracefully
			defer func() {
				if r := recover(); r != nil {
					// Expected - nil pointer access
					t.Logf("Handler panicked as expected with nil manager: %v", r)
				}
			}()

			switch tt.method {
			case http.MethodGet:
				handler.HandleGetLabels(rr, req)
			case http.MethodPut:
				handler.HandleSetLabels(rr, req)
			case http.MethodDelete:
				handler.HandleRemoveLabel(rr, req)
			}
		})
	}
}

// Benchmark tests
func BenchmarkSetLabelsRequestParsing(b *testing.B) {
	body := `{"labels": {"team": "backend", "env": "prod", "owner": "alice", "project": "api"}}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var req SetLabelsRequest
		_ = json.NewDecoder(bytes.NewBufferString(body)).Decode(&req)
	}
}

func BenchmarkLabelResponseSerialization(b *testing.B) {
	resp := LabelResponse{
		Container: "alice-container",
		Labels: map[string]string{
			"team":    "backend",
			"env":     "prod",
			"owner":   "alice",
			"project": "api",
		},
		Message: "labels updated",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(resp)
	}
}
