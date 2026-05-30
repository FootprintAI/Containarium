package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewClient tests client creation
func TestNewClient(t *testing.T) {
	client := NewClient("http://localhost:8080", "test-token")

	assert.NotNil(t, client)
	assert.Equal(t, "http://localhost:8080", client.baseURL)
	assert.Equal(t, "test-token", client.jwtToken)
	assert.NotNil(t, client.httpClient)
}

// TestClientDoRequest tests HTTP request handling
func TestClientDoRequest(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse string
		serverStatus   int
		expectError    bool
	}{
		{
			name:           "successful request",
			serverResponse: `{"success": true}`,
			serverStatus:   http.StatusOK,
			expectError:    false,
		},
		{
			name:           "server error",
			serverResponse: `{"error": "something went wrong"}`,
			serverStatus:   http.StatusInternalServerError,
			expectError:    true,
		},
		{
			name:           "unauthorized",
			serverResponse: `{"error": "unauthorized"}`,
			serverStatus:   http.StatusUnauthorized,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify auth header
				auth := r.Header.Get("Authorization")
				assert.Equal(t, "Bearer test-token", auth)

				// Verify content type
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

				w.WriteHeader(tt.serverStatus)
				w.Write([]byte(tt.serverResponse))
			}))
			defer server.Close()

			// Create client
			client := NewClient(server.URL, "test-token")

			// Make request
			resp, err := client.doRequest("GET", "/test", nil)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, resp)
			}
		})
	}
}

// TestClientListContainers tests list containers API call
func TestClientListContainers(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/v1/containers", r.URL.Path)

		resp := ListContainersResponse{
			Containers: []Container{
				{
					Name:     "alice-container",
					Username: "alice",
					State:    "Running",
				},
			},
			TotalCount: 1,
		}

		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Create client and call
	client := NewClient(server.URL, "test-token")
	resp, err := client.ListContainers()

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, 1, resp.TotalCount)
	assert.Len(t, resp.Containers, 1)
	assert.Equal(t, "alice-container", resp.Containers[0].Name)
}

// TestClientListRoutes verifies the new list_routes tool's wire path:
// correct method + path, query-string filter encoding, and that the
// daemon's proto-shaped response parses into ProxyRoute.
func TestClientListRoutes(t *testing.T) {
	t.Run("no filters: bare GET /v1/network/routes", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			assert.Equal(t, "/v1/network/routes", r.URL.Path)
			assert.Empty(t, r.URL.RawQuery, "no filters → no query string")
			_ = json.NewEncoder(w).Encode(ListRoutesResponse{
				Routes: []ProxyRoute{
					{
						Subdomain:   "alice-web",
						FullDomain:  "alice-web.example.com",
						ContainerIP: "10.0.3.42",
						Port:        80,
						Active:      true,
						AppName:     "alice-container",
					},
				},
				TotalCount: 1,
			})
		}))
		defer srv.Close()

		c := NewClient(srv.URL, "t")
		resp, err := c.ListRoutes("", false)
		require.NoError(t, err)
		require.Len(t, resp.Routes, 1)
		assert.Equal(t, "alice-web.example.com", resp.Routes[0].FullDomain)
		assert.True(t, resp.Routes[0].Active)
	})

	t.Run("with filters: both query params encoded", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "alice", r.URL.Query().Get("username"))
			assert.Equal(t, "true", r.URL.Query().Get("activeOnly"))
			_ = json.NewEncoder(w).Encode(ListRoutesResponse{Routes: nil, TotalCount: 0})
		}))
		defer srv.Close()

		c := NewClient(srv.URL, "t")
		_, err := c.ListRoutes("alice", true)
		require.NoError(t, err)
	})
}

// TestClientGetContainer tests get container API call
func TestClientGetContainer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/v1/containers/alice", r.URL.Path)

		resp := GetContainerResponse{
			Container: Container{
				Name:     "alice-container",
				Username: "alice",
				State:    "Running",
			},
		}

		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	resp, err := client.GetContainer("alice")

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "alice-container", resp.Container.Name)
	assert.Equal(t, "alice", resp.Container.Username)
}

// TestClientCreateContainer tests create container API call
func TestClientCreateContainer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/v1/containers", r.URL.Path)

		// Decode request body
		var req CreateContainerRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)

		assert.Equal(t, "alice", req.Username)
		assert.Equal(t, "4", req.Resources.CPU)
		assert.Equal(t, "8GB", req.Resources.Memory)

		resp := CreateContainerResponse{
			Container: Container{
				Name:     "alice-container",
				Username: "alice",
				State:    "Running",
			},
			Message: "Container created",
		}

		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	req := CreateContainerRequest{
		Username: "alice",
		Resources: &ResourceLimits{
			CPU:    "4",
			Memory: "8GB",
			Disk:   "50GB",
		},
	}

	resp, err := client.CreateContainer(req)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "alice-container", resp.Container.Name)
	assert.Equal(t, "Container created", resp.Message)
}

// TestClientDeleteContainer tests delete container API call
func TestClientDeleteContainer(t *testing.T) {
	tests := []struct {
		name  string
		force bool
	}{
		{"normal delete", false},
		{"force delete", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "DELETE", r.Method)
				assert.Equal(t, "/v1/containers/alice", r.URL.Path)

				// Check force query parameter
				force := r.URL.Query().Get("force")
				if tt.force {
					assert.Equal(t, "true", force)
				} else {
					assert.Equal(t, "false", force)
				}

				resp := DeleteContainerResponse{
					Message:       "Container deleted",
					ContainerName: "alice-container",
				}

				json.NewEncoder(w).Encode(resp)
			}))
			defer server.Close()

			client := NewClient(server.URL, "test-token")
			resp, err := client.DeleteContainer("alice", tt.force)

			require.NoError(t, err)
			assert.NotNil(t, resp)
			assert.Equal(t, "Container deleted", resp.Message)
		})
	}
}

// TestClientGetMetrics tests get metrics API call
func TestClientGetMetrics(t *testing.T) {
	tests := []struct {
		name     string
		username string
		path     string
	}{
		{"all containers", "", "/v1/metrics"},
		{"specific container", "alice", "/v1/metrics/alice"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)
				assert.Equal(t, tt.path, r.URL.Path)

				resp := GetMetricsResponse{
					Metrics: []ContainerMetrics{
						{
							Name:             "alice-container",
							CPUUsageSeconds:  100,
							MemoryUsageBytes: 1024 * 1024 * 100,
						},
					},
				}

				json.NewEncoder(w).Encode(resp)
			}))
			defer server.Close()

			client := NewClient(server.URL, "test-token")
			resp, err := client.GetMetrics(tt.username)

			require.NoError(t, err)
			assert.NotNil(t, resp)
			assert.Len(t, resp.Metrics, 1)
			assert.Equal(t, "alice-container", resp.Metrics[0].Name)
		})
	}
}

// TestClientGetSystemInfo tests get system info API call
func TestClientGetSystemInfo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/v1/system/info", r.URL.Path)

		resp := GetSystemInfoResponse{
			Info: SystemInfo{
				IncusVersion:          "0.6.0",
				OS:                    "Ubuntu 24.04",
				ContainersRunning:     5,
				ContainersTotal:       10,
				OTelCollectorEndpoint: "http://10.0.3.5:4318",
			},
		}

		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	resp, err := client.GetSystemInfo()

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "0.6.0", resp.Info.IncusVersion)
	assert.Equal(t, 5, resp.Info.ContainersRunning)
	// #370: the collector endpoint must round-trip so an agent can
	// discover where to point docker-in-LXC apps.
	assert.Equal(t, "http://10.0.3.5:4318", resp.Info.OTelCollectorEndpoint)
}

// TestClientPreMarshaledBodyNotDoubleEncoded is the regression test
// for #370: callers that pre-marshal their body to []byte (ToggleMonitoring,
// SetSecret, ResizeContainer, RefreshSecrets) must NOT get double-encoded
// by doRequest. The symptom was the daemon receiving the base64 of the
// JSON (e.g. "eyJlbmFibGVkIjp0cnVlfQ==") instead of {"enabled":true},
// and rejecting it as a proto syntax error. The handler here decodes the
// raw body as a JSON object — which fails outright if the body arrived as
// a base64 string literal.
func TestClientPreMarshaledBodyNotDoubleEncoded(t *testing.T) {
	t.Run("ToggleMonitoring", func(t *testing.T) {
		var gotBody []byte
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "/v1/containers/alice/monitoring", r.URL.Path)
			gotBody, _ = io.ReadAll(r.Body)
			json.NewEncoder(w).Encode(ToggleMonitoringResponse{Message: "ok", MonitoringEnabled: true})
		}))
		defer server.Close()

		resp, err := NewClient(server.URL, "test-token").ToggleMonitoring("alice", true)
		require.NoError(t, err)
		assert.True(t, resp.MonitoringEnabled)

		// The body must be a JSON object decodable into the typed shape —
		// a double-encoded []byte arrives as a quoted base64 string and
		// fails this decode.
		var decoded map[string]bool
		require.NoError(t, json.Unmarshal(gotBody, &decoded),
			"body must be a JSON object, got %q", string(gotBody))
		assert.True(t, decoded["enabled"])
	})

	t.Run("SetSecret", func(t *testing.T) {
		var gotBody []byte
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotBody, _ = io.ReadAll(r.Body)
			json.NewEncoder(w).Encode(SecretResponse{Message: "ok"})
		}))
		defer server.Close()

		_, err := NewClient(server.URL, "test-token").SetSecret("alice", "API_KEY", "s3cr3t")
		require.NoError(t, err)

		var decoded map[string]string
		require.NoError(t, json.Unmarshal(gotBody, &decoded),
			"body must be a JSON object, got %q", string(gotBody))
		assert.Equal(t, "API_KEY", decoded["name"])
		assert.Equal(t, "s3cr3t", decoded["value"])
	})
}

// TestClientAuthenticationHeader tests JWT token is sent correctly
func TestClientAuthenticationHeader(t *testing.T) {
	expectedToken := "test-jwt-token-123"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer "+expectedToken, auth, "Authorization header should contain Bearer token")

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"containers": [], "totalCount": 0}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, expectedToken)
	_, _ = client.ListContainers()
}

// TestClientErrorHandling tests various error conditions
func TestClientErrorHandling(t *testing.T) {
	tests := []struct {
		name         string
		serverStatus int
		serverBody   string
		expectError  bool
	}{
		{
			name:         "200 OK",
			serverStatus: http.StatusOK,
			serverBody:   `{"containers": [], "totalCount": 0}`,
			expectError:  false,
		},
		{
			name:         "400 Bad Request",
			serverStatus: http.StatusBadRequest,
			serverBody:   `{"error": "bad request"}`,
			expectError:  true,
		},
		{
			name:         "401 Unauthorized",
			serverStatus: http.StatusUnauthorized,
			serverBody:   `{"error": "unauthorized"}`,
			expectError:  true,
		},
		{
			name:         "404 Not Found",
			serverStatus: http.StatusNotFound,
			serverBody:   `{"error": "not found"}`,
			expectError:  true,
		},
		{
			name:         "500 Internal Server Error",
			serverStatus: http.StatusInternalServerError,
			serverBody:   `{"error": "internal error"}`,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.serverStatus)
				w.Write([]byte(tt.serverBody))
			}))
			defer server.Close()

			client := NewClient(server.URL, "test-token")
			_, err := client.ListContainers()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestAddRoute verifies the wire format and response handling for the
// AddRoute method. Confirms the request body shape matches what the
// grpc-gateway HTTP layer expects (camelCase fields).
func TestAddRoute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "/v1/network/routes", r.URL.Path)
		require.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var req AddRouteRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "blog.example.com", req.Domain)
		assert.Equal(t, "10.0.3.42", req.TargetIP)
		assert.Equal(t, int32(8080), req.TargetPort)
		assert.Equal(t, "alice-container", req.ContainerName)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"route": {
				"domain": "blog.example.com",
				"containerIp": "10.0.3.42",
				"port": 8080,
				"containerName": "alice-container"
			},
			"message": "route added"
		}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	resp, err := client.AddRoute(AddRouteRequest{
		Domain:        "blog.example.com",
		TargetIP:      "10.0.3.42",
		TargetPort:    8080,
		ContainerName: "alice-container",
	})
	require.NoError(t, err)
	assert.Equal(t, "blog.example.com", resp.Route.Domain)
	assert.Equal(t, "10.0.3.42", resp.Route.ContainerIP)
	assert.Equal(t, int32(8080), resp.Route.Port)
	assert.Equal(t, "route added", resp.Message)
}

func TestAddRoute_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"domain already exists"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.AddRoute(AddRouteRequest{Domain: "x", TargetIP: "y", TargetPort: 1})
	require.Error(t, err)
}

// TestToggleAutoSleep_WirePayload locks the on-wire request shape
// (POST, path, JSON field names) and verifies the response decoded
// from the daemon's gateway flows back through the typed struct.
func TestToggleAutoSleep_WirePayload(t *testing.T) {
	var captured map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/v1/containers/alice/auto-sleep", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		require.NoError(t, json.NewDecoder(r.Body).Decode(&captured))
		_, _ = w.Write([]byte(`{"message":"auto-sleep enabled at 30m","autoSleepEnabled":true,"idleThresholdMinutes":30}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok")
	resp, err := c.ToggleAutoSleep("alice", true, 30)
	require.NoError(t, err)

	// Field names must match the snake_case the grpc-gateway shim
	// accepts on input — gateway auto-converts both spellings on
	// decode, but locking snake_case here matches the literal client
	// body and guards against accidental camelCase rewrites that
	// older gateway builds reject.
	assert.Equal(t, true, captured["enabled"])
	assert.EqualValues(t, 30, captured["idle_threshold_minutes"])
	// Response decode round-trips the camelCase JSON cleanly.
	assert.True(t, resp.AutoSleepEnabled)
	assert.Equal(t, int32(30), resp.IdleThresholdMinutes)
}

// TestToggleAutoSleep_WirePayload_DisableOmitsThreshold — disable
// path still carries idle_threshold_minutes as 0 (Go zero value) over
// the wire; the daemon ignores it when enabled=false.
func TestToggleAutoSleep_WirePayload_DisableOmitsThreshold(t *testing.T) {
	var captured map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&captured))
		_, _ = w.Write([]byte(`{"message":"auto-sleep disabled","autoSleepEnabled":false,"idleThresholdMinutes":15}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok")
	_, err := c.ToggleAutoSleep("alice", false, 0)
	require.NoError(t, err)
	assert.Equal(t, false, captured["enabled"])
	assert.EqualValues(t, 0, captured["idle_threshold_minutes"])
}

// TestStartContainer_WirePayload_WaitForReady — verify the new
// waitForReady arg ships on the wire. Lock the JSON field name so a
// later refactor doesn't silently break daemons expecting the
// gateway-decoded request.
func TestStartContainer_WirePayload_WaitForReady(t *testing.T) {
	tests := []struct {
		name             string
		waitForReady     bool
		wantWaitForReady bool
	}{
		{"waitForReady=true", true, true},
		{"waitForReady=false", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var captured map[string]interface{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, "/v1/containers/alice/start", r.URL.Path)
				require.NoError(t, json.NewDecoder(r.Body).Decode(&captured))
				_, _ = w.Write([]byte(`{"message":"started","container":{"name":"alice-container","state":"Running"},"readyTimedOut":false}`))
			}))
			defer srv.Close()

			c := NewClient(srv.URL, "tok")
			resp, err := c.StartContainer("alice", tt.waitForReady)
			require.NoError(t, err)
			assert.Equal(t, tt.wantWaitForReady, captured["wait_for_ready"])
			assert.False(t, resp.ReadyTimedOut)
		})
	}
}

// TestStartContainer_DecodesReadyTimedOut — when the daemon reports
// ready_timed_out=true, the typed response struct must carry it
// through so the MCP handler can show the warning emoji.
func TestStartContainer_DecodesReadyTimedOut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"message":"timed out","container":{"name":"alice-container","state":"Running"},"readyTimedOut":true}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "tok")
	resp, err := c.StartContainer("alice", true)
	require.NoError(t, err)
	assert.True(t, resp.ReadyTimedOut)
}

// TestTriggerSecurityScan_WirePayloads locks the wire body for each
// scanner kind. All three protos now accept a container_name field,
// and the MCP always operates on one container, so all three bodies
// should carry it. The previous version of this code 400'd against
// pentest/ZAP because it sent the wrong field name; that's the
// regression this test guards.
func TestTriggerSecurityScan_WirePayloads(t *testing.T) {
	tests := []struct {
		kind         string
		path         string
		expectFields map[string]string
	}{
		{scanKindClamav, "/v1/security/clamav-scan", map[string]string{"containerName": "alice-container"}},
		{scanKindPentest, "/v1/pentest/scan", map[string]string{"containerName": "alice-container"}},
		{scanKindZap, "/v1/zap/scan", map[string]string{"containerName": "alice-container"}},
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, tt.path, r.URL.Path)
				var got map[string]string
				require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
				assert.Equal(t, tt.expectFields, got, "wire body must match proto fields exactly")
				_, _ = w.Write([]byte(`{"message":"queued","scannedCount":1}`))
			}))
			defer server.Close()

			client := NewClient(server.URL, "test-token")
			_, err := client.TriggerSecurityScan(tt.kind, "alice-container", "alice")
			require.NoError(t, err)
		})
	}
}
