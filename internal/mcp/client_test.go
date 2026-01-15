package mcp

import (
	"encoding/json"
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
				IncusVersion:      "0.6.0",
				OS:                "Ubuntu 24.04",
				ContainersRunning: 5,
				ContainersTotal:   10,
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
