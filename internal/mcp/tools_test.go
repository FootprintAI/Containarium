package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetStringArg tests the getStringArg helper
func TestGetStringArg(t *testing.T) {
	tests := []struct {
		name         string
		args         map[string]interface{}
		key          string
		defaultValue string
		expected     string
	}{
		{
			name:         "key exists with string value",
			args:         map[string]interface{}{"cpu": "4"},
			key:          "cpu",
			defaultValue: "2",
			expected:     "4",
		},
		{
			name:         "key missing returns default",
			args:         map[string]interface{}{},
			key:          "cpu",
			defaultValue: "2",
			expected:     "2",
		},
		{
			name:         "key exists with empty string returns default",
			args:         map[string]interface{}{"cpu": ""},
			key:          "cpu",
			defaultValue: "2",
			expected:     "2",
		},
		{
			name:         "key exists with wrong type returns default",
			args:         map[string]interface{}{"cpu": 123},
			key:          "cpu",
			defaultValue: "2",
			expected:     "2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getStringArg(tt.args, tt.key, tt.defaultValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestGetBoolArg tests the getBoolArg helper
func TestGetBoolArg(t *testing.T) {
	tests := []struct {
		name         string
		args         map[string]interface{}
		key          string
		defaultValue bool
		expected     bool
	}{
		{
			name:         "key exists with true",
			args:         map[string]interface{}{"force": true},
			key:          "force",
			defaultValue: false,
			expected:     true,
		},
		{
			name:         "key exists with false",
			args:         map[string]interface{}{"force": false},
			key:          "force",
			defaultValue: true,
			expected:     false,
		},
		{
			name:         "key missing returns default",
			args:         map[string]interface{}{},
			key:          "force",
			defaultValue: true,
			expected:     true,
		},
		{
			name:         "key exists with wrong type returns default",
			args:         map[string]interface{}{"force": "yes"},
			key:          "force",
			defaultValue: false,
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getBoolArg(tt.args, tt.key, tt.defaultValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestToolInputSchemaStructure tests that all tool schemas are well-formed
func TestToolInputSchemaStructure(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost:8080",
		JWTToken:  "test-token",
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	for _, tool := range server.tools {
		t.Run(tool.Name, func(t *testing.T) {
			schema := tool.InputSchema

			// Check required fields
			assert.Equal(t, "object", schema["type"])
			assert.NotNil(t, schema["properties"])

			// Validate properties structure
			properties, ok := schema["properties"].(map[string]interface{})
			require.True(t, ok, "properties should be a map")

			// Each property should have type and description
			for propName, propValue := range properties {
				prop, ok := propValue.(map[string]interface{})
				require.True(t, ok, "property %s should be a map", propName)

				assert.NotEmpty(t, prop["type"], "property %s should have type", propName)
				assert.NotEmpty(t, prop["description"], "property %s should have description", propName)
			}

			// Check required array if present
			if required, ok := schema["required"].([]string); ok {
				// All required fields should exist in properties
				for _, req := range required {
					assert.Contains(t, properties, req, "required field %s should exist in properties", req)
				}
			}
		})
	}
}

// TestCreateContainerToolSchema tests create_container tool schema
func TestCreateContainerToolSchema(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost:8080",
		JWTToken:  "test-token",
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	var createTool *Tool
	for i := range server.tools {
		if server.tools[i].Name == "create_container" {
			createTool = &server.tools[i]
			break
		}
	}

	require.NotNil(t, createTool, "create_container tool should exist")

	schema := createTool.InputSchema
	properties := schema["properties"].(map[string]interface{})

	// Check required parameters
	assert.Contains(t, properties, "username")
	assert.Contains(t, properties, "cpu")
	assert.Contains(t, properties, "memory")
	assert.Contains(t, properties, "disk")

	// Check username is required
	required, ok := schema["required"].([]string)
	require.True(t, ok)
	assert.Contains(t, required, "username")

	// Validate username property
	username := properties["username"].(map[string]interface{})
	assert.Equal(t, "string", username["type"])
	assert.NotEmpty(t, username["description"])
}

// TestGetContainerToolSchema tests get_container tool schema
func TestGetContainerToolSchema(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost:8080",
		JWTToken:  "test-token",
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	var getTool *Tool
	for i := range server.tools {
		if server.tools[i].Name == "get_container" {
			getTool = &server.tools[i]
			break
		}
	}

	require.NotNil(t, getTool, "get_container tool should exist")

	schema := getTool.InputSchema
	properties := schema["properties"].(map[string]interface{})

	// Check required username parameter
	assert.Contains(t, properties, "username")

	// Username should be required
	required, ok := schema["required"].([]string)
	require.True(t, ok)
	assert.Contains(t, required, "username")
}

// TestToolHandlerSignatures tests that all tools have valid handler signatures
func TestToolHandlerSignatures(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost:8080",
		JWTToken:  "test-token",
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	// Mock client for testing
	mockClient := NewClient("http://localhost:8080", "test-token")

	for _, tool := range server.tools {
		t.Run(tool.Name, func(t *testing.T) {
			// Handler should not be nil
			assert.NotNil(t, tool.Handler)

			// Handler should accept empty args without panicking
			// (will fail with API error, but should not panic)
			assert.NotPanics(t, func() {
				_, _ = tool.Handler(mockClient, map[string]interface{}{})
			})
		})
	}
}

// TestToolNameUniqueness tests that all tool names are unique
func TestToolNameUniqueness(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost:8080",
		JWTToken:  "test-token",
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	names := make(map[string]bool)
	for _, tool := range server.tools {
		assert.False(t, names[tool.Name], "Tool name '%s' should be unique", tool.Name)
		names[tool.Name] = true
	}
}

// TestToolSchemaJSONMarshaling tests that all schemas can be marshaled to JSON
func TestToolSchemaJSONMarshaling(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost:8080",
		JWTToken:  "test-token",
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	for _, tool := range server.tools {
		t.Run(tool.Name, func(t *testing.T) {
			// Marshal schema to JSON
			schemaJSON, err := json.Marshal(tool.InputSchema)
			require.NoError(t, err)
			assert.NotEmpty(t, schemaJSON)

			// Unmarshal back
			var schema map[string]interface{}
			err = json.Unmarshal(schemaJSON, &schema)
			require.NoError(t, err)

			// Verify structure preserved
			assert.Equal(t, tool.InputSchema["type"], schema["type"])
			assert.NotNil(t, schema["properties"])
		})
	}
}

// TestRequiredFieldValidation tests required field validation
func TestRequiredFieldValidation(t *testing.T) {
	tests := []struct {
		name     string
		toolName string
		args     map[string]interface{}
		hasError bool
	}{
		{
			name:     "create_container with username",
			toolName: "create_container",
			args:     map[string]interface{}{"username": "alice"},
			hasError: false, // Will fail at API level, but args are valid
		},
		{
			name:     "get_container with username",
			toolName: "get_container",
			args:     map[string]interface{}{"username": "alice"},
			hasError: false,
		},
		{
			name:     "delete_container with username",
			toolName: "delete_container",
			args:     map[string]interface{}{"username": "alice"},
			hasError: false,
		},
	}

	config := &Config{
		ServerURL: "http://localhost:8080",
		JWTToken:  "test-token",
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Find tool
			var tool *Tool
			for i := range server.tools {
				if server.tools[i].Name == tt.toolName {
					tool = &server.tools[i]
					break
				}
			}
			require.NotNil(t, tool)

			// Check if required fields are present
			if required, ok := tool.InputSchema["required"].([]string); ok {
				for _, req := range required {
					if tt.hasError {
						assert.NotContains(t, tt.args, req)
					} else {
						assert.Contains(t, tt.args, req, "Required field %s should be present", req)
					}
				}
			}
		})
	}
}

// TestToolDescriptionQuality tests that tool descriptions are informative
func TestToolDescriptionQuality(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost:8080",
		JWTToken:  "test-token",
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	for _, tool := range server.tools {
		t.Run(tool.Name, func(t *testing.T) {
			desc := tool.Description

			// Description should be non-empty
			assert.NotEmpty(t, desc)

			// Lower bound catches "TODO"-style placeholders; upper bound
			// catches runaway formatting. Rich descriptions with multi-step
			// workflows (see create_container, expose_port) are valuable
			// for agents to learn affordances from the tool list itself —
			// so the upper bound is generous.
			assert.GreaterOrEqual(t, len(desc), 20, "Description too short")
			assert.LessOrEqual(t, len(desc), 2000, "Description too long")

			// Description should not contain TODO or placeholders
			assert.NotContains(t, desc, "TODO")
			assert.NotContains(t, desc, "XXX")
			assert.NotContains(t, desc, "FIXME")
			assert.NotContains(t, desc, "placeholder")
		})
	}
}

// TestToolParameterDescriptions tests that all parameters have descriptions
func TestToolParameterDescriptions(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost:8080",
		JWTToken:  "test-token",
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	for _, tool := range server.tools {
		t.Run(tool.Name, func(t *testing.T) {
			properties, ok := tool.InputSchema["properties"].(map[string]interface{})
			if !ok {
				return // No properties to check
			}

			for paramName, paramValue := range properties {
				param := paramValue.(map[string]interface{})
				desc, hasDesc := param["description"]

				// All parameters should have descriptions
				assert.True(t, hasDesc, "Parameter %s should have description", paramName)
				if hasDesc {
					descStr := desc.(string)
					assert.NotEmpty(t, descStr, "Parameter %s description should not be empty", paramName)
					assert.GreaterOrEqual(t, len(descStr), 10, "Parameter %s description too short", paramName)
				}
			}
		})
	}
}

// ----- get_backend ----------------------------------------------------

func TestGetBackend_Found(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/backends", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"backends": [
				{"id": "local-host", "type": "local", "healthy": true, "containerCount": 5},
				{"id": "tunnel-gpu", "type": "tunnel", "healthy": true, "containerCount": 3,
				 "gpus": [{"vendor": "NVIDIA", "modelName": "GeForce RTX 4090", "vramBytes": 25769803776}]}
			]
		}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	out, err := handleGetBackend(client, map[string]interface{}{"id": "tunnel-gpu"})
	require.NoError(t, err)
	assert.Contains(t, out, "tunnel-gpu")
	assert.Contains(t, out, "GeForce RTX 4090")
	assert.NotContains(t, out, "local-host", "should only print the requested backend")
}

func TestGetBackend_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"backends":[{"id":"alpha","type":"local","healthy":true,"containerCount":0}]}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := handleGetBackend(client, map[string]interface{}{"id": "nope"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestGetBackend_RejectsMissingID(t *testing.T) {
	client := NewClient("http://unused", "token")
	_, err := handleGetBackend(client, map[string]interface{}{})
	require.Error(t, err)
}

// ----- expose_port -----------------------------------------------------

// TestGetIntArg tests the getIntArg helper across the JSON-decoded shapes
// agents tend to produce (float64 from encoding/json) plus native ints.
func TestGetIntArg(t *testing.T) {
	cases := []struct {
		name    string
		args    map[string]interface{}
		key     string
		want    int
		wantOK  bool
	}{
		{"float64 from JSON", map[string]interface{}{"p": float64(8080)}, "p", 8080, true},
		{"native int", map[string]interface{}{"p": 8080}, "p", 8080, true},
		{"missing", map[string]interface{}{}, "p", 0, false},
		{"wrong type", map[string]interface{}{"p": "8080"}, "p", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := getIntArg(tc.args, tc.key)
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestExposePort_HappyPath drives the full handler against an httptest
// server that mocks both the GetContainer lookup and the AddRoute POST.
// This catches wiring bugs (wrong path, wrong field name) the unit-only
// tests for getIntArg can't.
func TestExposePort_HappyPath(t *testing.T) {
	addRouteCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/containers/alice":
			_, _ = w.Write([]byte(`{
				"container": {
					"name": "alice-container",
					"username": "alice",
					"state": "Running",
					"network": {"ipAddress": "10.0.3.42"}
				}
			}`))
		case r.Method == "POST" && r.URL.Path == "/v1/network/routes":
			addRouteCalls++
			var req AddRouteRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
			// The handler must resolve the IP itself, not trust caller-supplied state.
			assert.Equal(t, "10.0.3.42", req.TargetIP)
			assert.Equal(t, int32(8080), req.TargetPort)
			assert.Equal(t, "blog.example.com", req.Domain)
			assert.Equal(t, "alice-container", req.ContainerName)
			_, _ = w.Write([]byte(`{
				"route": {
					"domain": "blog.example.com",
					"containerIp": "10.0.3.42",
					"port": 8080,
					"containerName": "alice-container"
				},
				"message": "route added"
			}`))
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	out, err := handleExposePort(client, map[string]interface{}{
		"username":       "alice",
		"container_port": float64(8080),
		"domain":         "blog.example.com",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, addRouteCalls)
	assert.Contains(t, out, "blog.example.com")
	assert.Contains(t, out, "10.0.3.42:8080")
}

func TestExposePort_RejectsMissingArgs(t *testing.T) {
	client := NewClient("http://unused", "token")
	cases := []struct {
		name string
		args map[string]interface{}
	}{
		{"no username", map[string]interface{}{"container_port": float64(80), "domain": "x.example"}},
		{"no port", map[string]interface{}{"username": "alice", "domain": "x.example"}},
		{"no domain", map[string]interface{}{"username": "alice", "container_port": float64(80)}},
		{"port out of range", map[string]interface{}{"username": "a", "container_port": float64(99999), "domain": "x.example"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := handleExposePort(client, tc.args)
			require.Error(t, err)
		})
	}
}

func TestExposePort_RejectsContainerWithoutIP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Container exists but has no IP yet (e.g. still starting).
		_, _ = w.Write([]byte(`{
			"container": {
				"name": "alice-container",
				"username": "alice",
				"state": "Stopped",
				"network": {"ipAddress": ""}
			}
		}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := handleExposePort(client, map[string]interface{}{
		"username":       "alice",
		"container_port": float64(8080),
		"domain":         "blog.example.com",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no IP address")
}
