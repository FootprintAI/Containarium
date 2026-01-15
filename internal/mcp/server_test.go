package mcp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestServerCreation tests MCP server creation
func TestServerCreation(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost:8080",
		JWTToken:  "test-token",
		Debug:     false,
	}

	server, err := NewServer(config)
	require.NoError(t, err)
	assert.NotNil(t, server)
	assert.Equal(t, config, server.config)
	assert.NotNil(t, server.client)
	assert.Len(t, server.tools, 8, "Should have 8 tools registered")
}

// TestServerTools tests tool registration
func TestServerTools(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost:8080",
		JWTToken:  "test-token",
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	expectedTools := []string{
		"create_container",
		"list_containers",
		"get_container",
		"delete_container",
		"start_container",
		"stop_container",
		"get_metrics",
		"get_system_info",
	}

	// Check all expected tools are registered
	toolNames := make(map[string]bool)
	for _, tool := range server.tools {
		toolNames[tool.Name] = true
	}

	for _, expected := range expectedTools {
		assert.True(t, toolNames[expected], "Tool '%s' should be registered", expected)
	}
}

// TestHandleInitialize tests the initialize method
func TestHandleInitialize(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost:8080",
		JWTToken:  "test-token",
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	req := &MCPRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params:  map[string]interface{}{},
	}

	resp := server.handleRequest(req)

	assert.Equal(t, "2.0", resp.JSONRPC)
	assert.Equal(t, 1, resp.ID)
	assert.Nil(t, resp.Error)
	assert.NotNil(t, resp.Result)

	// Check result structure
	result, ok := resp.Result.(map[string]interface{})
	require.True(t, ok)

	assert.Equal(t, "2024-11-05", result["protocolVersion"])
	assert.NotNil(t, result["serverInfo"])
	assert.NotNil(t, result["capabilities"])

	// Check server info
	serverInfo := result["serverInfo"].(map[string]interface{})
	assert.Equal(t, "containarium-mcp-server", serverInfo["name"])
	assert.Equal(t, "0.1.0", serverInfo["version"])
}

// TestHandleToolsList tests the tools/list method
func TestHandleToolsList(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost:8080",
		JWTToken:  "test-token",
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	req := &MCPRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}

	resp := server.handleRequest(req)

	assert.Equal(t, "2.0", resp.JSONRPC)
	assert.Equal(t, 2, resp.ID)
	assert.Nil(t, resp.Error)

	// Check tools list
	result, ok := resp.Result.(map[string]interface{})
	require.True(t, ok)

	tools, ok := result["tools"].([]map[string]interface{})
	require.True(t, ok)
	assert.Len(t, tools, 8)

	// Check first tool structure
	firstTool := tools[0]
	assert.NotEmpty(t, firstTool["name"])
	assert.NotEmpty(t, firstTool["description"])
	assert.NotNil(t, firstTool["inputSchema"])

	// Verify input schema is valid
	schema := firstTool["inputSchema"].(map[string]interface{})
	assert.Equal(t, "object", schema["type"])
	assert.NotNil(t, schema["properties"])
}

// TestHandleMethodNotFound tests unknown method handling
func TestHandleMethodNotFound(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost:8080",
		JWTToken:  "test-token",
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	req := &MCPRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "unknown/method",
	}

	resp := server.handleRequest(req)

	assert.Equal(t, "2.0", resp.JSONRPC)
	assert.Equal(t, 3, resp.ID)
	assert.NotNil(t, resp.Error)
	assert.Nil(t, resp.Result)

	// Check error
	assert.Equal(t, -32601, resp.Error.Code)
	assert.Contains(t, resp.Error.Message, "Method not found")
}

// TestHandleToolsCallInvalidParams tests invalid parameters
func TestHandleToolsCallInvalidParams(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost:8080",
		JWTToken:  "test-token",
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	tests := []struct {
		name   string
		params interface{}
	}{
		{
			name:   "missing name",
			params: map[string]interface{}{"arguments": map[string]interface{}{}},
		},
		{
			name:   "invalid name type",
			params: map[string]interface{}{"name": 123, "arguments": map[string]interface{}{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &MCPRequest{
				JSONRPC: "2.0",
				ID:      4,
				Method:  "tools/call",
				Params:  tt.params,
			}

			resp := server.handleRequest(req)

			assert.NotNil(t, resp.Error)
			assert.Equal(t, -32602, resp.Error.Code)
		})
	}
}

// TestHandleToolsCallToolNotFound tests tool not found error
func TestHandleToolsCallToolNotFound(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost:8080",
		JWTToken:  "test-token",
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	req := &MCPRequest{
		JSONRPC: "2.0",
		ID:      5,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      "nonexistent_tool",
			"arguments": map[string]interface{}{},
		},
	}

	resp := server.handleRequest(req)

	assert.NotNil(t, resp.Error)
	assert.Equal(t, -32602, resp.Error.Code)
	assert.Contains(t, resp.Error.Data, "not found")
}

// TestErrorResponse tests error response creation
func TestErrorResponse(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost:8080",
		JWTToken:  "test-token",
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	req := &MCPRequest{
		JSONRPC: "2.0",
		ID:      6,
		Method:  "test",
	}

	resp := server.createErrorResponse(req.ID, -32603, "Test error", "Test data")

	assert.Equal(t, "2.0", resp.JSONRPC)
	assert.Equal(t, 6, resp.ID)
	assert.NotNil(t, resp.Error)
	assert.Equal(t, -32603, resp.Error.Code)
	assert.Equal(t, "Test error", resp.Error.Message)
	assert.Equal(t, "Test data", resp.Error.Data)
}

// TestToolInputSchemas tests that all tools have valid input schemas
func TestToolInputSchemas(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost:8080",
		JWTToken:  "test-token",
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	for _, tool := range server.tools {
		t.Run(tool.Name, func(t *testing.T) {
			// Check schema exists
			assert.NotNil(t, tool.InputSchema)

			// Check schema is valid JSON Schema
			schema := tool.InputSchema
			assert.Equal(t, "object", schema["type"])
			assert.NotNil(t, schema["properties"])

			// Marshal to JSON to verify it's valid
			schemaJSON, err := json.Marshal(schema)
			require.NoError(t, err)
			assert.NotEmpty(t, schemaJSON)

			// Unmarshal back to verify structure
			var schemaCheck map[string]interface{}
			err = json.Unmarshal(schemaJSON, &schemaCheck)
			require.NoError(t, err)
		})
	}
}

// TestToolDescriptions tests that all tools have descriptions
func TestToolDescriptions(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost:8080",
		JWTToken:  "test-token",
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	for _, tool := range server.tools {
		t.Run(tool.Name, func(t *testing.T) {
			assert.NotEmpty(t, tool.Name, "Tool name should not be empty")
			assert.NotEmpty(t, tool.Description, "Tool description should not be empty")
			assert.NotNil(t, tool.Handler, "Tool handler should not be nil")

			// Description should be reasonable length
			assert.Greater(t, len(tool.Description), 10, "Description should be descriptive")
			assert.Less(t, len(tool.Description), 500, "Description should be concise")
		})
	}
}

// TestJSONRPCCompliance tests JSON-RPC 2.0 compliance
func TestJSONRPCCompliance(t *testing.T) {
	config := &Config{
		ServerURL: "http://localhost:8080",
		JWTToken:  "test-token",
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	tests := []struct {
		name     string
		request  *MCPRequest
		checkFn  func(*testing.T, *MCPResponse)
	}{
		{
			name: "response has jsonrpc field",
			request: &MCPRequest{
				JSONRPC: "2.0",
				ID:      1,
				Method:  "initialize",
			},
			checkFn: func(t *testing.T, resp *MCPResponse) {
				assert.Equal(t, "2.0", resp.JSONRPC)
			},
		},
		{
			name: "response has matching id",
			request: &MCPRequest{
				JSONRPC: "2.0",
				ID:      42,
				Method:  "tools/list",
			},
			checkFn: func(t *testing.T, resp *MCPResponse) {
				assert.Equal(t, 42, resp.ID)
			},
		},
		{
			name: "success response has result field",
			request: &MCPRequest{
				JSONRPC: "2.0",
				ID:      1,
				Method:  "initialize",
			},
			checkFn: func(t *testing.T, resp *MCPResponse) {
				assert.NotNil(t, resp.Result)
				assert.Nil(t, resp.Error)
			},
		},
		{
			name: "error response has error field",
			request: &MCPRequest{
				JSONRPC: "2.0",
				ID:      1,
				Method:  "invalid/method",
			},
			checkFn: func(t *testing.T, resp *MCPResponse) {
				assert.Nil(t, resp.Result)
				assert.NotNil(t, resp.Error)
				assert.NotEmpty(t, resp.Error.Message)
				assert.NotZero(t, resp.Error.Code)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := server.handleRequest(tt.request)
			tt.checkFn(t, resp)
		})
	}
}

// TestConfigValidation tests configuration validation
func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		shouldErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				ServerURL: "http://localhost:8080",
				JWTToken:  "token",
			},
			shouldErr: false,
		},
		{
			name: "empty server URL is accepted by NewServer (validation at runtime)",
			config: &Config{
				ServerURL: "",
				JWTToken:  "token",
			},
			shouldErr: false, // NewServer doesn't validate yet
		},
		{
			name: "empty JWT token is accepted by NewServer (validation at runtime)",
			config: &Config{
				ServerURL: "http://localhost:8080",
				JWTToken:  "",
			},
			shouldErr: false, // NewServer doesn't validate yet
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := NewServer(tt.config)
			if tt.shouldErr {
				assert.Error(t, err)
				assert.Nil(t, server)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, server)
			}
		})
	}
}
