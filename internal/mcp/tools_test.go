package mcp

import (
	"encoding/json"
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

			// Description should be reasonable length
			assert.GreaterOrEqual(t, len(desc), 20, "Description too short")
			assert.LessOrEqual(t, len(desc), 500, "Description too long")

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
