package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/footprintai/containarium/pkg/version"
)

// Server implements the MCP (Model Context Protocol) server
type Server struct {
	config *Config
	client API
	tools  []Tool
}

// NewServer creates a new MCP server. The backend is selected by newBackend
// from the credential: a hosted-control-plane API token (`ctnr_…`) gets the
// cloud backend (host-level ops report "not available here"); anything else
// gets the OSS daemon backend.
func NewServer(config *Config) (*Server, error) {
	server := &Server{
		config: config,
		client: newBackend(config),
		tools:  []Tool{},
	}

	// Register all tools
	server.registerTools()

	// #1922 step 7 — operator-curated tool allow-list, e.g. "tracker_*"
	// for an in-box agent mounting this server with a narrowly-scoped
	// JWT. Empty (the default) leaves every registered tool available,
	// unchanged from before this existed.
	if config.MCPTools != "" {
		filtered, err := filterToolsByAllowlist(server.tools, config.MCPTools)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", EnvMCPTools, err)
		}
		server.tools = filtered
	}

	return server, nil
}

// Start starts the MCP server (reads from stdin, writes to stdout)
func (s *Server) Start() error {
	scanner := bufio.NewScanner(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)

	for scanner.Scan() {
		line := scanner.Bytes()

		if s.config.Debug {
			log.Printf("Received: %s", string(line))
		}

		response, reply := s.handleLine(line)
		if !reply {
			continue
		}
		if err := encoder.Encode(response); err != nil {
			log.Printf("Failed to encode response: %v", err)
			continue
		}

		if s.config.Debug {
			respJSON, _ := json.Marshal(response)
			log.Printf("Sent: %s", string(respJSON))
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scanner error: %w", err)
	}

	return nil
}

// handleLine turns one line read from the client into the reply to send, and
// says whether there is one. It exists so that decision is a pure function of
// the bytes in, testable without a pipe.
//
// A message with no "id" member is a NOTIFICATION. JSON-RPC 2.0 says the server
// must not reply to one, and MCP clients send them on every connection —
// notifications/initialized closes the handshake. This server used to run every
// line through handleRequest, which answered the unknown method
// notifications/initialized with an error whose id is null; Claude Code's client
// validates responses strictly, rejects id:null and drops the connection about a
// second after it opens, so the agent saw its MCP server as failed and had no
// tools (#2529). Notifications are now consumed silently.
//
// Only a message that is not valid JSON gets an id:null error: with no id to
// echo, JSON-RPC defines exactly that reply.
func (s *Server) handleLine(line []byte) (*MCPResponse, bool) {
	var request MCPRequest
	if err := json.Unmarshal(line, &request); err != nil {
		return s.createErrorResponse(nil, -32700, "Parse error", err.Error()), true
	}

	// Presence, not value: "id": null is a request (discouraged, but a request),
	// a missing id is a notification. MCPRequest.ID cannot tell them apart.
	var members map[string]json.RawMessage
	if err := json.Unmarshal(line, &members); err == nil {
		if _, hasID := members["id"]; !hasID {
			if s.config.Debug {
				log.Printf("Notification %q: no reply", request.Method)
			}
			return nil, false
		}
	}

	return s.handleRequest(&request), true
}

// handleRequest handles an MCP request
func (s *Server) handleRequest(req *MCPRequest) *MCPResponse {
	switch req.Method {
	case "initialize":
		return s.handleInitialize(req)
	case "tools/list":
		return s.handleToolsList(req)
	case "tools/call":
		return s.handleToolsCall(req)
	case "ping":
		// Clients use ping as a liveness check; the answer is an empty result.
		return &MCPResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]interface{}{}}
	default:
		return s.createErrorResponse(req.ID, -32601, "Method not found", fmt.Sprintf("Unknown method: %s", req.Method))
	}
}

// handleInitialize handles the initialize request
func (s *Server) handleInitialize(req *MCPRequest) *MCPResponse {
	return &MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]interface{}{
				"tools": map[string]bool{},
			},
			"serverInfo": map[string]interface{}{
				"name":    "containarium-mcp-server",
				"version": version.GetVersion(),
			},
		},
	}
}

// handleToolsList handles the tools/list request. Phase 1.7
// — when the JWT carries a `scopes` claim we filter the
// catalog down to tools whose RequiredScope the token can
// satisfy. A nil/missing scopes claim is treated as "no
// restriction" (backwards compat for pre-1.7 tokens), in
// which case every registered tool is returned.
func (s *Server) handleToolsList(req *MCPRequest) *MCPResponse {
	granted := s.allowedScopes()
	tools := make([]map[string]interface{}, 0, len(s.tools))
	for i := range s.tools {
		if !toolAllowed(granted, &s.tools[i]) {
			continue
		}
		tools = append(tools, map[string]interface{}{
			"name":        s.tools[i].Name,
			"description": s.tools[i].Description,
			"inputSchema": s.tools[i].InputSchema,
		})
	}

	return &MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"tools": tools,
		},
	}
}

// handleToolsCall handles the tools/call request
func (s *Server) handleToolsCall(req *MCPRequest) *MCPResponse {
	var params struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}

	// Parse params
	paramsJSON, err := json.Marshal(req.Params)
	if err != nil {
		return s.createErrorResponse(req.ID, -32602, "Invalid params", err.Error())
	}

	if err := json.Unmarshal(paramsJSON, &params); err != nil {
		return s.createErrorResponse(req.ID, -32602, "Invalid params", err.Error())
	}

	// Find tool
	var tool *Tool
	for i := range s.tools {
		if s.tools[i].Name == params.Name {
			tool = &s.tools[i]
			break
		}
	}

	if tool == nil {
		return s.createErrorResponse(req.ID, -32602, "Tool not found", fmt.Sprintf("Tool '%s' not found", params.Name))
	}

	// Phase 1.7 — refuse calls to tools the JWT's scope set
	// doesn't cover. Daemon-side gates still enforce the
	// canonical check; this is a fast local rejection so
	// out-of-scope tool calls don't even hit the network.
	if !toolAllowed(s.allowedScopes(), tool) {
		return s.createErrorResponse(req.ID, -32603,
			fmt.Sprintf("Tool '%s' requires scope %s which the current token does not grant", tool.Name, requiredScopeText(tool)),
			"insufficient scope")
	}

	// Execute tool
	result, err := tool.Handler(s.client, params.Arguments)
	if err != nil {
		// Surface the actual error message in `message` so it reaches MCP
		// clients that only render the top-level `message` field (most do,
		// including Claude Code). The full err string also lands in `data`
		// for clients that show both. Constant "Tool execution failed"
		// alone was a UX deadend — every failure looked identical from
		// the agent's POV.
		return s.createErrorResponse(req.ID, -32603,
			fmt.Sprintf("Tool execution failed: %v", err),
			err.Error())
	}

	return &MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": result,
				},
			},
		},
	}
}

// createErrorResponse creates an error response
func (s *Server) createErrorResponse(id interface{}, code int, message, data string) *MCPResponse {
	return &MCPResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &MCPError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
}

// MCP protocol types

type MCPRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type MCPResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *MCPError   `json:"error,omitempty"`
}

type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}
