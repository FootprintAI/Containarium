package guacamole

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client wraps the Apache Guacamole REST API.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// New creates a new Guacamole REST API client.
func New(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// authResponse is the response from POST /api/tokens.
type authResponse struct {
	AuthToken  string `json:"authToken"`
	Username   string `json:"username"`
	DataSource string `json:"dataSource"`
}

// Authenticate obtains an auth token from Guacamole.
func (c *Client) Authenticate(username, password string) (string, error) {
	data := url.Values{
		"username": {username},
		"password": {password},
	}

	resp, err := c.httpClient.PostForm(c.baseURL+"/api/tokens", data)
	if err != nil {
		return "", fmt.Errorf("guacamole auth request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("guacamole auth failed (status %d): %s", resp.StatusCode, body)
	}

	var authResp authResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return "", fmt.Errorf("failed to decode auth response: %w", err)
	}

	return authResp.AuthToken, nil
}

// ConnectionConfig defines an RDP connection in Guacamole.
type ConnectionConfig struct {
	Name     string // Display name for the connection
	Hostname string // RDP target hostname/IP
	Port     string // RDP port (typically "3389")
	Username string // RDP username (e.g., "Administrator")
	Password string // RDP password
}

// connectionRequest is the Guacamole API request body for creating a connection.
type connectionRequest struct {
	ParentIdentifier string            `json:"parentIdentifier"`
	Name             string            `json:"name"`
	Protocol         string            `json:"protocol"`
	Parameters       map[string]string `json:"parameters"`
	Attributes       map[string]string `json:"attributes"`
}

// connectionResponse is the Guacamole API response from creating a connection.
type connectionResponse struct {
	Identifier       string `json:"identifier"`
	Name             string `json:"name"`
	ParentIdentifier string `json:"parentIdentifier"`
	Protocol         string `json:"protocol"`
}

// CreateConnection registers a new RDP connection in Guacamole.
// Returns the connection identifier.
func (c *Client) CreateConnection(authToken string, config ConnectionConfig) (string, error) {
	reqBody := connectionRequest{
		ParentIdentifier: "ROOT",
		Name:             config.Name,
		Protocol:         "rdp",
		Parameters: map[string]string{
			"hostname":         config.Hostname,
			"port":             config.Port,
			"username":         config.Username,
			"password":         config.Password,
			"security":         "nla",
			"ignore-cert":      "true",
			"resize-method":    "display-update",
			"enable-wallpaper": "true",
		},
		Attributes: map[string]string{
			"max-connections":          "2",
			"max-connections-per-user": "2",
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal connection request: %w", err)
	}

	reqURL := fmt.Sprintf("%s/api/session/data/postgresql/connections?token=%s", c.baseURL, authToken)
	req, err := http.NewRequest(http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("guacamole create connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("guacamole create connection failed (status %d): %s", resp.StatusCode, respBody)
	}

	var connResp connectionResponse
	if err := json.NewDecoder(resp.Body).Decode(&connResp); err != nil {
		return "", fmt.Errorf("failed to decode connection response: %w", err)
	}

	return connResp.Identifier, nil
}

// DeleteConnection removes a connection from Guacamole.
func (c *Client) DeleteConnection(authToken, connectionID string) error {
	reqURL := fmt.Sprintf("%s/api/session/data/postgresql/connections/%s?token=%s", c.baseURL, connectionID, authToken)
	req, err := http.NewRequest(http.MethodDelete, reqURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create delete request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("guacamole delete connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("guacamole delete connection failed (status %d): %s", resp.StatusCode, body)
	}

	return nil
}

// GetConnectionURL returns the Guacamole client URL for a given connection ID.
// The returned path is relative to the Guacamole base URL.
func GetConnectionURL(connectionID string) string {
	// Guacamole client URL format: /#/client/{base64-encoded-id}
	// The connection identifier for PostgreSQL datasource is: {id}\0c\0postgresql
	// Base64-encoded for URL embedding
	return fmt.Sprintf("/#/client/%s", connectionID)
}
