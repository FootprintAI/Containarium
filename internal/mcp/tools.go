package mcp

import (
	"encoding/json"
	"fmt"
)

// Tool represents an MCP tool (function)
type Tool struct {
	Name        string
	Description string
	InputSchema map[string]interface{}
	Handler     ToolHandler
}

// ToolHandler is a function that handles a tool call
type ToolHandler func(client *Client, args map[string]interface{}) (string, error)

// registerTools registers all available MCP tools
func (s *Server) registerTools() {
	s.tools = []Tool{
		{
			Name:        "create_container",
			Description: "Create a new LXC container for a user with specified resources and SSH keys",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Username for the container (required)",
					},
					"cpu": map[string]interface{}{
						"type":        "string",
						"description": "CPU limit (e.g., '4' for 4 cores, default: 4)",
					},
					"memory": map[string]interface{}{
						"type":        "string",
						"description": "Memory limit (e.g., '4GB', '2048MB', default: 4GB)",
					},
					"disk": map[string]interface{}{
						"type":        "string",
						"description": "Disk limit (e.g., '50GB', '100GB', default: 50GB)",
					},
					"ssh_keys": map[string]interface{}{
						"type":        "array",
						"items":       map[string]string{"type": "string"},
						"description": "SSH public keys to authorize (optional)",
					},
					"image": map[string]interface{}{
						"type":        "string",
						"description": "Container image (default: images:ubuntu/24.04)",
					},
					"enable_docker": map[string]interface{}{
						"type":        "boolean",
						"description": "Enable Docker support (default: true)",
					},
				},
				"required": []string{"username"},
			},
			Handler: handleCreateContainer,
		},
		{
			Name:        "list_containers",
			Description: "List all containers with their status and resource usage",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
			Handler: handleListContainers,
		},
		{
			Name:        "get_container",
			Description: "Get detailed information about a specific container including metrics",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Username of the container to get",
					},
				},
				"required": []string{"username"},
			},
			Handler: handleGetContainer,
		},
		{
			Name:        "delete_container",
			Description: "Delete a container permanently",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Username of the container to delete",
					},
					"force": map[string]interface{}{
						"type":        "boolean",
						"description": "Force delete even if container is running (default: false)",
					},
				},
				"required": []string{"username"},
			},
			Handler: handleDeleteContainer,
		},
		{
			Name:        "start_container",
			Description: "Start a stopped container",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Username of the container to start",
					},
				},
				"required": []string{"username"},
			},
			Handler: handleStartContainer,
		},
		{
			Name:        "stop_container",
			Description: "Stop a running container",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Username of the container to stop",
					},
					"force": map[string]interface{}{
						"type":        "boolean",
						"description": "Force stop (kill) instead of graceful shutdown (default: false)",
					},
				},
				"required": []string{"username"},
			},
			Handler: handleStopContainer,
		},
		{
			Name:        "get_metrics",
			Description: "Get runtime metrics (CPU, memory, disk, network) for containers",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Username of specific container (optional, empty for all containers)",
					},
				},
			},
			Handler: handleGetMetrics,
		},
		{
			Name:        "get_system_info",
			Description: "Get information about the Containarium host system",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
			Handler: handleGetSystemInfo,
		},
	}
}

// Tool handlers

func handleCreateContainer(client *Client, args map[string]interface{}) (string, error) {
	username, ok := args["username"].(string)
	if !ok || username == "" {
		return "", fmt.Errorf("username is required")
	}

	req := CreateContainerRequest{
		Username: username,
		Resources: &ResourceLimits{
			CPU:    getStringArg(args, "cpu", "4"),
			Memory: getStringArg(args, "memory", "4GB"),
			Disk:   getStringArg(args, "disk", "50GB"),
		},
		Image:        getStringArg(args, "image", "images:ubuntu/24.04"),
		EnableDocker: getBoolArg(args, "enable_docker", true),
	}

	// Handle SSH keys
	if sshKeys, ok := args["ssh_keys"].([]interface{}); ok {
		for _, key := range sshKeys {
			if keyStr, ok := key.(string); ok {
				req.SSHKeys = append(req.SSHKeys, keyStr)
			}
		}
	}

	resp, err := client.CreateContainer(req)
	if err != nil {
		return "", fmt.Errorf("failed to create container: %w", err)
	}

	result := fmt.Sprintf("✅ Container created successfully!\n\n")
	result += fmt.Sprintf("Name: %s\n", resp.Container.Name)
	result += fmt.Sprintf("Username: %s\n", resp.Container.Username)
	result += fmt.Sprintf("State: %s\n", resp.Container.State)
	if resp.Container.Network != nil && resp.Container.Network.IPAddress != "" {
		result += fmt.Sprintf("IP Address: %s\n", resp.Container.Network.IPAddress)
	}
	if resp.Container.Resources != nil {
		result += fmt.Sprintf("CPU: %s\n", resp.Container.Resources.CPU)
		result += fmt.Sprintf("Memory: %s\n", resp.Container.Resources.Memory)
		result += fmt.Sprintf("Disk: %s\n", resp.Container.Resources.Disk)
	}
	result += fmt.Sprintf("\n%s", resp.Message)

	return result, nil
}

func handleListContainers(client *Client, args map[string]interface{}) (string, error) {
	resp, err := client.ListContainers()
	if err != nil {
		return "", fmt.Errorf("failed to list containers: %w", err)
	}

	if len(resp.Containers) == 0 {
		return "No containers found.", nil
	}

	result := fmt.Sprintf("Found %d container(s):\n\n", resp.TotalCount)
	for _, container := range resp.Containers {
		result += fmt.Sprintf("📦 %s\n", container.Name)
		result += fmt.Sprintf("   Username: %s\n", container.Username)
		result += fmt.Sprintf("   State: %s\n", container.State)
		if container.Network != nil && container.Network.IPAddress != "" {
			result += fmt.Sprintf("   IP: %s\n", container.Network.IPAddress)
		}
		if container.Resources != nil {
			result += fmt.Sprintf("   Resources: CPU=%s, Memory=%s, Disk=%s\n",
				container.Resources.CPU, container.Resources.Memory, container.Resources.Disk)
		}
		result += "\n"
	}

	return result, nil
}

func handleGetContainer(client *Client, args map[string]interface{}) (string, error) {
	username, ok := args["username"].(string)
	if !ok || username == "" {
		return "", fmt.Errorf("username is required")
	}

	resp, err := client.GetContainer(username)
	if err != nil {
		return "", fmt.Errorf("failed to get container: %w", err)
	}

	// Pretty print as JSON
	jsonData, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal response: %w", err)
	}

	return string(jsonData), nil
}

func handleDeleteContainer(client *Client, args map[string]interface{}) (string, error) {
	username, ok := args["username"].(string)
	if !ok || username == "" {
		return "", fmt.Errorf("username is required")
	}

	force := getBoolArg(args, "force", false)

	resp, err := client.DeleteContainer(username, force)
	if err != nil {
		return "", fmt.Errorf("failed to delete container: %w", err)
	}

	return fmt.Sprintf("✅ %s", resp.Message), nil
}

func handleStartContainer(client *Client, args map[string]interface{}) (string, error) {
	username, ok := args["username"].(string)
	if !ok || username == "" {
		return "", fmt.Errorf("username is required")
	}

	resp, err := client.StartContainer(username)
	if err != nil {
		return "", fmt.Errorf("failed to start container: %w", err)
	}

	return fmt.Sprintf("✅ %s\nContainer state: %s", resp.Message, resp.Container.State), nil
}

func handleStopContainer(client *Client, args map[string]interface{}) (string, error) {
	username, ok := args["username"].(string)
	if !ok || username == "" {
		return "", fmt.Errorf("username is required")
	}

	force := getBoolArg(args, "force", false)

	resp, err := client.StopContainer(username, force)
	if err != nil {
		return "", fmt.Errorf("failed to stop container: %w", err)
	}

	return fmt.Sprintf("✅ %s\nContainer state: %s", resp.Message, resp.Container.State), nil
}

func handleGetMetrics(client *Client, args map[string]interface{}) (string, error) {
	username := getStringArg(args, "username", "")

	resp, err := client.GetMetrics(username)
	if err != nil {
		return "", fmt.Errorf("failed to get metrics: %w", err)
	}

	if len(resp.Metrics) == 0 {
		return "No metrics available.", nil
	}

	result := fmt.Sprintf("Container Metrics (%d container(s)):\n\n", len(resp.Metrics))
	for _, m := range resp.Metrics {
		result += fmt.Sprintf("📊 %s\n", m.Name)
		result += fmt.Sprintf("   CPU Usage: %d seconds\n", m.CPUUsageSeconds)
		result += fmt.Sprintf("   Memory: %d MB / %d MB peak\n",
			m.MemoryUsageBytes/1024/1024, m.MemoryPeakBytes/1024/1024)
		result += fmt.Sprintf("   Disk: %d MB\n", m.DiskUsageBytes/1024/1024)
		result += fmt.Sprintf("   Network: ↓%d MB ↑%d MB\n",
			m.NetworkRxBytes/1024/1024, m.NetworkTxBytes/1024/1024)
		result += fmt.Sprintf("   Processes: %d\n", m.ProcessCount)
		result += "\n"
	}

	return result, nil
}

func handleGetSystemInfo(client *Client, args map[string]interface{}) (string, error) {
	resp, err := client.GetSystemInfo()
	if err != nil {
		return "", fmt.Errorf("failed to get system info: %w", err)
	}

	result := "🖥️  System Information:\n\n"
	result += fmt.Sprintf("Hostname: %s\n", resp.Info.Hostname)
	result += fmt.Sprintf("OS: %s\n", resp.Info.OS)
	result += fmt.Sprintf("Kernel: %s\n", resp.Info.KernelVersion)
	result += fmt.Sprintf("Incus Version: %s\n", resp.Info.IncusVersion)
	result += fmt.Sprintf("\nContainers:\n")
	result += fmt.Sprintf("  Running: %d\n", resp.Info.ContainersRunning)
	result += fmt.Sprintf("  Stopped: %d\n", resp.Info.ContainersStopped)
	result += fmt.Sprintf("  Total: %d\n", resp.Info.ContainersTotal)

	return result, nil
}

// Helper functions

func getStringArg(args map[string]interface{}, key, defaultValue string) string {
	if val, ok := args[key].(string); ok && val != "" {
		return val
	}
	return defaultValue
}

func getBoolArg(args map[string]interface{}, key string, defaultValue bool) bool {
	if val, ok := args[key].(bool); ok {
		return val
	}
	return defaultValue
}
